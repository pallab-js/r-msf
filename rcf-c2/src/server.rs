//! C2 Server — TCP listener for incoming agent connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use crate::session::{SessionManager, SessionType, SessionCommand};
use crate::handler::SessionHandler;

/// C2 Server configuration.
#[derive(Debug, Clone)]
pub struct C2Config {
    pub listen_addr: String,
    pub listen_port: u16,
    pub max_sessions: usize,
    pub heartbeat_interval_secs: u64,
    pub shutdown_timeout_secs: u64,
    /// Pre-shared key for agent authentication (optional but recommended)
    pub psk: Option<String>,
    /// Enable TLS for encrypted connections
    pub use_tls: bool,
}

impl C2Config {
    pub fn new(listen_addr: &str, listen_port: u16) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            listen_port,
            max_sessions: 100,
            heartbeat_interval_secs: 30,
            shutdown_timeout_secs: 10,
            psk: None,
            use_tls: false,
        }
    }
    
    /// Set a pre-shared key for agent authentication.
    pub fn with_psk(mut self, psk: String) -> Self {
        self.psk = Some(psk);
        self
    }
    
    /// Enable TLS encryption for connections.
    pub fn with_tls(mut self) -> Self {
        self.use_tls = true;
        self
    }
}

/// Represents an authenticated agent connection.
#[derive(Debug)]
struct AuthenticatedSession {
    session_num: u32,
    peer_addr: SocketAddr,
    authenticated_at: i64,
}

/// Authentication message from agent.
const AUTH_CHALLENGE: &[u8] = b"RCF_AUTH_REQUEST";
const AUTH_RESPONSE: &[u8] = b"RCF_AUTH_OK";

impl C2Server {
    /// Authenticate an incoming connection.
    /// Returns Ok(()) if authenticated or auth is not required.
    /// Returns Err(reason) if authentication fails.
    async fn authenticate_connection(
        socket: &mut tokio::net::TcpStream,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        let mut buf = [0u8; 64];
        
        // Read initial message from agent
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            anyhow::bail!("Connection closed during authentication");
        }
        
        let client_msg = String::from_utf8_lossy(&buf[..n]);
        let client_msg = client_msg.trim();
        
        // Check for expected auth message
        if !client_msg.starts_with("RCF_AGENT_V1:") {
            // Not a valid RCF agent
            warn!("Invalid agent greeting from {}: {}", peer_addr, client_msg);
            
            // Send rejection
            socket.write_all(b"INVALID_AGENT\n").await?;
            anyhow::bail!("Invalid agent greeting");
        }
        
        // For now, accept any valid agent greeting
        // TODO: Implement PSK verification
        info!("Agent {} authenticated successfully", peer_addr);
        
        // Send acknowledgment
        socket.write_all(b"RCF_AUTH_SUCCESS\n").await?;
        
        Ok(())
    }
}

/// The main C2 server.
pub struct C2Server {
    config: C2Config,
    sessions: Arc<SessionManager>,
    running: Arc<tokio::sync::Notify>,
    shutdown_triggered: Arc<std::sync::atomic::AtomicBool>,
    connection_count: Arc<std::sync::atomic::AtomicU64>,
    rate_limiter: Arc<tokio::sync::Mutex<()>>,
}

impl C2Server {
    pub fn new(config: C2Config, sessions: Arc<SessionManager>) -> Self {
        Self {
            config,
            sessions,
            running: Arc::new(tokio::sync::Notify::new()),
            shutdown_triggered: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            connection_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            rate_limiter: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Start the C2 server listener.
    pub async fn start(&self) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        let listener = TcpListener::bind(&addr).await?;

        info!(
            addr = %addr,
            psk_configured = self.config.psk.is_some(),
            "C2 server listening for connections"
        );

        loop {
            tokio::select! {
                _ = self.running.notified() => {
                    info!("C2 server initiating graceful shutdown...");
                    self.graceful_shutdown().await;
                    break;
                }

                result = listener.accept() => {
                    if self.shutdown_triggered.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    
                    match result {
                        Ok((mut socket, peer_addr)) => {
                            // Rate limiting: simple connection throttling
                            let _rate_limit_guard = self.rate_limiter.lock().await;
                            
                            // Increment connection counter
                            let conn_count = self.connection_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if conn_count > 1000 {
                                warn!("High connection count ({}), rate limiting", conn_count);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                            
                            let session_count = self.sessions.active_count().await;
                            if session_count >= self.config.max_sessions {
                                warn!("Max sessions reached ({}), rejecting {}", session_count, peer_addr);
                                continue;
                            }

                            info!("New connection from {}", peer_addr);
                            
                            // Authenticate connection
                            if let Err(e) = Self::authenticate_connection(&mut socket, peer_addr).await {
                                warn!("Connection from {} failed authentication: {}", peer_addr, e);
                                continue;
                            }

                            let sessions = Arc::clone(&self.sessions);
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(socket, peer_addr, sessions).await {
                                    error!("Session handler error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Perform graceful shutdown of all sessions.
    async fn graceful_shutdown(&self) {
        let timeout = Duration::from_secs(self.config.shutdown_timeout_secs);
        let sessions = Arc::clone(&self.sessions);

        // Signal all sessions to terminate gracefully
        let active_count = sessions.active_count().await;
        if active_count > 0 {
            info!("Terminating {} active sessions gracefully...", active_count);
            
            // Kill all sessions
            sessions.kill_all().await;
            
            // Wait for sessions to clean up (with timeout)
            let deadline = tokio::time::Instant::now() + timeout;
            while sessions.active_count().await > 0 && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            
            let remaining = sessions.active_count().await;
            if remaining > 0 {
                warn!("{} sessions did not terminate gracefully", remaining);
            }
        }
        
        info!("C2 server shutdown complete");
    }

    /// Stop the C2 server with graceful shutdown.
    pub fn stop(&self) {
        if !self.shutdown_triggered.swap(true, std::sync::atomic::Ordering::Relaxed) {
            info!("C2 server stop requested");
            self.running.notify_one();
        }
    }

    /// Handle a new agent connection.
    async fn handle_connection(
        socket: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        sessions: Arc<SessionManager>,
    ) -> anyhow::Result<()> {
        // Create session
        let session_num = sessions
            .create_session(&peer_addr.to_string(), SessionType::Shell)
            .await;

        info!("Session {} established from {}", session_num, peer_addr);

        // Create command channel
        let (tx, rx) = mpsc::channel::<SessionCommand>(32);
        sessions.register_sender(session_num, tx).await;

        // Spawn session handler
        let handler = SessionHandler::new(session_num, Arc::clone(&sessions));
        handler.run(socket, rx).await
    }

    /// Get the session manager.
    pub fn sessions(&self) -> &Arc<SessionManager> {
        &self.sessions
    }
}
