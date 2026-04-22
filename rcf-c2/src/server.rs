//! C2 Server — TCP listener for incoming agent connections.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::handler::SessionHandler;
use crate::session::{SessionCommand, SessionManager, SessionType};

/// Sliding window rate limiter — tracks connections in a time window.
struct SlidingWindowRateLimiter {
    connections: Mutex<VecDeque<std::time::Instant>>,
    window: Duration,
    max_per_window: usize,
}

impl SlidingWindowRateLimiter {
    fn new(window: Duration, max_per_window: usize) -> Self {
        Self {
            connections: Mutex::new(VecDeque::new()),
            window,
            max_per_window,
        }
    }

    /// Check if a connection is allowed. Returns true if allowed, false if rate limited.
    async fn allow(&self) -> bool {
        let now = std::time::Instant::now();
        let mut conns = self.connections.lock().await;

        // Remove expired entries outside the window
        while let Some(&ts) = conns.front() {
            if now.duration_since(ts) > self.window {
                conns.pop_front();
            } else {
                break;
            }
        }

        if conns.len() >= self.max_per_window {
            false
        } else {
            conns.push_back(now);
            true
        }
    }
}

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
    /// Control port for console interaction (None = listen_port + 1)
    pub control_port: Option<u16>,
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
            control_port: None,
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

    /// Set the control port for console interaction.
    pub fn with_control_port(mut self, port: u16) -> Self {
        self.control_port = Some(port);
        self
    }
}

/// Represents an authenticated agent connection.
#[derive(Debug)]
pub struct AuthenticatedSession {
    pub session_num: u32,
    pub peer_addr: SocketAddr,
    pub authenticated_at: i64,
}

impl C2Server {
    /// Authenticate an incoming connection using PSK verification.
    /// Returns Ok(()) if authenticated or auth is not required.
    /// Returns Err(reason) if authentication fails.
    async fn authenticate_connection(
        socket: &mut tokio::net::TcpStream,
        peer_addr: SocketAddr,
        psk: &Option<String>,
    ) -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut buf = [0u8; 256];

        // Read initial message from agent
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            anyhow::bail!("Connection closed during authentication");
        }

        let client_msg = String::from_utf8_lossy(&buf[..n]);
        let client_msg = client_msg.trim();

        // Check for expected agent greeting prefix
        if !client_msg.starts_with("RCF_AGENT_V1:") {
            warn!("Invalid agent greeting from {}: {}", peer_addr, client_msg);
            socket.write_all(b"INVALID_AGENT\n").await?;
            anyhow::bail!("Invalid agent greeting");
        }

        // Extract PSK from greeting: "RCF_AGENT_V1:<psk>"
        let provided_psk = &client_msg["RCF_AGENT_V1:".len()..];

        // Verify PSK if configured - use constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        if let Some(expected_psk) = psk {
            let psk_equal = provided_psk.as_bytes().ct_eq(expected_psk.as_bytes());
            if bool::from(psk_equal) {
                warn!("PSK mismatch from {}: invalid key provided", peer_addr);
                socket.write_all(b"AUTH_FAILED\n").await?;
                anyhow::bail!("PSK mismatch");
            }
        }

        info!("Agent {} authenticated successfully", peer_addr);
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
    rate_limiter: SlidingWindowRateLimiter,
}

impl C2Server {
    pub fn new(config: C2Config, sessions: Arc<SessionManager>) -> Self {
        Self {
            config,
            sessions,
            running: Arc::new(tokio::sync::Notify::new()),
            shutdown_triggered: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            // Sliding window: 100 connections per 60 seconds
            rate_limiter: SlidingWindowRateLimiter::new(Duration::from_secs(60), 100),
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

        // Start control server for console interaction
        let control_port = self
            .config
            .control_port
            .unwrap_or(self.config.listen_port + 1);
        let sessions_clone = Arc::clone(&self.sessions);
        let control_addr = format!("{}:{}", self.config.listen_addr, control_port);
        let listen_addr = self.config.listen_addr.clone();
        info!(
            "C2 control server listening on {} (for console interaction)",
            control_addr
        );

        let _control_handle = tokio::spawn(async move {
            if let Err(e) =
                crate::control::start_control_server(&listen_addr, control_port, sessions_clone)
                    .await
            {
                error!("Control server error: {}", e);
            }
        });

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
                            // Rate limiting using sliding window
                            if !self.rate_limiter.allow().await {
                                warn!("Rate limiting connection from {} (too many connections in window)", peer_addr);
                                // Silently drop — don't waste resources on rate-limited connections
                                continue;
                            }

                            let session_count = self.sessions.active_count().await;
                            if session_count >= self.config.max_sessions {
                                warn!("Max sessions reached ({}), rejecting {}", session_count, peer_addr);
                                continue;
                            }

                            info!("New connection from {}", peer_addr);

                            // Authenticate connection
                            let psk = self.config.psk.clone();
                            if let Err(e) = Self::authenticate_connection(&mut socket, peer_addr, &psk).await {
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
        if !self
            .shutdown_triggered
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
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
