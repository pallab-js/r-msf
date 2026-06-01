//! C2 Server — TCP listener for incoming agent connections.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::auth::{AuthMethod, AuthResult, C2Auth};
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
    /// Pre-shared key for agent authentication (optional, legacy v0.2 compat)
    pub psk: Option<String>,
    /// Whether to use legacy PSK-only mode (v0.2 compat)
    pub legacy_psk: bool,
    /// Path to authorized keys directory
    pub authorized_keys_dir: Option<String>,
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
            legacy_psk: false,
            authorized_keys_dir: None,
            use_tls: false,
            control_port: None,
        }
    }

    /// Set a pre-shared key for agent authentication.
    pub fn with_psk(mut self, psk: String) -> Self {
        self.psk = Some(psk);
        self
    }

    /// Enable legacy PSK-only mode.
    pub fn with_legacy_psk(mut self) -> Self {
        self.legacy_psk = true;
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
    pub auth_method: AuthMethod,
    pub session_token: Option<[u8; 32]>,
}

/// The main C2 server.
pub struct C2Server {
    config: C2Config,
    sessions: Arc<SessionManager>,
    running: Arc<tokio::sync::Notify>,
    shutdown_triggered: Arc<std::sync::atomic::AtomicBool>,
    rate_limiter: SlidingWindowRateLimiter,
    auth: Arc<C2Auth>,
}

impl C2Server {
    pub fn new(config: C2Config, sessions: Arc<SessionManager>) -> Self {
        // Build the authenticator based on config
        let auth = if config.legacy_psk {
            let psk = config.psk.clone().unwrap_or_default();
            C2Auth::with_psk(psk)
        } else if let Some(ref psk) = config.psk {
            // Migration mode: PSK + Ed25519
            let keys = crate::auth::AuthorizedKeys::new();
            if let Some(ref dir) = config.authorized_keys_dir {
                let keys_clone = keys.clone();
                let dir_path = std::path::Path::new(dir);
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        match keys_clone.load_from_dir(dir_path).await {
                            Ok(count) => {
                                if count > 0 {
                                    info!("Loaded {} authorized keys from {}", count, dir);
                                }
                            }
                            Err(e) => warn!("Failed to load authorized keys: {}", e),
                        }
                    });
                });
            }
            C2Auth::with_both(psk.clone(), keys)
        } else {
            let keys = crate::auth::AuthorizedKeys::new();
            if let Some(ref dir) = config.authorized_keys_dir {
                let keys_clone = keys.clone();
                let dir_path = std::path::Path::new(dir);
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        match keys_clone.load_from_dir(dir_path).await {
                            Ok(count) => {
                                if count > 0 {
                                    info!("Loaded {} authorized keys from {}", count, dir);
                                }
                            }
                            Err(e) => warn!("Failed to load authorized keys: {}", e),
                        }
                    });
                });
            }
            C2Auth::with_authorized_keys(keys)
        };

        Self {
            config,
            sessions,
            running: Arc::new(tokio::sync::Notify::new()),
            shutdown_triggered: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            // Sliding window: 100 connections per 60 seconds
            rate_limiter: SlidingWindowRateLimiter::new(Duration::from_secs(60), 100),
            auth: Arc::new(auth),
        }
    }

    pub fn auth(&self) -> &Arc<C2Auth> {
        &self.auth
    }

    /// Start the C2 server listener.
    pub async fn start(&self) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        let listener = TcpListener::bind(&addr).await?;

        let auth_method = if self.config.legacy_psk {
            "psk (legacy)"
        } else if self.config.psk.is_some() {
            "ed25519 + psk (migration)"
        } else {
            "ed25519"
        };

        info!(
            addr = %addr,
            auth_method = %auth_method,
            "C2 server listening for connections"
        );

        // Start control server for console interaction
        let control_port = self
            .config
            .control_port
            .unwrap_or(self.config.listen_port + 1);
        let sessions_clone = Arc::clone(&self.sessions);
        let control_addr = format!("127.0.0.1:{}", control_port);
        let psk_for_control = self.config.psk.clone();
        info!(
            "C2 control server listening on {} (loopback only)",
            control_addr
        );

        let _control_handle = tokio::spawn(async move {
            if let Err(e) = crate::control::start_control_server_with_psk(
                "127.0.0.1",
                control_port,
                sessions_clone,
                psk_for_control,
            )
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
                                continue;
                            }

                            let session_count = self.sessions.active_count().await;
                            if session_count >= self.config.max_sessions {
                                warn!("Max sessions reached ({}), rejecting {}", session_count, peer_addr);
                                continue;
                            }

                            info!("New connection from {}", peer_addr);

                            // Authenticate connection
                            let auth = Arc::clone(&self.auth);
                            if let Err(e) = Self::authenticate_connection(&mut socket, peer_addr, &auth).await {
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

    /// Authenticate an incoming connection using the configured auth method.
    async fn authenticate_connection(
        socket: &mut tokio::net::TcpStream,
        peer_addr: SocketAddr,
        auth: &C2Auth,
    ) -> anyhow::Result<AuthResult> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let peer_str = peer_addr.to_string();

        // For Ed25519 auth, first issue a challenge
        if !auth.is_legacy_mode() {
            let nonce = auth.issue_challenge(&peer_str).await;
            // Send challenge to agent: "RCF_CHALLENGE:<nonce_hex>\n"
            let challenge_msg = format!("RCF_CHALLENGE:{}\n", hex::encode(nonce));
            socket.write_all(challenge_msg.as_bytes()).await?;
        }

        // Read initial greeting from agent
        let mut buf = [0u8; 512];
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            anyhow::bail!("Connection closed during authentication");
        }

        // Verify agent response
        let result = auth.verify_agent(&peer_str, &buf[..n]).await;

        if result.success {
            info!(
                "Agent {} authenticated successfully (method: {})",
                peer_addr, result.method
            );
            socket.write_all(b"RCF_AUTH_SUCCESS\n").await?;
            Ok(result)
        } else {
            warn!(
                "Authentication failed from {}: {}",
                peer_addr,
                result.reason.as_deref().unwrap_or("unknown")
            );
            socket.write_all(b"AUTH_FAILED\n").await?;
            anyhow::bail!(
                "Authentication failed: {}",
                result.reason.unwrap_or_default()
            );
        }
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
