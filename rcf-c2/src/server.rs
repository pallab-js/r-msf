//! C2 Server — TCP listener for incoming agent connections.

use std::net::SocketAddr;
use std::sync::Arc;

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
}

impl C2Config {
    pub fn new(listen_addr: &str, listen_port: u16) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            listen_port,
            max_sessions: 100,
            heartbeat_interval_secs: 30,
        }
    }
}

/// The main C2 server.
pub struct C2Server {
    config: C2Config,
    sessions: Arc<SessionManager>,
    running: Arc<tokio::sync::Notify>,
}

impl C2Server {
    pub fn new(config: C2Config, sessions: Arc<SessionManager>) -> Self {
        Self {
            config,
            sessions,
            running: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Start the C2 server listener.
    pub async fn start(&self) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        let listener = TcpListener::bind(&addr).await?;

        info!(
            addr = %addr,
            "C2 server listening for connections"
        );

        loop {
            tokio::select! {
                _ = self.running.notified() => {
                    info!("C2 server shutting down");
                    break;
                }

                result = listener.accept() => {
                    match result {
                        Ok((socket, peer_addr)) => {
                            let session_count = self.sessions.active_count().await;
                            if session_count >= self.config.max_sessions {
                                warn!("Max sessions reached ({}), rejecting {}", session_count, peer_addr);
                                continue;
                            }

                            info!("New connection from {}", peer_addr);
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

    /// Stop the C2 server.
    pub fn stop(&self) {
        self.running.notify_one();
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
