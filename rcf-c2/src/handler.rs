//! Session handler — manages command execution for a single session.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::session::{SessionManager, SessionCommand, SessionOutput};

/// Handles a single C2 session.
pub struct SessionHandler {
    session_num: u32,
    sessions: Arc<SessionManager>,
}

impl SessionHandler {
    pub fn new(session_num: u32, sessions: Arc<SessionManager>) -> Self {
        Self {
            session_num,
            sessions,
        }
    }

    /// Run the session handler loop.
    pub async fn run(
        self,
        socket: TcpStream,
        mut rx: mpsc::Receiver<SessionCommand>,
    ) -> anyhow::Result<()> {
        let peer = socket.peer_addr()?;
        let local = socket.local_addr()?;

        // Update session with addresses
        self.sessions
            .update_session_info(self.session_num, &local.to_string(), &format!("connected from {}", peer.ip()))
            .await;

        let mut reader = BufReader::new(socket);

        // Send welcome banner
        let banner = "\n[*] RCF Agent -- Session Established\n[*] Type 'exit' to close session\n\n$ ";
        let _ = reader.get_mut().write_all(banner.as_bytes()).await;

        let mut line = String::new();

        loop {
            tokio::select! {
                // Read from socket (agent output)
                result = reader.read_line(&mut line) => {
                    match result {
                        Ok(0) => {
                            // Connection closed
                            info!("Session {} disconnected", self.session_num);
                            break;
                        }
                        Ok(n) => {
                            let data = line.drain(..n).collect::<String>();
                            debug!("Session {} received: {:?}", self.session_num, data);
                            // In a real implementation, this would be forwarded to the console
                        }
                        Err(e) => {
                            warn!("Session {} read error: {}", self.session_num, e);
                            break;
                        }
                    }
                }

                // Send command to agent
                Some(cmd) = rx.recv() => {
                    match cmd {
                        SessionCommand::Execute(command) => {
                            if command.trim() == "exit" || command.trim() == "quit" {
                                info!("Session {} closing via exit command", self.session_num);
                                let _ = reader.get_mut().write_all(b"exit\n").await;
                                break;
                            }

                            debug!("Session {} executing: {}", self.session_num, command);
                            let cmd_with_nl = format!("{}\n", command.trim());
                            if let Err(e) = reader.get_mut().write_all(cmd_with_nl.as_bytes()).await {
                                warn!("Failed to send command to session {}: {}", self.session_num, e);
                            }

                            // Send prompt after command
                            let _ = reader.get_mut().write_all(b"$ ").await;
                        }

                        SessionCommand::Data(data) => {
                            if let Err(e) = reader.get_mut().write_all(&data).await {
                                warn!("Failed to send data to session {}: {}", self.session_num, e);
                            }
                        }

                        SessionCommand::Close => {
                            info!("Session {} closing via command", self.session_num);
                            break;
                        }
                    }
                }
            }
        }

        // Mark session as closed
        self.sessions.kill_session(self.session_num).await;

        Ok(())
    }

    /// Execute a command on the session and wait for output.
    pub async fn execute_command(
        &self,
        socket: &mut TcpStream,
        command: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<SessionOutput> {
        // Send command
        socket
            .write_all(format!("{}\n", command).as_bytes())
            .await?;

        // Read response with timeout
        let mut output = Vec::new();
        let mut buf = [0u8; 4096];

        match tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            socket.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) => {
                output.extend_from_slice(&buf[..n]);
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => warn!("Command timed out on session {}", self.session_num),
        }

        let output_str = String::from_utf8_lossy(&output).to_string();

        Ok(SessionOutput {
            session_id: self.session_num.to_string(),
            command: command.to_string(),
            stdout: output_str,
            stderr: String::new(),
            exit_code: None,
        })
    }
}
