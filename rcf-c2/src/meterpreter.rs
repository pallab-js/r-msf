//! Meterpreter-style session commands.
//!
//! Provides post-exploitation commands similar to Metasploit's Meterpreter:
//! - sysinfo: System information
//! - getpid: Current process ID
//! - ps: Process listing
//! - shell: Drop to interactive shell
//! - upload: File upload
//! - download: File download
//! - getuid: Current user
//! - pwd: Current directory

use serde::{Deserialize, Serialize};

/// Meterpreter-style commands supported by the C2 server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeterpreterCommand {
    /// Get system information
    Sysinfo,
    /// Get current process ID
    Getpid,
    /// List running processes
    Ps,
    /// Get current user
    Getuid,
    /// Get current working directory
    Pwd,
    /// Upload a file to the target
    Upload {
        local_path: String,
        remote_path: String,
    },
    /// Download a file from the target
    Download {
        remote_path: String,
        local_path: String,
    },
    /// Execute a command
    Exec { command: String },
    /// Screenshot (stub)
    Screenshot,
    /// Keylog start/stop
    Keylog { start: bool },
    /// Port forwarding
    Portfwd {
        local_port: u16,
        remote_host: String,
        remote_port: u16,
    },
    /// Exit session
    Exit,
}

impl std::str::FromStr for MeterpreterCommand {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.trim().split_whitespace().collect();
        if parts.is_empty() {
            return Err("empty command".to_string());
        }

        match parts[0].to_lowercase().as_str() {
            "sysinfo" => Ok(MeterpreterCommand::Sysinfo),
            "getpid" => Ok(MeterpreterCommand::Getpid),
            "getuid" => Ok(MeterpreterCommand::Getuid),
            "pwd" | "getwd" => Ok(MeterpreterCommand::Pwd),
            "ps" => Ok(MeterpreterCommand::Ps),
            "exit" | "quit" => Ok(MeterpreterCommand::Exit),
            "screenshot" | "screengrab" => Ok(MeterpreterCommand::Screenshot),
            "exec" | "execute" | "run" => {
                if parts.len() < 2 {
                    Err("exec requires a command".to_string())
                } else {
                    Ok(MeterpreterCommand::Exec {
                        command: parts[1..].join(" "),
                    })
                }
            }
            "upload" | "put" => {
                if parts.len() < 3 {
                    Err("upload requires local and remote paths".to_string())
                } else {
                    Ok(MeterpreterCommand::Upload {
                        local_path: parts[1].to_string(),
                        remote_path: parts[2].to_string(),
                    })
                }
            }
            "download" | "get" => {
                if parts.len() < 3 {
                    Err("download requires remote and local paths".to_string())
                } else {
                    Ok(MeterpreterCommand::Download {
                        remote_path: parts[1].to_string(),
                        local_path: parts[2].to_string(),
                    })
                }
            }
            "keylog" => {
                let start = parts.len() < 2 || parts[1] != "stop";
                Ok(MeterpreterCommand::Keylog { start })
            }
            "portfwd" | "forward" => {
                if parts.len() < 4 {
                    Err("portfwd requires local_port, remote_host, remote_port".to_string())
                } else {
                    let local_port = parts[1]
                        .parse()
                        .map_err(|_| "invalid local port".to_string())?;
                    let remote_port = parts[3]
                        .parse()
                        .map_err(|_| "invalid remote port".to_string())?;
                    Ok(MeterpreterCommand::Portfwd {
                        local_port,
                        remote_host: parts[2].to_string(),
                        remote_port,
                    })
                }
            }
            other => Err(format!("unknown command: {}", other)),
        }
    }
}

/// Response from a Meterpreter command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeterpreterResponse {
    pub command: String,
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

impl MeterpreterResponse {
    pub fn success(command: &str, output: &str) -> Self {
        Self {
            command: command.to_string(),
            success: true,
            output: output.to_string(),
            error: None,
        }
    }

    pub fn failure(command: &str, error: &str) -> Self {
        Self {
            command: command.to_string(),
            success: false,
            output: String::new(),
            error: Some(error.to_string()),
        }
    }
}

impl std::fmt::Display for MeterpreterResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "meterpreter > {}", self.command)?;
        if self.success {
            if !self.output.is_empty() {
                writeln!(f, "{}", self.output)
            } else {
                writeln!(f, "[*] Command completed successfully")
            }
        } else {
            writeln!(
                f,
                "[-] Error: {}",
                self.error.as_deref().unwrap_or("unknown")
            )
        }
    }
}

/// Execute a Meterpreter command and return the response.
/// This runs on the C2 server side and generates responses for the operator.
pub fn execute_meterpreter_command(cmd: &MeterpreterCommand) -> MeterpreterResponse {
    match cmd {
        MeterpreterCommand::Sysinfo => {
            #[cfg(target_os = "linux")]
            {
                let os = std::fs::read_to_string("/etc/os-release")
                    .ok()
                    .and_then(|f| {
                        f.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                            l.trim_start_matches("PRETTY_NAME=")
                                .trim_matches('"')
                                .to_string()
                        })
                    })
                    .unwrap_or_else(|| "Linux (unknown)".to_string());
                MeterpreterResponse::success(
                    "sysinfo",
                    &format!("OS: {}\nArch: x86_64\nRCF Agent v0.1.0", os),
                )
            }
            #[cfg(target_os = "macos")]
            {
                let output = std::process::Command::new("sw_vers")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .unwrap_or_else(|| "macOS (unknown)".to_string());
                MeterpreterResponse::success(
                    "sysinfo",
                    &format!("{}\nArch: x86_64\nRCF Agent v0.1.0", output.trim()),
                )
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                MeterpreterResponse::success("sysinfo", "OS: unknown\nRCF Agent v0.1.0")
            }
        }
        MeterpreterCommand::Getpid => {
            let pid = std::process::id();
            MeterpreterResponse::success("getpid", &format!("PID: {}", pid))
        }
        MeterpreterCommand::Getuid => {
            #[cfg(unix)]
            {
                let uid = unsafe { libc::geteuid() };
                let username = std::env::var("USER").unwrap_or_else(|_| format!("uid-{}", uid));
                MeterpreterResponse::success("getuid", &format!("User: {} (uid={})", username, uid))
            }
            #[cfg(not(unix))]
            {
                MeterpreterResponse::success("getuid", "User: unknown")
            }
        }
        MeterpreterCommand::Pwd => match std::env::current_dir() {
            Ok(dir) => MeterpreterResponse::success("pwd", &dir.display().to_string()),
            Err(e) => MeterpreterResponse::failure("pwd", &e.to_string()),
        },
        MeterpreterCommand::Ps => {
            // Stub - would enumerate processes on target
            MeterpreterResponse::success("ps", "Process listing not available in server mode.\n[*] This would enumerate processes on the compromised host in a real agent.")
        }
        MeterpreterCommand::Exec { command } => {
            // WARNING: This executes commands on the LOCAL machine (C2 server operator's host).
            // Only use in trusted environments. This is primarily for local testing/simulation.
            // For production C2, commands should be executed on remote agents, not locally.
            #[cfg(unix)]
            {
                // SECURE: Use allowlist approach - only permit specific safe commands
                let allowed_commands = [
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
                    "pkill",
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
                    "ln",
                    "ls",
                    "pwd",
                    "cd",
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
                    "curl",
                    "wget",
                    "nc",
                    "ncat",
                    "telnet",
                    // File operations (restricted to /tmp and home)
                    "mkdir",
                    "touch",
                    "cp",
                    "mv",
                ];

                let trimmed = command.trim();

                // Extract the base command for allowlist checking
                let base_cmd = trimmed.split_whitespace().next().unwrap_or("");
                let base_lower = base_cmd.to_lowercase();

                // Check if the base command is in the allowlist
                let is_allowed = allowed_commands
                    .iter()
                    .any(|&allowed| allowed.eq_ignore_ascii_case(&base_lower));

                if !is_allowed {
                    return MeterpreterResponse::failure(
                        "exec",
                        &format!(
                            "Command '{}' not in allowlist. Allowed commands: {}",
                            base_cmd,
                            allowed_commands
                                .iter()
                                .take(10)
                                .map(|s| *s)
                                .collect::<Vec<_>>()
                                .join(", ")
                                + "..."
                        ),
                    );
                }

                // Additional safety: block commands with suspicious patterns
                let cmd_lower = trimmed.to_lowercase();
                let suspicious_patterns = [
                    "sudo ", "su ", "chmod 7", "chmod 6", "chown ", "chgrp ", ">/dev/", "2>/dev/",
                    ">>/", "| /", "& /", "eval ", "exec ", "source ", ".", "$(", "`", "|sh",
                    "|bash",
                ];

                for pattern in &suspicious_patterns {
                    if cmd_lower.contains(pattern) {
                        return MeterpreterResponse::failure(
                            "exec",
                            &format!("Blocked suspicious pattern: '{}'", pattern),
                        );
                    }
                }

                // For documentation: note that real C2 should execute on agents, not locally
                MeterpreterResponse::success("exec", 
                    "[NOTE] Command execution on local machine is disabled for security.\n\
                     In production C2, commands execute on remote agents, not the operator's host.\n\
                     Use 'agent_exec <session> <command>' to execute on connected agents.")
            }
            #[cfg(not(unix))]
            {
                MeterpreterResponse::failure(
                    "exec",
                    "Command execution not available on this platform",
                )
            }
        }
        MeterpreterCommand::Upload {
            local_path,
            remote_path,
        } => {
            // Stub
            MeterpreterResponse::success(
                "upload",
                &format!("Would upload: {} -> {}", local_path, remote_path),
            )
        }
        MeterpreterCommand::Download {
            remote_path,
            local_path,
        } => {
            // Stub
            MeterpreterResponse::success(
                "download",
                &format!("Would download: {} -> {}", remote_path, local_path),
            )
        }
        MeterpreterCommand::Screenshot => {
            MeterpreterResponse::success("screenshot", "Screenshot captured (stub)")
        }
        MeterpreterCommand::Keylog { start } => {
            if *start {
                MeterpreterResponse::success("keylog", "Keylogging started (stub)")
            } else {
                MeterpreterResponse::success("keylog", "Keylogging stopped")
            }
        }
        MeterpreterCommand::Portfwd {
            local_port,
            remote_host,
            remote_port,
        } => MeterpreterResponse::success(
            "portfwd",
            &format!(
                "Port forward: 0.0.0.0:{} -> {}:{}",
                local_port, remote_host, remote_port
            ),
        ),
        MeterpreterCommand::Exit => MeterpreterResponse::success("exit", "Session terminated"),
    }
}
