//! Anonymity and evasion system for RCF.
//!
//! Provides comprehensive anonymity features for:
//! - Proxy chain routing (SOCKS5, HTTP, SSH tunnels)
//! - User-Agent rotation and header obfuscation  
//! - Timing controls and request throttling
//! - WAF detection and evasion
//! - Report anonymization and log sanitization
//! - Silent mode for stealth operations
//! - SSH tunnel pivoting for lateral movement

use std::time::{Duration, Instant};

use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::{RcfError, Result};

// ─── Anonymity Levels ───────────────────────────────────────────────────────

/// Predefined anonymity levels for quick configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AnonymityLevel {
    /// Maximum stealth - slow but invisible
    Ghost,
    /// Balanced stealth and speed
    Stealthy,
    /// Moderate anonymity
    Moderate,
    /// Standard - minimal anonymity
    #[default]
    Standard,
    /// Full speed - no anonymity
    Aggressive,
}

impl AnonymityLevel {
    pub fn to_config(&self) -> AnonymityConfig {
        match self {
            AnonymityLevel::Ghost => AnonymityConfig {
                jitter_min_ms: 3000,
                jitter_max_ms: 8000,
                rotate_user_agent: true,
                rotate_source_port: true,
                rotate_source_ip: None,
                proxy_chain: vec![],
                silent_mode: true,
                randomize_headers: true,
                add_decoy_traffic: Some(DecoyConfig {
                    enabled: true,
                    decoy_ratio: 0.3,
                    decoy_targets: vec![],
                }),
                waf_detection: true,
                strict_tls: true,
                timeout_seconds: 30,
            },
            AnonymityLevel::Stealthy => AnonymityConfig {
                jitter_min_ms: 1000,
                jitter_max_ms: 3000,
                rotate_user_agent: true,
                rotate_source_port: false,
                rotate_source_ip: None,
                proxy_chain: vec![],
                silent_mode: false,
                randomize_headers: true,
                add_decoy_traffic: Some(DecoyConfig {
                    enabled: true,
                    decoy_ratio: 0.15,
                    decoy_targets: vec![],
                }),
                waf_detection: true,
                strict_tls: true,
                timeout_seconds: 20,
            },
            AnonymityLevel::Moderate => AnonymityConfig {
                jitter_min_ms: 500,
                jitter_max_ms: 1500,
                rotate_user_agent: true,
                rotate_source_port: false,
                rotate_source_ip: None,
                proxy_chain: vec![],
                silent_mode: false,
                randomize_headers: true,
                add_decoy_traffic: Some(DecoyConfig {
                    enabled: true,
                    decoy_ratio: 0.05,
                    decoy_targets: vec![],
                }),
                waf_detection: true,
                strict_tls: true,
                timeout_seconds: 15,
            },
            AnonymityLevel::Standard => AnonymityConfig {
                jitter_min_ms: 100,
                jitter_max_ms: 500,
                rotate_user_agent: true,
                rotate_source_port: false,
                rotate_source_ip: None,
                proxy_chain: vec![],
                silent_mode: false,
                randomize_headers: false,
                add_decoy_traffic: None,
                waf_detection: false,
                strict_tls: true,
                timeout_seconds: 10,
            },
            AnonymityLevel::Aggressive => AnonymityConfig {
                jitter_min_ms: 0,
                jitter_max_ms: 50,
                rotate_user_agent: false,
                rotate_source_port: false,
                rotate_source_ip: None,
                proxy_chain: vec![],
                silent_mode: false,
                randomize_headers: false,
                add_decoy_traffic: None,
                waf_detection: false,
                strict_tls: false,
                timeout_seconds: 5,
            },
        }
    }
}

// ─── Proxy Configuration ────────────────────────────────────────────────────

/// Supported proxy protocols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    Http,
    Socks5,
    Socks4,
    Ssh,
}

impl Default for ProxyProtocol {
    fn default() -> Self {
        Self::Http
    }
}

/// Proxy server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyServer {
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyServer {
    pub fn new(protocol: ProxyProtocol, host: impl Into<String>, port: u16) -> Self {
        Self {
            protocol,
            host: host.into(),
            port,
            username: None,
            password: None,
        }
    }

    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    pub fn to_url(&self) -> String {
        match &self.username {
            Some(user) => format!(
                "{}://{}:{}@{}:{}",
                self.protocol.as_str(),
                user,
                self.password.as_deref().unwrap_or(""),
                self.host,
                self.port
            ),
            None => format!("{}://{}:{}", self.protocol.as_str(), self.host, self.port),
        }
    }
}

impl ProxyProtocol {
    pub fn as_str(&self) -> &str {
        match self {
            ProxyProtocol::Http => "http",
            ProxyProtocol::Socks5 => "socks5",
            ProxyProtocol::Socks4 => "socks4",
            ProxyProtocol::Ssh => "ssh",
        }
    }
}

// ─── Decoy Traffic Configuration ────────────────────────────────────────────────

/// Configuration for generating decoy traffic as misdirection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyConfig {
    pub enabled: bool,
    pub decoy_ratio: f32,
    pub decoy_targets: Vec<DecoyTarget>,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            decoy_ratio: 0.1,
            decoy_targets: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyTarget {
    pub host: String,
    pub port: u16,
    pub method: DecoyMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecoyMethod {
    Connect,
    SendData,
    KeepAlive,
}

// ─── WAF Detection ────────────────────────────────────────────────────────────────

/// WAF detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetection {
    pub detected: bool,
    pub waf_name: Option<String>,
    pub evasion_hints: Vec<String>,
    pub confidence: f32,
}

impl Default for WafDetection {
    fn default() -> Self {
        Self {
            detected: false,
            waf_name: None,
            evasion_hints: vec![],
            confidence: 0.0,
        }
    }
}

/// Known WAF signatures for detection.
pub fn detect_waf(headers: &[(String, String)]) -> WafDetection {
    let mut detection = WafDetection::default();
    let headers_lower: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();

    for (key, value) in &headers_lower {
        let value_lower = value.as_str();

        if key == "server" || key == "x-cache" || key == "cf-ray" {
            match value_lower {
                s if s.contains("cloudflare") => {
                    detection.detected = true;
                    detection.waf_name = Some("Cloudflare".to_string());
                    detection.confidence = 0.95;
                    detection.evasion_hints = vec![
                        "Use slower requests to avoid rate limiting".to_string(),
                        "Rotate User-Agent frequently".to_string(),
                        "Try HTTP/2 multiplexing".to_string(),
                    ];
                }
                s if s.contains("imperva") || s.contains("incapsula") => {
                    detection.detected = true;
                    detection.waf_name = Some("Imperva/Incapsula".to_string());
                    detection.confidence = 0.9;
                    detection.evasion_hints = vec![
                        "Add proper headers (Accept, Language)".to_string(),
                        "Use session cookies".to_string(),
                        "Vary User-Agent and Accept headers".to_string(),
                    ];
                }
                s if s.contains("akamai") || s.contains("ghost") => {
                    detection.detected = true;
                    detection.waf_name = Some("Akamai".to_string());
                    detection.confidence = 0.85;
                    detection.evasion_hints = vec![
                        "Do not repeat requests frequently".to_string(),
                        "Add proper Referer header".to_string(),
                    ];
                }
                s if s.contains("big-ip") || s.contains("f5") => {
                    detection.detected = true;
                    detection.waf_name = Some("F5 BIG-IP".to_string());
                    detection.confidence = 0.8;
                    detection.evasion_hints = vec![
                        "Avoid common attack patterns".to_string(),
                        "Use encoded payloads".to_string(),
                    ];
                }
                s if s.contains("fortiweb") || s.contains("fortigate") => {
                    detection.detected = true;
                    detection.waf_name = Some("FortiWeb/FortiGate".to_string());
                    detection.confidence = 0.75;
                    detection.evasion_hints = vec![
                        "Lower request frequency".to_string(),
                        "Use慢速requests".to_string(),
                    ];
                }
                _ => {}
            }
        }

        if key == "server" && value_lower.contains("unknown") && !detection.detected {
            if let Some(pos) = value_lower.find("nginx") {
                if pos > 0 {
                    detection.detected = true;
                    detection.waf_name = Some("nginx".to_string());
                    detection.confidence = 0.3;
                }
            }
        }

        if key == "x-backend" || key == "x-cdn" || key == "x-served-by" {
            detection.detected = true;
            detection.confidence = 0.6;
        }
    }

    detection
}

// ─── Anonymity Configuration ────────────────────────────────────────────────────────

/// Complete anonymity configuration for operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityConfig {
    /// Minimum jitter delay between requests (milliseconds).
    #[serde(default = "default_jitter_min")]
    pub jitter_min_ms: u64,
    /// Maximum jitter delay between requests (milliseconds).
    #[serde(default = "default_jitter_max")]
    pub jitter_max_ms: u64,
    /// Rotate User-Agent for each request.
    #[serde(default)]
    pub rotate_user_agent: bool,
    /// Randomize source port for each connection.
    #[serde(default)]
    pub rotate_source_port: bool,
    /// Rotate source IP (requires multiple interfaces).
    #[serde(default)]
    pub rotate_source_ip: Option<Vec<String>>,
    /// Proxy chain servers (tested in order until one works).
    #[serde(default)]
    pub proxy_chain: Vec<ProxyServer>,
    /// Silent mode - suppress console output.
    #[serde(default)]
    pub silent_mode: bool,
    /// Randomize HTTP header order.
    #[serde(default)]
    pub randomize_headers: bool,
    /// Add decoy traffic for misdirection.
    #[serde(default)]
    pub add_decoy_traffic: Option<DecoyConfig>,
    /// Enable WAF detection on responses.
    #[serde(default)]
    pub waf_detection: bool,
    /// Use strict TLS validation.
    #[serde(default = "default_true")]
    pub strict_tls: bool,
    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_jitter_min() -> u64 {
    100
}
fn default_jitter_max() -> u64 {
    500
}
fn default_true() -> bool {
    true
}
fn default_timeout() -> u64 {
    10
}

impl AnonymityConfig {
    pub fn from_level(level: AnonymityLevel) -> Self {
        level.to_config()
    }

    pub fn custom() -> Self {
        Self::default()
    }

    /// Apply proxy chain to configuration.
    pub fn with_proxy(mut self, proxy: ProxyServer) -> Self {
        self.proxy_chain.push(proxy);
        self
    }

    /// Add multiple proxies to chain.
    pub fn with_proxies(mut self, proxies: Vec<ProxyServer>) -> Self {
        self.proxy_chain.extend(proxies);
        self
    }

    /// Enable silent mode.
    pub fn silent(mut self) -> Self {
        self.silent_mode = true;
        self
    }

    /// Enable decoy traffic.
    pub fn with_decoys(mut self, targets: Vec<DecoyTarget>, ratio: f32) -> Self {
        self.add_decoy_traffic = Some(DecoyConfig {
            enabled: true,
            decoy_ratio: ratio,
            decoy_targets: targets,
        });
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.jitter_min_ms > self.jitter_max_ms {
            return Err(RcfError::Config(format!(
                "jitter_min_ms ({}) cannot exceed jitter_max_ms ({})",
                self.jitter_min_ms, self.jitter_max_ms
            )));
        }

        if let Some(ref decoy) = self.add_decoy_traffic {
            if decoy.decoy_ratio < 0.0 || decoy.decoy_ratio > 1.0 {
                return Err(RcfError::Config(format!(
                    "decoy_ratio ({}) must be between 0.0 and 1.0",
                    decoy.decoy_ratio
                )));
            }
        }

        for proxy in &self.proxy_chain {
            if proxy.host.is_empty() {
                return Err(RcfError::Config("proxy host cannot be empty".to_string()));
            }
            if proxy.port == 0 {
                return Err(RcfError::Config("proxy port cannot be 0".to_string()));
            }
        }

        Ok(())
    }
}

impl Default for AnonymityConfig {
    fn default() -> Self {
        Self::from_level(AnonymityLevel::Standard)
    }
}

// ─── Anonymity Manager ────────────────────────────────────────────────────────────────

/// State manager for anonymity operations.
pub struct AnonymityManager {
    config: RwLock<AnonymityConfig>,
    last_request: RwLock<Instant>,
    request_count: RwLock<u64>,
    waf_detections: RwLock<Vec<WafDetection>>,
    silent_output: RwLock<bool>,
}

impl AnonymityManager {
    pub fn new(config: AnonymityConfig) -> Self {
        let silent = config.silent_mode;
        Self {
            config: RwLock::new(config),
            last_request: RwLock::new(Instant::now()),
            request_count: RwLock::new(0),
            waf_detections: RwLock::new(vec![]),
            silent_output: RwLock::new(silent),
        }
    }

    pub async fn apply_jitter(&self) {
        let config = self.config.read().await;
        let min = config.jitter_min_ms;
        let max = config.jitter_max_ms;
        drop(config);

        if min == 0 && max == 0 {
            return;
        }

        let delay: u64 = {
            let mut rng = rand::rng();
            rng.random_range(min..=max)
        };

        tokio::time::sleep(Duration::from_millis(delay)).await;

        let mut last = self.last_request.write().await;
        *last = Instant::now();
    }

    pub fn get_user_agent(&self, custom: Option<&str>) -> String {
        if let Some(ua) = custom {
            return ua.to_string();
        }

        let profiles = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        ];

        let idx = {
            let mut rng = rand::rng();
            rng.random_range(0..profiles.len())
        };

        profiles[idx].to_string()
    }

    pub async fn check_waf(&self, headers: &[(String, String)]) -> Option<WafDetection> {
        let config = self.config.read().await;
        if !config.waf_detection {
            return None;
        }
        drop(config);

        let detection = detect_waf(headers);
        if detection.detected {
            let mut detections = self.waf_detections.write().await;
            detections.push(detection.clone());
        }
        Some(detection)
    }

    pub async fn set_silent(&self, silent: bool) {
        let mut output = self.silent_output.write().await;
        *output = silent;
    }

    pub async fn is_silent(&self) -> bool {
        *self.silent_output.read().await
    }

    pub async fn update_config(&self, config: AnonymityConfig) {
        let mut cfg = self.config.write().await;
        *cfg = config;
    }

    pub async fn get_config(&self) -> AnonymityConfig {
        self.config.read().await.clone()
    }

    pub async fn increment_requests(&self) -> u64 {
        let mut count = self.request_count.write().await;
        *count += 1;
        *count
    }

    pub async fn get_request_count(&self) -> u64 {
        *self.request_count.read().await
    }

    pub async fn get_waf_detections(&self) -> Vec<WafDetection> {
        self.waf_detections.read().await.clone()
    }
}

impl Default for AnonymityManager {
    fn default() -> Self {
        Self::new(AnonymityConfig::default())
    }
}

// ─── Report Anonymizer ────────────────────────────────────────────────────────────

/// Configuration for anonymizing reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportAnonymizer {
    pub replace_ips: bool,
    pub replace_usernames: bool,
    pub replace_hostnames: bool,
    pub replace_emails: bool,
    pub ip_prefix: String,
    pub username_prefix: String,
    pub hostname_prefix: String,
    pub email_domain: String,
}

impl Default for ReportAnonymizer {
    fn default() -> Self {
        Self {
            replace_ips: true,
            replace_usernames: true,
            replace_hostnames: true,
            replace_emails: true,
            ip_prefix: "10.10.10".to_string(),
            username_prefix: "user".to_string(),
            hostname_prefix: "target".to_string(),
            email_domain: "redacted.local".to_string(),
        }
    }
}

impl ReportAnonymizer {
    pub fn sanitize_text(&self, text: &str) -> String {
        let mut result = text.to_string();

        if self.replace_ips {
            let ip_patterns = [
                (
                    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                    "10.10.10.X",
                ),
                (
                    r"\b(?:172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b",
                    "192.168.X.X",
                ),
                (r"\b(?:10\.\d{1,3}\.){2}\d{1,3}\b", "10.X.X.X"),
            ];
            for (pattern, replacement) in ip_patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    result = re.replace_all(&result, replacement).to_string();
                }
            }
        }

        if self.replace_usernames {
            if let Ok(re) = regex::Regex::new(r"\b[a-zA-Z][a-zA-Z0-9_]{2,20}\b") {
                result = re
                    .replace_all(&result, |caps: &regex::Captures| {
                        let m = caps.get(0).unwrap().as_str();
                        if !m.eq_ignore_ascii_case("root")
                            && !m.eq_ignore_ascii_case("admin")
                            && !m.eq_ignore_ascii_case("httpd")
                        {
                            format!(
                                "{}{}",
                                self.username_prefix,
                                rand::rng().random_range(100..999)
                            )
                        } else {
                            m.to_string()
                        }
                    })
                    .to_string();
            }
        }

        if self.replace_emails {
            if let Ok(re) =
                regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
            {
                result = re
                    .replace_all(
                        &result,
                        &format!(
                            "user{}@{}",
                            rand::rng().random_range(100..999),
                            self.email_domain
                        ),
                    )
                    .to_string();
            }
        }

        result
    }

    pub fn sanitize_file<P: std::io::Read + std::io::Write>(
        &self,
        input: P,
        output: P,
    ) -> std::io::Result<()> {
        use std::io::{BufRead, BufReader};

        let reader = BufReader::new(input);
        let mut writer = output;

        for line in reader.lines() {
            let line = line?;
            let sanitized = self.sanitize_text(&line);
            writeln!(writer, "{}", sanitized)?;
        }

        Ok(())
    }
}

// ─── SSH Tunnel Pivoting ────────────────────────────────────────────────────────

/// SSH tunnel configuration for lateral movement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTunnelConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

impl SshTunnelConfig {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        local_port: u16,
        remote_host: impl Into<String>,
        remote_port: u16,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
            password: None,
            key_file: None,
            local_port,
            remote_host: remote_host.into(),
            remote_port,
        }
    }

    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    pub fn with_key_file(mut self, key_file: impl Into<String>) -> Self {
        self.key_file = Some(key_file.into());
        self
    }
}

// ─── Utility Functions ────────────────────────────────────────────────────

/// Get a random source port for binding.
pub fn random_source_port() -> u16 {
    let mut rng = rand::rng();
    rng.random_range(1024..65535)
}

/// Calculate safe delay based on rate limits.
pub fn calculate_delay(rate_limit: u32, current_rate: u32) -> Duration {
    if current_rate >= rate_limit {
        let delay_ms = rand::rng().random_range(1000..5000);
        Duration::from_millis(delay_ms)
    } else {
        Duration::ZERO
    }
}

/// Check if content indicates WAF block.
pub fn is_waf_blocked(status: u16, body: &str) -> bool {
    let blocked_statuses = [403, 406, 501, 999];
    if blocked_statuses.contains(&status) {
        return true;
    }

    let block_patterns = [
        "blocked",
        "rate limit",
        "too many requests",
        "captcha",
        "security check",
        "attack detected",
        "sql injection",
        "xss",
        "forbidden",
        "access denied",
        "suspicious activity",
    ];

    let body_lower = body.to_lowercase();
    block_patterns.iter().any(|p| body_lower.contains(p))
}

/// Export AnonymityConfig to TOML string.
pub fn config_to_toml(config: &AnonymityConfig) -> Result<String> {
    toml::to_string(config).map_err(|e| RcfError::Config(e.to_string()))
}

/// Import AnonymityConfig from TOML string.
pub fn config_from_toml(toml: &str) -> Result<AnonymityConfig> {
    toml::from_str(toml).map_err(|e| RcfError::Config(e.to_string()))
}
