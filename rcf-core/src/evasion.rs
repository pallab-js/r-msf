//! Evasion utilities for RCF scanners and exploits.
//!
//! Provides:
//! - Timing jitter (randomized delay between requests)
//! - User-Agent rotation (realistic browser fingerprints)
//! - Proxy chain support (HTTP/SOCKS5)
//! - TLS certificate pinning for C2

use std::time::Duration;

use rand::Rng;
use serde::{Deserialize, Serialize};

// ─── Timing Jitter ─────────────────────────────────────────────────────────

/// Apply randomized delay between requests to avoid IDS/IPS detection.
pub async fn apply_jitter(min_ms: u64, max_ms: u64) {
    let delay_ms: u64 = {
        let mut rng = rand::rng();
        rng.random_range(min_ms..=max_ms)
    };
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
}

// ─── User-Agent Rotation ────────────────────────────────────────────────────

/// Realistic browser User-Agent strings for rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserAgentProfile {
    ChromeWindows,
    ChromeMacOS,
    FirefoxWindows,
    FirefoxMacOS,
    SafariMacOS,
    SafariIOS,
    EdgeWindows,
    GoogleBot,
    BingBot,
    Custom(String),
}

impl UserAgentProfile {
    /// Get the User-Agent string for this profile.
    pub fn to_string(&self) -> String {
        match self {
            UserAgentProfile::ChromeWindows => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
            }
            UserAgentProfile::ChromeMacOS => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
            }
            UserAgentProfile::FirefoxWindows => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0".to_string()
            }
            UserAgentProfile::FirefoxMacOS => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0".to_string()
            }
            UserAgentProfile::SafariMacOS => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15".to_string()
            }
            UserAgentProfile::SafariIOS => {
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1".to_string()
            }
            UserAgentProfile::EdgeWindows => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0".to_string()
            }
            UserAgentProfile::GoogleBot => {
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)".to_string()
            }
            UserAgentProfile::BingBot => {
                "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)".to_string()
            }
            UserAgentProfile::Custom(s) => s.clone(),
        }
    }
}

impl std::fmt::Display for UserAgentProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Get a random User-Agent from the rotation pool.
pub fn get_random_agent() -> UserAgentProfile {
    let idx = {
        let mut rng = rand::rng();
        let profiles = [
            UserAgentProfile::ChromeWindows,
            UserAgentProfile::ChromeMacOS,
            UserAgentProfile::FirefoxWindows,
            UserAgentProfile::FirefoxMacOS,
            UserAgentProfile::SafariMacOS,
            UserAgentProfile::EdgeWindows,
        ];
        rng.random_range(0..profiles.len())
    };
    
    let profiles = [
        UserAgentProfile::ChromeWindows,
        UserAgentProfile::ChromeMacOS,
        UserAgentProfile::FirefoxWindows,
        UserAgentProfile::FirefoxMacOS,
        UserAgentProfile::SafariMacOS,
        UserAgentProfile::EdgeWindows,
    ];
    profiles[idx].clone()
}

// ─── Proxy Chain ────────────────────────────────────────────────────────────

/// Proxy configuration for routing requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy_url: Option<String>,
    pub proxy_type: ProxyType,
}

impl ProxyConfig {
    pub fn none() -> Self {
        Self {
            proxy_url: None,
            proxy_type: ProxyType::Http,
        }
    }

    pub fn http(url: &str) -> Self {
        Self {
            proxy_url: Some(url.to_string()),
            proxy_type: ProxyType::Http,
        }
    }

    pub fn socks5(url: &str) -> Self {
        Self {
            proxy_url: Some(url.to_string()),
            proxy_type: ProxyType::Socks5,
        }
    }
}

/// Supported proxy types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyType {
    Http,
    Socks5,
}

// ─── TLS Certificate Pinning ───────────────────────────────────────────────

/// TLS configuration with optional certificate pinning for C2 comms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub accept_invalid_certs: bool,
    pub pinned_certificate: Option<Vec<u8>>,
    pub pinned_public_key: Option<String>,
}

impl TlsConfig {
    /// Create an insecure TLS config (accepts all certificates).
    /// WARNING: This makes connections vulnerable to MITM attacks.
    /// Only use for pentesting targets where certificate validation
    /// is intentionally disabled.
    pub fn insecure() -> Self {
        Self {
            accept_invalid_certs: true,
            pinned_certificate: None,
            pinned_public_key: None,
        }
    }

    /// Create a strict TLS config (validates certificates).
    /// Use this for production or when certificate validation is required.
    pub fn strict() -> Self {
        Self {
            accept_invalid_certs: false,
            pinned_certificate: None,
            pinned_public_key: None,
        }
    }

    /// Create a TLS config with certificate pinning.
    pub fn pinned(public_key: &str) -> Self {
        Self {
            accept_invalid_certs: false,
            pinned_certificate: None,
            pinned_public_key: Some(public_key.to_string()),
        }
    }
}

impl Default for TlsConfig {
    /// Default: STRICT (validates certificates).
    /// This is the secure default. Use `TlsConfig::insecure()` only when
    /// intentionally pentesting targets with invalid/missing certificates.
    fn default() -> Self {
        Self::strict()
    }
}

// ─── Evasion Config ─────────────────────────────────────────────────────────

/// Complete evasion configuration for scanners and exploits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    /// Minimum jitter between requests (ms)
    pub jitter_min_ms: u64,
    /// Maximum jitter between requests (ms)
    pub jitter_max_ms: u64,
    /// Enable User-Agent rotation
    pub rotate_ua: bool,
    /// Proxy configuration
    pub proxy: ProxyConfig,
    /// TLS configuration
    pub tls: TlsConfig,
    /// Randomize header order
    pub randomize_headers: bool,
    /// Add random cache-busting parameters
    pub cache_bust: bool,
}

impl EvasionConfig {
    pub fn stealth() -> Self {
        Self {
            jitter_min_ms: 1000,
            jitter_max_ms: 5000,
            rotate_ua: true,
            proxy: ProxyConfig::none(),
            tls: TlsConfig::insecure(),
            randomize_headers: true,
            cache_bust: true,
        }
    }

    pub fn aggressive() -> Self {
        Self {
            jitter_min_ms: 0,
            jitter_max_ms: 100,
            rotate_ua: false,
            proxy: ProxyConfig::none(),
            tls: TlsConfig::insecure(),
            randomize_headers: false,
            cache_bust: false,
        }
    }
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self::aggressive()
    }
}
