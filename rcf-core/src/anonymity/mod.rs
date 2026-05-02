//! Anonymity and evasion system for RCF.
//!
//! Provides comprehensive anonymity features:
//! - Proxy chain routing (SOCKS5, HTTP, SSH tunnels) — see [`proxy`]
//! - Timing controls and request throttling — see [`timing`]
//! - WAF detection and evasion — see [`waf`]
//! - Report anonymization — see [`report`]
//! - Decoy traffic configuration — see [`decoy`]

pub mod decoy;
pub mod proxy;
pub mod report;
pub mod timing;
pub mod waf;

pub use decoy::{DecoyConfig, DecoyMethod, DecoyTarget};
pub use proxy::{ProxyProtocol, ProxyServer, SshTunnelConfig};
pub use report::ReportAnonymizer;
pub use timing::{AnonymityManager, calculate_delay, random_source_port};
pub use waf::{WafDetection, detect_waf, is_waf_blocked};

use serde::{Deserialize, Serialize};

use crate::error::Result;

// ─── Anonymity Levels ───────────────────────────────────────────────────────

/// Predefined anonymity levels for quick configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AnonymityLevel {
    /// Maximum stealth — slow but invisible.
    Ghost,
    /// Balanced stealth and speed.
    Stealthy,
    /// Moderate anonymity.
    Moderate,
    /// Standard — minimal anonymity.
    #[default]
    Standard,
    /// Full speed — no anonymity.
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

// ─── Anonymity Configuration ────────────────────────────────────────────────

/// Complete anonymity configuration for operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityConfig {
    #[serde(default = "default_jitter_min")]
    pub jitter_min_ms: u64,
    #[serde(default = "default_jitter_max")]
    pub jitter_max_ms: u64,
    #[serde(default)]
    pub rotate_user_agent: bool,
    #[serde(default)]
    pub rotate_source_port: bool,
    #[serde(default)]
    pub rotate_source_ip: Option<Vec<String>>,
    #[serde(default)]
    pub proxy_chain: Vec<ProxyServer>,
    #[serde(default)]
    pub silent_mode: bool,
    #[serde(default)]
    pub randomize_headers: bool,
    #[serde(default)]
    pub add_decoy_traffic: Option<DecoyConfig>,
    #[serde(default)]
    pub waf_detection: bool,
    #[serde(default = "default_true")]
    pub strict_tls: bool,
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

    pub fn with_proxy(mut self, proxy: ProxyServer) -> Self {
        self.proxy_chain.push(proxy);
        self
    }

    pub fn with_proxies(mut self, proxies: Vec<ProxyServer>) -> Self {
        self.proxy_chain.extend(proxies);
        self
    }

    pub fn silent(mut self) -> Self {
        self.silent_mode = true;
        self
    }

    pub fn with_decoys(mut self, targets: Vec<DecoyTarget>, ratio: f32) -> Self {
        self.add_decoy_traffic = Some(DecoyConfig {
            enabled: true,
            decoy_ratio: ratio,
            decoy_targets: targets,
        });
        self
    }

    pub fn validate(&self) -> Result<()> {
        use crate::error::RcfError;

        if self.jitter_min_ms > self.jitter_max_ms {
            return Err(RcfError::Config(format!(
                "jitter_min_ms ({}) cannot exceed jitter_max_ms ({})",
                self.jitter_min_ms, self.jitter_max_ms
            )));
        }

        if let Some(ref decoy) = self.add_decoy_traffic
            && !(0.0..=1.0).contains(&decoy.decoy_ratio)
        {
            return Err(RcfError::Config(format!(
                "decoy_ratio ({}) must be between 0.0 and 1.0",
                decoy.decoy_ratio
            )));
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

// ─── TOML helpers ───────────────────────────────────────────────────────────

/// Export `AnonymityConfig` to a TOML string.
pub fn config_to_toml(config: &AnonymityConfig) -> Result<String> {
    Ok(toml::to_string(config)?)
}

/// Import `AnonymityConfig` from a TOML string.
pub fn config_from_toml(toml_str: &str) -> Result<AnonymityConfig> {
    Ok(toml::from_str(toml_str)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_jitter_min_gt_max_errors() {
        let cfg = AnonymityConfig {
            jitter_min_ms: 5000,
            jitter_max_ms: 100,
            ..AnonymityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_valid_config_ok() {
        let cfg = AnonymityConfig::from_level(AnonymityLevel::Ghost);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_decoy_ratio_out_of_range() {
        let cfg = AnonymityConfig {
            add_decoy_traffic: Some(DecoyConfig {
                enabled: true,
                decoy_ratio: 1.5,
                decoy_targets: vec![],
            }),
            ..AnonymityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_toml_round_trip() {
        let cfg = AnonymityConfig::from_level(AnonymityLevel::Stealthy);
        let toml_str = config_to_toml(&cfg).unwrap();
        let restored = config_from_toml(&toml_str).unwrap();
        assert_eq!(cfg.jitter_min_ms, restored.jitter_min_ms);
        assert_eq!(cfg.jitter_max_ms, restored.jitter_max_ms);
        assert_eq!(cfg.silent_mode, restored.silent_mode);
    }
}
