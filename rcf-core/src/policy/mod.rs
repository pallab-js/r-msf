//! OpenSec Policy Engine for module execution.
//!
//! Provides a policy enforcement layer that validates module execution
//! against configurable rules before `run()` is called.
//!
//! Policies are defined in TOML files and support:
//! - Allow/deny rules for modules (with glob patterns)
//! - Target scope restrictions (CIDR ranges)
//! - Time-based access windows
//! - Operator identity checking

use chrono::{Local, Timelike};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

use crate::audit::{AuditCategory, AuditEntry, AuditLevel};
use crate::target::Target;

/// The result of a policy decision.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    /// Execution is explicitly allowed.
    Allowed,
    /// Execution is explicitly denied.
    Denied(String),
    /// No matching rule found (default behavior: deny).
    NoMatch,
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allowed)
    }
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Action: "allow" or "deny"
    pub action: String,
    /// Module name patterns (glob-style, e.g. "scanner/tcp_syn", "exploit/*")
    #[serde(default)]
    pub modules: Vec<String>,
    /// Target CIDR patterns (e.g. ["10.0.0.0/8", "192.168.0.0/16"])
    #[serde(default)]
    pub targets: Vec<String>,
    /// Allowed time windows (e.g. [{ start = "09:00", end = "17:00" }])
    #[serde(default)]
    pub time_windows: Vec<TimeWindow>,
    /// Required operator identity (username matching)
    pub operator: Option<String>,
    /// Description of why this rule exists
    pub reason: Option<String>,
}

/// A time window for restricting module execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start time in "HH:MM" 24-hour format
    pub start: String,
    /// End time in "HH:MM" 24-hour format
    pub end: String,
}

impl TimeWindow {
    fn is_active(&self) -> bool {
        let now = Local::now();
        let now_seconds = now.num_seconds_from_midnight();

        let parse_time = |s: &str| -> Option<u32> {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() != 2 {
                return None;
            }
            let h = parts[0].parse::<u32>().ok()?;
            let m = parts[1].parse::<u32>().ok()?;
            Some(h * 3600 + m * 60)
        };

        match (parse_time(&self.start), parse_time(&self.end)) {
            (Some(start), Some(end)) => {
                if start <= end {
                    now_seconds >= start && now_seconds < end
                } else {
                    // Wraps around midnight (e.g., 22:00 - 06:00)
                    now_seconds >= start || now_seconds < end
                }
            }
            _ => true, // If time parsing fails, don't restrict
        }
    }
}

/// The complete policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// List of policy rules
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    /// Default action when no rule matches ("allow" or "deny")
    #[serde(default = "default_action")]
    pub default_action: String,
    /// Whether policy enforcement is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_action() -> String {
    "deny".to_string()
}

fn default_enabled() -> bool {
    true
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_action: "deny".to_string(),
            enabled: true,
        }
    }
}

/// The policy engine that evaluates rules against module execution requests.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    config: PolicyConfig,
    compiled_modules: Vec<(Vec<Regex>, String)>, // (patterns, action)
}

impl PolicyEngine {
    /// Load a policy from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let contents =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read policy: {}", e))?;
        Self::from_toml(&contents)
    }

    /// Load a policy from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, String> {
        let config: PolicyConfig =
            toml::from_str(toml_str).map_err(|e| format!("Failed to parse policy: {}", e))?;
        Ok(Self::from_config(config))
    }

    /// Create a policy engine from a configured PolicyConfig.
    pub fn from_config(config: PolicyConfig) -> Self {
        let mut engine = Self {
            config,
            compiled_modules: Vec::new(),
        };
        engine.compile();
        engine
    }

    /// Create a permissive default policy (all modules allowed).
    pub fn permissive() -> Self {
        let config = PolicyConfig {
            rules: vec![PolicyRule {
                action: "allow".to_string(),
                modules: vec!["*".to_string()],
                targets: vec!["*".to_string()],
                time_windows: vec![],
                operator: None,
                reason: Some("Default permissive policy".to_string()),
            }],
            default_action: "allow".to_string(),
            enabled: true,
        };
        Self::from_config(config)
    }

    /// Create a restrictive default policy (all modules denied by default).
    pub fn restrictive() -> Self {
        let config = PolicyConfig {
            rules: vec![],
            default_action: "deny".to_string(),
            enabled: true,
        };
        Self::from_config(config)
    }

    fn compile(&mut self) {
        self.compiled_modules = self
            .config
            .rules
            .iter()
            .map(|r| {
                let patterns: Vec<Regex> = r
                    .modules
                    .iter()
                    .filter_map(|m| glob_to_regex(m).ok())
                    .collect();
                (patterns, r.action.clone())
            })
            .collect();
    }

    /// Validate a module execution request against the policy.
    ///
    /// Returns `PolicyDecision::Allowed` if the request passes all policy checks,
    /// or a denial reason otherwise.
    pub fn validate(
        &self,
        module_name: &str,
        target: &Target,
        operator: Option<&str>,
    ) -> PolicyDecision {
        if !self.config.enabled {
            return PolicyDecision::Allowed;
        }

        let mut first_match: Option<&PolicyRule> = None;

        for rule in &self.config.rules {
            if !self.module_matches(module_name, &rule.modules) {
                continue;
            }
            if !self.target_matches(target, &rule.targets) {
                continue;
            }
            if let Some(ref op) = rule.operator
                && operator.map(|o| o != op.as_str()).unwrap_or(true)
            {
                continue;
            }
            if !rule.time_windows.is_empty() && !rule.time_windows.iter().any(|tw| tw.is_active()) {
                continue;
            }

            first_match = Some(rule);
            break;
        }

        match first_match {
            Some(rule) => {
                if rule.action == "allow" {
                    PolicyDecision::Allowed
                } else {
                    let reason = rule.reason.clone().unwrap_or_else(|| {
                        format!("Denied by policy rule for module: {}", module_name)
                    });
                    PolicyDecision::Denied(reason)
                }
            }
            None => {
                if self.config.default_action == "allow" {
                    PolicyDecision::Allowed
                } else {
                    PolicyDecision::NoMatch
                }
            }
        }
    }

    fn module_matches(&self, module_name: &str, patterns: &[String]) -> bool {
        if patterns.is_empty() || patterns.iter().any(|p| p == "*") {
            return true;
        }
        patterns.iter().any(|pattern| {
            if let Ok(re) = glob_to_regex(pattern) {
                re.is_match(module_name)
            } else {
                module_name == pattern
            }
        })
    }

    fn target_matches(&self, target: &Target, patterns: &[String]) -> bool {
        if patterns.is_empty() || patterns.iter().any(|p| p == "*") {
            return true;
        }
        let target_str = target.to_string();
        patterns.iter().any(|pattern| {
            if pattern == "*" {
                return true;
            }
            if pattern.contains('/') {
                // Simple CIDR check
                ip_in_cidr(&target.host, pattern)
            } else {
                target_str.contains(pattern)
            }
        })
    }

    /// Convert policy decision into an audit entry.
    pub fn to_audit_entry(
        &self,
        decision: &PolicyDecision,
        module_name: &str,
        target: &Target,
    ) -> AuditEntry {
        let (level, message) = match decision {
            PolicyDecision::Allowed => (
                AuditLevel::Info,
                format!(
                    "Policy ALLOW: module '{}' on target '{}'",
                    module_name, target
                ),
            ),
            PolicyDecision::Denied(reason) => (
                AuditLevel::Warning,
                format!(
                    "Policy DENY: module '{}' on target '{}': {}",
                    module_name, target, reason
                ),
            ),
            PolicyDecision::NoMatch => (
                AuditLevel::Error,
                format!(
                    "Policy NO_MATCH: module '{}' on target '{}' (default: deny)",
                    module_name, target
                ),
            ),
        };

        AuditEntry::new(level, AuditCategory::SecurityViolation, message)
            .with_target(target.to_string())
    }

    /// Get a reference to the underlying policy config.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Generate the default policy configuration as a TOML string.
    pub fn default_policy_toml() -> String {
        r#"# RCF OpenSec Policy Configuration
# =====================================
# This file defines rules for module execution.
# Order matters: first matching rule wins.
# If no rule matches, the default_action applies.

# Enable or disable policy enforcement
enabled = true

# Default action when no rule matches ("allow" or "deny")
default_action = "deny"

# Policy rules
[[rules]]
action = "allow"
modules = ["scanner/*", "auxiliary/*"]
targets = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
time_windows = [{ start = "09:00", end = "17:00" }]
reason = "Allow scanning during business hours on internal networks"

[[rules]]
action = "deny"
modules = ["exploit/*"]
targets = ["*"]
reason = "Block all exploit modules by default - require explicit override"

[[rules]]
action = "allow"
modules = ["exploit/*"]
targets = ["10.0.0.0/8"]
operator = "admin"
time_windows = [{ start = "00:00", end = "23:59" }]
reason = "Allow admin to use exploit modules on internal network"
"#
        .to_string()
    }
}

/// Check if an IP address falls within a CIDR range.
fn ip_in_cidr(ip_str: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return false;
    }

    let network_ip: IpAddr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let prefix_len: u32 = match parts[1].parse() {
        Ok(len) if len <= 128 => len,
        _ => return false,
    };

    let target_ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match (network_ip, target_ip) {
        (IpAddr::V4(net), IpAddr::V4(tgt)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                u32::MAX
            } else {
                !0u32 << (32 - prefix_len)
            };
            let net_u32 = u32::from(net) & mask;
            let tgt_u32 = u32::from(tgt) & mask;
            net_u32 == tgt_u32
        }
        (IpAddr::V6(net), IpAddr::V6(tgt)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let net_bytes = net.octets();
            let tgt_bytes = tgt.octets();
            let full_bytes = (prefix_len / 8) as usize;
            let remaining_bits = prefix_len % 8;

            if net_bytes[..full_bytes] != tgt_bytes[..full_bytes] {
                return false;
            }

            if remaining_bits > 0 {
                let mask = !0u8 << (8 - remaining_bits);
                if full_bytes < 16
                    && (net_bytes[full_bytes] & mask) != (tgt_bytes[full_bytes] & mask)
                {
                    return false;
                }
            }
            true
        }
        _ => false, // IPv4 vs IPv6 mismatch
    }
}

/// Convert a glob pattern to a regex.
fn glob_to_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let mut re_str = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => re_str.push_str(".*"),
            '?' => re_str.push('.'),
            '.' => re_str.push_str("\\."),
            '/' => re_str.push('/'),
            other => re_str.push(other),
        }
    }
    re_str.push('$');
    Regex::new(&re_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::Target;

    fn test_target() -> Target {
        Target::new("192.168.1.1", 80)
    }

    #[test]
    fn test_permissive_policy_allows_all() {
        let engine = PolicyEngine::permissive();
        let decision = engine.validate("exploit/log4shell", &test_target(), None);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_restrictive_policy_denies_all() {
        let engine = PolicyEngine::restrictive();
        let decision = engine.validate("scanner/tcp_syn", &test_target(), None);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_allow_scanner_deny_exploit() {
        let config = PolicyConfig {
            rules: vec![
                PolicyRule {
                    action: "allow".to_string(),
                    modules: vec!["scanner/*".to_string()],
                    targets: vec!["*".to_string()],
                    time_windows: vec![],
                    operator: None,
                    reason: None,
                },
                PolicyRule {
                    action: "deny".to_string(),
                    modules: vec!["exploit/*".to_string()],
                    targets: vec!["*".to_string()],
                    time_windows: vec![],
                    operator: None,
                    reason: None,
                },
            ],
            default_action: "deny".to_string(),
            enabled: true,
        };
        let engine = PolicyEngine::from_config(config);

        assert!(
            engine
                .validate("scanner/tcp_syn", &test_target(), None)
                .is_allowed()
        );
        assert!(
            !engine
                .validate("exploit/log4shell", &test_target(), None)
                .is_allowed()
        );
    }

    #[test]
    fn test_glob_to_regex() {
        let re = glob_to_regex("scanner/*").unwrap();
        assert!(re.is_match("scanner/tcp_syn"));
        assert!(re.is_match("scanner/port/tcp"));
        assert!(!re.is_match("exploit/log4shell"));

        let re = glob_to_regex("exploit/**").unwrap();
        assert!(re.is_match("exploit/log4shell"));
    }

    #[test]
    fn test_target_matching_with_cidr() {
        let config = PolicyConfig {
            rules: vec![PolicyRule {
                action: "allow".to_string(),
                modules: vec!["*".to_string()],
                targets: vec!["10.0.0.0/8".to_string()],
                time_windows: vec![],
                operator: None,
                reason: None,
            }],
            default_action: "deny".to_string(),
            enabled: true,
        };
        let engine = PolicyEngine::from_config(config);

        let internal = Target::new("10.0.0.5", 80);
        let external = Target::new("8.8.8.8", 80);
        assert!(engine.validate("any/module", &internal, None).is_allowed());
        assert!(!engine.validate("any/module", &external, None).is_allowed());
    }

    #[test]
    fn test_operator_filtering() {
        let config = PolicyConfig {
            rules: vec![PolicyRule {
                action: "allow".to_string(),
                modules: vec!["*".to_string()],
                targets: vec!["*".to_string()],
                time_windows: vec![],
                operator: Some("admin".to_string()),
                reason: None,
            }],
            default_action: "deny".to_string(),
            enabled: true,
        };
        let engine = PolicyEngine::from_config(config);

        assert!(
            engine
                .validate("any/module", &test_target(), Some("admin"))
                .is_allowed()
        );
        assert!(
            !engine
                .validate("any/module", &test_target(), Some("user"))
                .is_allowed()
        );
    }

    #[test]
    fn test_disabled_policy_allows_all() {
        let config = PolicyConfig {
            rules: vec![PolicyRule {
                action: "deny".to_string(),
                modules: vec!["*".to_string()],
                targets: vec!["*".to_string()],
                time_windows: vec![],
                operator: None,
                reason: None,
            }],
            default_action: "deny".to_string(),
            enabled: false,
        };
        let engine = PolicyEngine::from_config(config);
        assert!(
            engine
                .validate("any/module", &test_target(), None)
                .is_allowed()
        );
    }

    #[test]
    fn test_time_window_parse() {
        let tw = TimeWindow {
            start: "09:00".to_string(),
            end: "17:00".to_string(),
        };
        // This will pass or fail depending on current time
        // but shouldn't panic
        let _ = tw.is_active();
    }

    #[test]
    fn test_policy_toml_roundtrip() {
        let toml_str = PolicyEngine::default_policy_toml();
        let engine = PolicyEngine::from_toml(&toml_str).unwrap();
        assert!(engine.config().enabled);
        assert_eq!(engine.config().rules.len(), 3);
    }
}
