//! Global execution context — holds shared state like RHOSTS, LPORT, etc.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Common option keys used across modules.
pub mod keys {
    pub const RHOSTS: &str = "RHOSTS";
    pub const RPORT: &str = "RPORT";
    pub const LHOST: &str = "LHOST";
    pub const LPORT: &str = "LPORT";
    pub const TARGET: &str = "TARGET";
    pub const PAYLOAD: &str = "PAYLOAD";
    pub const THREADS: &str = "THREADS";
    pub const TIMEOUT: &str = "TIMEOUT";
    pub const VERBOSE: &str = "VERBOSE";
    pub const SSL: &str = "SSL";
    pub const PROXIES: &str = "PROXIES";
    pub const DANGEROUS_CERTS: &str = "DANGEROUS_ACCEPT_INVALID_CERTS";
}

/// The global context holds all shared configuration.
///
/// This is equivalent to msfconsole's global options — values set here
/// are inherited by modules unless overridden locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    /// Global options (RHOSTS, LPORT, etc.)
    options: HashMap<String, String>,
    /// Currently selected module path
    pub current_module: Option<String>,
    /// Active session IDs
    pub sessions: Vec<u32>,
    /// Whether verbose output is enabled
    pub verbose: bool,
}

impl Context {
    /// Create a new context with default values.
    pub fn new() -> Self {
        let mut options = HashMap::new();
        options.insert(keys::LPORT.to_string(), "4444".to_string());
        options.insert(keys::RPORT.to_string(), "80".to_string());
        options.insert(keys::THREADS.to_string(), "10".to_string());
        options.insert(keys::TIMEOUT.to_string(), "10".to_string());
        options.insert(keys::SSL.to_string(), "false".to_string());
        options.insert(keys::VERBOSE.to_string(), "false".to_string());

        Self {
            options,
            current_module: None,
            sessions: Vec::new(),
            verbose: false,
        }
    }

    /// Set a global option.
    pub fn set(&mut self, key: &str, value: &str) {
        if key == keys::VERBOSE {
            self.verbose = value.to_lowercase() == "true" || value == "1";
        }
        self.options.insert(key.to_uppercase(), value.to_string());
    }

    /// Get a global option value.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.options.get(&key.to_uppercase())
    }

    /// Check if an option is set and non-empty.
    pub fn has_option(&self, key: &str) -> bool {
        self.options
            .get(&key.to_uppercase())
            .is_some_and(|v| !v.is_empty())
    }

    /// Get RHOSTS as a list (supports comma-separated and CIDR ranges).
    pub fn get_rhosts(&self) -> Vec<String> {
        self.get(keys::RHOSTS)
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default()
    }

    /// Get LPORT as a u16.
    pub fn get_lport(&self) -> u16 {
        self.get(keys::LPORT)
            .and_then(|v| v.parse().ok())
            .unwrap_or(4444)
    }

    /// Get RPORT as a u16.
    pub fn get_rport(&self) -> u16 {
        self.get(keys::RPORT)
            .and_then(|v| v.parse().ok())
            .unwrap_or(80)
    }

    /// Get THREADS as usize.
    pub fn get_threads(&self) -> usize {
        self.get(keys::THREADS)
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
    }

    /// Get TIMEOUT as u64 (seconds).
    pub fn get_timeout(&self) -> u64 {
        self.get(keys::TIMEOUT)
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
    }

    /// Returns true if the user has explicitly opted into accepting invalid TLS certificates.
    pub fn is_dangerous_certs(&self) -> bool {
        self.get(keys::DANGEROUS_CERTS)
            .map(|s| s == "true")
            .unwrap_or(false)
    }

    /// Unset (remove) an option.
    pub fn unset(&mut self, key: &str) {
        self.options.remove(&key.to_uppercase());
    }

    /// Get all options as a sorted list.
    pub fn list_options(&self) -> Vec<(String, String)> {
        let mut items: Vec<_> = self
            .options
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        items
    }

    /// Save context to a TOML file for persistence.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    /// Load context from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_has_default_options() {
        let ctx = Context::new();
        assert_eq!(ctx.get("LPORT"), Some(&"4444".to_string()));
        assert_eq!(ctx.get("RPORT"), Some(&"80".to_string()));
        assert_eq!(ctx.get("THREADS"), Some(&"10".to_string()));
    }

    #[test]
    fn test_set_get_round_trip() {
        let mut ctx = Context::new();
        ctx.set("RHOSTS", "10.0.0.1");
        assert_eq!(ctx.get("RHOSTS"), Some(&"10.0.0.1".to_string()));
        // Keys are case-insensitive
        assert_eq!(ctx.get("rhosts"), Some(&"10.0.0.1".to_string()));
    }

    #[test]
    fn test_has_option_missing_key() {
        let ctx = Context::new();
        assert!(!ctx.has_option("RHOSTS"));
    }

    #[test]
    fn test_has_option_empty_value() {
        let mut ctx = Context::new();
        ctx.set("RHOSTS", "");
        assert!(!ctx.has_option("RHOSTS"));
    }

    #[test]
    fn test_verbose_flag_synced() {
        let mut ctx = Context::new();
        assert!(!ctx.verbose);
        ctx.set("VERBOSE", "true");
        assert!(ctx.verbose);
    }

    #[test]
    fn test_get_lport_default() {
        let ctx = Context::new();
        assert_eq!(ctx.get_lport(), 4444);
    }

    #[test]
    fn test_tls_secure_by_default() {
        let ctx = Context::new();
        assert!(!ctx.is_dangerous_certs(), "TLS must be secure by default");
    }

    #[test]
    fn test_dangerous_certs_opt_in() {
        let mut ctx = Context::new();
        ctx.set(keys::DANGEROUS_CERTS, "true");
        assert!(ctx.is_dangerous_certs());
    }
}

/// Thread-safe shared context wrapper.
#[derive(Debug, Clone)]
pub struct SharedContext {
    inner: Arc<RwLock<Context>>,
}

impl SharedContext {
    pub fn new(ctx: Context) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ctx)),
        }
    }

    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, Context> {
        self.inner.read().await
    }

    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, Context> {
        self.inner.write().await
    }
}

/// Global shared HTTP client for reuse across modules.
/// Uses OnceLock for lazy initialization with thread-safe access.
#[cfg(feature = "reqwest")]
impl Context {
    /// Get a new HTTP client for making HTTP requests.
    /// TLS certificate validation is enabled by default.
    /// Set DANGEROUS_ACCEPT_INVALID_CERTS=true only for targets with self-signed certs.
    pub fn http_client(&self) -> anyhow::Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.is_dangerous_certs())
            .timeout(std::time::Duration::from_secs(30));

        // Add proxy from PROXIES option if set
        if let Some(proxy_url) = self.get(keys::PROXIES)
            && let Ok(proxy) = reqwest::Proxy::all(proxy_url)
        {
            builder = builder.proxy(proxy);
        }

        builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))
    }
}
