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
    pub const STRICT_TLS: &str = "STRICT_TLS";
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

    /// Get whether strict TLS validation is enabled.
    pub fn is_strict_tls(&self) -> bool {
        self.get("STRICT_TLS").map(|s| s == "true").unwrap_or(false)
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
    /// Uses the current context's TLS settings and proxy from PROXIES option.
    pub fn http_client(&self) -> anyhow::Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(!self.is_strict_tls())
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
