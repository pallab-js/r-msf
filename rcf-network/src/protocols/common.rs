//! Common types for protocol fingerprinting.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Detected service information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceInfo {
    /// Service name (e.g. "http", "ssh", "smb")
    pub service: String,
    /// Service version string (e.g. "OpenSSH 8.9p1")
    pub version: Option<String>,
    /// Detected operating system
    pub os: Option<String>,
    /// Additional key-value pairs
    pub extra: HashMap<String, String>,
}

impl ServiceInfo {
    pub fn new(service: &str) -> Self {
        Self {
            service: service.to_string(),
            version: None,
            os: None,
            extra: HashMap::new(),
        }
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    pub fn with_os(mut self, os: &str) -> Self {
        self.os = Some(os.to_string());
        self
    }

    pub fn with_extra(mut self, key: &str, value: &str) -> Self {
        self.extra.insert(key.to_string(), value.to_string());
        self
    }

    pub fn summary(&self) -> String {
        let mut parts = vec![self.service.clone()];
        if let Some(ref v) = self.version {
            parts.push(v.clone());
        }
        if let Some(ref o) = self.os {
            parts.push(format!("({})", o));
        }
        parts.join(" ")
    }
}

impl fmt::Display for ServiceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

/// Well-known port to service name mapping.
pub fn port_to_service(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        111 => Some("rpcbind"),
        135 => Some("msrpc"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        443 => Some("https"),
        445 => Some("microsoft-ds"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        2049 => Some("nfs"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        8080 => Some("http-proxy"),
        8443 => Some("https-alt"),
        9200 => Some("elasticsearch"),
        11211 => Some("memcached"),
        27017 => Some("mongodb"),
        _ => None,
    }
}
