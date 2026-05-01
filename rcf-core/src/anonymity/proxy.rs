//! Proxy chain and SSH tunnel configuration.

use serde::{Deserialize, Serialize};

/// Supported proxy protocols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    #[default]
    Http,
    Socks5,
    Socks4,
    Ssh,
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
