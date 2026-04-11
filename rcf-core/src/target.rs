//! Target representation and parsing.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::error::{RcfError, Result};

/// A single scan/exploitation target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Target {
    /// Host address (IP or hostname)
    pub host: String,
    /// Port number
    pub port: u16,
    /// Resolved IP address (if resolved)
    pub resolved_addr: Option<IpAddr>,
    /// Detected service name
    pub service: Option<String>,
    /// Detected service version
    pub version: Option<String>,
    /// Detected operating system
    pub os: Option<String>,
    /// Whether SSL/TLS is enabled
    pub ssl: bool,
}

impl Target {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            resolved_addr: None,
            service: None,
            version: None,
            os: None,
            ssl: false,
        }
    }

    pub fn with_ssl(mut self, ssl: bool) -> Self {
        self.ssl = ssl;
        self
    }

    /// Parse a "host:port" string into a Target.
    pub fn from_str(s: &str, default_port: u16) -> Result<Self> {
        if let Some((host, port_str)) = s.rsplit_once(':') {
            let port: u16 = port_str.parse().map_err(|_| RcfError::InvalidOption {
                name: "port".to_string(),
                reason: format!("invalid port '{}'", port_str),
            })?;
            Ok(Self::new(host, port))
        } else {
            Ok(Self::new(s, default_port))
        }
    }

    /// Get the display address.
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Convert to SocketAddr if resolved.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.resolved_addr.map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Parse a list of targets from a comma-separated string.
///
/// Supports formats:
/// - `192.168.1.1`
/// - `192.168.1.1:443`
/// - `192.168.1.1,192.168.1.2`
/// - `192.168.1.1-10` (range)
/// - `192.168.1.0/24` (CIDR notation)
pub fn parse_targets(input: &str, default_port: u16) -> Result<Vec<Target>> {
    let mut targets = Vec::new();

    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Handle CIDR notation
        if part.contains('/') {
            let cidr_hosts = parse_cidr(part, default_port)?;
            targets.extend(cidr_hosts);
            continue;
        }

        // Handle IP ranges like 192.168.1.1-10
        if let Some((base, range)) = part.rsplit_once('-')
            && let Ok(start) = range.parse::<u8>()
            && let Some((prefix, last_octet)) = base.rsplit_once('.')
            && let Ok(end) = last_octet.parse::<u8>()
        {
            for i in start..=end.min(254) {
                let host = format!("{}.{}", prefix, i);
                targets.push(Target::new(&host, default_port));
            }
            continue;
        }

        targets.push(Target::from_str(part, default_port)?);
    }

    Ok(targets)
}

/// Parse CIDR notation (e.g., "192.168.1.0/24") into a list of targets.
pub fn parse_cidr(cidr: &str, default_port: u16) -> Result<Vec<Target>> {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(RcfError::InvalidOption {
            name: "cidr".to_string(),
            reason: format!("invalid CIDR notation: {}", cidr),
        });
    }

    let ip: Ipv4Addr = parts[0].parse().map_err(|_| RcfError::InvalidOption {
        name: "cidr".to_string(),
        reason: format!("invalid IP address: {}", parts[0]),
    })?;

    let prefix_len: u8 = parts[1].parse().map_err(|_| RcfError::InvalidOption {
        name: "cidr".to_string(),
        reason: format!("invalid prefix length: {}", parts[1]),
    })?;

    if prefix_len > 32 {
        return Err(RcfError::InvalidOption {
            name: "cidr".to_string(),
            reason: "prefix length must be <= 32".to_string(),
        });
    }

    let network_bits = 32 - prefix_len;
    let num_hosts = 2u32.pow(network_bits as u32);

    // Limit to reasonable size to prevent abuse
    if num_hosts > 65536 {
        return Err(RcfError::InvalidOption {
            name: "cidr".to_string(),
            reason: "CIDR range too large (max /16)".to_string(),
        });
    }

    let network_addr = u32::from(ip) & (!((1u32 << network_bits) - 1));

    let mut targets = Vec::with_capacity(num_hosts as usize);
    for i in 0..num_hosts {
        let addr = network_addr + i;
        let ip = Ipv4Addr::from(addr);
        // Skip network and broadcast addresses
        if i == 0 || i == num_hosts - 1 {
            continue;
        }
        targets.push(Target::new(&ip.to_string(), default_port));
    }

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_30() {
        let targets = parse_cidr("192.168.1.0/30", 80).unwrap();
        assert_eq!(targets.len(), 2); // .1 and .2
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[1].host, "192.168.1.2");
    }

    #[test]
    fn test_parse_cidr_24() {
        let targets = parse_cidr("10.0.0.0/24", 80).unwrap();
        assert_eq!(targets.len(), 254); // .1 through .254
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(targets[253].host, "10.0.0.254");
    }

    #[test]
    fn test_parse_targets_mixed() {
        let targets = parse_targets("192.168.1.1,10.0.0.0/30", 80).unwrap();
        assert_eq!(targets.len(), 3); // 1 single + 2 from /30
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[1].host, "10.0.0.1");
        assert_eq!(targets[2].host, "10.0.0.2");
    }
}
