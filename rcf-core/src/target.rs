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
/// `max_targets` caps the total number of targets returned (default: 10000).
/// Supports: single IPs, `host:port`, comma-separated, IP ranges (`x.x.x.1-10`), CIDR.
pub fn parse_targets(input: &str, default_port: u16, max_targets: usize) -> Result<Vec<Target>> {
    let mut targets = Vec::new();

    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if targets.len() >= max_targets {
            break;
        }

        // Handle CIDR notation
        if part.contains('/') {
            let remaining = max_targets - targets.len();
            let cidr_hosts = parse_cidr(part, default_port, remaining)?;
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
                if targets.len() >= max_targets {
                    break;
                }
                targets.push(Target::new(&format!("{}.{}", prefix, i), default_port));
            }
            continue;
        }

        targets.push(Target::from_str(part, default_port)?);
    }

    Ok(targets)
}

/// Lazy iterator over IPv4 addresses in a CIDR block.
pub struct CidrIter {
    network_addr: u32,
    current: u32,
    end: u32,
    port: u16,
}

impl CidrIter {
    fn new(network_addr: u32, num_hosts: u32, port: u16) -> Self {
        Self {
            network_addr,
            current: 1, // skip network address (.0)
            end: num_hosts.saturating_sub(1), // skip broadcast
            port,
        }
    }
}

impl Iterator for CidrIter {
    type Item = Target;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.end {
            return None;
        }
        let addr = self.network_addr + self.current;
        self.current += 1;
        Some(Target::new(&Ipv4Addr::from(addr).to_string(), self.port))
    }
}

/// Parse CIDR notation into a lazy iterator, collecting up to `max_targets` hosts.
pub fn parse_cidr(cidr: &str, default_port: u16, max_targets: usize) -> Result<Vec<Target>> {
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

    let network_bits = 32 - prefix_len as u32;
    let num_hosts = 1u32.checked_shl(network_bits).unwrap_or(u32::MAX);
    let network_addr = u32::from(ip) & !(num_hosts - 1);

    Ok(CidrIter::new(network_addr, num_hosts, default_port)
        .take(max_targets)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_30() {
        let targets = parse_cidr("192.168.1.0/30", 80, 10000).unwrap();
        assert_eq!(targets.len(), 2); // .1 and .2
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[1].host, "192.168.1.2");
    }

    #[test]
    fn test_parse_cidr_24() {
        let targets = parse_cidr("10.0.0.0/24", 80, 10000).unwrap();
        assert_eq!(targets.len(), 254);
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(targets[253].host, "10.0.0.254");
    }

    #[test]
    fn test_parse_cidr_large_capped() {
        // /8 would be 16M hosts — max_targets=5 must cap it without OOM
        let targets = parse_cidr("10.0.0.0/8", 80, 5).unwrap();
        assert_eq!(targets.len(), 5);
    }

    #[test]
    fn test_parse_targets_mixed() {
        let targets = parse_targets("192.168.1.1,10.0.0.0/30", 80, 10000).unwrap();
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[1].host, "10.0.0.1");
        assert_eq!(targets[2].host, "10.0.0.2");
    }

    #[test]
    fn test_parse_targets_max_targets_cap() {
        let targets = parse_targets("10.0.0.0/24", 80, 10).unwrap();
        assert_eq!(targets.len(), 10);
    }
}
