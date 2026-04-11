//! Common types for port scanning.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Result of scanning a single port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub rtt_ms: Option<f64>,
}

impl ScanResult {
    pub fn open(port: u16, service: Option<&str>) -> Self {
        Self {
            port,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            service: service.map(String::from),
            version: None,
            banner: None,
            rtt_ms: None,
        }
    }

    pub fn closed(port: u16) -> Self {
        Self {
            port,
            protocol: "tcp".to_string(),
            state: PortState::Closed,
            service: None,
            version: None,
            banner: None,
            rtt_ms: None,
        }
    }

    pub fn filtered(port: u16) -> Self {
        Self {
            port,
            protocol: "tcp".to_string(),
            state: PortState::Filtered,
            service: None,
            version: None,
            banner: None,
            rtt_ms: None,
        }
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    pub fn with_banner(mut self, banner: &str) -> Self {
        self.banner = Some(banner.to_string());
        self
    }

    pub fn with_rtt(mut self, rtt_ms: f64) -> Self {
        self.rtt_ms = Some(rtt_ms);
        self
    }
}

/// Possible port states.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}

/// Configuration for a scan.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: String,
    pub ports: PortRange,
    pub timeout: Duration,
    pub concurrency: usize,
    pub ssl: bool,
}

impl ScanConfig {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            ports: PortRange::WellKnown,
            timeout: Duration::from_secs(3),
            concurrency: 100,
            ssl: false,
        }
    }

    pub fn with_ports(mut self, ports: PortRange) -> Self {
        self.ports = ports;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrency = n;
        self
    }

    pub fn with_ssl(mut self, ssl: bool) -> Self {
        self.ssl = ssl;
        self
    }
}

/// Port range specification.
#[derive(Debug, Clone, Default)]
pub enum PortRange {
    /// Scan a specific range: start..=end
    Range(u16, u16),
    /// Scan a single port
    Single(u16),
    /// Scan a list of specific ports
    List(Vec<u16>),
    /// Well-known ports (1-1023)
    WellKnown,
    /// Registered ports (1-49151)
    Registered,
    /// All ports (1-65535)
    All,
    /// Common ports list (21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    /// 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443)
    #[default]
    Common,
}

/// Common ports list as a static slice (avoids allocation on every call).
const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080, 8443,
];

impl PortRange {
    /// Convert to a list of ports.
    pub fn to_vec(&self) -> Vec<u16> {
        match self {
            PortRange::Range(start, end) => (*start..=*end).collect(),
            PortRange::Single(p) => vec![*p],
            PortRange::List(ports) => ports.clone(),
            PortRange::WellKnown => (1..=1023).collect(),
            PortRange::Registered => (1..=49151).collect(),
            PortRange::All => (1..=65535).collect(),
            PortRange::Common => COMMON_PORTS.to_vec(),
        }
    }

    /// Returns an iterator over ports (zero-allocation for static ranges).
    pub fn iter(&self) -> Box<dyn Iterator<Item = u16> + '_> {
        match self {
            PortRange::Range(start, end) => Box::new(*start..=*end),
            PortRange::Single(p) => Box::new(std::iter::once(*p)),
            PortRange::List(ports) => Box::new(ports.iter().copied()),
            PortRange::WellKnown => Box::new(1..=1023),
            PortRange::Registered => Box::new(1..=49151),
            PortRange::All => Box::new(1..=65535),
            PortRange::Common => Box::new(COMMON_PORTS.iter().copied()),
        }
    }

    /// Parse from a string like "1-1024", "80", "common", "all", "22,80,443"
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim().to_lowercase();
        match s.as_str() {
            "common" => Ok(PortRange::Common),
            "all" | "1-65535" => Ok(PortRange::All),
            "well-known" | "wellknown" => Ok(PortRange::WellKnown),
            "registered" => Ok(PortRange::Registered),
            _ => {
                // Handle comma-separated list
                if s.contains(',') {
                    let ports: Result<Vec<u16>, _> = s
                        .split(',')
                        .map(|p| {
                            p.trim()
                                .parse::<u16>()
                                .map_err(|_| format!("invalid port: {}", p.trim()))
                        })
                        .collect();
                    return ports.map(PortRange::List);
                }

                if let Some((start, end)) = s.split_once('-') {
                    let start: u16 = start
                        .trim()
                        .parse()
                        .map_err(|_| format!("invalid port: {}", start.trim()))?;
                    let end: u16 = end
                        .trim()
                        .parse()
                        .map_err(|_| format!("invalid port: {}", end.trim()))?;
                    if start > end {
                        return Err("start port must be <= end port".to_string());
                    }
                    Ok(PortRange::Range(start, end))
                } else {
                    let port: u16 = s.parse().map_err(|_| format!("invalid port: {}", s))?;
                    Ok(PortRange::Single(port))
                }
            }
        }
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortRange::Range(s, e) => write!(f, "{}-{}", s, e),
            PortRange::Single(p) => write!(f, "{}", p),
            PortRange::List(ports) => {
                let strs: Vec<_> = ports.iter().map(|p| p.to_string()).collect();
                write!(f, "{}", strs.join(","))
            }
            PortRange::WellKnown => write!(f, "well-known"),
            PortRange::Registered => write!(f, "registered"),
            PortRange::All => write!(f, "all"),
            PortRange::Common => write!(f, "common"),
        }
    }
}
