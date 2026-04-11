//! TCP SYN scanner — uses raw sockets to send SYN packets.
//!
//! On Linux with root privileges, uses raw socket SYN scanning.
//! Otherwise, falls back to TCP Connect scanner.

use std::time::Duration;

use crate::scanner::common::{PortRange, ScanConfig, ScanResult};
use crate::scanner::tcp_connect::TcpConnectScanner;

/// TCP SYN scanner — uses raw sockets to send SYN packets.
///
/// Advantages over Connect scan:
/// - Stealthier (only sends SYN, never completes handshake)
/// - Faster (no full TCP state setup)
/// - Less likely to be logged by target
///
/// Requirements:
/// - Root/Administrator privileges (Linux)
pub struct TcpSynScanner {
    /// Whether to use raw sockets (auto-detected)
    use_raw: bool,
}

impl TcpSynScanner {
    pub fn new() -> Self {
        Self {
            use_raw: Self::check_privileges(),
        }
    }

    /// Scan using SYN technique. Falls back to Connect scan if not root.
    pub async fn scan(&self, config: &ScanConfig) -> Vec<ScanResult> {
        if self.use_raw {
            #[cfg(target_os = "linux")]
            {
                let raw_scanner = crate::scanner::raw_syn::RawSynScanner::new();
                if raw_scanner.privileged {
                    let target_ip = match config.target.parse::<std::net::Ipv4Addr>() {
                        Ok(ip) => ip,
                        Err(_) => {
                            // DNS resolution needed — for now fall back
                            let connect = TcpConnectScanner::new();
                            return connect.scan(config).await;
                        }
                    };
                    return raw_scanner
                        .scan(target_ip, &config.ports, config.timeout, config.concurrency)
                        .await;
                }
            }
            // Fall through to connect scanner on non-Linux
        }

        let connect = TcpConnectScanner::new();
        connect.scan(config).await
    }

    /// Quick scan of common ports.
    pub async fn quick_scan(&self, host: &str) -> Vec<ScanResult> {
        let config = ScanConfig::new(host)
            .with_ports(PortRange::Common)
            .with_concurrency(200)
            .with_timeout(Duration::from_secs(3));
        self.scan(&config).await
    }

    /// Full scan of all 65535 ports.
    pub async fn full_scan(&self, host: &str) -> Vec<ScanResult> {
        let config = ScanConfig::new(host)
            .with_ports(PortRange::All)
            .with_concurrency(500)
            .with_timeout(Duration::from_secs(2));
        self.scan(&config).await
    }

    /// Check if we have the privileges needed for raw sockets.
    pub fn check_privileges() -> bool {
        #[cfg(unix)]
        {
            let uid = unsafe { libc::geteuid() };
            uid == 0
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Check if raw socket scanning is available.
    pub fn is_raw_available(&self) -> bool {
        self.use_raw
    }
}

impl Default for TcpSynScanner {
    fn default() -> Self {
        Self::new()
    }
}
