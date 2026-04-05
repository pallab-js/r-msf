//! TCP Connect scanner — cross-platform, no root required.
//!
//! Uses tokio's async TCP streams to connect to each port and
//! determine if it's open, closed, or filtered.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::scanner::common::{PortRange, ScanConfig, ScanResult};

/// A TCP Connect scanner that works without root privileges.
pub struct TcpConnectScanner;

impl TcpConnectScanner {
    pub fn new() -> Self {
        Self
    }

    /// Scan a single host, returning results for all specified ports.
    pub async fn scan(&self, config: &ScanConfig) -> Vec<ScanResult> {
        let ports = config.ports.to_vec();
        let total = ports.len();

        debug!(
            target = %config.target,
            ports = total,
            concurrency = config.concurrency,
            "Starting TCP connect scan"
        );

        let semaphore = Arc::new(Semaphore::new(config.concurrency));
        let mut handles = Vec::with_capacity(total);

        for port in ports {
            let sem = Arc::clone(&semaphore);
            let host = config.target.clone();
            let timeout_dur = config.timeout;
            let ssl = config.ssl;

            let handle = tokio::spawn(async move {
                let permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to acquire semaphore: {}", e);
                        return ScanResult::closed(port);
                    }
                };
                let result = probe_port(&host, port, timeout_dur, ssl).await;
                drop(permit);
                result
            });

            handles.push(handle);
        }

        let mut results = Vec::with_capacity(total);
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!("Task panic: {}", e);
                }
            }
        }

        // Sort by port number
        results.sort_by_key(|r| r.port);
        results
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
}

impl Default for TcpConnectScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Probe a single port and return the scan result.
async fn probe_port(host: &str, port: u16, timeout_dur: Duration, _ssl: bool) -> ScanResult {
    let addr = match format!("{}:{}", host, port).parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => return ScanResult::filtered(port),
    };

    let start = Instant::now();
    let result = timeout(timeout_dur, TcpStream::connect(addr)).await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;

    match result {
        Ok(Ok(_stream)) => {
            // Port is open
            let service = detect_service(port, _ssl);
            debug!("{}:{} is open ({:.1}ms)", host, port, elapsed);
            ScanResult::open(port, service).with_rtt(elapsed)
        }
        Ok(Err(_)) => {
            // Connection refused = closed
            debug!("{}:{} is closed", host, port);
            ScanResult::closed(port)
        }
        Err(_) => {
            // Timeout = filtered (firewall dropping packets)
            debug!("{}:{} is filtered (timeout)", host, port);
            ScanResult::filtered(port)
        }
    }
}

/// Detect common services by port number.
fn detect_service(port: u16, _ssl: bool) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("domain"),
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
        1433 => Some("ms-sql-s"),
        1521 => Some("oracle"),
        1723 => Some("pptp"),
        2049 => Some("nfs"),
        3306 => Some("mysql"),
        3389 => Some("ms-wbt-server"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        8080 => Some("http-proxy"),
        8443 => Some("https-alt"),
        9200 => Some("elasticsearch"),
        27017 => Some("mongodb"),
        _ => None,
    }
}
