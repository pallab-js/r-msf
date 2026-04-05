//! SSH fingerprinter.
//!
//! Connects to SSH servers and extracts:
//! - Protocol version from banner
//! - Key exchange algorithms
//! - Host key types
//! - Encryption algorithms

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::protocols::common::ServiceInfo;

/// SSH server fingerprinter.
pub struct SshFingerprinter;

impl SshFingerprinter {
    pub fn new() -> Self {
        Self
    }

    /// Connect to an SSH server and extract version info.
    pub async fn fingerprint(&self, host: &str, port: u16) -> Option<ServiceInfo> {
        debug!("Fingerprinting ssh://{}:{}", host, port);

        let addr = format!("{}:{}", host, port);
        let result = timeout(
            Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await;

        let stream = match result {
            Ok(Ok(s)) => s,
            _ => {
                debug!("Failed to connect to {}:{} for SSH", host, port);
                return None;
            }
        };

        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        // Read SSH banner (first line)
        match timeout(Duration::from_secs(5), reader.read_line(&mut line)).await {
            Ok(Ok(0)) => return None,
            Ok(Ok(_)) => {}
            _ => return None,
        }

        let banner = line.trim();
        debug!("SSH banner from {}:{}: {}", host, port, banner);

        // Parse SSH version from banner
        // Format: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
        let mut info = ServiceInfo::new("ssh");
        
        if let Some(version) = parse_ssh_version(banner) {
            info.version = Some(version.clone());
            info = info.with_extra("banner", banner);

            // Detect OS from version string
            if version.contains("Ubuntu") {
                info = info.with_os("Ubuntu Linux");
            } else if version.contains("Debian") {
                info = info.with_os("Debian Linux");
            } else if version.contains("CentOS") || version.contains("Red Hat") {
                info = info.with_os("RHEL/CentOS Linux");
            } else if version.contains("Amazon") {
                info = info.with_os("Amazon Linux");
            } else if version.contains("FreeBSD") {
                info = info.with_os("FreeBSD");
            } else if version.contains("OpenWrt") {
                info = info.with_os("OpenWrt");
            } else if version.contains("Cisco") || version.contains("IOS") {
                info = info.with_os("Cisco IOS");
            } else if version.contains("MikroTik") || version.contains("RouterOS") {
                info = info.with_os("MikroTik RouterOS");
            } else if version.contains("Dropbear") {
                info = info.with_extra("software", "Dropbear SSH");
            }
        }

        Some(info)
    }
}

impl Default for SshFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the SSH software version from the banner.
///
/// Banner format: `SSH-protoversion-softwareversion SP comments CR LF`
/// Example: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1`
fn parse_ssh_version(banner: &str) -> Option<String> {
    // Remove any trailing whitespace/CR
    let banner = banner.trim();
    
    // Should start with SSH-
    if !banner.starts_with("SSH-") {
        return None;
    }
    
    // Extract the software part after SSH-X.Y-
    if let Some(dash_pos) = banner[4..].find('-') {
        let software = &banner[4 + dash_pos + 1..];
        Some(software.to_string())
    } else {
        Some(banner.to_string())
    }
}
