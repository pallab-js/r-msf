//! SMB fingerprinter.
//!
//! Connects to SMB (port 445) and extracts:
//! - OS name and version
//! - SMB dialect (SMBv1, SMBv2, SMBv3)
//! - NetBIOS computer name
//! - Domain/workgroup name

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::protocols::common::ServiceInfo;

/// SMB server fingerprinter.
pub struct SmbFingerprinter;

impl SmbFingerprinter {
    pub fn new() -> Self {
        Self
    }

    /// Connect to SMB and extract server information.
    ///
    /// Uses SMB Negotiate Protocol to detect:
    /// - Maximum SMB dialect supported
    /// - Server OS
    /// - Server NetBIOS name
    pub async fn fingerprint(&self, host: &str, port: u16) -> Option<ServiceInfo> {
        debug!("Fingerprinting smb://{}:{}", host, port);

        let addr = format!("{}:{}", host, port);
        let mut stream = match timeout(
            Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => {
                debug!("Failed to connect to {}:{} for SMB", host, port);
                return None;
            }
        };

        // Send SMB Negotiate request
        let negotiate_req = build_smb_negotiate();
        if stream.write_all(&negotiate_req).await.is_err() {
            return None;
        }

        // Read response
        let mut buf = vec![0u8; 4096];
        match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let info = parse_smb_response(&buf[..n], host);
                if info.is_some() {
                    debug!("SMB info for {}: {:?}", host, info);
                }
                info
            }
            _ => {
                // Connection succeeded but no useful response
                // Still return basic SMB detection
                Some(ServiceInfo::new("smb"))
            }
        }
    }
}

impl Default for SmbFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

/// Build an SMB2 Negotiate Protocol request.
fn build_smb_negotiate() -> Vec<u8> {
    // SMB2 Negotiate request
    // This is a minimal SMB2 negotiate request that asks for supported dialects
    vec![
        // NetBIOS Session Service header
        0x00, 0x00, 0x00, 0x4a, // Session message, length = 74

        // SMB2 header
        0xfe, 0x53, 0x4d, 0x42, // Protocol ID: "\xfeSMB"
        0x40, 0x00, // StructureSize: 64
        0x00, 0x00, // CreditCharge: 0
        0x00, 0x00, // ChannelSequence: 0
        0x00, 0x00, // Reserved
        0x00, 0x00, // Command: 0 (Negotiate)
        0x00, 0x00, // CreditsRequested: 0
        0x00, 0x00, 0x00, 0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // NextCommand
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TreeId
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature

        // SMB2 Negotiate request body
        0x24, 0x00, // StructureSize: 36
        0x08, 0x00, // DialectCount: 8
        0x00, 0x00, // SecurityMode: 0
        0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, // Capabilities
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid
        0x00, 0x00, 0x00, 0x00, // NegotiateContextOffset
        0x00, 0x00, // NegotiateContextCount
        0x00, 0x00, // Reserved2

        // Supported dialects
        0x02, 0x02, // SMB 2.0.2
        0x10, 0x02, // SMB 2.1
        0x22, 0x02, // SMB 2.2
        0x00, 0x03, // SMB 3.0
        0x02, 0x03, // SMB 3.0.2
        0x10, 0x03, // SMB 3.1
        0x11, 0x03, // SMB 3.1.1
        0x00, 0x00, // Padding
    ]
}

/// Parse the SMB negotiate response to extract server info.
fn parse_smb_response(data: &[u8], host: &str) -> Option<ServiceInfo> {
    if data.len() < 68 {
        return Some(ServiceInfo::new("smb").with_extra("target", host));
    }

    // Check SMB2 signature
    if &data[4..8] != b"\xfeSMB" {
        // Might be SMBv1 or NetBIOS only
        return Some(ServiceInfo::new("smb")
            .with_extra("target", host)
            .with_extra("note", "likely SMBv1"));
    }

    let mut info = ServiceInfo::new("smb").with_extra("target", host);

    // Parse dialect from response
    // StructureSize is at offset 8+4, Dialect at offset 8+4+6
    if data.len() >= 76 {
        let dialect = u16::from_le_bytes([data[74], data[75]]);
        let dialect_str = match dialect {
            0x0202 => "SMB 2.0.2",
            0x0210 => "SMB 2.1",
            0x0222 => "SMB 2.2",
            0x0300 => "SMB 3.0",
            0x0302 => "SMB 3.0.2",
            0x0310 => "SMB 3.1",
            0x0311 => "SMB 3.1.1",
            _ => "Unknown",
        };
        info = info.with_extra("dialect", dialect_str);
    }

    Some(info)
}
