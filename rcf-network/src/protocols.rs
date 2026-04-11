//! Protocol handlers for fingerprinting and service detection (Phase 2).
//!
//! Includes:
//! - HTTP/HTTPS (banner grab, title, tech fingerprint)
//! - SSH (version exchange, algorithm detection)
//! - SMB (OS detection, share enumeration)
//! - FTP (banner grab, anonymous login check)
//! - DNS (version query, zone transfer check)

pub mod common;
pub mod http;
pub mod smb;
pub mod ssh;

pub use common::ServiceInfo;
pub use http::HttpFingerprinter;
pub use smb::SmbFingerprinter;
pub use ssh::SshFingerprinter;
