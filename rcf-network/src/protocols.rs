//! Protocol handlers for fingerprinting and service detection (Phase 2).
//!
//! Includes:
//! - HTTP/HTTPS (banner grab, title, tech fingerprint)
//! - SSH (version exchange, algorithm detection)
//! - SMB (OS detection, share enumeration)
//! - FTP (banner grab, anonymous login check)
//! - DNS (version query, zone transfer check)

pub mod http;
pub mod ssh;
pub mod smb;
pub mod common;

pub use http::HttpFingerprinter;
pub use ssh::SshFingerprinter;
pub use smb::SmbFingerprinter;
pub use common::ServiceInfo;
