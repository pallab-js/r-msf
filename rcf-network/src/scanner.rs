//! Port scanning implementations (Phase 2).
//!
//! Includes:
//! - TCP Connect scanner (cross-platform, no raw sockets needed)
//! - TCP SYN scanner using raw sockets (requires root, Linux only)
//! - UDP scanner (Phase 2.5)

pub mod tcp_connect;
pub mod tcp_syn;
#[cfg(target_os = "linux")]
pub mod raw_syn;
pub mod common;

pub use tcp_connect::TcpConnectScanner;
pub use tcp_syn::TcpSynScanner;
#[cfg(target_os = "linux")]
pub use raw_syn::RawSynScanner;
pub use common::{ScanResult, PortState, ScanConfig, PortRange};
