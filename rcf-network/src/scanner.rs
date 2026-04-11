//! Port scanning implementations (Phase 2).
//!
//! Includes:
//! - TCP Connect scanner (cross-platform, no raw sockets needed)
//! - TCP SYN scanner using raw sockets (requires root, Linux only)
//! - UDP scanner (Phase 2.5)

pub mod common;
#[cfg(target_os = "linux")]
pub mod raw_syn;
pub mod tcp_connect;
pub mod tcp_syn;

pub use common::{PortRange, PortState, ScanConfig, ScanResult};
#[cfg(target_os = "linux")]
pub use raw_syn::RawSynScanner;
pub use tcp_connect::TcpConnectScanner;
pub use tcp_syn::TcpSynScanner;
