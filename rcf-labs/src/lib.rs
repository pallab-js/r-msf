//! Lab-focused exploit modules for RCF.
//!
//! Implements real exploits for common vulnerability types found in:
//! - HackTheBox
//! - TryHackMe
//! - PortSwigger Web Security Academy
//! - OffSec (OSCP/OSWE)
//! - Metasploitable

pub mod advanced_exploits;
pub mod ctf_modules;
pub mod exploits;
pub mod missing_vulns;
pub mod more_protocol_exploits;
pub mod network_enum;
pub mod post_exploit;
pub mod post_linux;
pub mod protocol_exploits;
pub mod real_exploits;
pub mod scanners;
pub mod security;
pub mod web_exploits;

pub use advanced_exploits::*;
pub use ctf_modules::*;
pub use exploits::*;
pub use missing_vulns::*;
pub use more_protocol_exploits::*;
pub use network_enum::*;
pub use post_exploit::*;
pub use post_linux::*;
pub use protocol_exploits::*;
pub use real_exploits::*;
pub use scanners::*;
pub use web_exploits::*;
