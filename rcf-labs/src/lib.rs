//! Lab-focused exploit modules for RCF.
//!
//! Implements real exploits for common vulnerability types found in:
//! - HackTheBox
//! - TryHackMe
//! - PortSwigger Web Security Academy
//! - OffSec (OSCP/OSWE)
//! - Metasploitable

pub mod exploits;
pub mod scanners;
pub mod post_exploit;
pub mod missing_vulns;
pub mod advanced_exploits;
pub mod protocol_exploits;
pub mod real_exploits;
pub mod more_protocol_exploits;

pub use exploits::*;
pub use scanners::*;
pub use post_exploit::*;
pub use missing_vulns::*;
pub use advanced_exploits::*;
pub use protocol_exploits::*;
pub use real_exploits::*;
pub use more_protocol_exploits::*;
