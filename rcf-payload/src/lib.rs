//! Payload generator and compiler (RCF-Venom).
//!
//! Generates obfuscated shellcode for Linux (x86_64, x86).
//!
//! Supports encoding, polymorphic obfuscation, and staged delivery.

pub mod encoder;
pub mod executor;
pub mod generator;
pub mod output;
pub mod polymorphic;
pub mod stager;
pub mod templates;

pub use encoder::PayloadEncoder;
pub use executor::{ExecutionResult, PayloadExecutor};
pub use generator::{Arch, PayloadConfig, PayloadGenerator, PayloadType, Platform};
pub use output::{OutputFormat, PayloadOutput};
pub use polymorphic::PolymorphicEngine;
pub use stager::{StageServer, generate_stager, test_stager_connection};
