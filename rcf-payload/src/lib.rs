//! Payload generator and compiler (RCF-Venom).
//!
//! Generates obfuscated shellcode and cross-compiled payloads for:
//! - Unix (x86_64, ARM64)
//! - Windows (x86, x64)
//! - macOS (x86_64, ARM64)
//!
//! Supports encoding, encryption, and polymorphic obfuscation.

pub mod generator;
pub mod encoder;
pub mod templates;
pub mod polymorphic;
pub mod output;
pub mod pe_builder;
pub mod executor;

pub use generator::{PayloadConfig, PayloadType, PayloadGenerator, Platform, Arch};
pub use encoder::PayloadEncoder;
pub use polymorphic::PolymorphicEngine;
pub use output::{OutputFormat, PayloadOutput};
pub use pe_builder::PeBuilder;
pub use executor::{PayloadExecutor, ExecutionResult};
