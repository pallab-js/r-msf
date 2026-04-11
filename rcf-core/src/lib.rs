//! Core types, traits, and utilities for the Rust Cybersecurity Framework (RCF).
//!
//! This crate provides the foundational abstractions used throughout the framework,
//! including the Module trait, Context for global state, and common data types.

pub mod audit;
pub mod context;
pub mod error;
pub mod evasion;
pub mod jobs;
pub mod module;
pub mod msf_compat;
pub mod options;
pub mod output;
pub mod target;

pub use audit::{AuditCategory, AuditEntry, AuditLevel, AuditLogger};
pub use context::Context;
pub use error::{RcfError, Result};
pub use jobs::{Job, JobManager, JobStatus};
pub use module::{Module, ModuleCategory, ModuleInfo, ModuleType};
pub use options::{ModuleOption, ModuleOptions, OptionValue};
pub use output::{ModuleOutput, OutputFormat};
pub use target::Target;
