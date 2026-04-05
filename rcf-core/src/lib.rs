//! Core types, traits, and utilities for the Rust Cybersecurity Framework (RCF).
//!
//! This crate provides the foundational abstractions used throughout the framework,
//! including the Module trait, Context for global state, and common data types.

pub mod error;
pub mod module;
pub mod context;
pub mod target;
pub mod options;
pub mod output;
pub mod jobs;
pub mod msf_compat;
pub mod evasion;

pub use error::{RcfError, Result};
pub use module::{Module, ModuleType, ModuleInfo, ModuleCategory};
pub use context::Context;
pub use target::Target;
pub use options::{ModuleOptions, ModuleOption, OptionValue};
pub use output::{ModuleOutput, OutputFormat};
pub use jobs::{JobManager, Job, JobStatus};
