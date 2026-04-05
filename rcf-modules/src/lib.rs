//! Module registry and plugin system for RCF.
//!
//! Provides a trait-based internal module registry with optional
//! dynamic loading support via libloading.

pub mod registry;
pub mod manager;
pub mod builtin;

pub use registry::ModuleRegistry;
pub use manager::ModuleManager;
