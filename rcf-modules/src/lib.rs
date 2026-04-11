//! Module registry and plugin system for RCF.
//!
//! Provides a trait-based internal module registry with optional
//! dynamic loading support via libloading.

pub mod builtin;
pub mod manager;
pub mod registry;

pub use manager::ModuleManager;
pub use registry::ModuleRegistry;
