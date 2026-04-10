//! Interactive REPL console for the Rust Cybersecurity Framework.
//!
//! Provides an msfconsole-like command interface with auto-completion,
//! history, and module interaction.

pub mod console;
pub mod commands;
pub mod completer;
pub mod resource;

pub use console::RcfConsole;
pub use resource::{ResourceScript, ResourceExecutor};
