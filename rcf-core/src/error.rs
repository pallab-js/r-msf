//! Error types for RCF.

use thiserror::Error;

/// Result type alias using RCF errors.
pub type Result<T> = std::result::Result<T, RcfError>;

/// All error types used throughout the framework.
#[derive(Error, Debug)]
pub enum RcfError {
    #[error("Module error: {0}")]
    Module(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Payload error: {0}")]
    Payload(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Console error: {0}")]
    Console(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid option: {name} — {reason}")]
    InvalidOption { name: String, reason: String },

    #[error("Target unreachable: {host}:{port}")]
    UnreachableTarget { host: String, port: u16 },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Plugin load error: {0}")]
    PluginLoad(String),

    #[error("Execution timeout")]
    Timeout,

    #[error("Generic error: {0}")]
    Generic(String),
}

impl From<anyhow::Error> for RcfError {
    fn from(err: anyhow::Error) -> Self {
        RcfError::Generic(err.to_string())
    }
}
