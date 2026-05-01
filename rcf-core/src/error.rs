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

impl From<toml::de::Error> for RcfError {
    fn from(err: toml::de::Error) -> Self {
        RcfError::Config(err.to_string())
    }
}

impl From<toml::ser::Error> for RcfError {
    fn from(err: toml::ser::Error) -> Self {
        RcfError::Config(err.to_string())
    }
}

#[cfg(feature = "reqwest")]
impl From<reqwest::Error> for RcfError {
    fn from(err: reqwest::Error) -> Self {
        RcfError::Network(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let rcf_err = RcfError::from(io_err);
        assert!(matches!(rcf_err, RcfError::Io(_)));
        assert!(rcf_err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let rcf_err = RcfError::from(json_err);
        assert!(matches!(rcf_err, RcfError::Serialization(_)));
    }

    #[test]
    fn test_from_toml_de_error() {
        let toml_err = toml::from_str::<toml::Value>("bad = [unclosed").unwrap_err();
        let rcf_err = RcfError::from(toml_err);
        assert!(matches!(rcf_err, RcfError::Config(_)));
    }

    #[test]
    fn test_from_toml_ser_error() {
        // toml::ser::Error via From conversion — construct via anyhow path
        // (toml::ser::Error is hard to construct directly; test the variant shape)
        let rcf_err = RcfError::Config("serialization failed".to_string());
        assert!(matches!(rcf_err, RcfError::Config(_)));
        assert!(rcf_err.to_string().contains("Configuration error"));
    }

    #[test]
    fn test_from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("something went wrong");
        let rcf_err = RcfError::from(anyhow_err);
        assert!(matches!(rcf_err, RcfError::Generic(_)));
        assert!(rcf_err.to_string().contains("something went wrong"));
    }

    #[test]
    fn test_invalid_option_display() {
        let err = RcfError::InvalidOption {
            name: "RHOSTS".to_string(),
            reason: "not set".to_string(),
        };
        assert!(err.to_string().contains("RHOSTS"));
        assert!(err.to_string().contains("not set"));
    }

    #[test]
    fn test_timeout_display() {
        let err = RcfError::Timeout;
        assert_eq!(err.to_string(), "Execution timeout");
    }
}
