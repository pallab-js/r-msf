//! Decoy traffic configuration.

use serde::{Deserialize, Serialize};

/// Configuration for generating decoy traffic as misdirection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyConfig {
    pub enabled: bool,
    pub decoy_ratio: f32,
    pub decoy_targets: Vec<DecoyTarget>,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            decoy_ratio: 0.1,
            decoy_targets: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyTarget {
    pub host: String,
    pub port: u16,
    pub method: DecoyMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecoyMethod {
    Connect,
    SendData,
    KeepAlive,
}
