//! Binary integrity verification.
//!
//! Verifies the binary has not been tampered with using an Ed25519 signature.
//! On release builds, a companion `.sig` file is required next to the binary.
//! Debug builds log a warning on failure but continue.

use sha2::{Digest, Sha256};
use std::path::Path;

/// Embedded Ed25519 public key (hex-encoded).
/// This is the default key used for verification.
/// Rotate by setting `RCF_PUBKEY` env var at build time.
pub const EMBEDDED_PUBKEY: &str =
    "d1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";

/// Result of an integrity check.
#[derive(Debug, Clone, PartialEq)]
pub enum IntegrityStatus {
    Pass,
    Fail(String),
    NotApplicable(String),
}

impl IntegrityStatus {
    pub fn is_pass(&self) -> bool {
        matches!(self, IntegrityStatus::Pass)
    }
}

/// Verify the integrity of the running binary.
///
/// In release mode, this reads the binary at its own path,
/// hashes it, and verifies against the companion `.sig` file.
/// In debug mode, failure produces a warning and returns Pass.
pub fn verify_binary_integrity() -> IntegrityStatus {
    let binary_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return IntegrityStatus::NotApplicable(format!("Cannot get binary path: {}", e)),
    };

    do_verify(&binary_path)
}

fn do_verify(binary_path: &Path) -> IntegrityStatus {
    let binary_data = match std::fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            return IntegrityStatus::NotApplicable(format!("Cannot read binary: {}", e));
        }
    };

    let hash = Sha256::digest(&binary_data);

    // Companion .sig file: <binary>.sig
    let sig_path = binary_path.with_extension("sig");

    if !sig_path.exists() {
        if cfg!(debug_assertions) {
            return IntegrityStatus::Pass;
        }
        return IntegrityStatus::Fail(format!(
            "Missing signature file: {}. Run scripts/sign-release.sh to sign the binary.",
            sig_path.display()
        ));
    }

    let sig_data = match std::fs::read(&sig_path) {
        Ok(d) => d,
        Err(e) => {
            return IntegrityStatus::Fail(format!("Cannot read signature file: {}", e));
        }
    };

    if sig_data.len() != 64 {
        return IntegrityStatus::Fail("Invalid signature length (expected 64 bytes)".to_string());
    }

    let sig_bytes: [u8; 64] = match sig_data.try_into() {
        Ok(b) => b,
        Err(_) => {
            return IntegrityStatus::Fail("Invalid signature format".to_string());
        }
    };

    let signature = ed25519::Signature::from_bytes(&sig_bytes);

    let pubkey_hex = option_env!("RCF_PUBKEY").unwrap_or(EMBEDDED_PUBKEY);
    let pubkey_bytes = match hex_decode(pubkey_hex) {
        Some(b) if b.len() == 32 => b,
        _ => {
            return IntegrityStatus::NotApplicable("Invalid embedded public key".to_string());
        }
    };

    let pubkey_array: [u8; 32] = match pubkey_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return IntegrityStatus::NotApplicable("Invalid public key length".to_string());
        }
    };

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&pubkey_array) {
        Ok(k) => k,
        Err(_) => {
            return IntegrityStatus::NotApplicable("Invalid public key bytes".to_string());
        }
    };

    use ed25519_dalek::Verifier;
    match verifying_key.verify(&hash, &signature) {
        Ok(()) => IntegrityStatus::Pass,
        Err(e) => IntegrityStatus::Fail(format!(
            "Integrity check failed - binary may be compromised: {}",
            e
        )),
    }
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_decode() {
        let result = hex_decode("a1b2c3").unwrap();
        assert_eq!(result, vec![0xa1, 0xb2, 0xc3]);
    }

    #[test]
    fn test_hex_decode_empty() {
        assert_eq!(hex_decode(""), Some(vec![]));
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert_eq!(hex_decode("xyz"), None);
        assert_eq!(hex_decode("a"), None);
    }

    #[test]
    fn test_integrity_status_display() {
        assert!(IntegrityStatus::Pass.is_pass());
        assert!(!IntegrityStatus::Fail("test".to_string()).is_pass());
        assert!(!IntegrityStatus::NotApplicable("test".to_string()).is_pass());
    }
}
