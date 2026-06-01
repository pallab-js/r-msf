//! C2 Authentication — Ed25519 key-based session binding.
//!
//! Implements the cryptographic handshake between agents and C2:
//! 1. Agent generates Ed25519 keypair on first run
//! 2. C2 maintains authorized public keys
//! 3. Handshake: C2 sends nonce → Agent signs → C2 verifies
//! 4. Session token derived via HKDF
//!
//! Backward-compatible with v0.2 PSK auth via `--legacy-psk` flag.

use ed25519_dalek::VerifyingKey;
use rcf_core::crypto;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Duration for which a challenge nonce is valid (seconds).
const CHALLENGE_TIMEOUT_SECS: i64 = 60;

/// Authentication method used.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AuthMethod {
    /// PSK-based (v0.2 backward compat)
    PreSharedKey,
    /// Ed25519 signature-based
    Ed25519,
    /// No authentication (testing only)
    None,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::PreSharedKey => write!(f, "psk"),
            AuthMethod::Ed25519 => write!(f, "ed25519"),
            AuthMethod::None => write!(f, "none"),
        }
    }
}

/// Result of an authentication attempt.
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Whether authentication succeeded
    pub success: bool,
    /// Authentication method used
    pub method: AuthMethod,
    /// Agent public key (if Ed25519 auth)
    pub agent_pubkey: Option<[u8; 32]>,
    /// Derived session token (32 bytes)
    pub session_token: Option<[u8; 32]>,
    /// Failure reason (if any)
    pub reason: Option<String>,
}

/// A pending challenge for an agent connection.
#[derive(Debug)]
struct PendingChallenge {
    /// The nonce sent to the agent
    nonce: [u8; 32],
    /// When the challenge was issued
    created_at: i64,
    /// Peer address
    #[allow(dead_code)]
    peer_addr: String,
}

/// Manages authorized agent public keys.
#[derive(Debug, Clone)]
pub struct AuthorizedKeys {
    /// Map of hex-encoded public key → label/description
    keys: Arc<RwLock<HashMap<String, String>>>,
}

impl AuthorizedKeys {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add an authorized public key from raw bytes.
    pub async fn add_key(&self, pubkey_bytes: &[u8; 32], label: &str) {
        let hex = hex_encode(pubkey_bytes);
        self.keys.write().await.insert(hex, label.to_string());
    }

    /// Check if a public key is authorized.
    pub async fn is_authorized(&self, pubkey_bytes: &[u8; 32]) -> bool {
        let hex = hex_encode(pubkey_bytes);
        self.keys.read().await.contains_key(&hex)
    }

    /// Remove an authorized key.
    pub async fn remove_key(&self, pubkey_bytes: &[u8; 32]) {
        let hex = hex_encode(pubkey_bytes);
        self.keys.write().await.remove(&hex);
    }

    /// List all authorized keys (hex → label).
    pub async fn list_keys(&self) -> Vec<(String, String)> {
        let mut list: Vec<_> = self
            .keys
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        list.sort_by(|a, b| a.1.cmp(&b.1));
        list
    }

    /// Load authorized keys from a directory of raw key files (32-byte binary, .key extension)
    /// or hex-encoded key files (.hex extension).
    pub async fn load_from_dir(&self, dir: &std::path::Path) -> Result<usize, String> {
        if !dir.exists() {
            return Ok(0);
        }

        let mut count = 0;
        let mut entries = std::fs::read_dir(dir)
            .map_err(|e| format!("Failed to read directory {}: {}", dir.display(), e))?;

        while let Some(entry) = entries.next().transpose().map_err(|e| e.to_string())? {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            let key_bytes = if ext == "hex" {
                let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
                hex_decode(content.trim()).ok_or_else(|| "Invalid hex key".to_string())?
            } else if ext == "key" || ext == "pub" || ext == "bin" {
                std::fs::read(&path).map_err(|e| e.to_string())?
            } else {
                continue;
            };

            if key_bytes.len() != 32 {
                continue;
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            if let Ok(vk) = VerifyingKey::from_bytes(&arr) {
                let hex = hex_encode(&vk.to_bytes());
                let label = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                self.keys.write().await.insert(hex, label);
                count += 1;
            }
        }

        Ok(count)
    }
}

impl Default for AuthorizedKeys {
    fn default() -> Self {
        Self::new()
    }
}

/// C2 Authentication handler.
pub struct C2Auth {
    /// PSK for backward compatibility
    psk: Option<String>,
    /// Authorized agent public keys
    authorized_keys: AuthorizedKeys,
    /// Pending challenges (address → challenge)
    challenges: Arc<RwLock<HashMap<String, PendingChallenge>>>,
    /// Whether to use legacy PSK mode
    legacy_mode: bool,
}

impl C2Auth {
    /// Create a new PSK-based authenticator (v0.2 compat).
    pub fn with_psk(psk: String) -> Self {
        Self {
            psk: Some(psk),
            authorized_keys: AuthorizedKeys::new(),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            legacy_mode: true,
        }
    }

    /// Create a new Ed25519-based authenticator.
    pub fn with_authorized_keys(keys: AuthorizedKeys) -> Self {
        Self {
            psk: None,
            authorized_keys: keys,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            legacy_mode: false,
        }
    }

    /// Create with both PSK and Ed25519 support (migration mode).
    pub fn with_both(psk: String, keys: AuthorizedKeys) -> Self {
        Self {
            psk: Some(psk),
            authorized_keys: keys,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            legacy_mode: false,
        }
    }

    /// Start the handshake by issuing a nonce challenge.
    /// Returns the nonce to send to the agent.
    pub async fn issue_challenge(&self, peer_addr: &str) -> [u8; 32] {
        let nonce = crypto::generate_nonce();
        let challenge = PendingChallenge {
            nonce,
            created_at: chrono::Utc::now().timestamp(),
            peer_addr: peer_addr.to_string(),
        };
        self.challenges
            .write()
            .await
            .insert(peer_addr.to_string(), challenge);
        nonce
    }

    /// Verify an agent's signature response against the issued challenge.
    /// Also handles backward-compatible PSK auth.
    pub async fn verify_agent(&self, peer_addr: &str, auth_data: &[u8]) -> AuthResult {
        // Try PSK auth first (backward compatible)
        if let Some(ref psk) = self.psk
            && self.legacy_mode
        {
            let msg = String::from_utf8_lossy(auth_data);
            let msg = msg.trim();

            if let Some(provided_psk) = msg.strip_prefix("RCF_AGENT_V1:") {
                use subtle::ConstantTimeEq;
                let psk_equal = provided_psk.as_bytes().ct_eq(psk.as_bytes());
                if bool::from(psk_equal) {
                    // Derive session token from PSK
                    let session_token = crypto::derive_session_key(
                        psk.as_bytes(),
                        peer_addr.as_bytes(),
                        b"rcf-psk-session",
                    );
                    return AuthResult {
                        success: true,
                        method: AuthMethod::PreSharedKey,
                        agent_pubkey: None,
                        session_token: Some(session_token),
                        reason: None,
                    };
                }
            }
            // If PSK mode and PSK check fails, fail auth
            return AuthResult {
                success: false,
                method: AuthMethod::PreSharedKey,
                agent_pubkey: None,
                session_token: None,
                reason: Some("PSK authentication failed".to_string()),
            };
        }

        // Ed25519 auth: parse format "RCF_AGENT_V2:<pubkey_hex>:<signature_hex>"
        let msg = String::from_utf8_lossy(auth_data);
        let msg = msg.trim();

        if !msg.starts_with("RCF_AGENT_V2:") {
            return AuthResult {
                success: false,
                method: AuthMethod::Ed25519,
                agent_pubkey: None,
                session_token: None,
                reason: Some("Invalid agent greeting format".to_string()),
            };
        }

        let payload = &msg["RCF_AGENT_V2:".len()..];
        let parts: Vec<&str> = payload.split(':').collect();
        if parts.len() < 2 {
            return AuthResult {
                success: false,
                method: AuthMethod::Ed25519,
                agent_pubkey: None,
                session_token: None,
                reason: Some("Malformed Ed25519 auth data".to_string()),
            };
        }

        let pubkey_hex = parts[0];
        let signature_hex = parts[1];

        let pubkey_bytes = match hex_decode(pubkey_hex) {
            Some(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return AuthResult {
                    success: false,
                    method: AuthMethod::Ed25519,
                    agent_pubkey: None,
                    session_token: None,
                    reason: Some("Invalid public key hex".to_string()),
                };
            }
        };

        let signature_bytes = match hex_decode(signature_hex) {
            Some(b) if b.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return AuthResult {
                    success: false,
                    method: AuthMethod::Ed25519,
                    agent_pubkey: None,
                    session_token: None,
                    reason: Some("Invalid signature hex".to_string()),
                };
            }
        };

        // Check if key is authorized
        if !self.authorized_keys.is_authorized(&pubkey_bytes).await {
            return AuthResult {
                success: false,
                method: AuthMethod::Ed25519,
                agent_pubkey: Some(pubkey_bytes),
                session_token: None,
                reason: Some("Agent public key not authorized".to_string()),
            };
        }

        // Get the challenge nonce
        let nonce = {
            let challenges = self.challenges.read().await;
            challenges.get(peer_addr).and_then(|c| {
                // Check nonce age
                let age = chrono::Utc::now().timestamp() - c.created_at;
                if age > CHALLENGE_TIMEOUT_SECS {
                    return None;
                }
                Some(c.nonce)
            })
        };

        let nonce = match nonce {
            Some(n) => n,
            None => {
                return AuthResult {
                    success: false,
                    method: AuthMethod::Ed25519,
                    agent_pubkey: Some(pubkey_bytes),
                    session_token: None,
                    reason: Some("Challenge expired or not found".to_string()),
                };
            }
        };

        // Verify signature over nonce
        let verifying_key = match crypto::verifying_key_from_bytes(&pubkey_bytes) {
            Ok(k) => k,
            Err(e) => {
                return AuthResult {
                    success: false,
                    method: AuthMethod::Ed25519,
                    agent_pubkey: Some(pubkey_bytes),
                    session_token: None,
                    reason: Some(format!("Invalid verifying key: {}", e)),
                };
            }
        };

        match crypto::verify_signature(&verifying_key, &nonce, &signature_bytes) {
            Ok(()) => {
                // Derive session token from shared secret
                let session_token = crypto::derive_session_key(
                    &nonce, // Use nonce as shared secret
                    &pubkey_bytes,
                    b"rcf-ed25519-session",
                );

                // Clean up challenge
                self.challenges.write().await.remove(peer_addr);

                AuthResult {
                    success: true,
                    method: AuthMethod::Ed25519,
                    agent_pubkey: Some(pubkey_bytes),
                    session_token: Some(session_token),
                    reason: None,
                }
            }
            Err(e) => AuthResult {
                success: false,
                method: AuthMethod::Ed25519,
                agent_pubkey: Some(pubkey_bytes),
                session_token: None,
                reason: Some(format!("Signature verification failed: {}", e)),
            },
        }
    }

    /// Check if legacy PSK mode is active.
    pub fn is_legacy_mode(&self) -> bool {
        self.legacy_mode
    }

    /// Get a reference to the authorized keys store.
    pub fn authorized_keys(&self) -> &AuthorizedKeys {
        &self.authorized_keys
    }

    /// Get the configured PSK (if any).
    pub fn psk(&self) -> Option<&str> {
        self.psk.as_deref()
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
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
    use rcf_core::crypto;

    #[tokio::test]
    async fn test_psk_auth() {
        let auth = C2Auth::with_psk("test-psk-123".to_string());
        let greeting = b"RCF_AGENT_V1:test-psk-123";
        let result = auth.verify_agent("127.0.0.1:9000", greeting).await;
        assert!(result.success);
        assert_eq!(result.method, AuthMethod::PreSharedKey);
        assert!(result.session_token.is_some());
    }

    #[tokio::test]
    async fn test_psk_auth_fail() {
        let auth = C2Auth::with_psk("correct-psk".to_string());
        let greeting = b"RCF_AGENT_V1:wrong-psk";
        let result = auth.verify_agent("127.0.0.1:9000", greeting).await;
        assert!(!result.success);
    }

    #[tokio::test]
    async fn test_ed25519_auth_success() {
        let (signing_key, verifying_key) = crypto::generate_keypair();
        let pubkey_bytes = crypto::verifying_key_to_bytes(&verifying_key);

        let keys = AuthorizedKeys::new();
        keys.add_key(&pubkey_bytes, "test-agent").await;

        let auth = C2Auth::with_authorized_keys(keys);

        // Issue challenge
        let nonce = auth.issue_challenge("10.0.0.1:8000").await;

        // Agent signs the nonce
        let signature = crypto::sign_message(&signing_key, &nonce);

        let greeting = format!(
            "RCF_AGENT_V2:{}:{}",
            hex_encode(&pubkey_bytes),
            hex_encode(&signature)
        );

        let result = auth
            .verify_agent("10.0.0.1:8000", greeting.as_bytes())
            .await;
        assert!(result.success, "Auth failed: {:?}", result.reason);
        assert_eq!(result.method, AuthMethod::Ed25519);
        assert!(result.session_token.is_some());
    }

    #[tokio::test]
    async fn test_ed25519_auth_unauthorized_key() {
        let (_, verifying_key) = crypto::generate_keypair();
        let pubkey_bytes = crypto::verifying_key_to_bytes(&verifying_key);

        // Empty authorized keys
        let keys = AuthorizedKeys::new();
        let auth = C2Auth::with_authorized_keys(keys);

        let (_signing_key, _) = crypto::generate_keypair();
        let nonce = auth.issue_challenge("10.0.0.1:8000").await;
        let (signing_key, _) = crypto::generate_keypair();
        let signature = crypto::sign_message(&signing_key, &nonce);

        let greeting = format!(
            "RCF_AGENT_V2:{}:{}",
            hex_encode(&pubkey_bytes),
            hex_encode(&signature)
        );

        let result = auth
            .verify_agent("10.0.0.1:8000", greeting.as_bytes())
            .await;
        assert!(!result.success);
    }

    #[tokio::test]
    async fn test_ed25519_auth_expired_challenge() {
        let (signing_key, verifying_key) = crypto::generate_keypair();
        let pubkey_bytes = crypto::verifying_key_to_bytes(&verifying_key);

        let keys = AuthorizedKeys::new();
        keys.add_key(&pubkey_bytes, "test-agent").await;

        let auth = C2Auth::with_authorized_keys(keys);

        // Don't issue a challenge - use expired
        let nonce = [0u8; 32]; // fake nonce
        let signature = crypto::sign_message(&signing_key, &nonce);

        let greeting = format!(
            "RCF_AGENT_V2:{}:{}",
            hex_encode(&pubkey_bytes),
            hex_encode(&signature)
        );

        let result = auth
            .verify_agent("10.0.0.1:8000", greeting.as_bytes())
            .await;
        assert!(!result.success);
        let reason = result.reason.clone().unwrap_or_default();
        assert!(
            reason.to_lowercase().contains("challenge"),
            "Expected challenge error, got: {:?}",
            reason
        );
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let hex = hex_encode(&data);
        assert_eq!(hex, "deadbeef");
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, data);
    }
}
