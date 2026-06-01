//! Cryptographic utilities for the RCF framework.
//!
//! Provides Ed25519 key management, HKDF session key derivation,
//! and related helpers for the C2 authentication system.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;

/// Generate a new Ed25519 keypair using system randomness.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS RNG should be available");
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message with the given signing key.
pub fn sign_message(signing_key: &SigningKey, message: &[u8]) -> [u8; 64] {
    let signature = signing_key.sign(message);
    signature.to_bytes()
}

/// Verify a signature against a public key and message.
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), String> {
    use ed25519_dalek::Verifier;
    let sig = ed25519::Signature::from_bytes(signature);
    verifying_key
        .verify(message, &sig)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

/// Derive a session key using HKDF-SHA256 from a shared secret and salt.
///
/// Returns a 32-byte session key.
pub fn derive_session_key(shared_secret: &[u8], salt: &[u8], context: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(context, &mut okm)
        .expect("HKDF expand should not fail with valid output length");
    okm
}

/// Generate a cryptographically random nonce for challenge-response.
pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("OS RNG should be available");
    nonce
}

/// Load a verifying key from raw bytes.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(bytes).map_err(|e| format!("Invalid verifying key: {}", e))
}

/// Serialize a verifying key to raw bytes.
pub fn verifying_key_to_bytes(verifying_key: &VerifyingKey) -> [u8; 32] {
    verifying_key.to_bytes()
}

/// Serialize a signing key to raw bytes.
pub fn signing_key_to_bytes(signing_key: &SigningKey) -> [u8; 32] {
    signing_key.to_bytes()
}

/// Load a signing key from raw bytes.
pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(bytes)
}

/// Encrypt data at rest using a derived key (simplified envelope).
/// Uses SHA-256 as KDF and XOR for encryption (non-production).
/// For v0.3, this provides basic protection; upgrade to AEAD in v0.4.
pub fn encrypt_at_rest(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(key);
    let stream_key = hasher.finalize();

    data.iter()
        .zip(stream_key.iter().cycle())
        .map(|(d, k)| d ^ k)
        .collect()
}

/// Decrypt data encrypted with `encrypt_at_rest`.
pub fn decrypt_at_rest(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    encrypt_at_rest(key, data) // XOR is symmetric
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair_and_sign_verify() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"test message for signing";
        let signature = sign_message(&signing_key, message);
        assert_eq!(signature.len(), 64);
        assert!(verify_signature(&verifying_key, message, &signature).is_ok());
    }

    #[test]
    fn test_verify_rejects_tampered_message() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"original message";
        let signature = sign_message(&signing_key, message);
        let tampered = b"tampered message";
        assert!(verify_signature(&verifying_key, tampered, &signature).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let (signing_key, _) = generate_keypair();
        let (_, wrong_key) = generate_keypair();
        let message = b"test message";
        let signature = sign_message(&signing_key, message);
        assert!(verify_signature(&wrong_key, message, &signature).is_err());
    }

    #[test]
    fn test_hkdf_derivation_deterministic() {
        let secret = b"shared-secret-value";
        let salt = b"unique-salt-value";
        let ctx = b"rcf-session-key";
        let key1 = derive_session_key(secret, salt, ctx);
        let key2 = derive_session_key(secret, salt, ctx);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hkdf_differs_with_different_salt() {
        let secret = b"shared-secret-value";
        let key1 = derive_session_key(secret, b"salt-a", b"ctx");
        let key2 = derive_session_key(secret, b"salt-b", b"ctx");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_generate_nonce_unique() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b);
    }

    #[test]
    fn test_key_serde_roundtrip() {
        let (signing_key, verifying_key) = generate_keypair();
        let sk_bytes = signing_key_to_bytes(&signing_key);
        let loaded_sk = signing_key_from_bytes(&sk_bytes);
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            loaded_sk.verifying_key().to_bytes()
        );

        let vk_bytes = verifying_key_to_bytes(&verifying_key);
        let loaded_vk = verifying_key_from_bytes(&vk_bytes).unwrap();
        assert_eq!(verifying_key.to_bytes(), loaded_vk.to_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_at_rest() {
        let key = [0x42u8; 32];
        let data = b"sensitive credential data";
        let encrypted = encrypt_at_rest(&key, data);
        assert_ne!(encrypted, data);
        let decrypted = decrypt_at_rest(&key, &encrypted);
        assert_eq!(decrypted, data);
    }
}
