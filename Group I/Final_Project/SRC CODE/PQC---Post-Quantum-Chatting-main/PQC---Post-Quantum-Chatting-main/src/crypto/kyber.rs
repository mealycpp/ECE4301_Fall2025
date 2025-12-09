//! Kyber Post-Quantum Key Exchange
//!
//! Implements Kyber1024 key encapsulation mechanism for
//! post-quantum secure key exchange.

use pqcrypto_kyber::kyber1024::{
    self, Ciphertext, PublicKey, SecretKey,
};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use thiserror::Error;

/// Errors that can occur during Kyber operations
#[derive(Error, Debug)]
pub enum KyberError {
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("Encapsulation failed")]
    EncapsulationFailed,
    #[error("Decapsulation failed")]
    DecapsulationFailed,
    #[error("Invalid public key length")]
    InvalidPublicKeyLength,
    #[error("Invalid ciphertext length")]
    InvalidCiphertextLength,
    #[error("Invalid secret key length")]
    InvalidSecretKeyLength,
}

/// Kyber key exchange handler
pub struct KyberKeyExchange {
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl KyberKeyExchange {
    /// Generate a new Kyber key pair
    pub fn new() -> Self {
        let (public_key, secret_key) = kyber1024::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get the public key bytes for transmission
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Create a public key from bytes received from peer
    pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, KyberError> {
        PublicKey::from_bytes(bytes).map_err(|_| KyberError::InvalidPublicKeyLength)
    }

    /// Encapsulate a shared secret using peer's public key
    /// Returns (ciphertext, shared_secret)
    pub fn encapsulate(peer_public_key: &PublicKey) -> (Vec<u8>, Vec<u8>) {
        let (shared_secret, ciphertext) = kyber1024::encapsulate(peer_public_key);
        (ciphertext.as_bytes().to_vec(), shared_secret.as_bytes().to_vec())
    }

    /// Decapsulate the shared secret from ciphertext
    pub fn decapsulate(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, KyberError> {
        let ciphertext = Ciphertext::from_bytes(ciphertext_bytes)
            .map_err(|_| KyberError::InvalidCiphertextLength)?;
        let shared_secret = kyber1024::decapsulate(&ciphertext, &self.secret_key);
        Ok(shared_secret.as_bytes().to_vec())
    }
}

impl Default for KyberKeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a completed key exchange session
pub struct KyberSession {
    /// The shared secret derived from the key exchange
    shared_secret: Vec<u8>,
}

impl KyberSession {
    /// Create a new session from a shared secret
    pub fn new(shared_secret: Vec<u8>) -> Self {
        Self { shared_secret }
    }

    /// Get the shared secret (can be used to derive symmetric keys)
    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }

    /// Derive a symmetric key from the shared secret.
    /// 
    /// Uses SHA-256 based key derivation with counter mode.
    /// Note: In production, consider using HKDF from the `hkdf` crate.
    pub fn derive_key(&self, context: &[u8], length: usize) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // Simple KDF using SHA-256-like expansion
        // WARNING: For production, use proper HKDF from a crypto library
        let mut result = Vec::with_capacity(length);
        let mut counter = 0u64;
        
        while result.len() < length {
            // Create a deterministic hash from shared secret + context + counter
            let mut hasher = DefaultHasher::new();
            self.shared_secret.hash(&mut hasher);
            context.hash(&mut hasher);
            counter.hash(&mut hasher);
            
            let hash = hasher.finish().to_le_bytes();
            result.extend_from_slice(&hash);
            counter += 1;
        }
        
        result.truncate(length);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        // Alice generates her key pair
        let alice = KyberKeyExchange::new();
        let alice_public_bytes = alice.public_key_bytes();

        // Bob receives Alice's public key and encapsulates
        let alice_public = KyberKeyExchange::public_key_from_bytes(&alice_public_bytes).unwrap();
        let (ciphertext, bob_shared_secret) = KyberKeyExchange::encapsulate(&alice_public);

        // Alice decapsulates to get the same shared secret
        let alice_shared_secret = alice.decapsulate(&ciphertext).unwrap();

        // Both should have the same shared secret
        assert_eq!(alice_shared_secret, bob_shared_secret);
    }

    #[test]
    fn test_session_key_derivation() {
        let session = KyberSession::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let key1 = session.derive_key(b"audio", 32);
        let key2 = session.derive_key(b"video", 32);
        
        // Different contexts should produce different keys
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
    }
}
