// Provide a small, well-scoped AES-GCM context used by transport.
// This exports AesGcmCtx at crate root so other crates (transport) can use `aead::AesGcmCtx`.
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use std::convert::TryInto;
use anyhow::Result;

/// Simple AES-128-GCM context which composes an AES-GCM cipher with an 8-byte base nonce.
/// The actual 12-byte nonce used for each operation is base(8) || seq_u32_be(4).
#[derive(Clone)]
pub struct AesGcmCtx {
    cipher: Aes128Gcm,
    base: [u8; 8],
}

impl AesGcmCtx {
    /// Create a new context from a 16-byte key and 8-byte base.
    pub fn new(key16: [u8; 16], base8: [u8; 8]) -> Self {
        let key = Key::<Aes128Gcm>::from_slice(&key16);
        let cipher = Aes128Gcm::new(key);
        Self {
            cipher,
            base: base8,
        }
    }

    /// Encrypt with sequence number `seq` producing ciphertext bytes (tag appended).
    /// `aad` is additional authenticated data.
    pub fn encrypt(&self, seq: u32, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.base);
        nonce[8..].copy_from_slice(&seq.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce);
        let ct = self
            .cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(ct)
    }

    /// Decrypt ciphertext (expects tag appended) with sequence number `seq`.
    pub fn decrypt(&self, seq: u32, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.base);
        nonce[8..].copy_from_slice(&seq.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce);
        let pt = self
            .cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad })
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(pt)
    }
}