// src/aead_stream.rs
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use zeroize::Zeroize;

/// 16-byte AES-128 key, 12-byte GCM nonce base
pub struct Aes128GcmStream {
    cipher: Aes128Gcm,
    nonce_base: [u8; 12], // first 8 bytes base, last 4 used for counter
    ctr: u32,
}

impl Aes128GcmStream {
    pub fn new(key: [u8; 16], nonce_base: [u8; 12]) -> Result<Self> {
        let cipher = Aes128Gcm::new_from_slice(&key)?;
        Ok(Self { cipher, nonce_base, ctr: 0 })
    }

    #[inline]
    fn next_nonce(&mut self) -> [u8; 12] {
        let mut n = self.nonce_base;
        n[8..12].copy_from_slice(&self.ctr.to_be_bytes());
        self.ctr = self.ctr.wrapping_add(1);
        n
    }

    /// Encrypt a frame with AAD = seq (u64) + size (u32)
    pub fn encrypt_frame(&mut self, seq: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8..12].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
        let nonce = Nonce::from(self.next_nonce());
        let ct = self.cipher.encrypt(&nonce, Payload { msg: plaintext, aad: &aad })
            .map_err(|_| anyhow!("aes-gcm encrypt failed"))?;
        Ok(ct)
    }

    /// Decrypt a frame with the same AAD = seq + size
    pub fn decrypt_frame(&mut self, seq: u64, ciphertext: &[u8], size_hint: u32) -> Result<Vec<u8>> {
        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8..12].copy_from_slice(&size_hint.to_be_bytes());
        let nonce = Nonce::from(self.next_nonce());
        let pt = self.cipher.decrypt(&nonce, Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| anyhow!("aes-gcm decrypt failed (tag)"))?;
        Ok(pt)
    }
}

impl Drop for Aes128GcmStream {
    fn drop(&mut self) {
        self.nonce_base.zeroize();
        // cipher key is internal; rely on type drop + process isolation; avoid logging keys
    }
}
