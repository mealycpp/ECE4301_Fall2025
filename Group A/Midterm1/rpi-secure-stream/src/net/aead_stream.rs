use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use zeroize::Zeroize;

/// AES-128-GCM stream with 96-bit nonce base.
/// Nonce = nonce_base[0..8] || u32_be(seq - base_seq)
pub struct Aes128GcmStream {
    cipher: Aes128Gcm,
    nonce_base: [u8; 12],
    base_seq: u64, // seq where this key started
}

impl Aes128GcmStream {
    pub fn new(key: [u8; 16], nonce_base: [u8; 12]) -> Result<Self> {
        Ok(Self {
            cipher: Aes128Gcm::new_from_slice(&key)?,
            nonce_base,
            base_seq: 0,
        })
    }

    /// Rekey and set the base sequence for this key (usually the "next_seq" from REKEY control).
    pub fn rekey_at(&mut self, key: [u8; 16], nonce_base: [u8; 12], next_seq: u64) -> Result<()> {
        self.cipher = Aes128Gcm::new_from_slice(&key)?;
        self.nonce_base = nonce_base;
        self.base_seq = next_seq;
        Ok(())
    }

    #[inline]
    fn nonce_for(&self, seq: u64) -> [u8; 12] {
        let ctr = (seq.wrapping_sub(self.base_seq)) as u32;
        let mut n = self.nonce_base;
        n[8..12].copy_from_slice(&ctr.to_be_bytes());
        n
    }

    /// Encrypt frame: AAD = seq||pt_len
    pub fn encrypt_frame(&self, seq: u64, pt: &[u8], pt_len: u32) -> Result<Vec<u8>> {
        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8..12].copy_from_slice(&pt_len.to_be_bytes());

        let nonce = Nonce::from(self.nonce_for(seq));
        self.cipher
            .encrypt(&nonce, Payload { msg: pt, aad: &aad })
            .map_err(|_| anyhow!("aes-gcm encrypt failed"))
    }

    /// Decrypt frame: AAD must match sender (seq||pt_len)
    pub fn decrypt_frame(&self, seq: u64, ct: &[u8], pt_len: u32) -> Result<Vec<u8>> {
        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8..12].copy_from_slice(&pt_len.to_be_bytes());

        let nonce = Nonce::from(self.nonce_for(seq));
        self.cipher
            .decrypt(&nonce, Payload { msg: ct, aad: &aad })
            .map_err(|_| anyhow!("aes-gcm decrypt failed (tag)"))
    }
}

impl Drop for Aes128GcmStream {
    fn drop(&mut self) {
        self.nonce_base.zeroize();
    }
}
