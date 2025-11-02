use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use zeroize::Zeroize;

/// AES-128-GCM stream with 96-bit nonce base and 32-bit counter.
pub struct Aes128GcmStream {
    cipher: Aes128Gcm,
    nonce_base: [u8; 12],
    ctr: u32,
}

impl Aes128GcmStream {
    pub fn new(key: [u8; 16], nonce_base: [u8; 12]) -> Result<Self> {
        Ok(Self {
            cipher: Aes128Gcm::new_from_slice(&key)?,
            nonce_base,
            ctr: 0,
        })
    }

    /// Rekey and reset the internal nonce counter.
    pub fn rekey(&mut self, key: [u8; 16], nonce_base: [u8; 12]) -> Result<()> {
        self.cipher = Aes128Gcm::new_from_slice(&key)?;
        self.nonce_base = nonce_base;
        self.ctr = 0;
        Ok(())
    }

    #[inline]
    fn next_nonce(&mut self) -> [u8; 12] {
        let mut n = self.nonce_base;
        n[8..12].copy_from_slice(&self.ctr.to_be_bytes());
        self.ctr = self.ctr.wrapping_add(1);
        n
    }

    /// Encrypt frame: AAD = seq||pt_len
    pub fn encrypt_frame(&mut self, seq: u64, pt: &[u8], pt_len: u32) -> Result<Vec<u8>> {
        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8..12].copy_from_slice(&pt_len.to_be_bytes());

        let nonce = Nonce::from(self.next_nonce());
        self.cipher
            .encrypt(&nonce, Payload { msg: pt, aad: &aad })
            .map_err(|_| anyhow!("aes-gcm encrypt failed"))
    }

    /// Decrypt frame: AAD must match sender (seq||pt_len)
    pub fn decrypt_frame(&mut self, seq: u64, ct: &[u8], pt_len: u32) -> Result<Vec<u8>> {
        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8..12].copy_from_slice(&pt_len.to_be_bytes());

        let nonce = Nonce::from(self.next_nonce());
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
