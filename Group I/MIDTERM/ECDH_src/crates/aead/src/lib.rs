use aes_gcm::{
    aead::{Aead, KeyInit, Payload, generic_array::GenericArray},
    Aes128Gcm,
};
use anyhow::{anyhow, Result};

pub struct AesGcmCtx {
    cipher: Aes128Gcm,
    nonce_base: [u8; 8], // 64-bit random per direction
}

impl AesGcmCtx {
    pub fn new(key: [u8; 16], nonce_base: [u8; 8]) -> Self {
        let cipher = Aes128Gcm::new_from_slice(&key).expect("Aes128Gcm key");
        Self { cipher, nonce_base }
    }

    #[inline]
    fn make_nonce_bytes(&self, seq: u32) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.nonce_base);
        n[8..].copy_from_slice(&seq.to_be_bytes());
        n
    }

    /// Encrypt with AES-GCM; AAD typically = seq (big-endian)
    pub fn encrypt(&self, seq: u32, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let n = self.make_nonce_bytes(seq);
        let nonce = GenericArray::from_slice(&n); // &GenericArray<u8, U12>
        self.cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|_| anyhow!("encrypt failed"))
    }

    /// Decrypt with AES-GCM; AAD must match sender’s
    pub fn decrypt(&self, seq: u32, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let n = self.make_nonce_bytes(seq);
        let nonce = GenericArray::from_slice(&n);
        self.cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad })
            .map_err(|_| anyhow!("decrypt failed (tag mismatch?)"))
    }
}
