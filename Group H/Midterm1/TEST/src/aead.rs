use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes128Gcm, Nonce};

#[derive(Clone)]
pub struct AeadCtx { cipher: Aes128Gcm }

impl AeadCtx {
    pub fn new(key: [u8;16]) -> Self { Self { cipher: Aes128Gcm::new_from_slice(&key).unwrap() } }
    pub fn seal(&self, nonce: [u8;12], seq: u64, pt: &[u8]) -> Vec<u8> {
        let aad = seq.to_be_bytes();
        self.cipher.encrypt(Nonce::from_slice(&nonce), Payload{ msg: pt, aad: &aad }).unwrap()
    }
    pub fn open(&self, nonce: [u8;12], seq: u64, ct: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let aad = seq.to_be_bytes();
        self.cipher.decrypt(Nonce::from_slice(&nonce), Payload{ msg: ct, aad: &aad })
    }
}

#[derive(Clone)]
pub struct NonceCtr { base:[u8;8], ctr:u32 }
impl NonceCtr {
    pub fn new(base:[u8;8]) -> Self { Self{ base, ctr:0 } }
    pub fn next(&mut self) -> [u8;12] { let mut n=[0u8;12]; n[..8].copy_from_slice(&self.base); n[8..].copy_from_slice(&self.ctr.to_be_bytes()); self.ctr=self.ctr.wrapping_add(1); n }
    pub fn reset(&mut self, base:[u8;8]) { self.base = base; self.ctr = 0; }
}