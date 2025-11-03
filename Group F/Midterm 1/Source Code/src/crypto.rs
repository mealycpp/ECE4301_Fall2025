use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use sha2::{Digest, Sha256};
use hkdf::Hkdf;
use sha2::Sha256 as Sha256Hkdf;

use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Nonce};

use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use ring::hmac;

pub fn os_rand_bytes(out: &mut [u8]) { OsRng.fill_bytes(out); }

pub fn os_rand_maybe_mix(out: &mut [u8]) {
    OsRng.fill_bytes(out);
    if let Ok(mut f) = std::fs::File::open("/dev/hwrng") {
        use std::io::Read;
        let mut buf = vec![0u8; out.len()];
        if f.read_exact(&mut buf).is_ok() {
            for (o, b) in out.iter_mut().zip(buf) { *o ^= b; }
            let h = Sha256::digest(&out);
            out.iter_mut().zip(h).for_each(|(o, hh)| *o ^= hh);
        }
    }
}

pub const KDF_CTX: &[u8] = b"ECE4301-midterm-2025";

pub fn hkdf_expand_128_96(secret: &[u8], salt: &[u8]) -> ([u8;16],[u8;12]) {
    let hk = Hkdf::<Sha256Hkdf>::new(Some(salt), secret);
    let mut key = [0u8;16];
    let mut nonce_base = [0u8;12];
    hk.expand(KDF_CTX, &mut key).expect("hkdf key");
    hk.expand(&[b"nonce", KDF_CTX].concat(), &mut nonce_base).expect("hkdf nonce");
    (key, nonce_base)
}

pub struct AeadState(Aes128Gcm);
impl AeadState {
    pub fn new(key: [u8;16]) -> Self { Self(Aes128Gcm::new_from_slice(&key).unwrap()) }
    pub fn seal(&self, nonce: [u8;12], aad: &[u8], pt: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.0.encrypt(Nonce::from_slice(&nonce), aes_gcm::aead::Payload{ msg: pt, aad })
            .map_err(|e| anyhow::anyhow!("aead encrypt: {:?}", e))
    }
    pub fn open(&self, nonce: [u8;12], aad: &[u8], ct: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.0.decrypt(Nonce::from_slice(&nonce), aes_gcm::aead::Payload{ msg: ct, aad })
            .map_err(|e| anyhow::anyhow!("aead decrypt: {:?}", e))
    }
}

#[derive(Clone)]
pub struct NonceMgr { base:[u8;12], ctr:u32 }
impl NonceMgr {
    pub fn new(base:[u8;12])->Self{ Self{base,ctr:0} }
    pub fn next(&mut self)->[u8;12]{ let mut n=self.base; n[8..12].copy_from_slice(&self.ctr.to_be_bytes()); self.ctr=self.ctr.checked_add(1).expect("nonce overflow"); n }
    pub fn near_limit(&self)->bool{ self.ctr >= (1u32<<20) - 10_000 }
}
impl Drop for NonceMgr { fn drop(&mut self){ self.base.zeroize(); } }

pub fn hmac_sha256(key:&[u8], data:&[u8]) -> Vec<u8> {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    ring::hmac::sign(&k, data).as_ref().to_vec()
}

pub fn rsa_generate(bits: usize) -> anyhow::Result<(RsaPrivateKey,RsaPublicKey)> {
    let sk = RsaPrivateKey::new(&mut OsRng, bits).map_err(|e| anyhow::anyhow!("rsa gen: {e:?}"))?;
    Ok((sk.clone(), RsaPublicKey::from(sk)))
}
pub fn rsa_wrap(pk:&RsaPublicKey, key:&[u8]) -> anyhow::Result<Vec<u8>> {
    pk.encrypt(&mut OsRng, Oaep::new::<Sha256Hkdf>(), key)
        .map_err(|e| anyhow::anyhow!("rsa wrap: {e:?}"))
}
pub fn rsa_unwrap(sk:&RsaPrivateKey, ct:&[u8]) -> anyhow::Result<Vec<u8>> {
    sk.decrypt(Oaep::new::<Sha256Hkdf>(), ct)
        .map_err(|e| anyhow::anyhow!("rsa unwrap: {e:?}"))
}

// (Optional) leave P-256 helpers minimal & compile-clean; we'll wire later.
pub mod p256_kx {
    use super::*;
    use p256::ecdh::EphemeralSecret;
    use p256::{PublicKey, EncodedPoint};

    pub struct Offer { pub eph_pub_sec1: Vec<u8>, pub salt:[u8;32] }

    pub fn offer(peer_pub: &PublicKey) -> (Offer, ([u8;16],[u8;12])) {
        let sk = EphemeralSecret::random(&mut OsRng);
        let pk = EncodedPoint::from(sk.public_key());
        let shared = sk.diffie_hellman(peer_pub); // takes &PublicKey
        let mut salt=[0u8;32]; super::os_rand_maybe_mix(&mut salt);
        let (k, n) = super::hkdf_expand_128_96(shared.raw_secret_bytes(), &salt);
        (Offer{eph_pub_sec1: pk.as_bytes().to_vec(), salt}, (k,n))
    }
}
