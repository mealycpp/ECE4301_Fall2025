use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit},
    Nonce,
};

use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;
use p256::ecdh::EphemeralSecret;
use p256::{PublicKey, EncodedPoint};
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};
use std::time::Instant;

pub fn log_arm_crypto_support() {
    #[cfg(target_arch = "aarch64")]
    {
        let aes   = std::arch::is_aarch64_feature_detected!("aes");
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        eprintln!("ARMv8 Crypto Extensions — AES: {aes}, PMULL: {pmull}");
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        eprintln!("Non-aarch64 build; ARM CE not applicable.");
    }
}

pub struct AeadCtx {
    cipher: Aes128Gcm,
    nonce_base: [u8; 8],
    ctr: u32,
}

impl AeadCtx {
    pub fn new(aes_key_128: [u8; 16], nonce_base: [u8; 8]) -> Self {
        let cipher = Aes128Gcm::new_from_slice(&aes_key_128).unwrap();
        Self { cipher, nonce_base, ctr: 0 }
    }

    /// Adopt a new 64-bit nonce base and reset the counter.
    pub fn set_nonce_base(&mut self, nb: [u8;8]) {
    self.nonce_base = nb;
    self.ctr = 0;
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.nonce_base);
        n[8..].copy_from_slice(&self.ctr.to_be_bytes());
        self.ctr = self.ctr.wrapping_add(1);
        n
    }

    pub fn encrypt(&mut self, aad: &[u8], pt: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = Nonce::from(self.next_nonce());
        let ct = self
            .cipher
            .encrypt(&nonce, aes_gcm::aead::Payload { msg: pt, aad })
            .map_err(|e| anyhow::anyhow!("AEAD encrypt failed: {e:?}"))?;
        Ok(ct)
    }

    pub fn decrypt(&mut self, aad: &[u8], ct_and_tag: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = Nonce::from(self.next_nonce());
        let pt = self
            .cipher
            .decrypt(&nonce, aes_gcm::aead::Payload { msg: ct_and_tag, aad })
            .map_err(|e| anyhow::anyhow!("AEAD decrypt failed: {e:?}"))?;
        Ok(pt)
    }
}

// ------- ECDH flow -------

pub struct EcdhInitiatorState {
    pub secret: EphemeralSecret,
    pub salt: [u8; 32],
    pub pub_bytes: Vec<u8>,
}

pub fn ecdh_start() -> EcdhInitiatorState {
    let secret = EphemeralSecret::random(&mut rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    let pub_bytes = EncodedPoint::from(public).as_bytes().to_vec();
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    EcdhInitiatorState { secret, salt, pub_bytes }
}

/// Returns (AEAD ctx, initiator's local nonce_base) — caller may overwrite the base later.
pub fn ecdh_finish(
    my: EcdhInitiatorState,
    peer_pub_bytes: &[u8],
    info: &[u8],
) -> anyhow::Result<(AeadCtx, [u8; 8])> {
    let peer_pub = PublicKey::from_sec1_bytes(peer_pub_bytes)?;
    let shared = my.secret.diffie_hellman(&peer_pub);
    let hk = Hkdf::<Sha256>::new(Some(&my.salt), shared.raw_secret_bytes());
    let mut aes_key = [0u8; 16];
    hk.expand(&[info, b"-aes"].concat(), &mut aes_key)
        .map_err(|e| anyhow::anyhow!("HKDF expand: {e:?}"))?;
    let mut nonce_base = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce_base);
    Ok((AeadCtx::new(aes_key, nonce_base), nonce_base))
}

pub fn ecdh_responder(
    peer_pub_bytes: &[u8],
    salt: &[u8],
    info: &[u8],
) -> anyhow::Result<(Vec<u8>, AeadCtx, [u8; 8])> {
    let my_secret = EphemeralSecret::random(&mut rand::rngs::OsRng);
    let my_public = PublicKey::from(&my_secret);
    let my_pub_bytes = EncodedPoint::from(my_public).as_bytes().to_vec();
    let peer_pub = PublicKey::from_sec1_bytes(peer_pub_bytes)?;
    let shared = my_secret.diffie_hellman(&peer_pub);
    let hk = Hkdf::<Sha256>::new(Some(salt), shared.raw_secret_bytes());
    let mut aes_key = [0u8; 16];
    hk.expand(&[info, b"-aes"].concat(), &mut aes_key)
        .map_err(|e| anyhow::anyhow!("HKDF expand: {e:?}"))?;
    let mut nonce_base = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce_base);
    Ok((my_pub_bytes, AeadCtx::new(aes_key, nonce_base), nonce_base))
}

// ------- RSA helpers -------

pub fn rsa_wrap_unwrap(session_key_16: &[u8]) -> anyhow::Result<(RsaPrivateKey, Vec<u8>)> {
    let mut rng = rand::rngs::OsRng;
    let sk = RsaPrivateKey::new(&mut rng, 2048)?;
    let pk = RsaPublicKey::from(&sk);
    let wrapped = pk.encrypt(&mut rng, Oaep::new::<Sha256>(), session_key_16)?;
    Ok((sk, wrapped))
}

pub fn rsa_unwrap(sk: &RsaPrivateKey, wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pt = sk.decrypt(Oaep::new::<Sha256>(), wrapped)?;
    Ok(pt)
}

pub fn timeit<F: FnOnce()>(_label: &str, f: F) -> std::time::Duration {
    let t0 = Instant::now();
    f();
    t0.elapsed()
}
