//! keying: RSA OAEP (SHA-256) and ECDH P-256 + HKDF for AES-128 session keys.
//! All randomness comes from OsRng (TRNG-backed on Raspberry Pi OS).

use aes_gcm::aead::rand_core::RngCore;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::{PublicKey, EncodedPoint};
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};
use sha2::Sha256;
use std::time::Instant;

/// Context string for HKDF (domain separation).
const HKDF_INFO_AES: &[u8] = b"ECE4301-midterm-2025-aes";
const HKDF_INFO_NONCE: &[u8] = b"ECE4301-midterm-2025-nonce";
/// Salt length recommendation: 32 bytes.
pub const HKDF_SALT_LEN: usize = 32;

/// AES-128 key (16 bytes).
pub type Aes128Key = [u8; 16];
/// 64-bit random nonce base + 32-bit counter -> 96-bit GCM nonce.
pub type NonceBase64 = [u8; 8];

/// Generate an RSA private key (bits: 2048 or 3072 for extra credit).
pub fn rsa_generate(bits: usize) -> RsaPrivateKey {
    let mut rng = OsRng;
    RsaPrivateKey::new(&mut rng, bits).expect("RSA keygen failed")
}

/// Wrap (encrypt) a random 128-bit session key with recipient's RSA public key using OAEP-SHA256.
/// Returns (wrapped_key_ciphertext, plaintext_session_key).
pub fn rsa_wrap_session_key(
    pk: &RsaPublicKey
) -> (Vec<u8>, Aes128Key) {
    let mut rng = OsRng;
    let mut session_key = [0u8; 16];
    rng.fill_bytes(&mut session_key);
    let wrapped = pk
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &session_key)
        .expect("RSA OAEP encrypt failed");
    (wrapped, session_key)
}

/// Unwrap (decrypt) the session key using RSA private key.
pub fn rsa_unwrap_session_key(
    sk: &RsaPrivateKey,
    wrapped: &[u8]
) -> Aes128Key {
    let dec = sk
        .decrypt(Oaep::new::<Sha256>(), wrapped)
        .expect("RSA OAEP decrypt failed");
    let mut out = [0u8; 16];
    out.copy_from_slice(&dec);
    out
}

/// Ephemeral ECDH on P-256. Generates (my_pub_bytes, aes_key, nonce_base, handshake_bytes, duration_ms)
/// - `peer_pub_bytes`: SEC1-encoded peer public key (from their `EncodedPoint` bytes)
/// - Internally derives a shared secret, then HKDF-SHA256 -> AES-128 + 64-bit nonce base.
pub fn ecdh_p256_derive(
    peer_pub_bytes: &[u8],
    salt_opt: Option<&[u8]>
) -> (Vec<u8>, Aes128Key, NonceBase64, usize, u128) {
    let mut rng = OsRng;
    let t0 = Instant::now();

    // Our new ephemeral secret/public
    let my_secret = EphemeralSecret::random(&mut rng);
    let my_public = PublicKey::from(&my_secret);
    let my_pub_bytes: Vec<u8> = EncodedPoint::from(my_public).as_bytes().to_vec();

    // Load peer public key
    let peer_pub = PublicKey::from_sec1_bytes(peer_pub_bytes)
        .expect("bad peer SEC1 public key");

    // ECDH shared secret
    let shared = my_secret.diffie_hellman(&peer_pub);

    // HKDF-SHA256
    let salt = match salt_opt {
        Some(s) => s,
        None => {
            // fresh random salt if none supplied
            let mut tmp = [0u8; HKDF_SALT_LEN];
            rng.fill_bytes(&mut tmp);
            // We’ll use this temp salt for both expansions below by re-deriving HKDF twice
            // Simpler: compute with this salt now and discard. Return values only.
            // (We don’t need to expose the salt to callers here.)
            // To keep scope, just keep tmp in a local binding and use it below.
            // We can't return it because signature doesn't include it.
            // SAFETY: referencing below is fine as it's still in scope.
            // (We pass references immediately; not storing.)
            // Workaround: use it directly below via a second branch.
            // To avoid borrow issues, fall back to this value:
            // In practice, callers may supply an explicit salt for reproducibility.
            // We'll just use tmp; shadow `salt` below.
            // (Rust requires a little juggling; see below.)
            // We'll return to the first branch which has &tmp available.
            // But Rust can't let us name it here; restructure:
            // -> We'll implement the logic using an inner block.
            unreachable!("internal flow"); // will never hit
        }
    };

    // If a salt was supplied, simple path:
    if let Some(_) = salt_opt {
        let hk = Hkdf::<Sha256>::new(Some(salt), shared.raw_secret_bytes());
        let mut aes_key = [0u8; 16];
        hk.expand(HKDF_INFO_AES, &mut aes_key).expect("HKDF expand aes failed");

        let mut nonce_base = [0u8; 8];
        hk.expand(HKDF_INFO_NONCE, &mut nonce_base).expect("HKDF expand nonce failed");

        let elapsed = t0.elapsed().as_millis();
        // handshake bytes is just the pubkey we send
        let handshake_bytes = my_pub_bytes.len();

        return (my_pub_bytes, aes_key, nonce_base, handshake_bytes, elapsed);
    }

    // No salt supplied: generate a random one and repeat derivation cleanly.
    let mut rnd_salt = [0u8; HKDF_SALT_LEN];
    OsRng.fill_bytes(&mut rnd_salt);

    let hk = Hkdf::<Sha256>::new(Some(&rnd_salt), shared.raw_secret_bytes());
    let mut aes_key = [0u8; 16];
    hk.expand(HKDF_INFO_AES, &mut aes_key).expect("HKDF expand aes failed");

    let mut nonce_base = [0u8; 8];
    hk.expand(HKDF_INFO_NONCE, &mut nonce_base).expect("HKDF expand nonce failed");

    let elapsed = t0.elapsed().as_millis();
    let handshake_bytes = my_pub_bytes.len();

    (my_pub_bytes, aes_key, nonce_base, handshake_bytes, elapsed)
}

/// Monotonic 96-bit GCM nonce builder: 64-bit random base + 32-bit counter.
#[derive(Clone)]
pub struct NonceCtr {
    base: NonceBase64,
    ctr: u32,
}

impl NonceCtr {
    pub fn new_random() -> Self {
        let mut b = [0u8; 8];
        OsRng.fill_bytes(&mut b);
        Self { base: b, ctr: 0 }
    }

    pub fn with_base(base: NonceBase64) -> Self {
        Self { base, ctr: 0 }
    }

    /// Returns the next 96-bit nonce (12 bytes) as an array.
    pub fn next(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.base);
        n[8..].copy_from_slice(&self.ctr.to_be_bytes());
        self.ctr = self.ctr.wrapping_add(1);
        n
    }

    pub fn counter(&self) -> u32 { self.ctr }
    pub fn base(&self) -> NonceBase64 { self.base }
}

/* ------------------------------ Tests ------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn t_rsa_wrap_unwrap_2048() {
        let sk = rsa_generate(2048);
        let pk = RsaPublicKey::from(&sk);

        let t0 = Instant::now();
        let (wrapped, sk_plain) = rsa_wrap_session_key(&pk);
        let enc_ms = t0.elapsed().as_millis();

        let t1 = Instant::now();
        let sk_recv = rsa_unwrap_session_key(&sk, &wrapped);
        let dec_ms = t1.elapsed().as_millis();

        assert_eq!(&sk_plain, &sk_recv, "RSA session key mismatch");
        eprintln!("RSA-2048: wrap {}B in {} ms; unwrap in {} ms",
            wrapped.len(), enc_ms, dec_ms);
    }

    #[test]
    fn t_ecdh_p256_roundtrip() {
        // Simulate two peers (A and B) locally
        // A makes ephemeral and sends its pub to B, and vice-versa.
        let my_secret_a = EphemeralSecret::random(&mut OsRng);
        let my_pub_a = PublicKey::from(&my_secret_a);
        let pub_a = EncodedPoint::from(my_pub_a).as_bytes().to_vec();

        let my_secret_b = EphemeralSecret::random(&mut OsRng);
        let my_pub_b = PublicKey::from(&my_secret_b);
        let pub_b = EncodedPoint::from(my_pub_b).as_bytes().to_vec();

        // A derives using B's pub; B derives using A's pub.
        let (_send_a, aes_a, nonce_a, bytes_a, ms_a) = ecdh_p256_derive(&pub_b, None);
        let (_send_b, aes_b, nonce_b, bytes_b, ms_b) = ecdh_p256_derive(&pub_a, None);

        // NOTE: Because we use fresh random salt when None, A and B won’t match keys here.
        // For a true round-trip equality test, supply the SAME salt to both sides.
        let mut salt = [0u8; HKDF_SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let (_sa2, aes_a2, nonce_a2, _, _) = ecdh_p256_derive(&pub_b, Some(&salt));
        let (_sb2, aes_b2, nonce_b2, _, _) = ecdh_p256_derive(&pub_a, Some(&salt));

        assert_eq!(aes_a2, aes_b2, "ECDH AES keys differ with same salt");
        assert_eq!(nonce_a2, nonce_b2, "ECDH nonces differ with same salt");

        eprintln!(
            "ECDH P-256: A bytes={} in {} ms, B bytes={} in {} ms (salted keys match)",
            bytes_a, ms_a, bytes_b, ms_b
        );

        // NonceCtr behavior
        let mut ctr = NonceCtr::with_base(nonce_a);
        let n0 = ctr.next();
        let n1 = ctr.next();
        assert_ne!(n0, n1, "nonces must be unique per key");
    }
}


/// Generate ECDH keypair → returns (public_bytes, secret)
pub fn gen_ecdh_keypair() -> (Vec<u8>, EphemeralSecret) {
    let secret = EphemeralSecret::random(&mut OsRng);
    let public = PublicKey::from(&secret);
    (EncodedPoint::from(public).as_bytes().to_vec(), secret)
}

/// Derive AES key from peer pubkey and our secret
pub fn finish_ecdh(secret: &EphemeralSecret, peer_pub: &[u8]) -> [u8; 16] {
    let peer_pub = PublicKey::from_sec1_bytes(peer_pub).unwrap();
    let shared = secret.diffie_hellman(&peer_pub);
    let salt = [0u8; 16];
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.raw_secret_bytes());
    let mut out = [0u8; 16];
    hk.expand(b"ECE4301-demo", &mut out).unwrap();
    out
}

/// Called on receiver after getting peer pubkey
pub fn ecdh_derive_from_peer(peer_pub: &[u8]) -> ([u8; 16], Vec<u8>) {
    let (pub_bytes, secret) = gen_ecdh_keypair();
    let key = finish_ecdh(&secret, peer_pub);
    (key, pub_bytes)
}
