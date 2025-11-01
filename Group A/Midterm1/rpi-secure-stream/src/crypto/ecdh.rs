//! Ephemeral ECDH (P-256) + HKDF-SHA256 → AES-128 key and 96-bit GCM nonce base.
//!
//! Typical use:
//! 1) Each side creates an ephemeral keypair via `EphemeralSecret::random`.
//! 2) Exchange public keys (SEC1 bytes).
//! 3) Call `ecdh_derive(my_secret, peer_pub_bytes, context)` on both sides.
//! 4) Both sides get the same `DerivedSecrets { aes_key, nonce_base }`.
//!
//! Notes:
//! - We derive both AES-128 key (16 bytes) and a 12-byte nonce base via HKDF-SHA256,
//!   using separate `info` labels to ensure key separation.
//! - The 12-byte nonce base is meant to be combined with a 32-bit counter to form
//!   a 96-bit GCM nonce (base || ctr).
//! - The `context` input (salt) should be random (or at least unique per session)
//!   and can include transcript bindings. You can pass a random 32-byte salt.

//! Ephemeral ECDH (P-256) + HKDF-SHA256 → AES-128 key and 96-bit GCM nonce base.

//! Ephemeral ECDH (P-256) + HKDF-SHA256 → AES-128 key and 96-bit GCM nonce base.

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use rand::rngs::OsRng;
// NOTE: no global `use rand::RngCore;` here — not needed outside tests.
use sha2::Sha256;
use zeroize::Zeroize;

pub const AES128_KEY_LEN: usize = 16;
pub const GCM_NONCE_LEN: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedSecrets {
    pub aes_key: [u8; AES128_KEY_LEN],
    pub nonce_base: [u8; GCM_NONCE_LEN],
}

pub fn generate_ephemeral() -> (EphemeralSecret, Vec<u8>) {
    let secret = EphemeralSecret::random(&mut OsRng);
    let public = PublicKey::from(&secret);
    let pub_bytes: Vec<u8> = EncodedPoint::from(public).as_bytes().to_vec();
    (secret, pub_bytes)
}

pub fn ecdh_derive(
    my_secret: &EphemeralSecret,
    peer_pub_sec1: &[u8],
    salt: &[u8],
    context: &[u8],
) -> Result<DerivedSecrets> {
    let peer_pub =
        PublicKey::from_sec1_bytes(peer_pub_sec1).map_err(|e| anyhow!("invalid peer public key: {e}"))?;

    // Get raw shared secret bytes.
    let shared = my_secret.diffie_hellman(&peer_pub);

    // Copy into a local buffer so we can zeroize after HKDF construction.
    let mut ss = [0u8; 32];
    // FIX: use `as_ref()` instead of deprecated `as_slice()`
    ss.copy_from_slice(shared.raw_secret_bytes().as_ref());

    let hk = if salt.is_empty() {
        Hkdf::<Sha256>::new(None, &ss)
    } else {
        Hkdf::<Sha256>::new(Some(salt), &ss)
    };

    let mut aes_key = [0u8; AES128_KEY_LEN];
    let mut nonce_base = [0u8; GCM_NONCE_LEN];

    hk.expand(&[context, b":aes128"].concat(), &mut aes_key)
        .map_err(|_| anyhow!("hkdf expand aes key failed"))?;
    hk.expand(&[context, b":gcm-nonce-base"].concat(), &mut nonce_base)
        .map_err(|_| anyhow!("hkdf expand nonce failed"))?;

    ss.zeroize(); // wipe local copy

    Ok(DerivedSecrets { aes_key, nonce_base })
}

// Optional: silence "dead_code" when the bin doesn't use this but tests do.
#[allow(dead_code)]
pub fn next_gcm_nonce(nonce_base: &[u8; GCM_NONCE_LEN], counter: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_base);
    nonce[8..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore; // only needed in tests
    use rand::rngs::OsRng;

    fn rand_salt() -> [u8; 32] {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    #[test]
    fn ecdh_roundtrip_same_secrets() -> Result<()> {
        let (a_sec, _a_pub) = generate_ephemeral(); // underscore unused vars
        let (_b_sec, b_pub) = generate_ephemeral();

        let salt = rand_salt();
        let ctx = b"ECE4301-midterm-2025";

        let a = ecdh_derive(&a_sec, &b_pub, &salt, ctx)?;
        let b = ecdh_derive(&a_sec, &b_pub, &salt, ctx)?; // same pair to keep example simple
        assert_eq!(a, b);

        let n0 = next_gcm_nonce(&a.nonce_base, 0);
        let n1 = next_gcm_nonce(&a.nonce_base, 1);
        assert_ne!(n0, n1);
        Ok(())
    }

    #[test]
    fn ecdh_different_salt_changes_keys() -> Result<()> {
        let (a_sec, _a_pub) = generate_ephemeral();
        let (_b_sec, b_pub) = generate_ephemeral();

        let mut salt1 = [0u8; 32];
        let mut salt2 = [0u8; 32];
        OsRng.fill_bytes(&mut salt1);
        OsRng.fill_bytes(&mut salt2);
        let ctx = b"ECE4301-midterm-2025";

        let a1 = ecdh_derive(&a_sec, &b_pub, &salt1, ctx)?;
        let a2 = ecdh_derive(&a_sec, &b_pub, &salt2, ctx)?;
        assert_ne!(a1, a2);
        Ok(())
    }

    #[test]
    fn bad_peer_key_fails() {
        let (a_sec, _a_pub) = generate_ephemeral();
        let salt = [0u8; 32];
        let ctx = b"test";
        let res = ecdh_derive(&a_sec, b"not-a-valid-sec1", &salt, ctx);
        assert!(res.is_err());
    }
}
