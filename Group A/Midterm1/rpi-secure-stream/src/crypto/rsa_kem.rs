//! RSA OAEP (SHA-256) key transport helpers.
//!
//! Provides a KEM-like “wrap/unwrap” for a randomly-sampled 128-bit session key.
//! - `rsa_wrap`: given recipient's RSA public key, samples a random 16-byte session key
//!   and returns (ciphertext, plaintext_session_key).
//! - `rsa_unwrap`: given recipient's RSA private key and the wrapped blob, recovers the session key.
//!
//! Unit tests generate a local 2048-bit keypair and round-trip the session key.

//! RSA OAEP (SHA-256) key transport helpers.

use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rand::RngCore; // <-- needed for OsRng.fill_bytes
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use zeroize::Zeroize;

pub const SESSION_KEY_LEN: usize = 16; // 128-bit AES key

pub fn rsa_wrap(recipient_pk: &RsaPublicKey) -> Result<(Vec<u8>, [u8; SESSION_KEY_LEN])> {
    let mut session_key = [0u8; SESSION_KEY_LEN];
    OsRng.fill_bytes(&mut session_key); // now compiles

    let label = Oaep::new::<Sha256>();
    let mut rng = OsRng;
    let wrapped = recipient_pk
        .encrypt(&mut rng, label, &session_key)
        .map_err(|e| anyhow!("rsa oaep encrypt failed: {e}"))?;

    Ok((wrapped, session_key))
}

pub fn rsa_unwrap(recipient_sk: &RsaPrivateKey, wrapped: &[u8]) -> Result<[u8; SESSION_KEY_LEN]> {
    let label = Oaep::new::<Sha256>();
    let mut session = recipient_sk
        .decrypt(label, wrapped)
        .map_err(|e| anyhow!("rsa oaep decrypt failed: {e}"))?;

    if session.len() != SESSION_KEY_LEN {
        return Err(anyhow!(
            "unexpected session key length: got {}, want {}",
            session.len(),
            SESSION_KEY_LEN
        ));
    }

    let mut out = [0u8; SESSION_KEY_LEN];
    out.copy_from_slice(&session);

    // hygiene: wipe temp
    session.zeroize();
    Ok(out)
}

pub fn generate_rsa_keypair(bits: usize) -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = OsRng;
    let sk = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| anyhow!("rsa keygen failed: {e}"))?;
    let pk = RsaPublicKey::from(&sk);
    Ok((sk, pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip_2048() -> Result<()> {
        let (sk, pk) = generate_rsa_keypair(2048)?;
        let (wrapped, mut plain) = rsa_wrap(&pk)?;
        let unwrapped = rsa_unwrap(&sk, &wrapped)?;
        assert_eq!(plain, unwrapped);
        plain.zeroize();
        Ok(())
    }

    #[test]
    fn wrong_key_fails() -> Result<()> {
        let (_sk_a, pk_a) = generate_rsa_keypair(2048)?;
        let (sk_b, _pk_b) = generate_rsa_keypair(2048)?;
        let (wrapped, _plain) = rsa_wrap(&pk_a)?;
        let res = rsa_unwrap(&sk_b, &wrapped);
        assert!(res.is_err());
        Ok(())
    }
}
