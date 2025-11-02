use rand::rngs::OsRng;
use rand::RngCore;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, DecodePublicKey}, Oaep};
use sha2::Sha256;

/// Print ARM crypto support (unchanged)
pub fn log_arm_crypto_support() {
    // The `is_aarch64_feature_detected!` macro is only available on aarch64 targets.
    // Guard it so the crate builds on x86_64 as well.
    #[cfg(target_arch = "aarch64")]
    {
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        eprintln!("ARMv8 Crypto Extensions — AES: {aes}, PMULL: {pmull}");
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        eprintln!("ARMv8 Crypto Extensions — AES: false, PMULL: false");
    }
}

/// ---------- RSA OAEP demo: wraps a 128-bit session key and unwraps it
pub fn demo_rsa() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let sk = RsaPrivateKey::new(&mut rng, 2048)?;   // >=2048 (3072 = extra credit)
    let pk = RsaPublicKey::from(&sk);

    let mut session_key = [0u8; 16];
    rng.fill_bytes(&mut session_key);

    let wrapped = pk.encrypt(&mut rng, Oaep::new::<Sha256>(), &session_key)?;
    let unwrapped = sk.decrypt(Oaep::new::<Sha256>(), &wrapped)?;

    assert_eq!(unwrapped, session_key);
    println!("RSA OAEP OK: wrapped {} bytes, unwrapped session key matches", wrapped.len());
    Ok(())
}

// ----------- RSA key management utilities ------------

/// Generate a new RSA keypair (server-side)
pub fn generate_rsa_keypair() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key generation failed")
}

/// Export the public key as DER bytes
pub fn export_rsa_public_key(pk: &RsaPublicKey) -> Vec<u8> {
    pk.to_public_key_der().expect("DER encode failed").as_ref().to_vec()
}

/// Import public key from DER bytes
pub fn import_rsa_public_key(der_bytes: &[u8]) -> RsaPublicKey {
    RsaPublicKey::from_public_key_der(der_bytes).expect("DER decode failed")
}
