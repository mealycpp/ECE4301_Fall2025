use rand::rngs::OsRng;
use rand::RngCore;
use std::arch::is_aarch64_feature_detected;

pub fn log_arm_crypto_support() {
    // Required by your HW-acceleration proof (§2.2 / §3.2.1)
    let aes = std::arch::is_aarch64_feature_detected!("aes");
    let pmull = std::arch::is_aarch64_feature_detected!("pmull");
    eprintln!("ARMv8 Crypto Extensions — AES: {aes}, PMULL: {pmull}");
}

// ---------- ECDH (P-256) demo: derives a 128-bit AES key + 96-bit nonce base
pub fn demo_ecdh() -> Result<(), Box<dyn std::error::Error>> {
    use hkdf::Hkdf;
    use p256::ecdh::EphemeralSecret;
    use p256::{EncodedPoint, PublicKey};
    use secrecy::ExposeSecret;
    use sha2::Sha256;

    // Alice
    let alice_secret = EphemeralSecret::random(&mut OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let alice_pub_bytes = EncodedPoint::from(alice_public).as_bytes().to_vec();

    // Bob
    let bob_secret = EphemeralSecret::random(&mut OsRng);
    let bob_public = PublicKey::from(&bob_secret);
    let bob_pub_bytes = EncodedPoint::from(bob_public).as_bytes().to_vec();

    // Exchange and compute shared secrets
    let bob_view_of_alice = PublicKey::from_sec1_bytes(&alice_pub_bytes)?;
    let alice_view_of_bob = PublicKey::from_sec1_bytes(&bob_pub_bytes)?;
    let alice_shared = alice_secret.diffie_hellman(&alice_view_of_bob);
    let bob_shared   = bob_secret.diffie_hellman(&bob_view_of_alice);

    // Compare raw bytes (need ExposeSecret)
let a_bytes = alice_shared.raw_secret_bytes();
let b_bytes = bob_shared.raw_secret_bytes();
assert_eq!(a_bytes.as_slice(), b_bytes.as_slice(), "ECDH shared secrets must match");

// HKDF -> AES-128 key
let hk = hkdf::Hkdf::<sha2::Sha256>::new(
    Some(b"salt:ECE4301-midterm-2025"),
    a_bytes.as_slice(),
);
let mut aes_key = [0u8; 16];
hk.expand(b"ctx:aes-128-gcm", &mut aes_key).expect("HKDF expand failed");

    // 96-bit nonce base (8B random + 4B counter later)
    let mut nonce_base = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_base);

    println!("ECDH OK:");
    println!("  aes_key[0..4] = {:02x?}", &aes_key[..4]);
    println!("  nonce_base    = {:02x?}", &nonce_base);
    Ok(())
}

// ---------- RSA OAEP demo: wraps a 128-bit session key and unwraps it
pub fn demo_rsa() -> Result<(), Box<dyn std::error::Error>> {
    use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

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
