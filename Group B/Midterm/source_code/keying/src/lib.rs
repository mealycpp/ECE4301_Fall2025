pub mod rsa;


// keying/src/lib.rs
use p256::ecdh::EphemeralSecret;
use p256::{PublicKey, EncodedPoint};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::rngs::OsRng;

/// Generate an ephemeral P-256 keypair for ECDH.
/// Returns (public_key_bytes_sec1, secret_for_finish).
pub fn gen_ecdh_keypair() -> (Vec<u8>, EphemeralSecret) {
    let secret = EphemeralSecret::random(&mut OsRng);
    let public = PublicKey::from(&secret);
    let pub_bytes = EncodedPoint::from(public).as_bytes().to_vec();
    (pub_bytes, secret)
}

/// Finish ECDH using our `EphemeralSecret` and peer's SEC1 public bytes.
/// Derive an AES-128 key with HKDF-SHA256 and return it (16 bytes).
pub fn finish_ecdh(secret: &EphemeralSecret, peer_pub_sec1: &[u8]) -> [u8; 16] {
    let peer_pub = PublicKey::from_sec1_bytes(peer_pub_sec1)
        .expect("peer sec1 is invalid");
    let shared = secret.diffie_hellman(&peer_pub);

    // ⬇️ changed from `shared.as_bytes()` to:
    let hk = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes().as_ref());

    let mut aes_key = [0u8; 16];
    hk.expand(b"ECE4301-midterm-2025-aes", &mut aes_key).expect("HKDF expand");
    aes_key
}

/// Receiver-side helper: given peer's public (SEC1), generate our pair,
/// derive AES-128 key, and return (key, our_pub_sec1).
pub fn ecdh_derive_from_peer(peer_pub_sec1: &[u8]) -> ([u8; 16], Vec<u8>) {
    let (our_pub, our_secret) = gen_ecdh_keypair();
    let key = finish_ecdh(&our_secret, peer_pub_sec1);
    (key, our_pub)
}
