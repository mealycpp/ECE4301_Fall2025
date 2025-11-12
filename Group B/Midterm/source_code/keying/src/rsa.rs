use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};
use rsa::pkcs1::{EncodeRsaPublicKey, DecodeRsaPublicKey};
use sha2::Sha256;
use rand::rngs::OsRng;
use rand::RngCore;

pub fn rsa_generate(bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let sk = RsaPrivateKey::new(&mut rng, bits).expect("rsa gen");
    let pk = RsaPublicKey::from(&sk);
    (sk, pk)
}

pub fn rsa_pub_to_der(pk: &RsaPublicKey) -> Vec<u8> {
    pk.to_pkcs1_der().expect("pkcs1 der").as_bytes().to_vec()
}

pub fn rsa_pub_from_der(der: &[u8]) -> RsaPublicKey {
    RsaPublicKey::from_pkcs1_der(der).expect("pkcs1 parse")
}

pub fn rsa_wrap_aes_key(pk: &RsaPublicKey, aes_key: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    pk.encrypt(&mut rng, Oaep::new::<Sha256>(), aes_key).expect("rsa wrap")
}

pub fn rsa_unwrap_aes_key(sk: &RsaPrivateKey, wrapped: &[u8]) -> Vec<u8> {
    sk.decrypt(Oaep::new::<Sha256>(), wrapped).expect("rsa unwrap")
}

/// Sample a fresh 16-byte AES key and 8-byte nonce base
pub fn sample_session_material() -> ([u8;16], [u8;8]) {
    let mut rng = OsRng;
    let mut k = [0u8;16];
    let mut n = [0u8;8];
    rng.fill_bytes(&mut k);
    rng.fill_bytes(&mut n);
    (k, n)
}
