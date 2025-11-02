use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, Payload},
    Nonce,
};
use rand::RngCore;
use std::time::Instant;

fn main() {
    // Random key
    let mut rng = rand::rngs::OsRng;
    let key = Aes128Gcm::generate_key(&mut rng);
    let cipher = Aes128Gcm::new(&key);

    // 256 MB buffer to encrypt
    let mut data = vec![0u8; 256 * 1024 * 1024];
    rng.fill_bytes(&mut data);

    // 96-bit nonce (owned) — non-deprecated
    let nonce = Nonce::from([0u8; 12]);

    // Time a single large encryption
    let start = Instant::now();
    let _ct = cipher
        .encrypt(&nonce, Payload { msg: &data, aad: &[] })
        .expect("encrypt");
    let dur = start.elapsed();

    let mbps = (data.len() as f64 / 1_000_000.0) / dur.as_secs_f64();
    eprintln!("AES-GCM throughput: {mbps:.2} MB/s");
}
