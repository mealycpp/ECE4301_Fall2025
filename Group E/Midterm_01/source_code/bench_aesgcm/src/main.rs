use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit}};
use rand::RngCore;
use instant::Instant;

fn main() {
    let mut key = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // Build a Nonce (GenericArray<u8, U12>) once; we'll REUSE it in this bench
    // NOTE: Reusing a nonce is insecure in real systems; this is only for throughput timing.
    let nonce = aes_gcm::Nonce::from(nonce_bytes);

    let total = 256 * 1024 * 1024usize; // 256 MB
    let chunk = 64 * 1024usize;
    let iters = total / chunk;

    let mut buf = vec![0u8; chunk];
    rand::rngs::OsRng.fill_bytes(&mut buf);

    let t0 = Instant::now();
    for i in 0..iters {
        let aad = (i as u64).to_be_bytes();
        // 👇 pass a reference to the Nonce
        let _ = cipher.encrypt(&nonce, aes_gcm::aead::Payload { msg: &buf, aad: &aad }).unwrap();
    }
    let dt = t0.elapsed().as_secs_f64();
    let mbps = (total as f64 / (1024.0 * 1024.0)) / dt;
    println!(
        "Encrypt {} MB in {:.3}s = {:.1} MB/s",
        total / 1024 / 1024,
        dt,
        mbps
    );
}
