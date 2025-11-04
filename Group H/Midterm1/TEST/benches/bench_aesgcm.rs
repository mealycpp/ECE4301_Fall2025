use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Nonce};
use rand::RngCore;
use std::time::Instant;

fn main() {
    let mut key = [0u8; 16];
    let mut nonce_base = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut key);
    rand::rngs::OsRng.fill_bytes(&mut nonce_base);
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();

    let total = 256 * 1024 * 1024; // 256 MiB
    let mut buf = vec![0u8; total];
    rand::rngs::OsRng.fill_bytes(&mut buf);

    let start = Instant::now();
    let mut off = 0usize;
    let mut ctr: u32 = 0;
    while off < total {
        let end = (off + 16 * 1024).min(total);
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&nonce_base[..8]);
        n[8..].copy_from_slice(&ctr.to_be_bytes());
        ctr = ctr.wrapping_add(1);
        let _ct = cipher.encrypt(Nonce::from_slice(&n), &buf[off..end]).unwrap();
        off = end;
    }

    let secs = start.elapsed().as_secs_f64();
    let mbps = (total as f64 / 1_000_000.0) / secs;
    println!("aes-gcm encrypt: {:.1} MB/s", mbps);

    // Feature detection (guarded so non-aarch64 still compiles)
    #[cfg(target_arch = "aarch64")]
    {
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        eprintln!("ARMv8 Crypto Extensions ? AES: {aes}, PMULL: {pmull}");
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        eprintln!("ARMv8 Crypto Extensions ? not aarch64");
    }
}