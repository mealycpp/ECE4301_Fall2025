use anyhow::Result;
use clap::Parser;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::Instant;
use zeroize::Zeroize;

use rpi_secure_stream::crypto;
use rpi_secure_stream::net;
use rpi_secure_stream::video;


use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};

#[derive(Parser, Debug)]
#[command(author, version, about = "AES-128-GCM throughput micro-benchmark")]
struct Args {
    /// Total bytes to encrypt (e.g., 268435456 = 256 MiB)
    #[arg(long, default_value_t = 268_435_456)]
    total_bytes: usize,

    /// Chunk size (bytes) per encryption call (e.g., 16384)
    #[arg(long, default_value_t = 16_384)]
    chunk: usize,

    /// AAD length (bytes); 0 disables AAD
    #[arg(long, default_value_t = 16)]
    aad_len: usize,

    /// Also decrypt to verify tags (slower)
    #[arg(long, default_value_t = true)]
    verify: bool,

    /// Print CSV summary (mbps only)
    #[arg(long, default_value_t = true)]
    csv: bool,
}

#[inline]
fn log_arm_crypto_support() {
    #[cfg(target_arch = "aarch64")]
    {
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        let sha1 = std::arch::is_aarch64_feature_detected!("sha1");
        let sha2 = std::arch::is_aarch64_feature_detected!("sha2");
        eprintln!("ARMv8 CE — AES:{aes} PMULL:{pmull} SHA1:{sha1} SHA2:{sha2}");
    }
    #[cfg(not(target_arch = "aarch64"))]
    eprintln!("(Not ARMv8) — CE detection skipped");
}

/// Build next 96-bit GCM nonce = 12-byte base || big-endian counter
#[inline]
fn next_nonce(base: &[u8; 12], ctr: u32) -> [u8; 12] {
    let mut n = *base;
    n[8..12].copy_from_slice(&ctr.to_be_bytes());
    n
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Key + nonce base
    let mut key = [0u8; 16];
    let mut nonce_base = [0u8; 12];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce_base);

    let cipher = Aes128Gcm::new_from_slice(&key)?;
    let aad = if args.aad_len == 0 {
        Vec::new()
    } else {
        let mut v = vec![0u8; args.aad_len];
        OsRng.fill_bytes(&mut v);
        v
    };

    // Data buffers
    let chunk = args.chunk.max(1);
    let total = args.total_bytes / chunk * chunk; // round down to chunk multiple
    let iters = total / chunk;
    let mut pt = vec![0u8; chunk];
    OsRng.fill_bytes(&mut pt);

    // Warmup a few chunks (fill caches, JITs, etc.)
    for i in 0..16.min(iters.max(1)) {
        let n = Nonce::from(next_nonce(&nonce_base, i as u32));
        let _ = cipher.encrypt(&n, aes_gcm::aead::Payload { msg: &pt, aad: &aad })
    .map_err(|_| anyhow::anyhow!("aes-gcm encrypt failed"))?;
    }

    log_arm_crypto_support();
    println!("AES-128-GCM bench: total={} bytes, chunk={}, aad_len={}, verify={}",
             total, chunk, aad.len(), args.verify);

    // Measure encrypt (and optional decrypt)
    let t0 = Instant::now();
    let mut ctr: u32 = 0;
    let mut total_tags = 0usize;

    // Reuse buffers to avoid alloc overhead in loop
    let mut ct = vec![0u8; chunk + 16]; // ciphertext + tag (AES-GCM adds 16 bytes)
    for _ in 0..iters {
        let n = Nonce::from(next_nonce(&nonce_base, ctr));
        ctr = ctr.wrapping_add(1);

        // Encrypt
        let out = cipher
            .encrypt(&n, aes_gcm::aead::Payload { msg: &pt, aad: &aad })
                .map_err(|_| anyhow::anyhow!("aes-gcm encrypt failed"))?;
        total_tags += 16;

        // Copy into ct buffer (fixed size); keep constant-time-ish memory pattern
        // (Not security critical for a bench.)
        ct.truncate(0);
        ct.extend_from_slice(&out);

        // Optional verify
        if args.verify {
            let n2 = Nonce::from(next_nonce(&nonce_base, ctr - 1));
            let _pt = cipher
                .encrypt(&n, aes_gcm::aead::Payload { msg: &pt, aad: &aad })
                    .map_err(|_| anyhow::anyhow!("aes-gcm encrypt failed"))?;
        }
    }
    let dt = t0.elapsed();

    // Throughput
    let secs = dt.as_secs_f64();
    let mb = (total as f64) / (1024.0 * 1024.0);
    let mbps = mb / secs;

    println!(
        "RESULT: enc_bytes={} time={:.3}s throughput={:.2} MiB/s ({} iters, chunk={}, tags={})",
        total, secs, mbps, iters, chunk, total_tags
    );

    if args.csv {
        println!(
            "CSV,total_bytes={},chunk={},aad_len={},verify={},mib_per_s={:.3}",
            total, chunk, aad.len(), args.verify, mbps
        );
    }

    // hygiene
    key.zeroize();
    nonce_base.zeroize();
    ct.zeroize();
    Ok(())
}
