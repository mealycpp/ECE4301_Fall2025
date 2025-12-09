use aes_gcm::{Aes128Gcm, Nonce, aead::{Aead, KeyInit}};
use aes_gcm::aead::consts::U12;
use rand::{RngCore, rngs::OsRng};
use std::time::Instant;

const BENCHMARK_SIZE: usize = 256 * 1024 * 1024; // 256 MB
const CHUNK_SIZE: usize = 460_000; // ~460KB per frame (640x480 YUV420)

/// Check CPU features by reading /proc/cpuinfo
fn check_cpu_features() -> (bool, bool) {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let aes = cpuinfo.contains(" aes");
        let pmull = cpuinfo.contains(" pmull");
        (aes, pmull)
    }
    
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    {
        (false, false)
    }
}

fn main() {
    println!("=== AES-128-GCM Hardware Acceleration Benchmark ===\n");
    
    // Check CPU features
    #[cfg(target_arch = "aarch64")]
    {
        let (aes_detected, pmull_detected) = check_cpu_features();
        
        println!("CPU Features:");
        println!("  AES:   {}", if aes_detected { "✓ DETECTED" } else { "✗ NOT DETECTED" });
        println!("  PMULL: {}", if pmull_detected { "✓ DETECTED" } else { "✗ NOT DETECTED" });
        println!();
        
        if !aes_detected || !pmull_detected {
            eprintln!("WARNING: Hardware crypto extensions not detected!");
            eprintln!("Ensure compilation with: RUSTFLAGS=\"-C target-cpu=native\"");
            println!();
        }
    }
    
    #[cfg(not(target_arch = "aarch64"))]
    {
        println!("CPU Features:");
        println!("  Platform: Not aarch64");
        println!("  Hardware acceleration unavailable");
        println!();
    }
    
    // Generate test data
    println!("Generating {} MB of random test data...", BENCHMARK_SIZE / (1024 * 1024));
    let mut data = vec![0u8; BENCHMARK_SIZE];
    OsRng.fill_bytes(&mut data);
    
    // Generate key and cipher
    let mut key = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    
    // Generate nonce base
    let mut nonce_base = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_base);
    
    println!("Starting encryption benchmark...\n");
    
    let start = Instant::now();
    let mut total_encrypted = 0usize;
    let mut counter = 0u32;
    
    for chunk in data.chunks(CHUNK_SIZE) {
        // Build nonce
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&nonce_base);
        nonce_bytes[8..].copy_from_slice(&counter.to_be_bytes());
        let nonce: Nonce<U12> = Nonce::from(nonce_bytes);
        counter += 1;
        
        // Encrypt
        let _ciphertext = cipher.encrypt(&nonce, chunk)
            .expect("Encryption failed");
        
        total_encrypted += chunk.len();
    }
    
    let duration = start.elapsed();
    let seconds = duration.as_secs_f64();
    let mb_processed = total_encrypted as f64 / (1024.0 * 1024.0);
    let throughput_mbps = mb_processed / seconds;
    
    println!("=== Results ===");
    println!("Total encrypted: {:.2} MB", mb_processed);
    println!("Time elapsed:    {:.3} seconds", seconds);
    println!("Throughput:      {:.2} MB/s", throughput_mbps);
    println!("Frames/sec:      {:.2} fps (@ 460KB/frame)", counter as f64 / seconds);
    println!();
    
    // Performance expectations
    println!("=== Performance Analysis ===");
    #[cfg(target_arch = "aarch64")]
    {
        let (aes_detected, pmull_detected) = check_cpu_features();
        
        if aes_detected && pmull_detected {
            if throughput_mbps > 500.0 {
                println!("✓ EXCELLENT: Hardware acceleration is working optimally");
            } else if throughput_mbps > 200.0 {
                println!("✓ GOOD: Hardware acceleration appears active");
            } else {
                println!("⚠ WARNING: Low throughput despite HW support detected");
                println!("  Expected: >200 MB/s with ARMv8 Crypto Extensions");
                println!("  Check: Compilation flags, CPU governor, thermal throttling");
            }
        } else {
            if throughput_mbps < 100.0 {
                println!("✓ Expected software-only performance");
            } else {
                println!("⚠ Unexpectedly high performance without HW detection");
            }
        }
    }
    
    #[cfg(not(target_arch = "aarch64"))]
    {
        println!("Running in software-only mode (not aarch64)");
    }
    
    println!();
    println!("To build control (software-only) version:");
    println!("  RUSTFLAGS='-C target-feature=-aes,-pmull' cargo build --release");
}