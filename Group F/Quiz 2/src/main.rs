use std::env;
use std::fs::File;
use std::io::{Read};
use std::time::Instant;

use sha1::Sha1;
use sha2::{Sha256, Digest};

const SIZES: [usize; 4] = [
    1 * 1024,        // 1 KiB
    8 * 1024,        // 8 KiB
    64 * 1024,       // 64 KiB
    1 * 1024 * 1024, // 1 MiB
];

const TRIALS: usize = 5;

fn bench_sha1() {
    println!("=== SHA-1 benchmark ({} trials) ===", TRIALS);
    for &size in &SIZES {
        let mut buf = vec![0u8; size];
        // deterministic contents, not important, but not all zeros
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }

        let mut total_bytes: u64 = 0;
        let start = Instant::now();
        for _ in 0..TRIALS {
            let mut hasher = Sha1::new();
            hasher.update(&buf);
            let _digest = hasher.finalize();
            total_bytes += size as u64;
        }
        let elapsed = start.elapsed();
        let secs = elapsed.as_secs_f64();
        let mb = total_bytes as f64 / (1024.0 * 1024.0);
        let throughput = mb / secs; // MB/s

        println!(
            "size = {:7} bytes, total = {:6.2} MiB, time = {:7.4} s, throughput = {:8.2} MB/s",
            size, mb, secs, throughput
        );
    }
}

fn bench_sha256() {
    println!("=== SHA-256 benchmark ({} trials) ===", TRIALS);
    for &size in &SIZES {
        let mut buf = vec![0u8; size];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }

        let mut total_bytes: u64 = 0;
        let start = Instant::now();
        for _ in 0..TRIALS {
            let mut hasher = Sha256::new();
            hasher.update(&buf);
            let _digest = hasher.finalize();
            total_bytes += size as u64;
        }
        let elapsed = start.elapsed();
        let secs = elapsed.as_secs_f64();
        let mb = total_bytes as f64 / (1024.0 * 1024.0);
        let throughput = mb / secs;

        println!(
            "size = {:7} bytes, total = {:6.2} MiB, time = {:7.4} s, throughput = {:8.2} MB/s",
            size, mb, secs, throughput
        );
    }
}

// Hash one file (for camera demo)
fn hash_file(path: &str, mode: &str) {
    let mut file = File::open(path).expect("failed to open file");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("failed to read file");

    println!("=== Hashing file: {} (mode: {}) ===", path, mode);

    let start = Instant::now();
    match mode {
        "sha1" => {
            let mut hasher = Sha1::new();
            hasher.update(&buf);
            let digest = hasher.finalize();
            let elapsed = start.elapsed();
            println!("SHA-1  digest: {:x}", digest);
            println!("Time: {:.6} s", elapsed.as_secs_f64());
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(&buf);
            let digest = hasher.finalize();
            let elapsed = start.elapsed();
            println!("SHA-256 digest: {:x}", digest);
            println!("Time: {:.6} s", elapsed.as_secs_f64());
        }
        _ => {
            eprintln!("Unknown mode {}", mode);
        }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  sha-lab --mode sha1   --bench");
    eprintln!("  sha-lab --mode sha256 --bench");
    eprintln!("  sha-lab --mode sha1   <file1> [file2 ...]");
    eprintln!("  sha-lab --mode sha256 <file1> [file2 ...]");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        print_usage();
        return;
    }

    // Very simple manual arg parsing
    let mut mode: Option<String> = None;
    let mut bench = false;
    let mut files: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                if i + 1 >= args.len() {
                    eprintln!("--mode requires an argument (sha1 or sha256)");
                    return;
                }
                mode = Some(args[i + 1].clone());
                i += 2;
            }
            "--bench" => {
                bench = true;
                i += 1;
            }
            other => {
                // treat as file path
                files.push(other.to_string());
                i += 1;
            }
        }
    }

    let mode = match mode {
        Some(m) => m,
        None => {
            eprintln!("Missing --mode sha1|sha256");
            print_usage();
            return;
        }
    };

    if bench {
        // Benchmark mode
        match mode.as_str() {
            "sha1" => bench_sha1(),
            "sha256" => bench_sha256(),
            _ => {
                eprintln!("Unknown mode {}, expected sha1 or sha256", mode);
            }
        }
    } else {
        if files.is_empty() {
            eprintln!("No files given");
            print_usage();
            return;
        }
        for f in &files {
            hash_file(f, &mode);
        }
    }
}
