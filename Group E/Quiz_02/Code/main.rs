use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::time::Instant;

use sha1::Sha1;
use sha2::{Sha256, Digest};

const SIZES: [usize; 4] = [
    1024,          // 1 KiB
    8 * 1024,      // 8 KiB
    64 * 1024,     // 64 KiB
    1024 * 1024,   // 1 MiB
];

fn print_usage() {
    eprintln!(
        "Usage:
  pi_sha_bench bench [trials]
      Benchmark SHA-1 and SHA-256 on random buffers of
      1 KiB, 8 KiB, 64 KiB, 1 MiB (default 5 trials).

  pi_sha_bench files <path1> [path2 ...]
      Hash one or more files, printing SHA-1, SHA-256
      and wall-clock time per file."
    );
}

fn bench(trials: u32) {
    println!("Benchmarking with {} trials per size", trials);
    println!("Sizes: 1 KiB, 8 KiB, 64 KiB, 1 MiB");
    println!("Throughput reported in MiB/s (2^20 bytes).");
    println!();

    for &size in &SIZES {
        bench_one::<Sha1>("SHA-1", size, trials);
        bench_one::<Sha256>("SHA-256", size, trials);
        println!();
    }
}

fn bench_one<H>(name: &str, size: usize, trials: u32)
where
    H: Digest + Default,
{
    // For benchmarking we don't really need randomness, but it's cheap enough.
    let mut buf = vec![0u8; size];
    fill_with_pseudo_random(&mut buf);

    let mut mbps = Vec::with_capacity(trials as usize);
    let bytes_as_mib = size as f64 / (1024.0 * 1024.0);

    for _ in 0..trials {
        let mut hasher = H::new();
        let start = Instant::now();
        hasher.update(&buf);
        let _digest = hasher.finalize();
        let elapsed = start.elapsed().as_secs_f64();
        let throughput = bytes_as_mib / elapsed; // MiB/s
        mbps.push(throughput);
    }

    let mean: f64 = mbps.iter().sum::<f64>() / trials as f64;

    println!(
        "{:<8} {:>9} bytes: {:8.2} MiB/s ({} trials)",
        name, size, mean, trials
    );
}

fn fill_with_pseudo_random(buf: &mut [u8]) {
    // Quick & dirty pseudo-random filler (no need for a crate here).
    let mut state: u64 = 0x1234_5678_9abc_def0;
    for b in buf.iter_mut() {
        // Simple xorshift
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        *b = (state & 0xFF) as u8;
    }
}

fn hash_files(paths: &[String]) -> io::Result<()> {
    if paths.is_empty() {
        print_usage();
        std::process::exit(1);
    }

    for path in paths {
        let mut file = File::open(path)?;
        let mut buf = [0u8; 8192];

        let mut sha1_hasher = Sha1::new();
        let mut sha256_hasher = Sha256::new();

        let start = Instant::now();
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            sha1_hasher.update(chunk);
            sha256_hasher.update(chunk);
        }
        let elapsed = start.elapsed().as_secs_f64();

        let digest1 = sha1_hasher.finalize();
        let digest256 = sha256_hasher.finalize();

        println!("{path}:");
        println!("  SHA-1   = {:x}", digest1);
        println!("  SHA-256 = {:x}", digest256);
        println!("  time    = {:.6} s", elapsed);
        println!();
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    // drop program name
    args.remove(0);
    let cmd = args[0].as_str();

    match cmd {
        "bench" => {
            let trials = if args.len() >= 2 {
                args[1].parse().unwrap_or(5)
            } else {
                5
            };
            bench(trials);
        }
        "files" => {
            let paths: Vec<String> = args[1..].to_vec();
            hash_files(&paths)?;
        }
        _ => {
            // Convenience: if they just pass filenames, treat as files mode.
            hash_files(&args)?;
        }
    }

    Ok(())
}
