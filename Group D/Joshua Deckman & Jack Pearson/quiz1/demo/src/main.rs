use anyhow::Result;
use clap::Parser;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

use aes::Aes128;
use cipher::{KeyIvInit, StreamCipher};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// AES-128 CTR-mode demo for benchmarking HW vs SW backends.
///
/// IMPORTANT: Performance demo only (no AEAD/MAC).
#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Args {
    /// MiB of data to encrypt per iteration
    #[arg(long, default_value_t = 128)]
    mib: usize,

    /// Number of iterations (fresh keystream each time)
    #[arg(long, default_value_t = 10)]
    iterations: usize,

    /// Seed RNG for reproducibility (omit for random)
    #[arg(long)]
    seed: Option<u64>,

    /// Print build/runtime info and exit
    #[arg(long = "print-info")]
    print_info: bool,

    /// Suppress per-iteration timing output
    #[arg(long)]
    quiet: bool,
}

fn print_info() {
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.print_info {
        print_info();
        return Ok(());
    }

    let bytes = args.mib * 1024 * 1024;
    let mut rng: ChaCha20Rng = match args.seed {
        Some(s) => ChaCha20Rng::seed_from_u64(s),
        None => ChaCha20Rng::from_entropy(),
    };

    // Data buffer to (en|de)crypt in-place.
    let mut buf = vec![0u8; bytes];
    rng.fill_bytes(&mut buf);

    // Generate AES-128 key + 128-bit nonce (CTR uses 128b counter block)
    let mut key = [0u8; 16];
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce);

    for i in 0..args.iterations {
        // Reset plaintext each round to keep work comparable
        rng.fill_bytes(&mut buf);

        let start = Instant::now();
        let mut cipher = Aes128Ctr::new(&key.into(), &nonce.into());
        cipher.apply_keystream(&mut buf);
        let dt = start.elapsed();

        if !args.quiet {
            let mb = (bytes as f64) / (1024.0 * 1024.0);
            let gbps = (bytes as f64) * 8.0 / dt.as_secs_f64() / 1e9;
            println!(
                "iter {:>3}: {:>7.2} MiB in {:>8.3} s  |  {:>7.2} Gbps",
                i + 1, mb, dt.as_secs_f64(), gbps
            );
        }
    }

    Ok(())
}

