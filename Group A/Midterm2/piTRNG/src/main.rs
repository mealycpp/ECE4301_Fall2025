use std::env;
use std::fs::File;
use std::io::{Read, Result};

fn read_trng(num_bytes: usize) -> Result<Vec<u8>> {
    let mut f = File::open("/dev/hwrng")?;
    let mut buf = vec![0u8; num_bytes];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn monobit_stats(data: &[u8]) -> (u64, u64) {
    let mut ones = 0u64;
    let mut zeros = 0u64;

    for byte in data {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 {
                ones += 1;
            } else {
                zeros += 1;
            }
        }
    }

    (zeros, ones)
}

fn byte_histogram(data: &[u8]) -> [u64; 256] {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    counts
}

fn main() -> Result<()> {
    // Default to 1024 bytes unless user specifies.
    let args: Vec<String> = env::args().collect();
    let num_bytes: usize = if args.len() > 1 {
        args[1].parse().unwrap_or(1024)
    } else {
        1024
    };

    println!("Reading {num_bytes} bytes from /dev/hwrng ...");
    let data = read_trng(num_bytes)?;

    // Hex dump of first 64 bytes for the demo
    println!("First 64 bytes (hex):");
    for (i, b) in data.iter().take(64).enumerate() {
        print!("{:02x} ", b);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }
    println!();

    // Simple statistical checks
    let (zeros, ones) = monobit_stats(&data);
    let total_bits = zeros + ones;
    println!("Monobit stats:");
    println!("  total bits:   {}", total_bits);
    println!("  zeros:        {} ({:.3}%)", zeros, zeros as f64 * 100.0 / total_bits as f64);
    println!("  ones:         {} ({:.3}%)", ones,  ones  as f64 * 100.0 / total_bits as f64);

    let hist = byte_histogram(&data);
    println!("\nByte histogram (value: count for first 16 values):");
    for i in 0..16 {
        println!("  {:3}: {}", i, hist[i]);
    }

    Ok(())
}

