use std::fs::File;
use std::io::{Read, Result};
use std::path::Path;
use std::io::Write;

const HWRNG_PATH: &str = "/dev/hwrng";

const SAMPLE_SIZE: usize = 100_000;

fn main() -> Result<()> {
    // 1. Read raw bytes from /dev/hwrng
    if !Path::new(HWRNG_PATH).exists() {
        eprintln!("Error: {} does not exist. Is the hardware RNG enabled?", HWRNG_PATH);
        std::process::exit(1);
    }

    let mut file = File::open(HWRNG_PATH)?;
    let mut buf = vec![0u8; SAMPLE_SIZE];
    file.read_exact(&mut buf)?;

    println!("Read {} bytes from {}", buf.len(), HWRNG_PATH);
    println!();

    // 2. Print a small hex dump sample
    print_hex_sample(&buf, 64);
    println!();

    // 3. Run simple tests
    bit_frequency_test(&buf);
    println!();

    runs_test(&buf);
    println!();

    byte_histogram(&buf);

    Ok(())
}

/// Print the first `n` bytes as a hex dump.
fn print_hex_sample(data: &[u8], n: usize) {
    let n = n.min(data.len());
    println!("Hex sample (first {} bytes):", n);
    for (i, b) in data[..n].iter().enumerate() {
        if i % 16 == 0 {
            print!("\n{:04x}: ", i);
        }
        print!("{:02x} ", b);
    }
    println!("\n");
}

/// Count zeros and ones in the entire buffer.
fn bit_frequency_test(data: &[u8]) {
    let mut zeros: u64 = 0;
    let mut ones: u64 = 0;

    for byte in data {
        for i in 0..8 {
            let bit = (byte >> i) & 1;
            if bit == 0 {
                zeros += 1;
            } else {
                ones += 1;
            }
        }
    }

    let total = zeros + ones;
    let zeros_ratio = zeros as f64 / total as f64;
    let ones_ratio = ones as f64 / total as f64;

    println!("Bit frequency test:");
    println!("  Total bits:   {}", total);
    println!("  Zeros:        {} ({:.6})", zeros, zeros_ratio);
    println!("  Ones:         {} ({:.6})", ones, ones_ratio);
    println!("  Ideally, both should be close to 0.5.");
}

/// Simple runs test on bits: count total runs and max run length.
fn runs_test(data: &[u8]) {
    if data.is_empty() {
        println!("Runs test: no data.");
        return;
    }

    let mut last_bit: u8 = data[0] & 1;
    let mut current_run_len: u64 = 1;
    let mut total_runs: u64 = 0;
    let mut max_run_len: u64 = 1;

    // Iterate through all bits
    let mut first = true;
    for byte in data {
        for i in 0..8 {
            let bit = (byte >> i) & 1;

            if first {
                // We already initialized with first bit of first byte.
                first = false;
                continue;
            }

            if bit == last_bit {
                current_run_len += 1;
            } else {
                total_runs += 1;
                if current_run_len > max_run_len {
                    max_run_len = current_run_len;
                }
                current_run_len = 1;
                last_bit = bit;
            }
        }
    }

    // Final run
    total_runs += 1;
    if current_run_len > max_run_len {
        max_run_len = current_run_len;
    }

    println!("Runs test (on bits):");
    println!("  Total runs:      {}", total_runs);
    println!("  Max run length:  {}", max_run_len);
    println!("  Very long runs or very few runs may indicate bias.");
}

/// Build and print a simple byte value histogram.
fn byte_histogram(data: &[u8]) {
    let mut counts = [0u64; 256];

    for &b in data {
        counts[b as usize] += 1;
    }

    println!("Byte histogram (0–255):");
    let total = data.len() as f64;

    // Print all values, with relative frequency
    for (value, &count) in counts.iter().enumerate() {
        let freq = count as f64 / total;
        println!("  {:3}: {:8} ({:.6})", value, count, freq);
    }
// Store and plot
fn write_histogram_csv(counts: &[u64; 256], filename: &str) {
    let mut file = File::create(filename).expect("Unable to create file");
    writeln!(file, "value,count").unwrap();

    for (value, &count) in counts.iter().enumerate() {
        writeln!(file, "{},{}", value, count).unwrap();
    }

    println!("Histogram written to {}", filename);
    }
// Function Call
write_histogram_csv(&counts, "histogram.csv");
}
