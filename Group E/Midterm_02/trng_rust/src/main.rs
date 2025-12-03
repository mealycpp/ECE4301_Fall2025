use std::fs::File;
use std::io::{Read, Write};

const BYTES_TO_READ: usize = 100_000;

fn main() {
    println!("Reading {} bytes from /dev/hwrng...", BYTES_TO_READ);

    let mut file = File::open("/dev/hwrng")
        .expect("Failed to open /dev/hwrng. Are you root?");
    
    let mut buf = vec![0u8; BYTES_TO_READ];
    file.read_exact(&mut buf)
        .expect("Failed to read enough bytes from /dev/hwrng");

    println!("Actually read {} bytes", buf.len());

    // --- Basic stats: mean and standard deviation ---
    let sum: f64 = buf.iter().map(|&b| b as f64).sum();
    let mean = sum / buf.len() as f64;

    let var_sum: f64 = buf.iter().map(|&b| {
        let x = b as f64;
        (x - mean).powi(2)
    }).sum();
    let variance = var_sum / (buf.len() as f64);
    let std_dev = variance.sqrt();

    println!("Mean byte value: {:.2} (expected ~127.5)", mean);
    println!("Std dev of bytes: {:.2}", std_dev);

    // --- Histogram for 0..=255 ---
    let mut hist = [0u64; 256];
    for &b in &buf {
        hist[b as usize] += 1;
    }

    // --- Shannon entropy per byte ---
    let total: f64 = buf.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &hist {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    println!("Shannon entropy per byte: {:.4} bits (max is 8.0)", entropy);

    // --- Bit-level stats: zeros/ones balance ---
    let mut zeros: u64 = 0;
    let mut ones: u64 = 0;
    for &b in &buf {
        let ones_in_byte = b.count_ones() as u64;
        ones += ones_in_byte;
        zeros += 8 - ones_in_byte;
    }
    let total_bits = zeros + ones;
    let frac_ones = ones as f64 / total_bits as f64;

    println!(
        "Bit count: zeros={}, ones={}, ones fraction={:.4}",
        zeros, ones, frac_ones
    );

    // --- Save histogram as CSV for plotting ---
    let mut out = File::create("histogram.csv").expect("Failed to create histogram.csv");
    writeln!(out, "value,count").expect("Failed to write header");
    for (value, &count) in hist.iter().enumerate() {
        writeln!(out, "{},{}", value, count).expect("Failed to write histogram row");
    }
    println!("Saved histogram data to histogram.csv in current directory");
}
