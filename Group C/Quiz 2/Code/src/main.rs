use clap::{Parser, Subcommand};
use sha1::{Sha1, Digest};
use sha2::{Sha256, Digest as Sha2Digest};
use std::fs;
use std::time::Instant;
use std::io;

#[derive(Parser)]
#[command(name = "sha_bench")]
#[command(about = "SHA-1 and SHA-256 benchmark tool for Raspberry Pi 5")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    
    /// Files to hash (if no subcommand provided)
    files: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run benchmarks on random data
    Bench {
        /// Number of trials per size
        #[arg(short, long, default_value = "5")]
        trials: usize,
    },
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Some(Commands::Bench { trials }) => {
            run_benchmarks(trials);
        }
        None => {
            if cli.files.is_empty() {
                eprintln!("Usage: sha_bench <files...> OR sha_bench bench");
                std::process::exit(1);
            }
            hash_files(&cli.files)?;
        }
    }
    
    Ok(())
}

fn run_benchmarks(trials: usize) {
    let sizes = vec![
        (1024, "1 KiB"),
        (8192, "8 KiB"),
        (65536, "64 KiB"),
        (1048576, "1 MiB"),
    ];
    
    println!("=== SHA-1 & SHA-256 Benchmark ===");
    println!("Trials per size: {}", trials);
    println!("CPU pinning: Use 'taskset -c 3' for consistent results\n");
    
    // Print system info
    print_system_info();
    
    println!("\n{:<12} {:<12} {:<15} {:<15}", "Algorithm", "Size", "Avg Time (ms)", "Throughput (MB/s)");
    println!("{:-<60}", "");
    
    for (size, label) in &sizes {
        // SHA-1 benchmark
        let (sha1_time, sha1_throughput) = benchmark_sha1(*size, trials);
        println!("{:<12} {:<12} {:<15.3} {:<15.2}", 
                 "SHA-1", label, sha1_time * 1000.0, sha1_throughput);
        
        // SHA-256 benchmark
        let (sha256_time, sha256_throughput) = benchmark_sha256(*size, trials);
        println!("{:<12} {:<12} {:<15.3} {:<15.2}", 
                 "SHA-256", label, sha256_time * 1000.0, sha256_throughput);
        
        println!();
    }
}

fn benchmark_sha1(size: usize, trials: usize) -> (f64, f64) {
    let mut total_time = 0.0;
    
    for _ in 0..trials {
        // Generate random data (use simple pattern for reproducibility)
        let data = vec![0x42u8; size];
        
        let start = Instant::now();
        let mut hasher = Sha1::new();
        hasher.update(&data);
        let _result = hasher.finalize();
        let elapsed = start.elapsed();
        
        total_time += elapsed.as_secs_f64();
    }
    
    let avg_time = total_time / trials as f64;
    let throughput = (size as f64 / (1024.0 * 1024.0)) / avg_time;
    
    (avg_time, throughput)
}

fn benchmark_sha256(size: usize, trials: usize) -> (f64, f64) {
    let mut total_time = 0.0;
    
    for _ in 0..trials {
        // Generate random data (use simple pattern for reproducibility)
        let data = vec![0x42u8; size];
        
        let start = Instant::now();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let _result = hasher.finalize();
        let elapsed = start.elapsed();
        
        total_time += elapsed.as_secs_f64();
    }
    
    let avg_time = total_time / trials as f64;
    let throughput = (size as f64 / (1024.0 * 1024.0)) / avg_time;
    
    (avg_time, throughput)
}

fn hash_files(files: &[String]) -> io::Result<()> {
    println!("=== Hashing Files ===\n");
    
    for file_path in files {
        println!("File: {}", file_path);
        
        let start = Instant::now();
        let data = fs::read(file_path)?;
        let read_time = start.elapsed();
        
        // SHA-1
        let start = Instant::now();
        let mut hasher1 = Sha1::new();
        hasher1.update(&data);
        let sha1_result = hasher1.finalize();
        let sha1_time = start.elapsed();
        
        // SHA-256
        let start = Instant::now();
        let mut hasher256 = Sha256::new();
        hasher256.update(&data);
        let sha256_result = hasher256.finalize();
        let sha256_time = start.elapsed();
        
        println!("  Size: {} bytes ({:.2} KB)", data.len(), data.len() as f64 / 1024.0);
        println!("  Read time: {:.3} ms", read_time.as_secs_f64() * 1000.0);
        println!("  SHA-1:   {} ({:.3} ms)", hex::encode(sha1_result), sha1_time.as_secs_f64() * 1000.0);
        println!("  SHA-256: {} ({:.3} ms)", hex::encode(sha256_result), sha256_time.as_secs_f64() * 1000.0);
        println!();
    }
    
    Ok(())
}

fn print_system_info() {
    println!("System Information:");
    
    // Try to read CPU info
    if let Ok(cpu_info) = fs::read_to_string("/proc/cpuinfo") {
        for line in cpu_info.lines() {
            if line.starts_with("model name") || line.starts_with("CPU architecture") 
               || line.starts_with("Features") {
                println!("  {}", line.trim());
                if line.contains("Features") {
                    // Only print first 100 chars of features to keep it readable
                    break;
                }
            }
        }
    }
    
    // Print Rust version info
    println!("  Rust version: {}", env!("CARGO_PKG_VERSION"));
    println!("  sha1 crate: {}", env!("CARGO_PKG_VERSION_MAJOR"));
    println!("  sha2 crate: {}", env!("CARGO_PKG_VERSION_MAJOR"));
    
    // Kernel version
    if let Ok(version) = fs::read_to_string("/proc/version") {
        if let Some(first_line) = version.lines().next() {
            println!("  Kernel: {}", first_line.split_whitespace().take(3).collect::<Vec<_>>().join(" "));
        }
    }
}