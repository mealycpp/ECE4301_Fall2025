use clap::{Parser, Subcommand};
use sha1::{Sha1, Digest};
use sha2::Sha256;
use std::fs;
use std::time::Instant;
use rand::Rng;

#[derive(Parser)]
#[command(name = "sha-bench")]
#[command(about = "SHA-1 and SHA-256 benchmarking tool for Raspberry Pi 5", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Bench {
        #[arg(short, long, default_value_t = 5)]
        trials: usize,
    },
    Hash {
        files: Vec<String>,
    },
}

const BUFFER_SIZES: [usize; 4] = [
    1024,
    8192,
    65536,
    1048576,
];

fn print_system_info() {
    println!("=== System Information ===");
    
    if let Ok(os_release) = fs::read_to_string("/etc/os-release") {
        for line in os_release.lines() {
            if line.starts_with("PRETTY_NAME=") {
                println!("OS: {}", line.trim_start_matches("PRETTY_NAME=").trim_matches('"'));
                break;
            }
        }
    }
    
    if let Ok(kernel) = fs::read_to_string("/proc/version") {
        if let Some(version) = kernel.split_whitespace().nth(2) {
            println!("Kernel: {}", version);
        }
    }
    
    println!("sha1 crate: {}", env!("CARGO_PKG_VERSION"));
    println!("sha2 crate: {}", env!("CARGO_PKG_VERSION"));
    
    #[cfg(feature = "force-soft")]
    println!("Build: Software-only (no AArch64 acceleration)");
    
    #[cfg(not(feature = "force-soft"))]
    println!("Build: Accelerated (AArch64 instructions enabled)");
    
    println!();
}

fn benchmark_sha1(data: &[u8], trials: usize) -> (f64, Vec<f64>, String) {
    let mut total_duration = 0u128;
    let mut hash_hex = String::new();
    let mut trial_throughputs = Vec::new();
    
    for _ in 0..trials {
        let start = Instant::now();
        let mut hasher = Sha1::new();
        hasher.update(data);
        let result = hasher.finalize();
        let duration = start.elapsed();
        
        let duration_secs = duration.as_nanos() as f64 / 1_000_000_000.0;
        let trial_throughput = (data.len() as f64 / (1024.0 * 1024.0)) / duration_secs;
        trial_throughputs.push(trial_throughput);
        
        total_duration += duration.as_nanos();
        hash_hex = format!("{:x}", result);
    }
    
    let avg_duration_secs = (total_duration / trials as u128) as f64 / 1_000_000_000.0;
    let throughput_mbps = (data.len() as f64 / (1024.0 * 1024.0)) / avg_duration_secs;
    
    (throughput_mbps, trial_throughputs, hash_hex)
}

fn benchmark_sha256(data: &[u8], trials: usize) -> (f64, Vec<f64>, String) {
    let mut total_duration = 0u128;
    let mut hash_hex = String::new();
    let mut trial_throughputs = Vec::new();
    
    for _ in 0..trials {
        let start = Instant::now();
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let duration = start.elapsed();
        
        let duration_secs = duration.as_nanos() as f64 / 1_000_000_000.0;
        let trial_throughput = (data.len() as f64 / (1024.0 * 1024.0)) / duration_secs;
        trial_throughputs.push(trial_throughput);
        
        total_duration += duration.as_nanos();
        hash_hex = format!("{:x}", result);
    }
    
    let avg_duration_secs = (total_duration / trials as u128) as f64 / 1_000_000_000.0;
    let throughput_mbps = (data.len() as f64 / (1024.0 * 1024.0)) / avg_duration_secs;
    
    (throughput_mbps, trial_throughputs, hash_hex)
}

fn run_benchmarks(trials: usize) {
    print_system_info();
    
    println!("=== SHA-1 Benchmarks ===");
    println!("{:<12} {:<15} {:<20}", "Buffer Size", "Avg Throughput", "Sample Hash (truncated)");
    println!("{}", "-".repeat(60));
    
    for &size in &BUFFER_SIZES {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
        
        let (throughput, trial_data, hash) = benchmark_sha1(&data, trials);
        let size_str = format_size(size);
        println!("{:<12} {:<15} {:<20}", size_str, format!("{:.2} MB/s", throughput), &hash[..16]);
        
        print!("  Trials: ");
        for (i, t) in trial_data.iter().enumerate() {
            if i > 0 { print!(", "); }
            print!("{:.2}", t);
        }
        println!(" MB/s\n");
    }
    
    println!("=== SHA-256 Benchmarks ===");
    println!("{:<12} {:<15} {:<20}", "Buffer Size", "Avg Throughput", "Sample Hash (truncated)");
    println!("{}", "-".repeat(60));
    
    for &size in &BUFFER_SIZES {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
        
        let (throughput, trial_data, hash) = benchmark_sha256(&data, trials);
        let size_str = format_size(size);
        println!("{:<12} {:<15} {:<20}", size_str, format!("{:.2} MB/s", throughput), &hash[..16]);
        
        print!("  Trials: ");
        for (i, t) in trial_data.iter().enumerate() {
            if i > 0 { print!(", "); }
            print!("{:.2}", t);
        }
        println!(" MB/s\n");
    }
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1048576 {
        format!("{} MiB", bytes / 1048576)
    } else if bytes >= 1024 {
        format!("{} KiB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}

fn hash_files(files: Vec<String>) {
    print_system_info();
    
    for filepath in files {
        println!("=== File: {} ===", filepath);
        
        match fs::read(&filepath) {
            Ok(data) => {
                let start = Instant::now();
                let mut hasher1 = Sha1::new();
                hasher1.update(&data);
                let sha1_result = hasher1.finalize();
                let sha1_duration = start.elapsed();
                
                let start = Instant::now();
                let mut hasher256 = Sha256::new();
                hasher256.update(&data);
                let sha256_result = hasher256.finalize();
                let sha256_duration = start.elapsed();
                
                let file_size = data.len();
                let size_str = format_size(file_size);
                
                println!("Size: {}", size_str);
                println!("SHA-1:   {} ({:.6} s)", format!("{:x}", sha1_result), sha1_duration.as_secs_f64());
                println!("SHA-256: {} ({:.6} s)", format!("{:x}", sha256_result), sha256_duration.as_secs_f64());
                println!();
            }
            Err(e) => {
                eprintln!("Error reading file '{}': {}", filepath, e);
                println!();
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Bench { trials } => {
            run_benchmarks(trials);
        }
        Commands::Hash { files } => {
            hash_files(files);
        }
    }
}
