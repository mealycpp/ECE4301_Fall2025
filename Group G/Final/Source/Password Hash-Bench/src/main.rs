use std::io::{self, Write};
use std::time::Instant;
use sha2::{Sha256, Sha512, Digest};
use blake2::{Blake2b512, Blake2s256};
use blake3;
use std::sync::Arc;
use std::thread;

fn main() {
    println!("=== Password Hash Benchmark ===\n");
    
    // Get password from user
    print!("Enter password to hash: ");
    io::stdout().flush().unwrap();
    
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    let password = password.trim().to_string();
    
    if password.is_empty() {
        println!("Error: Password cannot be empty");
        return;
    }
    
    // Get core count
    print!("Select number of cores (1, 2, or 4): ");
    io::stdout().flush().unwrap();
    
    let mut cores_input = String::new();
    io::stdin().read_line(&mut cores_input).unwrap();
    let num_cores: usize = cores_input.trim().parse().unwrap_or(1);
    
    if num_cores < 1 || num_cores > 4 {
        println!("Error: Core count must be 1, 2, or 4");
        return;
    }
    
    println!("\n{}\n", "=".repeat(70));
    
    // SHA-256
    println!("Hashing in SHA-256...\n");
    benchmark_hash("SHA-256", num_cores, &password, |pwd| {
        let mut hasher = Sha256::new();
        hasher.update(pwd.as_bytes());
        format!("{:x}", hasher.finalize())
    });
    
    // SHA-512
    println!("\nHashing in SHA-512...\n");
    benchmark_hash("SHA-512", num_cores, &password, |pwd| {
        let mut hasher = Sha512::new();
        hasher.update(pwd.as_bytes());
        format!("{:x}", hasher.finalize())
    });
    
    // BLAKE2b
    println!("\nHashing in BLAKE2b-512...\n");
    benchmark_hash("BLAKE2b-512", num_cores, &password, |pwd| {
        let mut hasher = Blake2b512::new();
        hasher.update(pwd.as_bytes());
        format!("{:x}", hasher.finalize())
    });
    
    // BLAKE2s
    println!("\nHashing in BLAKE2s-256...\n");
    benchmark_hash("BLAKE2s-256", num_cores, &password, |pwd| {
        let mut hasher = Blake2s256::new();
        hasher.update(pwd.as_bytes());
        format!("{:x}", hasher.finalize())
    });
    
    // BLAKE3
    println!("\nHashing in BLAKE3...\n");
    benchmark_hash("BLAKE3", num_cores, &password, |pwd| {
        let mut hasher = blake3::Hasher::new();
        hasher.update(pwd.as_bytes());
        format!("{}", hasher.finalize())
    });
    
    println!("\n{}", "=".repeat(70));
    println!("\nBenchmark complete!");
}

fn benchmark_hash<F>(name: &str, num_cores: usize, password: &str, hash_fn: F) 
where 
    F: Fn(&str) -> String + Send + Sync + 'static,
{
    const BENCH_RUNS: usize = 10;
    
    let hash_fn = Arc::new(hash_fn);
    let password = Arc::new(password.to_string());
    
    // Collect timing data and hash result
    let mut times = Vec::new();
    let mut hash_result = String::new();
    
    let start_total = Instant::now();
    
    for run in 0..BENCH_RUNS {
        let mut handles = vec![];
        let runs_per_core = 1; // Each iteration does 1 hash per core
        
        let run_start = Instant::now();
        
        for _ in 0..num_cores {
            let hash_fn = Arc::clone(&hash_fn);
            let password = Arc::clone(&password);
            
            let handle = thread::spawn(move || {
                hash_fn(&password)
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads and get result from first one
        for (i, handle) in handles.into_iter().enumerate() {
            let result = handle.join().unwrap();
            if i == 0 && run == 0 {
                hash_result = result;
            }
        }
        
        let run_elapsed = run_start.elapsed();
        times.push(run_elapsed.as_micros());
    }
    
    let total_elapsed = start_total.elapsed();
    
    // Calculate statistics
    let min = *times.iter().min().unwrap() as f64 / 1_000.0; // Convert to ms
    let max = *times.iter().max().unwrap() as f64 / 1_000.0;
    let avg = times.iter().sum::<u128>() as f64 / times.len() as f64 / 1_000.0;
    
    // Calculate standard deviation
    let variance = times.iter()
        .map(|&t| {
            let diff = (t as f64 / 1_000.0) - avg;
            diff * diff
        })
        .sum::<f64>() / times.len() as f64;
    let std_dev = variance.sqrt();
    
    // Calculate throughput
    let total_hashes = (BENCH_RUNS * num_cores) as f64;
    let total_time_sec = total_elapsed.as_secs_f64();
    let hashes_per_sec = total_hashes / total_time_sec;
    
    // Calculate energy efficiency metric (hashes per millisecond)
    let hashes_per_ms = 1.0 / avg * num_cores as f64;
    
    // Display results
    println!("{}", name);
    println!("{}", hash_result);
    println!("{:.2} ms", avg);
    println!();
    println!("Timing Statistics ({} runs, {} core(s)):", BENCH_RUNS, num_cores);
    println!("  Average:        {:.2} ms", avg);
    println!("  Min:            {:.2} ms", min);
    println!("  Max:            {:.2} ms", max);
    println!("  Std Dev:        {:.2} ms", std_dev);
    println!();
    println!("Performance Metrics:");
    println!("  Throughput:     {:.0} hashes/sec", hashes_per_sec);
    println!("  Total Time:     {:.3} sec", total_time_sec);
    println!("  Hashes/ms:      {:.2}", hashes_per_ms);
}
