use std::time::Instant;
use std::fs::File;
use std::io::Write;
use sha2::{Sha256, Sha512, Digest};
use blake2::{Blake2b512, Blake2s256};
use blake3;
use std::sync::Arc;
use std::thread;

fn main() {
    println!("=== Comprehensive Hash Benchmark ===\n");
    println!("Testing input sizes: 16B, 64B, 256B, 1KB, 4KB, 16KB, 64KB, 256KB, 1MB, 16MB");
    println!("Testing core counts: 1, 2, 4");
    println!("Algorithms: SHA-256, SHA-512, BLAKE2b, BLAKE2s, BLAKE3\n");
    
    let sizes = vec![
        (16, "16B"),
        (64, "64B"),
        (256, "256B"),
        (1024, "1KB"),
        (4 * 1024, "4KB"),
        (16 * 1024, "16KB"),
        (64 * 1024, "64KB"),
        (256 * 1024, "256KB"),
        (1024 * 1024, "1MB"),
        (16 * 1024 * 1024, "16MB"),
    ];
    
    let core_counts = vec![1, 2, 4];
    
    // Create CSV file
    let mut csv_file = File::create("hash_benchmark_results.csv").expect("Failed to create CSV file");
    
    // Write CSV header
    writeln!(csv_file, "Algorithm,Cores,InputSize,InputSizeBytes,AvgTimeMs,MinTimeMs,MaxTimeMs,StdDevMs,ThroughputHashesSec,ThroughputMBs,HashesPerMs").expect("Failed to write header");
    
    let total_tests = sizes.len() * core_counts.len() * 5; // 5 algorithms
    let mut test_count = 0;
    
    for (size_bytes, size_label) in &sizes {
        println!("\n{}", "=".repeat(70));
        println!("Testing with input size: {}", size_label);
        println!("{}", "=".repeat(70));
        
        // Generate test data
        let test_data: Vec<u8> = (0..*size_bytes).map(|i| (i % 256) as u8).collect();
        
        for &cores in &core_counts {
            println!("\n--- {} core(s) ---", cores);
            
            // SHA-256
            test_count += 1;
            print!("[{}/{}] SHA-256... ", test_count, total_tests);
            std::io::stdout().flush().unwrap();
            let stats = benchmark_algorithm("SHA-256", cores, &test_data, |data| {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            });
            println!("✓ {:.3} ms", stats.avg_time_ms);
            write_csv_row(&mut csv_file, "SHA-256", cores, size_label, *size_bytes, &stats);
            
            // SHA-512
            test_count += 1;
            print!("[{}/{}] SHA-512... ", test_count, total_tests);
            std::io::stdout().flush().unwrap();
            let stats = benchmark_algorithm("SHA-512", cores, &test_data, |data| {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            });
            println!("✓ {:.3} ms", stats.avg_time_ms);
            write_csv_row(&mut csv_file, "SHA-512", cores, size_label, *size_bytes, &stats);
            
            // BLAKE2b
            test_count += 1;
            print!("[{}/{}] BLAKE2b-512... ", test_count, total_tests);
            std::io::stdout().flush().unwrap();
            let stats = benchmark_algorithm("BLAKE2b-512", cores, &test_data, |data| {
                let mut hasher = Blake2b512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            });
            println!("✓ {:.3} ms", stats.avg_time_ms);
            write_csv_row(&mut csv_file, "BLAKE2b-512", cores, size_label, *size_bytes, &stats);
            
            // BLAKE2s
            test_count += 1;
            print!("[{}/{}] BLAKE2s-256... ", test_count, total_tests);
            std::io::stdout().flush().unwrap();
            let stats = benchmark_algorithm("BLAKE2s-256", cores, &test_data, |data| {
                let mut hasher = Blake2s256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            });
            println!("✓ {:.3} ms", stats.avg_time_ms);
            write_csv_row(&mut csv_file, "BLAKE2s-256", cores, size_label, *size_bytes, &stats);
            
            // BLAKE3
            test_count += 1;
            print!("[{}/{}] BLAKE3... ", test_count, total_tests);
            std::io::stdout().flush().unwrap();
            let stats = benchmark_algorithm("BLAKE3", cores, &test_data, |data| {
                let mut hasher = blake3::Hasher::new();
                hasher.update(data);
                hasher.finalize().as_bytes().to_vec()
            });
            println!("✓ {:.3} ms", stats.avg_time_ms);
            write_csv_row(&mut csv_file, "BLAKE3", cores, size_label, *size_bytes, &stats);
        }
    }
    
    println!("\n{}", "=".repeat(70));
    println!("\n✅ Benchmark complete!");
    println!("Results saved to: hash_benchmark_results.csv");
}

struct BenchmarkStats {
    avg_time_ms: f64,
    min_time_ms: f64,
    max_time_ms: f64,
    std_dev_ms: f64,
    throughput_hashes_sec: f64,
    throughput_mbs: f64,
    hashes_per_ms: f64,
}

fn benchmark_algorithm<F>(
    _name: &str,
    num_cores: usize,
    test_data: &[u8],
    hash_fn: F
) -> BenchmarkStats
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    // Adjust number of runs based on data size
    let bench_runs = if test_data.len() >= 1024 * 1024 {
        10  // 1MB+: 10 runs
    } else if test_data.len() >= 16 * 1024 {
        50  // 16KB+: 50 runs
    } else {
        100 // Small: 100 runs
    };
    
    let hash_fn = Arc::new(hash_fn);
    let test_data = Arc::new(test_data.to_vec());
    
    // Warmup
    let warmup_runs = (bench_runs / 10).max(5);
    for _ in 0..warmup_runs {
        let _ = hash_fn(&test_data);
    }
    
    // Benchmark
    let mut times = Vec::new();
    
    for _ in 0..bench_runs {
        let mut handles = vec![];
        let run_start = Instant::now();
        
        for _ in 0..num_cores {
            let hash_fn = Arc::clone(&hash_fn);
            let test_data = Arc::clone(&test_data);
            
            let handle = thread::spawn(move || {
                hash_fn(&test_data)
            });
            
            handles.push(handle);
        }
        
        for handle in handles {
            let _ = handle.join();
        }
        
        let elapsed = run_start.elapsed();
        times.push(elapsed.as_micros());
    }
    
    // Calculate statistics
    let min = *times.iter().min().unwrap() as f64 / 1_000.0;
    let max = *times.iter().max().unwrap() as f64 / 1_000.0;
    let avg = times.iter().sum::<u128>() as f64 / times.len() as f64 / 1_000.0;
    
    let variance = times.iter()
        .map(|&t| {
            let diff = (t as f64 / 1_000.0) - avg;
            diff * diff
        })
        .sum::<f64>() / times.len() as f64;
    let std_dev = variance.sqrt();
    
    // Calculate throughput
    let total_hashes = (bench_runs * num_cores) as f64;
    let total_time_sec = times.iter().sum::<u128>() as f64 / 1_000_000.0;
    let throughput_hashes_sec = total_hashes / total_time_sec;
    
    // Calculate MB/s throughput
    let bytes_per_hash = test_data.len() as f64;
    let throughput_mbs = (throughput_hashes_sec * bytes_per_hash) / (1024.0 * 1024.0);
    
    let hashes_per_ms = num_cores as f64 / avg;
    
    BenchmarkStats {
        avg_time_ms: avg,
        min_time_ms: min,
        max_time_ms: max,
        std_dev_ms: std_dev,
        throughput_hashes_sec,
        throughput_mbs,
        hashes_per_ms,
    }
}

fn write_csv_row(
    file: &mut File,
    algorithm: &str,
    cores: usize,
    size_label: &str,
    size_bytes: usize,
    stats: &BenchmarkStats,
) {
    writeln!(
        file,
        "{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.2},{:.2},{:.2}",
        algorithm,
        cores,
        size_label,
        size_bytes,
        stats.avg_time_ms,
        stats.min_time_ms,
        stats.max_time_ms,
        stats.std_dev_ms,
        stats.throughput_hashes_sec,
        stats.throughput_mbs,
        stats.hashes_per_ms,
    ).expect("Failed to write CSV row");
}
