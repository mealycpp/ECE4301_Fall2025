use clap::{Parser, Subcommand, ValueEnum};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum HashAlgorithm { Sha1, Sha256, Both }

#[derive(Parser, Debug)]
#[command(name = "pi5-sha-bench", version, about = "SHA-1 & SHA-256 benchmark for Raspberry Pi 5")]
struct CommandLineArgs {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Benchmark randomized buffers at given sizes (in bytes)
    Benchmark {
        /// Comma-separated sizes in bytes (e.g., 1024,8192,65536,1048576)
        #[arg(long, default_value = "1024,8192,65536,1048576")]
        buffer_sizes: String,
        /// Number of trials per size
        #[arg(long, default_value_t = 5)]
        trials_per_size: usize,
        /// Which hashing algorithm(s) to use
        #[arg(long, value_enum, default_value_t = HashAlgorithm::Both)]
        algorithm: HashAlgorithm,
        /// Optional CSV output file path (prints to stdout if not provided)
        #[arg(long)]
        output_csv: Option<PathBuf>,
        /// Random seed for reproducibility
        #[arg(long, default_value_t = 42u64)]
        random_seed: u64,
    },
    /// Hash one or more files and print digests with timing information
    HashFiles {
        /// Algorithm to use for file hashing
        #[arg(long, value_enum, default_value_t = HashAlgorithm::Both)]
        algorithm: HashAlgorithm,
        /// List of files to hash
        files: Vec<PathBuf>,
    }
}

fn main() {
    let args = CommandLineArgs::parse();
    match args.command {
        Command::Benchmark { buffer_sizes, trials_per_size, algorithm, output_csv, random_seed } => {
            run_benchmark(&buffer_sizes, trials_per_size, algorithm, output_csv, random_seed)
        }
        Command::HashFiles { algorithm, files } => hash_input_files(algorithm, &files),
    }
}

fn run_benchmark(buffer_sizes: &str, trials_per_size: usize, algorithm: HashAlgorithm, output_csv: Option<PathBuf>, random_seed: u64) {
    let mut writer: Box<dyn Write> = if let Some(path) = output_csv {
        Box::new(File::create(path).expect("Failed to create CSV file"))
    } else {
        Box::new(std::io::stdout())
    };

    writeln!(writer, "algorithm,size_bytes,trial,throughput_MBps,total_bytes,elapsed_ms").unwrap();

    let sizes_in_bytes: Vec<usize> = buffer_sizes
        .split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
        .collect();

    let mut prng = StdRng::seed_from_u64(random_seed);

    for &size_bytes in &sizes_in_bytes {
        let mut randomized_message = vec![0u8; size_bytes];
        prng.fill_bytes(&mut randomized_message);

        let algorithms_to_run: Vec<HashAlgorithm> = match algorithm {
            HashAlgorithm::Both => vec![HashAlgorithm::Sha1, HashAlgorithm::Sha256],
            _ => vec![algorithm],
        };

        for selected_algorithm in algorithms_to_run {
            for trial_idx in 0..trials_per_size {
                let t0 = Instant::now();
                match selected_algorithm {
                    HashAlgorithm::Sha1 => {
                        use sha1::{Digest, Sha1};
                        let mut hasher = Sha1::new();
                        hasher.update(&randomized_message);
                        let _digest = hasher.finalize();
                    }
                    HashAlgorithm::Sha256 => {
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(&randomized_message);
                        let _digest = hasher.finalize();
                    }
                    HashAlgorithm::Both => unreachable!(),
                }
                let dt = t0.elapsed();
                let elapsed_ms = (dt.as_secs_f64() * 1000.0) as u64;
                let throughput_mbps = (size_bytes as f64) / dt.as_secs_f64() / 1_000_000.0; // decimal MB/s

                writeln!(
                    writer,
                    "{},{},{},{:.6},{},{}",
                    algorithm_name(selected_algorithm),
                    size_bytes,
                    trial_idx + 1,
                    throughput_mbps,
                    size_bytes,
                    elapsed_ms
                ).unwrap();
            }
        }
    }
}

fn algorithm_name(algo: HashAlgorithm) -> &'static str {
    match algo {
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Both => "both",
    }
}

fn hash_input_files(algorithm: HashAlgorithm, files: &[PathBuf]) {
    let algorithms_to_run: Vec<HashAlgorithm> = match algorithm {
        HashAlgorithm::Both => vec![HashAlgorithm::Sha1, HashAlgorithm::Sha256],
        _ => vec![algorithm],
    };

    for file_path in files {
        let file = File::open(file_path).expect("Failed to open file");
        let mut reader = BufReader::new(file);
        let mut chunk = vec![0u8; 8 * 1024 * 1024]; // 8 MiB chunk

        for algo in &algorithms_to_run {
            let t0 = Instant::now();
            match algo {
                HashAlgorithm::Sha1 => {
                    use sha1::{Digest, Sha1};
                    let mut hasher = Sha1::new();
                    loop {
                        let n = reader.read(&mut chunk).expect("Read error");
                        if n == 0 { break; }
                        hasher.update(&chunk[..n]);
                    }
                    let digest = hasher.finalize();
                    let secs = t0.elapsed().as_secs_f64();
                    println!(
                        "sha1 {} {}s {}",
                        file_path.display(),
                        format_seconds(secs),
                        hex::encode(digest)
                    );
                }
                HashAlgorithm::Sha256 => {
                    use sha2::{Digest, Sha256};
                    reader.seek(SeekFrom::Start(0)).expect("Seek error");
                    let mut hasher = Sha256::new();
                    loop {
                        let n = reader.read(&mut chunk).expect("Read error");
                        if n == 0 { break; }
                        hasher.update(&chunk[..n]);
                    }
                    let digest = hasher.finalize();
                    let secs = t0.elapsed().as_secs_f64();
                    println!(
                        "sha256 {} {}s {}",
                        file_path.display(),
                        format_seconds(secs),
                        hex::encode(digest)
                    );
                }
                HashAlgorithm::Both => unreachable!(),
            }
        }
    }
}

fn format_seconds(seconds: f64) -> String {
    format!("{:.3}", seconds)
}
