use clap::{Parser, Subcommand};
use rand::{rngs::SmallRng, RngCore, SeedableRng};
use std::{fs::File, io::{BufReader, Read}, time::Instant};
use digest::{Digest};
use sha1::Sha1;
use sha2::Sha256;

#[derive(Parser, Debug)]
#[command(version, about="SHA-1 & SHA-256 bench + file hasher (Pi 5)")]
struct Cli {
    /// CSV output file (bench mode). If omitted prints to stdout.
    #[arg(long)]
    out: Option<String>,

    /// Trials per size (bench)
    #[arg(long, default_value_t = 5)]
    trials: usize,

    /// Buffer sizes in bytes (bench). Default: 1KiB,8KiB,64KiB,1MiB
    #[arg(long)]
    sizes: Option<Vec<usize>>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Benchmark randomized buffers
    Bench,
    /// Hash one or more files (prints digests and wall-clock time)
    Hash {
        #[arg(required = true)]
        files: Vec<String>
    },
}

const DEFAULT_SIZES: &[usize] = &[
    1*1024, 8*1024, 64*1024, 1*1024*1024
];

fn mib_per_sec(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / (1024.0*1024.0)) / secs
}

fn bench_algo<F>(name: &str, sizes: &[usize], trials: usize, mut do_hash: F) -> Vec<String>
where F: FnMut(&[u8]) {
    let mut out = Vec::new();
    let build = if cfg!(feature="accel") {"accel"} else {"soft"};
    // CSV header
    out.push("algo,build,size_bytes,trial,mib_per_s".to_string());

    let mut rng = SmallRng::seed_from_u64(42);
    for &sz in sizes {
        // Prepare a buffer once per size
        let mut buf = vec![0u8; sz];
        rng.fill_bytes(&mut buf);

        for t in 1..=trials {
            let start = Instant::now();
            do_hash(&buf);
            let secs = start.elapsed().as_secs_f64();
            out.push(format!("{},{},{},{},{}",
                name, build, sz, t, mib_per_sec(sz, secs)));
        }
    }
    out
}

fn hash_sha1_bytes(data: &[u8]) {
    let mut h = Sha1::new();
    h.update(data);
    let _ = h.finalize(); // digest not used in bench
}
fn hash_sha256_bytes(data: &[u8]) {
    let mut h = Sha256::new();
    h.update(data);
    let _ = h.finalize();
}

fn hash_file(path: &str) -> anyhow::Result<(String, String, f64)> {
    let file = File::open(path)?;
    let mut r = BufReader::new(file);
    let mut buf = vec![0u8; 1*1024*1024]; // 1 MiB streaming
    let mut s1 = Sha1::new();
    let mut s256 = Sha256::new();

    let start = Instant::now();
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 { break; }
        s1.update(&buf[..n]);
        s256.update(&buf[..n]);
    }
    let secs = start.elapsed().as_secs_f64();
    let d1 = hex::encode(s1.finalize());
    let d256 = hex::encode(s256.finalize());
    Ok((d1, d256, secs))
}

fn write_or_print(lines: &[String], path: &Option<String>) -> anyhow::Result<()> {
    if let Some(p) = path {
        std::fs::write(p, lines.join("\n"))?;
        eprintln!("wrote {}", p);
    } else {
        println!("{}", lines.join("\n"));
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Bench => {
            let sizes = cli.sizes.clone().unwrap_or_else(|| DEFAULT_SIZES.to_vec());
            let mut all = Vec::new();
            let mut part = bench_algo("sha1", &sizes, cli.trials, hash_sha1_bytes);
            all.append(&mut part);
            let mut part = bench_algo("sha256", &sizes, cli.trials, hash_sha256_bytes);
            all.append(&mut part);
            write_or_print(&all, &cli.out)?;
        }
        Cmd::Hash { files } => {
            let build = if cfg!(feature="accel") {"accel"} else {"soft"};
            for f in files {
                let (d1, d256, secs) = hash_file(&f)?;
                println!("file={}\nbuild={}\nSHA1  = {}\nSHA256= {}\nwall  = {:.6} s\n",
                         f, build, d1, d256, secs);
            }
        }
    }
    Ok(())
}
