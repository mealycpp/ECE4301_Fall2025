// Library crate that binaries can import: sha_bench::{run_random_bench, hash_files}

use sha1::{Sha1, Digest as _};
use sha2::{Sha256};
use rand::RngCore;
use std::fs;
use std::time::Instant;

pub fn run_random_bench() {
    let sizes = [1024usize, 8192, 65_536, 1_048_576];
    let trials = 5;

    println!("algo,size_bytes,trial,mbps");

    for &size in &sizes {
        for trial in 1..=trials {
            let mut buf = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut buf);

            // SHA-1
            let start = Instant::now();
            let mut h1 = Sha1::new();
            h1.update(&buf);
            let _ = h1.finalize();
            let secs = start.elapsed().as_secs_f64();
            let mbps = (size as f64 * 8.0) / (secs * 1_000_000.0);
            println!("sha1,{},{},{:.3}", size, trial, mbps);

            // SHA-256
            let start = Instant::now();
            let mut h2 = Sha256::new();
            h2.update(&buf);
            let _ = h2.finalize();
            let secs = start.elapsed().as_secs_f64();
            let mbps = (size as f64 * 8.0) / (secs * 1_000_000.0);
            println!("sha256,{},{},{:.3}", size, trial, mbps);
        }
    }
}

pub fn hash_files(files: &[String]) {
    for f in files {
        let data = fs::read(f).expect("Unable to read file");

        let start = Instant::now();
        let mut h1 = Sha1::new();
        h1.update(&data);
        let _ = h1.finalize();
        let t1 = start.elapsed().as_secs_f64();

        let start = Instant::now();
        let mut h2 = Sha256::new();
        h2.update(&data);
        let _ = h2.finalize();
        let t2 = start.elapsed().as_secs_f64();

        println!("{}, sha1: {:.6} sec", f, t1);
        println!("{}, sha256: {:.6} sec", f, t2);
    }
}
