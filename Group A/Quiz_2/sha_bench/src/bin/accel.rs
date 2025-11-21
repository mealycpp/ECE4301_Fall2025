use std::env;
use sha_bench::{run_random_bench, hash_files};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        println!("Running accelerated SHA benchmark on random buffers...");
        run_random_bench();
    } else {
        println!("Hashing files with accelerated SHA...");
        hash_files(&args);
    }
}
