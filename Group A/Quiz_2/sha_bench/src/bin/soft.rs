use std::env;
use sha_bench::{run_random_bench, hash_files};

fn main() {
    // Software-only path (no asm features compiled in)
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("[soft] Running random-buffer benchmark…");
        run_random_bench();
    } else {
        eprintln!("[soft] Hashing files…");
        hash_files(&args);
    }
}
