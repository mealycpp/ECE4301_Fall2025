use std::env;
use sha_bench::{run_random_bench, hash_files};

fn main() {
    // Accelerated path (AArch64 SHA1/SHA2 asm compiled in)
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("[accel] Running random-buffer benchmark…");
        run_random_bench();
    } else {
        eprintln!("[accel] Hashing files…");
        hash_files(&args);
    }
}
