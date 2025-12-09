# Password Hash Benchmark (`password_hash_bench`
### A RUST password application that ask for a password input and core count (1, 2, or 4), then sequentially tests SHA-256, SHA-512, BLAKE2b-512, BLAKE2s-256, and BLAKE3 algorithms. Runs 10 iterations per algorithm and displays timing statistics, throughput, and performance metrics in real-time on the console - designed for quick manual testing with different passwords.
#### Build

    cd password_hash_bench
    RUSTFLAGS="-C target-cpu=native" cargo build --release
#### Run

    `./target/release/password_hash_bench`
