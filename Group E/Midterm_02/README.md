Raspberry Pi Hardware TRNG Demo (Rust)

This project demonstrates how to access and validate the Raspberry Pi hardware True Random Number Generator (TRNG) through `/dev/hwrng`. A Rust program reads raw entropy from the hardware RNG, performs basic statistical checks, and generates a histogram to visually confirm uniformly distributed randomness.

Project Structure
-----------------
trng_rust/                  # Rust project (source only)
├── Cargo.toml
└── src/main.rs
plot_hist_from_csv.py       # Python script that plots histogram from CSV
trng_histogram_rust.png     # Histogram image generated from hardware TRNG data
trng_analyze.py             # Python version of TRNG analysis (optional)
README.md                   # Documentation

Prerequisites
-------------
Hardware:
- Raspberry Pi with hardware TRNG support (Pi 4, Pi 5, Zero 2 W, etc.)

Software:
Install Rust:
    sudo apt update
    sudo apt install -y rustc cargo

Install Python + plotting tools:
    sudo apt install -y python3 python3-pip python3-matplotlib

Verify TRNG device:
    ls -l /dev/hwrng

1. Build and Run the Rust TRNG Analyzer
---------------------------------------
The Rust program reads 100,000 bytes from `/dev/hwrng` and computes:
- Mean byte value
- Standard deviation
- Shannon entropy per byte
- Bit-level zero/one balance
- A 256-bin histogram (saved to histogram.csv)

Run:
    cd trng_rust
    sudo cargo run

Example Output:
    Reading 100000 bytes...
    Mean byte value: 127.64
    Std dev: 73.94
    Entropy: 7.9983 bits
    Ones fraction: 0.5009

Expected ideal values:
- Mean ≈ 127.5
- Std dev ≈ 73.9
- Entropy ≈ 8.0
- Ones fraction ≈ 0.5

2. Generate Histogram Plot
--------------------------
From project root:
    python3 plot_hist_from_csv.py

Produces:
    trng_histogram_rust.png

3. Summary
----------
This project demonstrates:
- Accessing the Pi hardware TRNG
- Reading raw entropy in Rust
- Running basic randomness tests
- Visualizing distribution of byte values

The results confirm high-entropy, unbiased randomness suitable for cryptographic use.

