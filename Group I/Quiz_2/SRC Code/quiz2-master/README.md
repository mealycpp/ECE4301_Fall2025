# SHA-1 & SHA-256 Benchmarking Tool for Raspberry Pi 5

ECE 4301 — Crypto on Chip - Quiz #2

## Overview

This Rust CLI benchmarks SHA-1 and SHA-256 hashing performance on Raspberry Pi 5, comparing software-only implementation against AArch64 hardware-accelerated instructions.

## Build Instructions

### Prerequisites

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Build Accelerated Version (with AArch64 SHA instructions)

```bash
cargo build --release
```

The binary will be at: `target/release/quiz2`

### Build Software-Only Version (no AArch64 acceleration)

```bash
# Set environment variable to force software-only implementation
RUSTFLAGS="-C target-feature=-sha2,-sha3" cargo build --release --features force-soft
```

Or create a separate binary:

```bash
# Build and copy to different name
RUSTFLAGS="-C target-feature=-sha2,-sha3" cargo build --release
cp target/release/quiz2 target/release/quiz2-soft

# Then build accelerated version
cargo build --release
cp target/release/quiz2 target/release/quiz2-accel
```

### Alternative: Build with explicit target features

```bash
# Software-only build
RUSTFLAGS="-C target-cpu=generic" cargo build --release
mv target/release/quiz2 quiz2-soft

# Accelerated build
RUSTFLAGS="-C target-cpu=native" cargo build --release
mv target/release/quiz2 quiz2-accel
```

## Usage

### Run Benchmarks

Benchmark hashing performance on randomized buffers (1 KiB, 8 KiB, 64 KiB, 1 MiB):

```bash
# Run with default 5 trials per size
./target/release/quiz2 bench

# Run with 10 trials per size
./target/release/quiz2 bench --trials 10

# Pin to CPU core 3 (recommended for consistent results)
taskset -c 3 ./target/release/quiz2 bench
```

### Hash Files

Hash specific files and display digests with timing:

```bash
# Hash single file
./target/release/quiz2 hash image1.jpg

# Hash multiple files
./target/release/quiz2 hash image1.jpg image2.jpg image3.jpg

# Pin to CPU core 3
taskset -c 3 ./target/release/quiz2 hash *.jpg
```

## Camera Demo Workflow

### 1. Capture Images

```bash
# Capture 5 images using Pi camera
rpicam-still -o image1.jpg
rpicam-still -o image2.jpg
rpicam-still -o image3.jpg
rpicam-still -o image4.jpg
rpicam-still -o image5.jpg

# Or use libcamera-still if available
libcamera-still -o image1.jpg
```

### 2. Run Software-Only Version

```bash
taskset -c 3 ./quiz2-soft hash image1.jpg image2.jpg image3.jpg image4.jpg image5.jpg > results-soft.txt
```

### 3. Run Accelerated Version

```bash
taskset -c 3 ./quiz2-accel hash image1.jpg image2.jpg image3.jpg image4.jpg image5.jpg > results-accel.txt
```

### 4. Compare Results

```bash
echo "=== Software-Only Results ==="
cat results-soft.txt
echo -e "\n=== Accelerated Results ==="
cat results-accel.txt
```

## Benchmark Data Collection

### Rust Benchmarks

```bash
# Software-only benchmark
taskset -c 3 ./quiz2-soft bench --trials 10 > rust-soft-bench.txt

# Accelerated benchmark
taskset -c 3 ./quiz2-accel bench --trials 10 > rust-accel-bench.txt
```

### Engine Baselines

#### Option 1: Using kcapi-speed

```bash
# Install kcapi-tools if needed
sudo apt-get install libkcapi-tools

# Test SHA-1 with crypto engine
kcapi-speed -c sha1-ce 1024 8192 65536 1048576 > engine-sha1-ce.txt
kcapi-speed -c sha1 1024 8192 65536 1048576 > engine-sha1.txt

# Test SHA-256 with crypto engine
kcapi-speed -c sha256-ce 1024 8192 65536 1048576 > engine-sha256-ce.txt
kcapi-speed -c sha256 1024 8192 65536 1048576 > engine-sha256.txt
```

#### Option 2: Using OpenSSL

```bash
# SHA-1 benchmarks
openssl speed -evp sha1 > openssl-sha1.txt

# SHA-256 benchmarks
openssl speed -evp sha256 > openssl-sha256.txt
```

## System Information

Check your system details:

```bash
# OS version
cat /etc/os-release

# Kernel version
uname -r

# CPU info
lscpu | grep -E "Architecture|CPU\(s\)|Model name"

# Check for SHA extensions
cat /proc/cpuinfo | grep -i sha
```

## Output Format

### Benchmark Output

```
=== System Information ===
OS: Raspberry Pi OS (Debian GNU/Linux 12 bookworm)
Kernel: 6.6.x
sha1 crate: 0.1.0
sha2 crate: 0.1.0
Build: Accelerated (AArch64 instructions enabled)

=== SHA-1 Benchmarks ===
Buffer Size  Throughput      Sample Hash (truncated)
------------------------------------------------------------
1 KiB        XXX.XX MB/s     1234567890abcdef
8 KiB        XXX.XX MB/s     abcdef1234567890
64 KiB       XXX.XX MB/s     fedcba0987654321
1 MiB        XXX.XX MB/s     0123456789abcdef
```

### File Hash Output

```
=== File: image1.jpg ===
Size: 2.5 MiB
SHA-1:   a1b2c3d4e5f6... (0.012345 s)
SHA-256: 9f8e7d6c5b4a... (0.023456 s)
```

## Project Structure

```
quiz2/
├── Cargo.toml          # Dependencies and build configuration
├── src/
│   └── main.rs         # Main CLI implementation
├── README.md           # This file
├── target/
│   └── release/
│       ├── quiz2       # Compiled binary
│       ├── quiz2-soft  # Software-only binary
│       └── quiz2-accel # Accelerated binary
└── results/            # Benchmark results (create this)
    ├── rust-soft-bench.txt
    ├── rust-accel-bench.txt
    ├── engine-*.txt
    └── images/
```

## Dependencies

- **sha1** (0.10): RustCrypto SHA-1 implementation
- **sha2** (0.10): RustCrypto SHA-256 implementation
- **clap** (4.5): Command-line argument parsing
- **rand** (0.8): Random number generation for benchmarks

## Notes

- Always use `taskset -c 3` (or another single core) to pin execution to one CPU core for consistent benchmark results
- Run at least 5 trials per buffer size (default) for statistical validity
- The accelerated build automatically uses AArch64 SHA instructions when available
- Software-only build forces pure Rust implementation for comparison
- Record all system information (OS, kernel, crate versions) in your report

## Troubleshooting

### Build Issues

If you encounter build errors:

```bash
# Update Rust toolchain
rustup update

# Clean and rebuild
cargo clean
cargo build --release
```

### Camera Issues

If camera capture fails:

```bash
# Check camera is detected
vcgencmd get_camera

# Try alternative camera command
libcamera-hello --list-cameras
```

## License

Educational use only - ECE 4301 Quiz #2
