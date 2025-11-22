# SHA-1 & SHA-256 Benchmark Tool

Rust implementation for benchmarking SHA-1 and SHA-256 on Raspberry Pi 5, comparing software-only vs hardware-accelerated (ARMv8 Crypto Extensions) implementations.

## Quick Start Guide

### Prerequisites

1. **Raspberry Pi 5** with Raspberry Pi OS
2. **Rust toolchain** installed:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```
3. **Camera tool** (optional, for demo):
   ```bash
   sudo apt install ffmpeg  # For USB cameras
   # OR
   sudo apt install rpicam-apps  # For Pi Camera Module
   ```

### Step-by-Step Installation & Execution

#### Step 1: Set Up Project
```bash
# Create project directory
mkdir -p ~/Documents/rust/Quiz2
cd ~/Documents/rust/Quiz2

# Create the necessary files:
# - Cargo.toml (project configuration)
# - src/main.rs (main code)
# - build.sh (build script)
# - run_all_benchmarks.sh (benchmark runner)
# - run_camera_demo.sh (camera demo script)
```

#### Step 2: Build Both Versions
```bash
# Make scripts executable
chmod +x build.sh run_all_benchmarks.sh run_camera_demo.sh

# Build software-only and hardware-accelerated versions
./build.sh
```

**Expected output:**
```
=== Building SHA Benchmark Tool ===
...
Created: sha_bench_soft    (883K)
Created: sha_bench_accel   (887K)
```

#### Step 3: Test Individual Builds
```bash
# Test software-only version (pure Rust implementation)
taskset -c 3 ./sha_bench_soft bench --trials 5

# Test hardware-accelerated version (with ARMv8 SHA instructions)
taskset -c 3 ./sha_bench_accel bench --trials 5
```

**Expected results:**
- Software: ~200-440 MB/s
- Accelerated: ~780-1,230 MB/s (3-5× faster!)

#### Step 4: Run Complete Benchmark Suite
```bash
# This runs everything and saves results to logs/
./run_all_benchmarks.sh
```

**What it does:**
1. Runs Rust software-only benchmarks (10 trials)
2. Runs Rust accelerated benchmarks (10 trials)
3. Runs OpenSSL engine baselines
4. Saves all output to `logs/` directory

**Output files:**
- `logs/rust_soft_output.txt` - Software benchmark results
- `logs/rust_accel_output.txt` - Accelerated benchmark results
- `logs/engine_baseline.txt` - OpenSSL performance data
- `logs/system_info.txt` - CPU, kernel, versions

#### Step 5: Run Camera Demo
```bash
# Captures images and hashes them with both versions
./run_camera_demo.sh
```

**What it does:**
1. Detects your camera (USB or Pi Camera)
2. Captures 5 images to `images/` directory
3. Hashes all images with software version (shows timing)
4. Hashes all images with accelerated version (shows timing)
5. Saves output to `demo_output.txt`

**Manual camera demo (if script fails):**
```bash
# For USB camera
mkdir -p images
for i in {1..5}; do
    ffmpeg -f v4l2 -i /dev/video0 -frames:v 1 -s 1280x720 images/capture_$i.jpg -y
    sleep 1
done

# Hash with both versions
time ./sha_bench_soft images/*.jpg
time ./sha_bench_accel images/*.jpg
```

#### Step 6: Review Results
```bash
# View benchmark logs
cat logs/rust_soft_output.txt
cat logs/rust_accel_output.txt
cat logs/engine_baseline.txt

# View demo results
cat demo_output.txt

# Compare digests (should match)
grep 'SHA-256:' demo_output.txt | sort
```

## Project Structure

```
Quiz2/
├── Cargo.toml              # Rust project configuration
├── src/
│   └── main.rs             # Main benchmark implementation
├── build.sh                # Builds both versions
├── run_all_benchmarks.sh   # Complete benchmark suite
├── run_camera_demo.sh      # Camera demo script
├── sha_bench_soft          # Software-only binary
├── sha_bench_accel         # Hardware-accelerated binary
├── logs/                   # Benchmark results
│   ├── rust_soft_output.txt
│   ├── rust_accel_output.txt
│   ├── engine_baseline.txt
│   └── system_info.txt
├── images/                 # Captured images
│   ├── capture_1.jpg
│   ├── capture_2.jpg
│   └── ...
└── demo_output.txt         # Camera demo results
```

## Building

### Software-Only Build (No Hardware Acceleration)

```bash
# Disable asm feature for pure software implementation
cargo build --release --no-default-features --features std
cp target/release/Quiz2 sha_bench_soft
```

### Hardware-Accelerated Build (ARMv8 SHA Extensions)

```bash
# Enable native CPU features including SHA extensions
RUSTFLAGS="-C target-cpu=native" cargo build --release
cp target/release/Quiz2 sha_bench_accel
```

### Verify Hardware Support

```bash
# Check if your Pi has SHA extensions
grep -i sha /proc/cpuinfo
# Should show "sha1 sha2" in Features line
```

## Usage

### Run Benchmarks

```bash
# Pin to single core for consistent results
taskset -c 3 ./sha_bench_soft bench --trials 10
taskset -c 3 ./sha_bench_accel bench --trials 10
```

**Options:**
- `--trials N` - Number of trials per message size (default: 5)

### Hash Files

```bash
# Hash specific files
./sha_bench_soft image1.jpg image2.jpg image3.jpg
./sha_bench_accel image1.jpg image2.jpg image3.jpg
```

## Benchmark Output Format

The benchmark outputs a table with:
- Algorithm (SHA-1 or SHA-256)
- Message size (1 KiB, 8 KiB, 64 KiB, 1 MiB)
- Average time in milliseconds
- Throughput in MB/s

```
Algorithm    Size         Avg Time (ms)   Throughput (MB/s)
------------------------------------------------------------
SHA-1        1 KiB        0.005           191.34         
SHA-256      1 KiB        0.007           137.94         
SHA-1        8 KiB        0.027           292.01         
SHA-256      8 KiB        0.051           152.44         
...
```

## System Engine Baselines

### Using OpenSSL

```bash
# Test with each size
for size in 1024 8192 65536 1048576; do
  echo "=== Testing with block size: $size ==="
  openssl speed -seconds 3 -bytes $size -evp sha1 sha256
done
```

**Expected OpenSSL performance:**
- SHA-256 @ 1 MiB: ~1,500 MB/s (fastest)

## Expected Results

### Performance Comparison

| Implementation | SHA-256 @ 1 MiB | Notes |
|----------------|-----------------|-------|
| Rust Software | ~200-230 MB/s | Pure software implementation |
| Rust Accelerated | ~780-1,230 MB/s | ARMv8 SHA instructions (3-5× faster) |
| OpenSSL Engine | ~1,500 MB/s | Hand-optimized assembly (best) |

### Speedup Factors

Hardware acceleration typically provides:
- **SHA-1**: 1.9-2.2× speedup
- **SHA-256**: 3.4-3.7× speedup (more rounds benefit more from hardware)

Speedup is more pronounced with larger message sizes (≥64 KiB) due to reduced overhead relative to computation time.

### Why OpenSSL is Faster

OpenSSL achieves 1.8-2.0× better performance than RustCrypto accelerated because:
1. **Hand-optimized assembly** - not just compiler intrinsics
2. **Better instruction scheduling** - optimized for specific CPU pipelines
3. **Kernel-space execution** - reduces context-switching overhead
4. **Years of expert tuning** - by cryptography specialists

## Troubleshooting

### No speedup observed
```bash
# Verify hardware support
grep sha /proc/cpuinfo

# Check binaries are different
ls -lh sha_bench_*
md5sum sha_bench_*

# Ensure not thermal throttling
vcgencmd measure_temp
```

### Inconsistent results
```bash
# Use taskset to pin to one core
taskset -c 3 ./sha_bench_accel bench

# Disable CPU frequency scaling
sudo cpupower frequency-set -g performance

# Run more trials
./sha_bench_accel bench --trials 20
```

### Camera not working
```bash
# List video devices
ls -l /dev/video*

# Check USB devices
lsusb

# Test camera directly
ffmpeg -f v4l2 -i /dev/video0 -frames:v 1 test.jpg -y

# Or use sample images instead
wget -O images/capture_1.jpg "https://picsum.photos/1920/1080"
```

## Dependencies

- Rust 1.70 or later
- `sha1` crate v0.10
- `sha2` crate v0.10
- `clap` v4.5 (CLI argument parsing)
- `hex` v0.4 (digest formatting)

## For the Report

### Data Collection
1. System info: Check `logs/system_info.txt`
2. Benchmark data: Parse throughput from log files
3. Speedup calculation: `speedup = accel_throughput / soft_throughput`

### Plot Creation
Create two plots (SHA-1 and SHA-256), each showing:
- X-axis: Message size (log scale: 1KB, 8KB, 64KB, 1MB)
- Y-axis: Throughput (MB/s)
- Three lines: Rust-soft, Rust-accel, OpenSSL

### Key Analysis Points
1. **Hardware acceleration effectiveness** - Why 3-5× speedup?
2. **SHA-256 vs SHA-1** - Why does SHA-256 benefit more?
3. **OpenSSL gap** - Why is it still 1.8-2× faster?
4. **Small vs large packets** - When does acceleration matter most?

## License

Educational use for ECE 4301 - Crypto on Chip