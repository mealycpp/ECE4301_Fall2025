# SHA-1 & SHA-256 Benchmarking on Raspberry Pi 5
### ECE 4301 — Crypto on Chip — Quiz #2

## Overview
This project benchmarks SHA-1 and SHA-256 performance on a Raspberry Pi 5 using:
- **Rust (software-only)**
- **Rust (accelerated with Armv8 SHA1/SHA2 instructions)**
- **OpenSSL EVP engine**

It includes benchmarking randomized buffers, camera image hashing, throughput plots, and a three-page report.

---

## Project Structure
```
pi5-sha-bench/
├── Cargo.toml
├── src/
│   └── main.rs
├── scripts/
│   └── plot.py
├── data/
│   ├── rust_soft.csv
│   ├── rust_accel.csv
│   ├── engine.csv
│   ├── demo_soft.txt
│   ├── demo_accel.txt
├── report/
│   ├── report.md
│   ├── report.pdf
│   ├── sha1_throughput.png
│   └── sha256_throughput.png
└── artifacts.zip
```

---

## Build Instructions

### 1. Install Dependencies
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev openssl python3-pip
pip3 install matplotlib
```

---

### 2. Build Software-Only (soft)
```bash
cargo build --release
cp target/release/pi5-sha-bench target/release/pi5-sha-bench-soft
```

---

### 3. Build Accelerated Version (accel)
```bash
RUSTFLAGS='-C target-cpu=native -C target-feature=+sha1,+sha2'     cargo build --release --features accel

cp target/release/pi5-sha-bench target/release/pi5-sha-bench-accel
```

---

## Benchmarking

### Rust — Software-Only
```bash
sudo taskset -c 3 ./target/release/pi5-sha-bench-soft benchmark     --algorithm both     --out data/rust_soft.csv
```

### Rust — Accelerated
```bash
sudo taskset -c 3 ./target/release/pi5-sha-bench-accel benchmark     --algorithm both     --out data/rust_accel.csv
```

---

## Engine Baseline (OpenSSL)
```bash
mkdir -p data

for ALG in sha1 sha256; do
  for SZ in 1024 8192 65536 1048576; do
    openssl speed -evp $ALG -bytes $SZ | tee -a data/engine_openssl.raw
  done
done
```

Then convert the raw file to:
```
data/engine.csv
```

---

## Camera Demo

### Capture Images
```bash
mkdir -p imgs
rpicam-still -o imgs/img_1.jpg -n
rpicam-still -o imgs/img_2.jpg -n
rpicam-still -o imgs/img_3.jpg -n
rpicam-still -o imgs/img_4.jpg -n
rpicam-still -o imgs/img_5.jpg -n
```

### Hash Using Soft Version
```bash
sudo taskset -c 3 ./target/release/pi5-sha-bench-soft hash-files     --algorithm both imgs/*.jpg | tee data/demo_soft.txt
```

### Hash Using Accelerated Version
```bash
sudo taskset -c 3 ./target/release/pi5-sha-bench-accel hash-files     --algorithm both imgs/*.jpg | tee data/demo_accel.txt
```

---

## Plot Generation
```bash
python3 scripts/plot.py   --rust-soft data/rust_soft.csv   --rust-accel data/rust_accel.csv   --engine data/engine.csv   --out-dir report
```

This generates:
- `sha1_throughput.png`
- `sha256_throughput.png`

---

## Notes
- The demo video must be ≤ 3 minutes.
- All raw logs, CSV files, report, and plots are included in the repo.
