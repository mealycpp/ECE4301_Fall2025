# Pi 5 SHA-1 & SHA-256 Benchmark — Rust (Soft vs Accel) & Engine Baselines

This project benchmarks SHA-1 and SHA-256 performance on a **Raspberry Pi 5** using:

- **Rust (soft)** – software-only hashing using RustCrypto digests  
- **Rust (accel)** – AArch64 hardware-accelerated SHA1/SHA2 using RustCrypto `asm` backend  
- **Engine** – Linux kernel crypto API (`kcapi-speed`) **or** OpenSSL EVP (`openssl speed -evp`)  

It also provides a CLI to hash real files (used for the Pi camera image demo).

This repository is designed to match the requirements for **ECE 4301 — Crypto on Chip (Quiz #2)**.

---

# Project Structure

pi5-sha-bench/
├─ Cargo.toml
├─ src/
│ └─ main.rs
├─ scripts/
│ └─ plot.py
├─ data/ # auto-generated during benchmarking
│ ├─ rust_soft.csv
│ ├─ rust_accel.csv
│ ├─ engine.csv
│ ├─ engine_kcapi.raw
│ ├─ engine_openssl.raw
│ ├─ demo_soft.txt
│ └─ demo_accel.txt
└─ report/
├─ sha1_throughput.png
├─ sha256_throughput.png
└─ report.md

---

# Environment

Tested on:

- **Raspberry Pi 5** (Cortex-A76, Armv8.2-A)  
- **Raspberry Pi OS Bookworm 64-bit**
- Kernel version (add yours):


Required packages:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev libkcapi-tools openssl python3-pip
