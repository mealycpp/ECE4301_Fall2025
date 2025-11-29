# ECE 4301 Midterm 2  
## True Random Number Generator (TRNG) on Raspberry Pi 5 Crypto Engine

This project implements and demonstrates a True Random Number Generator using the Raspberry Pi 5 hardware crypto engine.

The goal is to obtain hardware-backed random bytes from the Raspberry Pi 5’s cryptographic subsystem, analyze them, and confirm that the TRNG is functioning correctly.

---

## Overview
The Raspberry Pi 5 includes a hardware TRNG integrated into the SoC. The Linux kernel exposes this entropy through:
- **`getrandom()`**
- Rust's **`rand::rngs::OsRng`**
- **`/dev/hwrng`**

This project implements a simple Rust program that collects random bytes from these interfaces and performs statistical checks to demonstrate correct TRNG behavior.

## Requirements
**Hardware:**
- Raspberry Pi 5
- Raspberry Pi OS
- Rust toolchain
- Python 3 + **`matplotlib`**

**Software Libraries:**
- Rust: **`rand = "0.8"`**
- Python: **`matplotlib`**

## How to Build
Run the following on the Raspberry Pi 5:
**`cargo build --release`**
This compiles the TRNG demo with optimizations enabled.

## How to Run the TRNG Demo
To generate 4096 bytes of entropy:
**`cargo run --release --bin trng_demo > trng_output.hex`**

## Statistical Analysis
Run the Python script to validate the TRNG output:
**`python3 analyze_trng.py`**
