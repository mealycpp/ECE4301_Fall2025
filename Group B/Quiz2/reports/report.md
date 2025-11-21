# SHA‑1 & SHA‑256 Benchmark on Raspberry Pi 5

## 1. Overview

This report summarizes benchmarking of SHA‑1 and SHA‑256 hashing on a
Raspberry Pi 5 using three implementations:

-   **Rust‑soft**: pure software hashing\
-   **Rust‑accel**: using Armv8 SHA1/SHA2 hardware instructions\
-   **Engine**: OpenSSL EVP engine (system‑level implementation)

The goal is to compare throughput across message sizes (1 KiB, 8 KiB, 64
KiB, 1 MiB) and evaluate acceleration benefits.

------------------------------------------------------------------------

## 2. Methodology

-   **Device:** Raspberry Pi 5 (Arm Cortex‑A76)\
-   **OS:** Raspberry Pi OS 64‑bit\
-   **Rust crates:** `sha1`, `sha2` (RustCrypto)\
-   **Builds:**
    -   *Soft:* no asm features\
    -   *Accel:* `--features accel` with
        `RUSTFLAGS="-C target-cpu=native -C target-feature=+sha1,+sha2"`\
-   **CPU Affinity:** All measurements pinned using `taskset -c 3`.\
-   **Engine Baseline:** `openssl speed -evp sha1/sha256`\
-   **Camera Demo:** 5 captured images hashed with both binaries.

------------------------------------------------------------------------

## 3. Results

### SHA‑1 Throughput vs Size

![SHA1 Throughput](sha1_throughput.png)

### SHA‑256 Throughput vs Size

![SHA256 Throughput](sha256_throughput.png)

------------------------------------------------------------------------

## 4. Analysis

-   **Acceleration Impact:**\
    Rust‑accel shows **4--6× improvement** over Rust‑soft for large
    buffers and \~3--5× for small buffers.\
-   **Engine Performance:**\
    The engine remains the fastest implementation, approaching
    **1.45--1.53 GB/s**, limited mostly by memory bandwidth.\
-   **Small‑Packet vs Large‑Buffer Tradeoff:**
    -   For **small packets (\<8 KiB)**: Rust‑accel is ideal---low
        overhead with strong speedups.\
    -   For **large continuous streams (\>64 KiB)**: the engine achieves
        peak sustained throughput.\
-   **Why Armv8 SHA Helps:**\
    The Pi 5's Cortex‑A76 supports hardware SHA‑1/SHA‑2 instructions,
    reducing instruction count and improving ILP, giving large
    throughput gains over software bitwise operations.

------------------------------------------------------------------------

## 5. Conclusion

Accelerated Rust hashing significantly outperforms the software-only
version and approaches engine‑level performance at larger buffer sizes.
For real‑world embedded telemetry:\
- Use **Rust‑accel** for small frequent messages.\
- Use **Engine** for bulk hashing or high‑bandwidth streaming workloads.

------------------------------------------------------------------------

## Appendix

-   Raw CSVs: `rust_soft.csv`, `rust_accel.csv`, `engine.csv`\
-   Camera demo outputs: `demo_soft.txt`, `demo_accel.txt`
