# Quiz 2 — SHA-1 & SHA-256 on Raspberry Pi 5 (Rust Implementation)
**ECE 4301 — Crypto on Chip**  
**Team:** Omar, Jack, Jesse, Stan  
**Semester:** Fall 2025  

---

## Overview

This assignment focuses on implementing **SHA-1** and **SHA-256** hashing algorithms in **Rust** on a **Raspberry Pi 5**.  
We developed multiple builds, benchmarked them across various message sizes, and analyzed the performance impact of **Armv8 hardware acceleration** available on AArch64.

This repository contains:

- All source code for SHA-1 and SHA-256 implementations  
- Benchmarking utilities  
- A full written report (PDF)  
- Slides and supporting documentation  
## Project Objective

The primary goal was to:

1. Implement SHA-1 and SHA-256 in Rust using RustCrypto crates  
2. Build two versions:
   - **Software-only build** (forces pure software hashing)  
   - **Accelerated build** (enables Armv8 SHA1/SHA2 instructions)  
3. Compare performance against:
   - Kernel crypto engine  
   - OpenSSL EVP engine  
4. Benchmark throughput from **1 KiB → 1 MiB**  
5. Demonstrate real-world hashing using Raspberry Pi camera images  

---

## Method Summary

### **Hardware / Software Setup**
- Raspberry Pi 5 (4 GiB), Cortex-A76 @ ~2.4 GHz  
- Rust toolchain (stable)  
- RustCrypto crates: `sha1 0.10` & `sha2 0.10`  
- Benchmarks pinned to a single CPU core  
- Two Rust feature sets:
  - `soft` → force software hashing  
  - `accel` → enable Armv8 SHA instructions  

### **CLI Modes Implemented**
- **Benchmark mode:**  
  Runs repeated trials over fixed message sizes (1 KiB, 8 KiB, 64 KiB, 1 MiB)
- **File hashing mode:**  
  Computes digest + wall-clock time for image files

---

## Key Results

### **Speedup from Armv8 Acceleration**
- **SHA-1:** ~3× faster with acceleration  
- **SHA-256:** ~5× faster with acceleration  

Acceleration benefits increase with message size and remain stable past 8 KiB.

### **Real-World Demo (Camera Images)**
- Soft SHA-256 on ~1 MiB JPEG: **~6.3 ms**  
- Accel SHA-256 on same file: **~1.3 ms**

This aligns with the large throughput gains.

---

## PDF Report

You can access the complete analysis, tables, figures, and conclusions here:


---

## Conclusion

Enabling **Armv8 SHA instructions** on Raspberry Pi 5 provides substantial performance gains for both SHA-1 and SHA-256.  
Our Rust accelerated build performs within the same range as system engines while maintaining clean, flexible Rust code.  
The results confirm that hardware acceleration is strongly recommended for real-time or large-buffer hashing tasks.
