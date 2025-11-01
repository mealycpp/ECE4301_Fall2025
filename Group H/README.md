Members

- Caleb Jala-Guinto
- Isabel Warth
- Manuel Alvarado

This repository contains two SHA-256 benchmarking programs designed to evaluate cryptographic performance on the Raspberry Pi 5:

SHAonPi5usingCrypto.txt → benchmarks SHA-256 via OpenSSL EVP or custom ARM intrinsics.

SHAonPi5usingISA.txt → benchmarks SHA-256 via Linux AF_ALG interface, which uses kernel-level ISA acceleration (if available).

Both scripts report:

Execution time

Throughput (MB/s)

Latency (per message or per chunk)

CPU scheduling statistics (context switches, user/system time)
File 1: SHAonPi5usingCrypto.txt
🔧 Description

This program benchmarks SHA-256 hashing using:

OpenSSL EVP interface (default)

Optional custom external implementation using ARMv8 SHA ISA intrinsics

It measures latency, throughput, and per-thread performance under CPU pinning.

🏗️ Build

Save the file as sha_bench.c and compile:

File 2: SHAonPi5usingISA.txt
🔧 Description

This program uses Linux’s AF_ALG interface to access hardware-accelerated hashing (via kernel crypto API).
It measures per-chunk latency, total throughput, and context switches to show CPU–kernel cooperation.

🏗️ Build

Save the file as sha_afalg_bench.c and compile:
