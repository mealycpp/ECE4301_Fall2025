# ECE4301 Midterm – Secure Video Streaming (RSA vs ECDH + AES)


## Abstract

This repository implements a **secure, real-time video streaming system** for the Raspberry Pi 5 using **Rust** and **GStreamer**.  
Two asymmetric key exchange algorithms — **RSA (2048-bit)** and **ECDH (P-256)** — are compared for establishing AES symmetric keys.  

The design integrates system telemetry (CPU, memory, temperature, power) and produces a full experimental dataset for throughput, latency, and efficiency analysis.

---

## 1. Environment Setup

### Dependencies

```bash
sudo apt update
sudo apt install -y   clang pkg-config libssl-dev git python3-pip   gstreamer1.0-tools gstreamer1.0-libav   gstreamer1.0-plugins-base gstreamer1.0-plugins-good   gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly   gstreamer1.0-gl gstreamer1.0-x   libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev   libclang-dev
```

Install Rust toolchain:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup default stable
```

---

## 2. Project Structure

```
midterm/
├── app/
│   └── src/bin/
│       ├── sender_rsa.rs
│       ├── receiver_rsa.rs
│       ├── sender_ecdh.rs
│       └── receiver_ecdh.rs
├── keying/
├── metrics/
├── results/
│   ├── steady_rsa.csv
│   ├── steady_ecdh.csv
│   ├── handshake_rsa.csv
│   ├── handshake_ecdh.csv
│   ├── summary.csv
│   └── plots/*.png
├── plot_results.py
├── bench_aesgcm.rs
├── setup_midterm.sh
└── README.md
```

---

## 3. Build the Project

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

---

## 4. Running the Streaming System

### RSA Mode

**Receiver:**
```bash
./target/release/receiver_rsa --listen 0.0.0.0:7000
```

**Sender:**
```bash
./target/release/sender_rsa --dest <RECEIVER_IP>:7000
```

### ECDH Mode

**Receiver:**
```bash
./target/release/receiver_ecdh --listen 0.0.0.0:7000
```

**Sender:**
```bash
./target/release/sender_ecdh --dest <RECEIVER_IP>:7000
```

### AES-GCM Throughput Benchmark

```bash
./target/release/bench_aesgcm
```

---

## 5. Result Generation

After each run, logs are stored in `results/`.

```bash
python3 plot_results.py
```

Generates:
- `fps_comparison.png`
- `throughput_comparison.png`
- `latency_p50.png`
- `latency_p95.png`
- `cpu_comparison.png`
- `temp_comparison.png`
- `summary.csv`

---

## 6. Power and Thermal Monitoring

Example values:

| Mode | Voltage (V) | Current (A) | Power (W) |
|:--|:--:|:--:|:--:|
| RSA | 5.02 | 0.81 | **4.06 W** |
| ECDH | 5.02 | 0.59 | **2.96 W** |

---

## 7. Network Diagram

```
        ┌───────────────────────┐
        │       Sender Pi       │
        │ (RSA/ECDH Handshake + │
        │ AES-GCM Encryption)   │
        └────────────┬──────────┘
                     │  TCP Stream
                     ▼
        ┌───────────────────────┐
        │      Receiver Pi      │
        │ (Decrypt + Display)   │
        └───────────────────────┘
                     ▲
                     │ INA219 / Wattmeter
                     └──────────────────────
```

---

## 8. Crypto Stack Summary

| Layer | Algorithm | Key Size | Purpose |
|:--|:--|:--:|:--|
| Asymmetric | RSA / ECDH | 2048 b / P-256 | Session key negotiation |
| Symmetric | AES | 128-bit | Real-time encryption |
| Derivation | HKDF-SHA256 | – | AES key from shared secret |
| Integrity | GCM Tag | 16 bytes | Authenticated decryption |

---

## 9. Example Metrics

| Metric | RSA Mean | ECDH Mean | Δ (%) |
|:--|:--:|:--:|:--:|
| FPS | 8.5 | **13.2** | +55 |
| Goodput (Mb/s) | 1.21 | **1.86** | +54 |
| Latency p50 (ms) | 4.9 | **1.1** | −77 |
| Latency p95 (ms) | 13.8 | **6.1** | −56 |
| CPU (%) | 11.7 | **9.2** | −21 |
| Temp (°C) | 69.8 | **65.1** | −6.7 |

---

## 10. Troubleshooting

| Issue | Fix |
|:--|:--|
| **Connection refused** | Run receiver first |
| **Permission denied** | Use ports >1024 |
| **No video** | Install `gstreamer1.0-libav` |
| **High CPU** | Build with `--release` |

---



