# AES Demo — Raspberry Pi 5 Crypto Engine vs CPU

This folder contains the demo materials and source code used for **ECE 4301 – Quiz #1**  
to benchmark AES-128 encryption performance on the Raspberry Pi 5 hardware crypto engine  
versus a standard CPU software implementation.

---

## 📂 Contents
| File | Description |
|------|--------------|
| `AES Demo on Hardware (Pi 5 crypto Engine) vs Software (CPU).pptx` | Slides summarizing system overview, benchmark setup, and results (~21.6× hardware speed-up). |
| `main_hw.rs` | Rust source using the Pi 5 **hardware AES engine** via ARMv8 crypto intrinsics. |
| `main_cpu.rs` | Rust source using the **software (CPU-only)** AES implementation. |
| `hw_out.txt`, `hw_perf.txt` | Output and performance logs for the hardware AES run. |
| `cpu_out.txt`, `cpu_perf.txt` | Output and performance logs for the CPU AES run. |

---

## 🧰 Prerequisites (on Raspberry Pi 5)

Before running, ensure your Pi 5 is set up with Rust and required tools:

```bash
sudo apt update
sudo apt install clang perf
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
rustup toolchain install nightly

Instructions For Runninf Haedware AES Demo (main_hw.rs) 

cargo new aes_hw_demo
cd aes_hw_demo

cp /path/to/demo/main_hw.rs src/main.rs

RUSTFLAGS="-C target-cpu=cortex-a76 -C target-feature=+neon,+crypto" cargo +nightly build --release
./target/release/aes_hw_demo

perf stat ./target/release/aes_hw_demo > hw_perf.txt 2>&1

Instructions For Running CPU AES Demo (main_cpu.rs)

cargo new aes_cpu_demo
cd aes_cpu_demo

cp /path/to/demo/main_cpu.rs src/main.rs

cargo +nightly build --release
./target/release/aes_cpu_demo

perf stat ./target/release/aes_cpu_demo > cpu_perf.txt 2>&1


Notes

The hardware version uses ARMv8 NEON + AES intrinsics available on Pi 5.

The CPU version executes equivalent AES rounds purely in software.

For full reproducibility, use Raspberry Pi OS Bookworm 64-bit or newer.

Output logs (*_out.txt, *_perf.txt) can be compared for timing and CPU utilization.
