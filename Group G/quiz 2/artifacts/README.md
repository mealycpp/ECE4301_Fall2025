# Quiz 2 – SHA-1 & SHA-256 on Raspberry Pi 5

Rust CLI + scripts to benchmark SHA-1 and SHA-256 on a Raspberry Pi 5 and compare:

1. **Rust-soft**   – software-only SHA (Armv8 SHA1/SHA2 disabled)
2. **Rust-accel**  – Rust with Armv8 SHA1/SHA2 enabled
3. **Engine**      – platform crypto engine (kcapi-speed / OpenSSL)

All results (logs, CSVs, plots, images) live in the `out/` and `demo_imgs/` directories.

---

## 1. Build commands (soft / accel)

Run all commands from the repo root:

### To build and run soft
\cd ~/quiz-2/sha-cli\
cargo build --release\
./target/release/sha-cli sha1 soft\
./target/release/sha-cli sha256 soft

### To build and run accel
cd ~/quiz-2/sha-cli\
RUSTFLAGS="-C target-feature=+crypto" cargo build --release

### CRYPTO ENGINE SCRIPT
cd ~/quiz-2/scripts\
python3 make_engine_csv.py

#### BENCHMARK SCRIPT (bench.sh)
cd ~/quiz-2/scripts\
./bench.sh

### Camera Demo
cd ~/quiz-2/scripts\
./capture_and_hash.sh
