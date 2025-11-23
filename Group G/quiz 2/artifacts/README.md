# Quiz 2 – SHA-1 & SHA-256 on Raspberry Pi 5

Rust CLI + scripts to benchmark SHA-1 and SHA-256 on a Raspberry Pi 5 and compare:

1. **Rust-soft**   – software-only SHA (Armv8 SHA1/SHA2 disabled)
2. **Rust-accel**  – Rust with Armv8 SHA1/SHA2 enabled
3. **Engine**      – platform crypto engine (kcapi-speed / OpenSSL)

All results (logs, CSVs, plots, images) live in the `out/` and `demo_imgs/` directories.

---

## 1. Build commands (soft / accel)

Run all commands from the repo root:

```bash
cd ~/quiz-2
cargo build --release --bin soft  --features soft
cargo build --release --bin accel --features accel

