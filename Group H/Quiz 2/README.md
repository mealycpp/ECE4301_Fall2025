# SHA‑1 & SHA‑256 on Raspberry Pi 5 — Rust vs “Engine”

This repo contains a tiny Rust CLI that implements SHA‑1 and SHA‑256 two ways—**software‑only** (`soft`) and **hardware‑accelerated** (`accel`, using Armv8 Crypto Extensions)—and compares both to the platform **Engine** (OpenSSL EVP). It also includes a quick camera demo using a Logitech USB webcam.

Use this README to build, run, benchmark, plot results, and assemble the report artifacts.

---

## Contents
- [What you’ll build & expect](#what-youll-build--expect)
- [Prereqs](#prereqs)
- [Build](#build)
- [CLI usage](#cli-usage)
- [Benchmarking](#benchmarking)
- [Engine baselines (OpenSSL)](#engine-baselines-openssl)
- [Camera demo (Logitech webcam)](#camera-demo-logitech-webcam)
- [Plots & tables](#plots--tables)
- [Interpreting the data](#interpreting-the-data)
- [Reproducibility notes](#reproducibility-notes)
- [Troubleshooting](#troubleshooting)
- [Packaging deliverables](#packaging-deliverables)
- [Repo layout](#repo-layout)

---

## What you’ll build & expect
- Two binaries:
  - `soft` — portable software path (no Arm SHA instructions)
  - `accel` — enables AArch64 assembly backends (Armv8 SHA1/SHA2)
- A benchmark that measures **throughput (MiB/s)** at sizes **1 KiB, 8 KiB, 64 KiB, 1 MiB** over **≥5 trials**, pinned to **one core**.
- Engine baselines via `openssl speed -evp sha1/sha256` at the same sizes.
- A webcam demo that hashes 3–5 JPEGs and prints **SHA‑1**, **SHA‑256**, and **wall‑clock time** per file.

**What to expect:**
- Identical digests between `soft` and `accel` (correctness).
- **Small sizes (1–8 KiB):** limited by overhead → modest gains.
- **Large sizes (≥64 KiB):** **`accel`** clearly outperforms `soft`; Engine may be comparable or slightly faster.

---

## Prereqs
On the Raspberry Pi 5 (AArch64, Debian 12/Bookworm expected):
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev openssl git \
                    fswebcam ffmpeg v4l-utils python3-matplotlib python3-venv python3-pip
# Optional (stabilize clocks):
# sudo apt install -y linux-cpupower
# sudo cpupower frequency-set -g performance

uname -a        # record in report
uname -m        # should be aarch64
rustc -Vv       # record in report
cargo -V
openssl version -a
```

---

## Build
From the repo root:
```bash
# SOFT (software-only)
cargo build --release --bin soft
cp target/release/soft ./soft

# ACCEL (Armv8 SHA asm)
RUSTFLAGS="-C target-cpu=native" cargo build --release --bin accel --features accel
cp target/release/accel ./accel
```
> The `accel` feature enables AArch64 asm backends in `sha1`/`sha2`. `-C target-cpu=native` lets the compiler use the CPU’s crypto features.

Record versions for the report (optional but recommended):
```bash
uname -a            | tee _sys.txt
cat /etc/os-release | tee -a _sys.txt
rustc -Vv           | tee -a _sys.txt
cargo tree -i sha1 -i sha2 | tee _crates.txt
```

---

## CLI usage
**Subcommands:**
- `bench` — synthetic benchmarks on randomized buffers (outputs CSV rows)
- `hash`  — hashes files, printing both digests and wall‑time per file

**Global flags (must come before the subcommand):**
- `--trials N` (default `5`)
- `--out PATH` (CSV output file for `bench`)
- `--sizes` (optional; repeat the flag for each size or rely on defaults)

**Examples:**
```bash
# Benchmarks (defaults to 1KiB,8KiB,64KiB,1MiB) pinned to core 3
taskset -c 3 ./soft  --trials 5 --out rust_soft.csv  bench
taskset -c 3 ./accel --trials 5 --out rust_accel.csv bench

# Hash some files (used in the demo)
./soft  hash demo_imgs/*.jpg
./accel hash demo_imgs/*.jpg
```
**CSV schema (bench):** `algo,build,size_bytes,trial,mib_per_s`

---

## Benchmarking
Run each binary with identical settings and CPU pinning:
```bash
# SOFT
taskset -c 3 ./soft  --trials 5 --out rust_soft.csv  bench
# ACCEL
taskset -c 3 ./accel --trials 5 --out rust_accel.csv bench
```
Why pin to one core? Minimizes scheduling noise and makes soft/accel/engine fair to compare.

---

## Engine baselines (OpenSSL)
Measure the system’s optimized path at the same sizes and save raw logs:
```bash
for B in 1024 8192 65536 1048576; do
  taskset -c 3 openssl speed -elapsed -evp sha1   -bytes $B | tee -a engine_openssl_sha1.txt
  taskset -c 3 openssl speed -elapsed -evp sha256 -bytes $B | tee -a engine_openssl_sha256.txt
done
```
These logs are used to generate the **Engine** curve in plots and must be included in artifacts.

---

## Camera demo (Logitech webcam)
Capture 3–5 stills with `fswebcam` (or `ffmpeg`) and hash them with both builds.
```bash
mkdir -p demo_imgs
# Try 1920x1080; fall back to 1280x720 if needed
for i in 1 2 3 4 5; do
  fswebcam -d /dev/video0 -r 1920x1080 --skip 5 --no-banner "demo_imgs/img${i}.jpg"
  sleep 0.3
done

# Hash and save logs
echo "== Soft =="   | tee demo_soft_files.txt
taskset -c 3 ./soft  hash demo_imgs/*.jpg | tee -a demo_soft_files.txt

echo "== Accel =="  | tee demo_accel_files.txt
taskset -c 3 ./accel hash demo_imgs/*.jpg | tee -a demo_accel_files.txt
```
What to expect: identical digests across builds; `accel` should have noticeably lower wall time on at least one image.

---

## Plots & tables
This repo includes `parse_engine.py`, which reads the two Rust CSVs and the two OpenSSL logs to produce tables and figures.

At the top of the script, ensure headless plotting:
```python
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
```
Run:
```bash
python3 parse_engine.py
```
**Outputs:**
- `engine.csv` — Engine throughput per size (MiB/s)
- `agg.csv` — Means of Rust‑soft, Rust‑accel, Engine per algo+size
- `speedups.csv` — Accel/Soft ratios per algo+size
- `plot_sha1.png`, `plot_sha256.png` — figures for the report (Page 2)

---

## Interpreting the data
- **Throughput (MiB/s):** `bytes / seconds / 2^20`. Higher is better.
- **Small sizes (1–8 KiB):** latency‑dominated; gains can be modest.
- **Large sizes (≥64 KiB):** acceleration shines; expect clear uplift vs software.
- **Engine vs Rust‑accel:** Engine may be slightly faster due to hand‑tuned asm and micro‑optimizations; sometimes they tie.
- **Speedups:** Use `speedups.csv` to quote `accel/soft` ratios (per size, per algorithm) in the report.

**Recommendation framing for the report:**
- **Small‑packet telemetry:** choose the simpler path unless accel shows a consistent, material uplift on your device.
- **Large‑buffer or bulk hashing:** prefer **`accel`**; consider Engine if it’s consistently higher and an external dependency is acceptable.

---

## Reproducibility notes
Include in your report’s Page 1:
- OS/Kernel (`/etc/os-release`, `uname -a`)
- Rust toolchain and crate versions (`rustc -Vv`, `cargo tree -i sha1 -i sha2`)
- Build flags (`soft` vs `accel`), CPU pinning (`taskset -c 3`)
- Benchmark sizes and trials, metric (MiB/s mean)
- Engine command and versions (`openssl version -a`)

---

## Troubleshooting
- **anyhow missing:** add `anyhow = "1"` under `[dependencies]` in `Cargo.toml`.
- **Flags after subcommand not recognized:** put global flags **before** `bench`/`hash`.
- **`--sizes` multi‑value:** repeat the flag (e.g., `--sizes 1024 --sizes 8192 …`) or just use defaults.
- **Matplotlib headless:** ensure `python3-matplotlib` is installed and `matplotlib.use("Agg")` is set.
- **CSV header duplicated:** re‑run `parse_engine.py` (it skips stray headers) or strip repeats with `awk`.
- **Webcam permissions:** `sudo usermod -aG video "$USER"` (relog) or run capture with `sudo`.

---

## Packaging deliverables
Create `artifacts.zip` containing code, data, logs, and plots:
```bash
mkdir -p out
cp -r src Cargo.toml \
      rust_soft.csv rust_accel.csv engine.csv agg.csv speedups.csv \
      engine_openssl_sha1.txt engine_openssl_sha256.txt \
      plot_sha1.png plot_sha256.png \
      demo_soft_files.txt demo_accel_files.txt \
      _sys.txt _crates.txt README.md out/
zip -r artifacts.zip out
```
Also export your **≤3‑page PDF report** and commit both to your course GitHub group folder.

---

## Repo layout
```
.
├── Cargo.toml
├── src/
│   └── main.rs              # CLI (bench + hash)
├── soft / accel             # built binaries (created after build)
├── rust_soft.csv            # bench results (soft)
├── rust_accel.csv           # bench results (accel)
├── engine_openssl_sha1.txt  # raw OpenSSL logs
├── engine_openssl_sha256.txt
├── parse_engine.py          # makes engine.csv, agg.csv, speedups.csv, plots
├── plot_sha1.png
├── plot_sha256.png
├── demo_imgs/               # webcam images
├── demo_soft_files.txt
├── demo_accel_files.txt
├── _sys.txt                 # system info for report
├── _crates.txt              # crate versions/tree for report
└── README.md
```

That’s it—build, run, plot, interpret, and package. Happy hashing!

