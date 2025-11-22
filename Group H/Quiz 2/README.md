# SHA‑1 & SHA‑256 on Raspberry Pi 5 — Demo & User Guide

A compact guide to: **(1)** run a successful live demo with a Logitech USB webcam, **(2)** benchmark Rust `soft` vs `accel` builds, **(3)** generate Engine baselines and plots, and **(4)** use this program as a day‑to‑day file hasher.

---

## What this project is
- Two Rust binaries:  
  - **`soft`** — software‑only SHA‑1/SHA‑256 (portable path; no ARM SHA instructions)  
  - **`accel`** — same algorithms with **Armv8 Crypto Extensions** enabled (AArch64 asm backends)  
- A CLI with two subcommands:  
  - **`bench`** → synthetic throughput benchmarks (MiB/s) on randomized buffers  
  - **`hash`** → hashes real files, printing SHA‑1, SHA‑256, and wall‑clock time
- Engine baseline measured via `openssl speed` and converted to `engine.csv` for plotting.

**Why it matters:** hardware SHA instructions reduce cycles/byte. Expect modest gains on tiny inputs (latency‑bound) and bigger gains on ≥64 KiB buffers. Engine often ties or slightly beats accel thanks to hand‑tuned asm.

---

## 0) TL;DR Demo Script (≤3 min)
1. **Goal (10 s):** “We compare Rust `soft` vs `accel` vs Engine for SHA‑1/SHA‑256 on a Pi 5.”  
2. **Capture (30–45 s):** Take 3–5 webcam stills into `demo_imgs/`.  
3. **Hash (45 s):** `soft hash` then `accel hash` on the same images; point at one clear wall‑time gap.  
4. **Plots (40 s):** Show `plot_sha1.png`, `plot_sha256.png` (three curves: soft/accel/engine).  
5. **Takeaway (15 s):** “Acceleration helps, especially for larger buffers; Engine is comparable. Recommendation differs for small vs large payloads.”

---

## 1) Prerequisites (Pi 5 / Debian 12)
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev openssl git \
                    fswebcam ffmpeg v4l-utils python3-matplotlib python3-venv python3-pip
# Rust toolchain (if cargo not found)
sudo apt install -y curl
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env" && echo 'source "$HOME/.cargo/env"' >> ~/.bashrc
# Optional for repeatability:
# sudo apt install -y linux-cpupower && sudo cpupower frequency-set -g performance
```

**Sanity:** `cargo -V`, `rustc -Vv`, `openssl version -a`, `uname -m` (should be `aarch64`).

---

## 2) Build
From the project root:
```bash
# SOFT (software-only)
cargo build --release --bin soft
cp target/release/soft ./soft

# ACCEL (Armv8 SHA asm)
RUSTFLAGS="-C target-cpu=native" cargo build --release --bin accel --features accel
cp target/release/accel ./accel
```
> `accel` enables AArch64 asm in `sha1`/`sha2` and lets the compiler target your CPU features.

Record versions for the report (optional but recommended):
```bash
uname -a            | tee _sys.txt
cat /etc/os-release | tee -a _sys.txt
rustc -Vv           | tee -a _sys.txt
cargo tree -i sha1 -i sha2 | tee _crates.txt
```

---

## 3) CLI Usage
Subcommands:
- `bench` — synthetic throughput benchmarks (CSV rows)
- `hash` — hashes files (prints SHA‑1, SHA‑256, wall‑time)

**Global flags (must be before the subcommand):**
- `--trials N` (default 5)
- `--out PATH` (CSV path for `bench`)
- `--sizes` (optional; repeat the flag per value, or use defaults 1KiB,8KiB,64KiB,1MiB)

**Examples:**
```bash
# Benchmarks pinned to one core for fairness
taskset -c 3 ./soft  --trials 5 --out rust_soft.csv  bench
taskset -c 3 ./accel --trials 5 --out rust_accel.csv bench

# Hash real files (used in demo)
./soft  hash demo_imgs/*.jpg
./accel hash demo_imgs/*.jpg
```
CSV schema: `algo,build,size_bytes,trial,mib_per_s`.

---

## 4) Engine Baselines (robust, no‑parse path)
Use this provided script to build `engine.csv` directly from `openssl speed` output (no regex parsing headaches):
```bash
./engine_csv.sh
sed -n '1,10p' engine.csv   # should show sha1/sha256 rows for 4 sizes each
```
> If `./engine_csv.sh` isn’t executable: `chmod +x engine_csv.sh`.

**What it does:** runs EVP for sha1/sha256 at 1KiB, 8KiB, 64KiB, 1MiB, extracts the `…k` value (decimal kB/s), converts to MiB/s, and writes `engine.csv`.

---

## 5) Plots & Tables
Two options; both end at the same figures:

**A) Direct from CSVs (recommended now):**
```bash
python3 plot_from_csvs.py
ls -lh plot_sha1.png plot_sha256.png
```
**B) Original parser route:** `python3 parse_engine.py` (ensure it’s patched for OpenSSL 3.x and headless `matplotlib.use("Agg")`).

**Outputs:**
- `plot_sha1.png`, `plot_sha256.png` — three curves each (Rust‑soft, Rust‑accel, Engine)
- `engine.csv`, `agg.csv`, `speedups.csv`

---

## 6) Webcam Capture for Demo (Logitech USB)
Either **fswebcam** (simplest) or **ffmpeg**.
```bash
# Create demo_imgs and capture 5 stills
mkdir -p demo_imgs
for i in 1 2 3 4 5; do
  fswebcam -d /dev/video0 -r 1920x1080 --skip 5 --no-banner "demo_imgs/img${i}.jpg"
  sleep 0.3
done
# If fswebcam fails, try ffmpeg:
# for i in 1 2 3 4 5; do
#   ffmpeg -y -f v4l2 -input_format mjpeg -video_size 1920x1080 -i /dev/video0 -frames:v 1 "demo_imgs/img${i}.jpg"; sleep 0.3; done

# Hash those images and save logs
echo "== Soft =="   | tee demo_soft_files.txt
taskset -c 3 ./soft  hash demo_imgs/*.jpg | tee -a demo_soft_files.txt

echo "== Accel =="  | tee demo_accel_files.txt
taskset -c 3 ./accel hash demo_imgs/*.jpg | tee -a demo_accel_files.txt
```
> If you see “permission denied” when capturing: `sudo usermod -aG video "$USER"` and log out/in (or use `sudo` for the capture step).

**What to point out during demo:** identical digests across builds; one image with noticeably lower `wall` time on `accel`.

---

## 7) Interpreting Results (what to expect)
- **Correctness:** digests must match across `soft`/`accel` and standard tools (`sha1sum`, `sha256sum`).
- **Small sizes (1–8 KiB):** latency/call overhead dominates → modest gains.
- **Large sizes (≥64 KiB):** throughput approaches peak; `accel` shows clear uplift vs `soft`.
- **Engine:** often comparable or slightly faster than `accel` at large sizes due to hand‑tuned asm.
- **Speedups:** see `speedups.csv` for `accel/soft` ratios per size and algorithm.

**Recommendation framing:**
- **Small‑packet telemetry:** prefer the simplest path unless acceleration shows material, consistent gains.
- **Large buffers / bulk hashing:** prefer `accel`; consider Engine if it’s consistently higher and acceptable as a dependency.

---

## 8) Everyday Usage (as a file hasher)
You can use these binaries outside the lab for fast file hashing.
```bash
# Hash any files; prints SHA-1, SHA-256, and wall time
./accel hash ~/Downloads/*.iso
# or portable build
./soft  hash ~/data/*.bin
```
To integrate in scripts, capture just the digests:
```bash
./accel hash somefile | awk -F'= ' '/^SHA256/ {print $2}'
```

---

## 9) Troubleshooting
- **`cargo: command not found`** → Install rustup and `source "$HOME/.cargo/env"` (see Prereqs). Avoid `sudo cargo …`.
- **Flags after subcommand ignored** → Put global flags **before** `bench`/`hash`.
- **`--sizes` multiple values** → Repeat the flag (`--sizes 1024 --sizes 8192 …`) or use defaults.
- **Engine curve missing** → Use `./engine_csv.sh` to rebuild `engine.csv`, then `python3 plot_from_csvs.py`.
- **Matplotlib needs display** → Ensure `python3-matplotlib` is installed and `matplotlib.use("Agg")` is at top of plotting scripts.
- **Webcam access** → Add user to `video` group or run capture with `sudo`.

---

## 10) Packaging Deliverables
```bash
mkdir -p out
cp -r src Cargo.toml \
      rust_soft.csv rust_accel.csv engine.csv agg.csv speedups.csv \
      plot_sha1.png plot_sha256.png \
      demo_soft_files.txt demo_accel_files.txt \
      _sys.txt _crates.txt README.md out/
zip -r artifacts.zip out
```
Include your ≤3‑page report PDF in the course GitHub group folder.

---

## 11) Repo Layout (expected)
```
.
├── Cargo.toml
├── src/
│   └── main.rs
├── soft / accel                # binaries after build
├── rust_soft.csv               # bench results (soft)
├── rust_accel.csv              # bench results (accel)
├── engine_csv.sh               # builds engine.csv from openssl speed
├── engine.csv                  # engine throughput (MiB/s)
├── plot_from_csvs.py           # plots from three CSVs
├── parse_engine.py             # (alt) logs→plots pipeline
├── plot_sha1.png
├── plot_sha256.png
├── demo_imgs/
├── demo_soft_files.txt
├── demo_accel_files.txt
├── _sys.txt
├── _crates.txt
└── README.md
```

**You’re demo‑ready.** Build soft/accel, capture 3–5 stills, run both hashers, show the two plots, and close with a small‑vs‑large recommendation.

