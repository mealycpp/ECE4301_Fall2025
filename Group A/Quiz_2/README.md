# SHA-1 & SHA-256 on Raspberry Pi 5 — Rust (soft vs accel)

Tiny benchmarking CLI that compares **software-only** vs **ARMv8-accelerated** SHA hashing on a Raspberry Pi 5.  
Two Rust binaries are built from the same code path but with **different Cargo features**:

- `soft` → **software only** (no asm)
- `accel` → **AArch64 SHA1/SHA2 assembly enabled**

The repo also includes a batch script to run both binaries on the same set of images and log results.

---

## Project layout

```
sha_bench/
├─ Cargo.toml            # feature matrix: soft vs accel (asm)
├─ run_mass.sh           # batch build + run script (pins to one core)
├─ src/
│  ├─ lib.rs             # shared logic: run_random_bench(), hash_files()
│  └─ bin/
│     ├─ soft.rs         # software-only binary
│     └─ accel.rs        # accelerated binary
├─ images/               # input images (captured separately)
└─ output_pipe/          # output logs (created by run_mass.sh)
```

### Key files

- **`Cargo.toml`**
  - Defines features:
    - `soft` (no asm)
    - `accel = ["sha1/asm", "sha2/asm"]`
  - Binaries:
    - `soft` requires feature `soft`
    - `accel` requires feature `accel`

- **`src/lib.rs`**
  - `run_random_bench()`: random buffers at 1 KiB, 8 KiB, 64 KiB, 1 MiB; prints CSV (`algo,size_bytes,trial,mbps`)
  - `hash_files(&[String])`: loads each file, computes SHA-1 and SHA-256, prints wall-clock seconds per file

- **`src/bin/soft.rs`**
  - CLI entrypoint (software path). If args given → hashes files; otherwise runs the random-buffer benchmark.

- **`src/bin/accel.rs`**
  - CLI entrypoint (accelerated path). Same behavior as `soft`, but compiled with ARM asm enabled.

- **`run_mass.sh`**
  - Builds both binaries (with the correct features)
  - Pins each run to a single core (`taskset -c 3`)
  - Uses `RUSTFLAGS="-C target-cpu=native"` for the **accelerated** build/run
  - Runs both binaries over the same images and appends results into `output_pipe/soft.txt` and `output_pipe/accel.txt`

---

## Prerequisites

- Raspberry Pi 5 (AArch64 / 64-bit OS)
- Rust toolchain (`rustup`, `cargo`)
- (Recommended) Images captured beforehand (USB cam: `fswebcam`)

Check that the CPU exposes SHA extensions:
```bash
grep -i features /proc/cpuinfo
# Expect to see: sha1 sha2
```

---

## Build matrix (manual)

Build **software-only** binary:
```bash
cargo build --release --no-default-features --features soft --bin soft
```

Build **accelerated** binary (AArch64 asm + CPU features):
```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release --no-default-features --features accel --bin accel
```

> `-C target-cpu=native` lets LLVM emit/allow the ARMv8 crypto extensions on the Pi.

---

## Running manually

Hash images (software):
```bash
taskset -c 3 cargo run --release --no-default-features --features soft --bin soft -- images/img1.jpg images/img2.jpg
```

Hash images (accelerated):
```bash
RUSTFLAGS="-C target-cpu=native" taskset -c 3 cargo run --release --no-default-features --features accel --bin accel -- images/img1.jpg images/img2.jpg
```

Run the random-buffer benchmark:
```bash
# software
taskset -c 3 cargo run --release --no-default-features --features soft --bin soft

# accelerated
RUSTFLAGS="-C target-cpu=native" taskset -c 3 cargo run --release --no-default-features --features accel --bin accel
```

---

## `run_mass.sh` explained

**What it does (high level):**
1. Builds `soft` and `accel` with the **correct** feature flags.
2. Pins execution to CPU core **3** (“pin to one core”).
3. Runs both binaries over a fixed list of images.
4. Appends results to `output_pipe/soft.txt` and `output_pipe/accel.txt`.

**Run the script:**
```bash
chmod +x run_mass.sh
./run_mass.sh
```

---

## Capturing images

**USB webcam** (`/dev/video0`) 

- `fswebcam` :
  ```bash
  sudo apt-get install -y fswebcam
  mkdir -p images
  for i in 1 2 3 4 5; do
    fswebcam -d /dev/video0 -r 1280x720 --no-banner "images/img$i.jpg"
    sleep 0.5
  done
  ```

---

## Engine baselines
OpenSSL EVP:
```bash
openssl speed -evp sha1
openssl speed -evp sha256
```

Try to use the same sizes as the Rust benchmark (1 KiB, 8 KiB, 64 KiB, 1 MiB) and save console output for your report.


## Repro commands (quick)

```bash
# Software only
cargo run --release --no-default-features --features soft --bin soft -- images/img*.jpg

# Accelerated
RUSTFLAGS="-C target-cpu=native" cargo run --release --no-default-features --features accel --bin accel -- images/img*.jpg
```

---

## License

For course use. See assignment guidelines for sharing restrictions.
