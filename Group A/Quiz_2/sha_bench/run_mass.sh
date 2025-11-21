#!/usr/bin/env bash
set -euo pipefail

# Where your images live (adjust if needed)
IMAGES=(images/andy1.jpg images/bed5.jpg images/green5.jpg images/img1.jpg)

# Output folder
mkdir -p output_pipe
: > output_pipe/soft.txt
: > output_pipe/accel.txt

echo "=== Building SOFT (no asm) ==="
cargo build --release --no-default-features --features soft --bin soft

echo "=== Building ACCEL (asm enabled) ==="
# Compile with CPU features enabled so the ARMv8 crypto extensions get used
RUSTFLAGS="-C target-cpu=native" cargo build --release --no-default-features --features accel --bin accel

echo "=== Running SOFT on images ==="
for img in "${IMAGES[@]}"; do
  echo "---- soft $img ----" | tee -a output_pipe/soft.txt
  taskset -c 3 cargo run --release --no-default-features --features soft --bin soft -- "$img" >> output_pipe/soft.txt
done

echo "=== Running ACCEL on images ==="
for img in "${IMAGES[@]}"; do
  echo "---- accel $img ----" | tee -a output_pipe/accel.txt
  # Important: keep the same CPU pinning; pass RUSTFLAGS at run-time too
  RUSTFLAGS="-C target-cpu=native" taskset -c 3 cargo run --release --no-default-features --features accel --bin accel -- "$img" >> output_pipe/accel.txt
done

echo "All done. Results in output_pipe/soft.txt and output_pipe/accel.txt"
