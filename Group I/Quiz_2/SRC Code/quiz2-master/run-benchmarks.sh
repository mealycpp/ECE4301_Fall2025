#!/bin/bash
# run-benchmarks.sh - Run all benchmarks and collect data

set -e

TRIALS=5
CPU_CORE=3

echo "==================================================="
echo "SHA-1 & SHA-256 Benchmark Suite"
echo "==================================================="
echo ""

# Create results directory
mkdir -p results

echo "Step 1: Building binaries..."
./build.sh
echo ""

echo "Step 2: Running Rust benchmarks..."

# Software-only benchmarks
echo "  Running software-only benchmarks..."
taskset -c $CPU_CORE ./quiz2-soft bench --trials $TRIALS | tee results/rust-soft-bench.txt

echo ""

# Accelerated benchmarks
echo "  Running accelerated benchmarks..."
taskset -c $CPU_CORE ./quiz2-accel bench --trials $TRIALS | tee results/rust-accel-bench.txt

echo ""
echo "Step 3: Running OpenSSL engine benchmarks..."

# OpenSSL benchmarks
echo "  SHA-1..."
openssl speed -evp sha1 2>&1 | tee results/openssl-sha1.txt

echo "  SHA-256..."
openssl speed -evp sha256 2>&1 | tee results/openssl-sha256.txt

echo ""
echo "Step 4: Checking for kcapi-speed (optional)..."
if command -v kcapi-speed &> /dev/null; then
    echo "  Found kcapi-speed, running tests..."
    kcapi-speed -c sha1 1024 8192 65536 1048576 2>&1 | tee results/kcapi-sha1.txt || true
    kcapi-speed -c sha256 1024 8192 65536 1048576 2>&1 | tee results/kcapi-sha256.txt || true
else
    echo "  kcapi-speed not found (optional). Install with: sudo apt-get install libkcapi-tools"
fi

echo ""
echo "==================================================="
echo "Benchmarks complete! Results saved in results/"
echo "==================================================="
echo ""
echo "Files created:"
ls -lh results/
