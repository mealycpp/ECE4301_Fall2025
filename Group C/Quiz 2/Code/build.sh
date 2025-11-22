#!/bin/bash

# Build script for SHA benchmark tool
# Creates both software-only and hardware-accelerated versions

set -e  # Exit on error

echo "=== Building SHA Benchmark Tool ==="
echo ""

# Check if on Raspberry Pi
if [ ! -f /proc/cpuinfo ]; then
    echo "Warning: Cannot detect CPU info"
else
    echo "CPU Features:"
    grep "Features" /proc/cpuinfo | head -1
    echo ""
fi

# Clean previous builds
echo "Cleaning previous builds..."
cargo clean

echo ""
echo "=== Building Software-Only Version ==="
echo "Disabling hardware acceleration features..."

# Build without asm feature (pure software implementation)
cargo build --release --no-default-features --features std

# Copy to specific name (use Quiz2 binary name)
cp target/release/Quiz2 sha_bench_soft
echo "Created: sha_bench_soft"

echo ""
echo "=== Building Hardware-Accelerated Version ==="
echo "Enabling native CPU features..."

# Clean to force rebuild
cargo clean

# Build with all features including asm + native CPU target
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Copy to specific name (use Quiz2 binary name)
cp target/release/Quiz2 sha_bench_accel
echo "Created: sha_bench_accel"

echo ""
echo "=== Build Complete ==="
echo ""

# Show binary sizes
ls -lh sha_bench_soft sha_bench_accel

echo ""
echo "=== Verification ==="

# Try to verify the builds are different
if command -v readelf &> /dev/null; then
    echo ""
    echo "Checking for ARM architecture features in binaries:"
    echo ""
    echo "Software-only version:"
    readelf -A sha_bench_soft | grep -i "tag" || echo "  No special tags"
    echo ""
    echo "Accelerated version:"
    readelf -A sha_bench_accel | grep -i "tag" || echo "  No special tags"
fi

echo ""
echo "Build complete! Next steps:"
echo "  1. Run benchmarks: taskset -c 3 ./sha_bench_soft bench"
echo "  2. Run benchmarks: taskset -c 3 ./sha_bench_accel bench"
echo "  3. Hash files: ./sha_bench_soft image1.jpg image2.jpg"