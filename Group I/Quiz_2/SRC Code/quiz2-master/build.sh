#!/bin/bash
# build.sh - Build both soft and accel versions

set -e

echo "Building SHA benchmarking binaries..."
echo ""

# Build accelerated version (default, with AArch64 instructions)
echo "[1/2] Building accelerated version..."
cargo build --release
cp target/release/quiz2 quiz2-accel
echo "      ✓ quiz2-accel created"
echo ""

# Build software-only version (force-soft feature)
echo "[2/2] Building software-only version..."
cargo build --release --features force-soft
cp target/release/quiz2 quiz2-soft
echo "      ✓ quiz2-soft created"
echo ""

echo "Build complete!"
echo ""
echo "Binaries:"
echo "  quiz2-soft  - Software-only (no AArch64 acceleration)"
echo "  quiz2-accel - Accelerated (uses AArch64 SHA instructions)"
echo ""
echo "Next steps:"
echo "  ./run-benchmarks.sh  - Run benchmarks"
echo "  ./camera-demo.sh     - Camera demo"
