#!/bin/bash
set -e

echo "=========================================="
echo "Raspberry Pi 5 Secure Streaming Setup"
echo "=========================================="
echo

# Check if running on RPi
if [ ! -f /proc/device-tree/model ]; then
    echo "Warning: Not running on Raspberry Pi"
else
    MODEL=$(tr -d '\0' < /proc/device-tree/model)
    echo "Detected: $MODEL"
    if [[ ! "$MODEL" =~ "Raspberry Pi 5" ]]; then
        echo "Warning: This project is optimized for Raspberry Pi 5"
    fi
fi
echo

# Update system
echo "==> Updating system packages..."
sudo apt update
sudo apt upgrade -y

# Install dependencies
echo "==> Installing system dependencies..."
sudo apt install -y \
    clang \
    pkg-config \
    libssl-dev \
    gstreamer1.0-tools \
    gstreamer1.0-libav \
    gstreamer1.0-plugins-base \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-ugly \
    gstreamer1.0-gl \
    libgstreamer1.0-dev \
    libgstreamer-plugins-base1.0-dev \
    python3-pip \
    python3-matplotlib \
    python3-pandas \
    python3-numpy

# Install Rust if not present
if ! command -v rustc &> /dev/null; then
    echo "==> Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "==> Rust already installed: $(rustc --version)"
fi

# Ensure stable toolchain
rustup default stable
rustup update

# Verify CPU features
echo
echo "==> Checking CPU features..."
if grep -q "aes" /proc/cpuinfo && grep -q "pmull" /proc/cpuinfo; then
    echo "✓ ARMv8 Crypto Extensions detected (aes, pmull)"
else
    echo "✗ Warning: Crypto extensions not found in /proc/cpuinfo"
fi

# Set CPU governor to performance
echo
echo "==> Setting CPU governor to performance mode..."
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null
echo "✓ CPU governor set to performance"

# Enable camera (if applicable)
echo
echo "==> Configuring camera..."
if ! grep -q "^camera_auto_detect=1" /boot/firmware/config.txt; then
    echo "camera_auto_detect=1" | sudo tee -a /boot/firmware/config.txt > /dev/null
    echo "✓ Camera auto-detect enabled (reboot required)"
else
    echo "✓ Camera already configured"
fi

# Build workspace
echo
echo "==> Building workspace..."
cd "$(dirname "$0")"

# Create directory structure
mkdir -p crates/{crypto,metrics,stream,bench,group}/src
mkdir -p data plots scripts

# Build all binaries
echo "==> Compiling with hardware acceleration enabled..."
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Run feature detection
echo
echo "==> Testing hardware acceleration..."
./target/release/bench || echo "Benchmark not built yet"

# Set executable permissions
chmod +x scripts/*.py 2>/dev/null || true

echo
echo "=========================================="
echo "Setup complete!"
echo "=========================================="
echo
echo "Next steps:"
echo "1. Run './target/release/stream --print-config' to verify setup"
echo "2. Run './target/release/bench' to benchmark AES-GCM performance"
echo "3. See README.md for usage instructions"
echo
echo "For two-node streaming:"
echo "  Receiver: ./target/release/stream --mode receiver --mechanism ecdh"
echo "  Sender:   ./target/release/stream --mode sender --mechanism ecdh --host <receiver-ip>"
echo