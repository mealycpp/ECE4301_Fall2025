#!/bin/bash

# Comprehensive benchmark script
# Runs Rust benchmarks (soft + accel) and system engine baselines

set -e

TRIALS=10
CORE=3  # Pin to core 3
LOG_DIR="logs"

echo "=== SHA Benchmark Suite ==="
echo "Date: $(date)"
echo "Trials: $TRIALS"
echo "CPU Core: $CORE"
echo ""

# Create log directory
mkdir -p "$LOG_DIR"

# System info
echo "=== System Information ===" | tee "$LOG_DIR/system_info.txt"
echo "" | tee -a "$LOG_DIR/system_info.txt"
uname -a | tee -a "$LOG_DIR/system_info.txt"
echo "" | tee -a "$LOG_DIR/system_info.txt"
grep "model name\|Features\|CPU architecture" /proc/cpuinfo | tee -a "$LOG_DIR/system_info.txt"
echo "" | tee -a "$LOG_DIR/system_info.txt"
rustc --version | tee -a "$LOG_DIR/system_info.txt"
echo "" | tee -a "$LOG_DIR/system_info.txt"

# Check CPU temperature before starting
if command -v vcgencmd &> /dev/null; then
    echo "Initial CPU temperature:" | tee -a "$LOG_DIR/system_info.txt"
    vcgencmd measure_temp | tee -a "$LOG_DIR/system_info.txt"
    echo "" | tee -a "$LOG_DIR/system_info.txt"
fi

echo "=== Running Rust Software-Only Benchmark ===" 
echo ""
taskset -c $CORE ./sha_bench_soft bench --trials $TRIALS | tee "$LOG_DIR/rust_soft_output.txt"
echo ""
sleep 5  # Let CPU cool down

echo "=== Running Rust Accelerated Benchmark ===" 
echo ""
taskset -c $CORE ./sha_bench_accel bench --trials $TRIALS | tee "$LOG_DIR/rust_accel_output.txt"
echo ""
sleep 5  # Let CPU cool down

# Engine baselines
echo "=== Running System Engine Baselines ==="
echo ""

# Try kcapi-speed first
if command -v kcapi-speed &> /dev/null; then
    echo "Using kcapi-speed..." | tee "$LOG_DIR/engine_baseline.txt"
    echo "" | tee -a "$LOG_DIR/engine_baseline.txt"
    
    for size in 1024 8192 65536 1048576; do
        echo "--- Block size: $size ---" | tee -a "$LOG_DIR/engine_baseline.txt"
        taskset -c $CORE kcapi-speed -b $size sha1-ce sha1 sha256-ce sha256 2>&1 | tee -a "$LOG_DIR/engine_baseline.txt"
        echo "" | tee -a "$LOG_DIR/engine_baseline.txt"
        sleep 2
    done
    
# Fallback to OpenSSL
elif command -v openssl &> /dev/null; then
    echo "Using OpenSSL speed..." | tee "$LOG_DIR/engine_baseline.txt"
    echo "" | tee -a "$LOG_DIR/engine_baseline.txt"
    
    for size in 1024 8192 65536 1048576; do
        echo "--- Block size: $size ---" | tee -a "$LOG_DIR/engine_baseline.txt"
        taskset -c $CORE openssl speed -seconds 3 -bytes $size -evp sha1 sha256 2>&1 | tee -a "$LOG_DIR/engine_baseline.txt"
        echo "" | tee -a "$LOG_DIR/engine_baseline.txt"
        sleep 2
    done
else
    echo "Warning: Neither kcapi-speed nor openssl found!" | tee "$LOG_DIR/engine_baseline.txt"
fi

# Final temperature check
if command -v vcgencmd &> /dev/null; then
    echo ""
    echo "Final CPU temperature:"
    vcgencmd measure_temp
fi

echo ""
echo "=== Benchmark Complete ==="
echo "Results saved in $LOG_DIR/"
echo ""
echo "Files:"
ls -lh "$LOG_DIR/"

echo ""
echo "Next steps:"
echo "  1. Review logs in $LOG_DIR/"
echo "  2. Create plots from the data"
echo "  3. Run camera demo: ./run_camera_demo.sh"