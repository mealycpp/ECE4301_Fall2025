#!/bin/bash

# Camera demo script for SHA benchmark
# Captures images and hashes them with both versions

set -e

NUM_IMAGES=5
IMAGE_DIR="images"
DEMO_LOG="demo_output.txt"

echo "=== SHA Benchmark Camera Demo ===" | tee "$DEMO_LOG"
echo "Date: $(date)" | tee -a "$DEMO_LOG"
echo "" | tee -a "$DEMO_LOG"

# Create image directory
mkdir -p "$IMAGE_DIR"

# Check what camera tools are available
if command -v ffmpeg &> /dev/null && [ -e /dev/video0 ]; then
    # USB camera with ffmpeg
    CAM_CMD="ffmpeg"
    CAM_DEVICE="/dev/video0"
    echo "Using USB camera via ffmpeg at $CAM_DEVICE" | tee -a "$DEMO_LOG"
elif command -v rpicam-still &> /dev/null; then
    CAM_CMD="rpicam-still"
    CAM_DEVICE=""
    echo "Using Pi camera via rpicam-still" | tee -a "$DEMO_LOG"
elif command -v libcamera-still &> /dev/null; then
    CAM_CMD="libcamera-still"
    CAM_DEVICE=""
    echo "Using Pi camera via libcamera-still" | tee -a "$DEMO_LOG"
else
    echo "Error: No camera capture tool found!" | tee -a "$DEMO_LOG"
    echo "Install ffmpeg: sudo apt install ffmpeg" | tee -a "$DEMO_LOG"
    exit 1
fi

echo "" | tee -a "$DEMO_LOG"

# Capture images
echo "=== Capturing Images ===" | tee -a "$DEMO_LOG"
for i in $(seq 1 $NUM_IMAGES); do
    echo "Capturing image $i/$NUM_IMAGES..." | tee -a "$DEMO_LOG"
    OUTPUT_FILE="$IMAGE_DIR/capture_$i.jpg"
    
    if [ "$CAM_CMD" = "ffmpeg" ]; then
        ffmpeg -f v4l2 -i $CAM_DEVICE -frames:v 1 -s 1280x720 "$OUTPUT_FILE" -y 2>&1 | tail -3
    else
        # rpicam-still or libcamera-still
        $CAM_CMD -o "$OUTPUT_FILE" --width 1920 --height 1080 -t 1000
    fi
    
    sleep 1
done

echo "" | tee -a "$DEMO_LOG"
echo "Captured images:" | tee -a "$DEMO_LOG"
ls -lh "$IMAGE_DIR"/*.jpg | tee -a "$DEMO_LOG"
echo "" | tee -a "$DEMO_LOG"

# Hash with software version
echo "=== Hashing with Software-Only Version ===" | tee -a "$DEMO_LOG"
echo "" | tee -a "$DEMO_LOG"
time ./sha_bench_soft "$IMAGE_DIR"/*.jpg 2>&1 | tee -a "$DEMO_LOG"
echo "" | tee -a "$DEMO_LOG"

# Wait a moment
sleep 2

# Hash with accelerated version
echo "=== Hashing with Hardware-Accelerated Version ===" | tee -a "$DEMO_LOG"
echo "" | tee -a "$DEMO_LOG"
time ./sha_bench_accel "$IMAGE_DIR"/*.jpg 2>&1 | tee -a "$DEMO_LOG"
echo "" | tee -a "$DEMO_LOG"

echo "=== Demo Complete ===" | tee -a "$DEMO_LOG"
echo "" | tee -a "$DEMO_LOG"
echo "Demo output saved to: $DEMO_LOG"
echo "Images saved in: $IMAGE_DIR/"
echo ""
echo "To verify digests match:"
echo "  grep 'SHA-1:' $DEMO_LOG | sort"
echo "  grep 'SHA-256:' $DEMO_LOG | sort"
echo ""
echo "Performance comparison:"
echo "  Look for 'real' time differences in the output above"