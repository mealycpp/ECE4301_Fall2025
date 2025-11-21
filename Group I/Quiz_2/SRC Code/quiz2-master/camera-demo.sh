#!/bin/bash
# camera-demo.sh - Capture images and run hash demo

set -e

NUM_IMAGES=5
OUTPUT_DIR="camera_images"

echo "==================================================="
echo "Camera Demo - SHA Hash Comparison"
echo "==================================================="
echo ""

# Create output directory
mkdir -p $OUTPUT_DIR

echo "Step 1: Capturing $NUM_IMAGES images..."

for i in $(seq 1 $NUM_IMAGES); do
    echo "  Capturing image $i/$NUM_IMAGES..."
    
    # Try rpicam-still first, fall back to libcamera-still
    if command -v rpicam-still &> /dev/null; then
        rpicam-still -o $OUTPUT_DIR/image$i.jpg --width 1920 --height 1080 --timeout 1
    elif command -v libcamera-still &> /dev/null; then
        libcamera-still -o $OUTPUT_DIR/image$i.jpg --width 1920 --height 1080 -t 1
    else
        echo "Error: No camera command found. Install rpicam-apps or libcamera-apps"
        exit 1
    fi
    
    sleep 1
done

echo ""
echo "Step 2: Running software-only hash..."
echo "==================================================="
taskset -c 3 ./quiz2-soft hash $OUTPUT_DIR/*.jpg | tee results/demo-soft.txt

echo ""
echo "Step 3: Running accelerated hash..."
echo "==================================================="
taskset -c 3 ./quiz2-accel hash $OUTPUT_DIR/*.jpg | tee results/demo-accel.txt

echo ""
echo "==================================================="
echo "Demo complete!"
echo "==================================================="
echo ""
echo "Images saved in: $OUTPUT_DIR/"
echo "Results saved in: results/demo-*.txt"
echo ""
echo "Compare timing differences:"
echo ""
echo "Software-only times:"
grep -o "[0-9]\+\.[0-9]\+ s" results/demo-soft.txt | head -5
echo ""
echo "Accelerated times:"
grep -o "[0-9]\+\.[0-9]\+ s" results/demo-accel.txt | head -5
