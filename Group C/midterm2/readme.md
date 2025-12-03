# Raspberry Pi TRNG Midterm Project - Setup Guide

## Overview
This project demonstrates the Raspberry Pi's hardware True Random Number Generator (TRNG) with comprehensive testing and visualization.

## Files Included
* `rpi_trng_demo.py` - Python implementation with visualization
* `trng_test.c` - C implementation for direct hardware access


## Prerequisites

### Install Python Dependencies
```bash
sudo apt-get update
sudo apt-get install python3-pip python3-numpy python3-matplotlib
pip3 install numpy matplotlib --break-system-packages
```

### Install Build Tools (for C version)
```bash
sudo apt-get install build-essential
```

## Running the Python Demo

### Method 1: Full Test Suite with Visualization
```bash
sudo python3 rpi_trng_demo.py
```

This will:
- Run 6 comprehensive tests on the hardware RNG
- Generate statistical analysis
- Create visualization plots saved as `trng_analysis.png`
- Show all results in the terminal

### Method 2: Quick Test
```bash
# Just check basic output
sudo cat /dev/hwrng | hexdump -C | head

# Read some random numbers
sudo python3 -c "
import os
with open('/dev/hwrng', 'rb') as f:
    data = f.read(16)
    print('Random bytes:', data.hex())
"
```

## Running the C Demo

### Compile
```bash
gcc -o trng_test trng_test.c -lm
```

### Run
```bash
sudo ./trng_test
```

This will run 5 statistical tests in C and display results.

## Understanding the Output

### Tests Performed

1. **Basic Output Test**
   - Shows raw hex bytes and integers from the RNG
   - Confirms device is accessible and producing output

2. **Distribution Test (Chi-Square)**
   - Tests if byte values are uniformly distributed (0-255)
   - Chi-square < 293.25 indicates good uniform distribution

3. **Entropy Test**
   - Calculates Shannon entropy (ideal = 8.0 bits/byte)
   - Values > 7.9 indicate high-quality randomness

4. **Correlation Test**
   - Checks if consecutive bytes are independent
   - Low correlation (~0.0) is desired

5. **NIST Monobit Test**
   - Tests balance of 0s and 1s in bit stream
   - P-value > 0.01 indicates good balance

6. **Performance Benchmark**
   - Measures throughput of the hardware RNG

### Visualization Output

The Python script generates `trng_analysis.png` with 4 plots:

1. **Distribution Histogram** - Shows frequency of each byte value
2. **Visual Randomness** - 16x16 grayscale image of random data
3. **Bit Pattern** - Black/white visualization of individual bits
4. **Correlation Plot** - Scatter plot showing independence of consecutive bytes

## Additional Resources

- Raspberry Pi Hardware Documentation: https://datasheets.raspberrypi.com/
- NIST Statistical Test Suite: https://csrc.nist.gov/projects/random-bit-generation/
- Linux /dev/random Documentation: https://man7.org/linux/man-pages/man4/random.4.html

## Quick Reference Commands

```bash
# Check RNG device exists
ls -l /dev/hwrng

# Quick random hex dump
sudo dd if=/dev/hwrng bs=16 count=1 2>/dev/null | hexdump -C

# Monitor RNG statistics
cat /proc/sys/kernel/random/entropy_avail

# Benchmark RNG speed
sudo dd if=/dev/hwrng of=/dev/null bs=1M count=10 status=progress
```