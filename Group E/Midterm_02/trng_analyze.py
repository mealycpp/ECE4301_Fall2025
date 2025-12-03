#!/usr/bin/env python3
import numpy as np

BYTES_TO_READ = 100000  # 100 KB

def main():
    print(f"Reading {BYTES_TO_READ} bytes from /dev/hwrng ...")
    with open("/dev/hwrng", "rb") as f:
        data = f.read(BYTES_TO_READ)

    print(f"Actually read {len(data)} bytes")

    # Convert to NumPy array of uint8
    arr = np.frombuffer(data, dtype=np.uint8)

    # Basic stats
    mean = arr.mean()
    std = arr.std()
    print(f"Mean byte value: {mean:.2f} (expected ~127.5)")
    print(f"Std dev of bytes: {std:.2f}")

    # Byte histogram and entropy
    hist, _ = np.histogram(arr, bins=256, range=(0, 256))
    probs = hist / hist.sum()

    import math
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    print(f"Shannon entropy per byte: {entropy:.4f} bits (max is 8.0)")

    # Bit-level balance
    bits = np.unpackbits(arr)
    ones = int(bits.sum())
    zeros = int(bits.size - ones)
    frac_ones = ones / bits.size
    print(f"Bit count: zeros={zeros}, ones={ones}, ones fraction={frac_ones:.4f}")

    # Save histogram plot
    import matplotlib
    matplotlib.use("Agg")  # non-GUI backend
    import matplotlib.pyplot as plt

    plt.figure()
    plt.bar(range(256), hist)
    plt.xlabel("Byte value (0–255)")
    plt.ylabel("Count")
    plt.title("TRNG Byte Histogram")
    plt.tight_layout()
    plt.savefig("trng_histogram.png")
    print("Saved histogram as trng_histogram.png in current directory")

if __name__ == "__main__":
    main()
