#!/usr/bin/env python3

import matplotlib.pyplot as plt

HWRNG_DEVICE = "/dev/hwrng"

def get_random_bytes(n: int) -> bytes:
    with open(HWRNG_DEVICE, "rb") as f:
        return f.read(n)

def main():
    N_BYTES = 10000
    data = get_random_bytes(N_BYTES)
    vals = list(data)

    plt.hist(vals, bins=256, range=(0, 255), density=True)
    plt.title("Histogram of TRNG Byte Values")
    plt.xlabel("Byte value (0–255)")
    plt.ylabel("Relative frequency")

    plt.tight_layout()
    plt.savefig("histogram_trng_bytes.png")
    plt.show()

if __name__ == "__main__":
    main()
