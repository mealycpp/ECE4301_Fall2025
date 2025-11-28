#!/usr/bin/env python3

import struct
import math

HWRNG_DEVICE = "/dev/hwrng"

def get_random_bytes(n: int) -> bytes:
    with open(HWRNG_DEVICE, "rb") as f:
        return f.read(n)

def bytes_to_bits(data: bytes):
    bits = []
    for b in data:
        for i in range(8):
            bits.append((b >> i) & 1)
    return bits

def monobit_test(bits):
    ones = sum(bits)
    zeros = len(bits) - ones
    return zeros, ones

def main():
    N_BYTES = 4096  # 4096 bytes = 32,768 bits
    data = get_random_bytes(N_BYTES)
    bits = bytes_to_bits(data)

    zeros, ones = monobit_test(bits)
    total = len(bits)
    p_zero = zeros / total
    p_one = ones / total

    print(f"Total bits: {total}")
    print(f"Zeros: {zeros}, Ones: {ones}")
    print(f"P(0) ≈ {p_zero:.4f}, P(1) ≈ {p_one:.4f}")

if __name__ == "__main__":
    main()
