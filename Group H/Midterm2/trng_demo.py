#!/usr/bin/env python3

import struct

HWRNG_DEVICE = "/dev/hwrng"

def get_random_bytes(n):
    with open(HWRNG_DEVICE, "rb") as f:
        return f.read(n)

def get_random_uint32():
    # 4 bytes -> 32-bit unsigned int
    data = get_random_bytes(4)
    return struct.unpack("I", data)[0]

def main():
    print("Reading 10 random 32-bit integers from /dev/hwrng:")
    for i in range(10):
        r = get_random_uint32()
        print(f"{i}: {r}")

if __name__ == "__main__":
    main()
