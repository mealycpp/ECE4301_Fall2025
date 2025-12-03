#!/usr/bin/env bash

echo "--- Demonstration for Quiz 2 ---"
echo "A hexdump of 256 bytes of data from the TRNG:"
head -c 256 /dev/hwrng | hexdump


echo "Producing a 1 MB file ('hwrng.out') of random data from the TRNG..."
head -c 1000000 /dev/hwrng >hwrng.out

