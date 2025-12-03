#!/usr/bin/env python3
import csv
import matplotlib
matplotlib.use("Agg")  # no GUI needed
import matplotlib.pyplot as plt

values = []
counts = []

with open("trng_rust/histogram.csv", "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        values.append(int(row["value"]))
        counts.append(int(row["count"]))

plt.figure()
plt.bar(values, counts)
plt.xlabel("Byte value (0–255)")
plt.ylabel("Count")
plt.title("TRNG Byte Histogram (Rust, /dev/hwrng)")
plt.tight_layout()
plt.savefig("trng_histogram_rust.png")
print("Saved trng_histogram_rust.png in", __file__.rsplit("/", 1)[0] or ".")
