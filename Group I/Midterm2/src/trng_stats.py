import os
from collections import Counter
import matplotlib.pyplot as plt

N_BYTES = 100000  # 100 kB

#--- Read bytes from TRNG ---
with open("/dev/hwrng", "rb") as f:
    data = f.read(N_BYTES)

#--- Bit frequency check ---
bitstring = ''.join(f'{byte:08b}' for byte in data)
ones = bitstring.count('1')
zeros = bitstring.count('0')
total_bits = len(bitstring)

print(f"Total bits:   {total_bits}")
print(f"Ones:         {ones} ({ones/total_bits:.4f})")
print(f"Zeros:        {zeros} ({zeros/total_bits:.4f})")

#--- Byte histogram ---
counts = Counter(data)

#Show a preview of some values
print("\nExample counts for first few byte values:")
for v in range(10):
    print(f"value {v:3d}: {counts[v]} occurrences")

#--- Create output directory ---
output_dir = "histograms"
os.makedirs(output_dir, exist_ok=True)

#--- Save histogram plot ---
values = list(range(256))
freqs = [counts[v] for v in values]

plt.figure(figsize=(10, 5))
plt.bar(values, freqs)
plt.xlabel("Byte Value (0–255)")
plt.ylabel("Frequency")
plt.title(f"TRNG Byte Histogram ({N_BYTES} bytes)")

output_path = os.path.join(output_dir, "byte_histogram.png")
plt.savefig(output_path, dpi=300, bbox_inches="tight")
plt.close()

print(f"\nHistogram saved to: {output_path}")