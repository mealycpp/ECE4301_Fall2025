import matplotlib.pyplot as plt

data = []

# 1) Read hex bytes from the file
with open("trng_output.hex") as f:
    for line in f:
        line = line.strip()
        for i in range(0, len(line), 2):
            chunk = line[i:i+2]
            if len(chunk) == 2:
                try:
                    data.append(int(chunk, 16))
                except ValueError:
                    pass

n = len(data)
print(f"Bytes: {n}")

# 2) Mean of the byte values
mean = sum(data) / n
print(f"Mean: {mean:.2f}")

# 3) Bit frequency (count zeros and ones)
bits = []
for b in data:
    for k in range(8):
        bits.append((b >> k) & 1)

zeros = bits.count(0)
ones = bits.count(1)
bias = (ones - zeros) / len(bits)
print(f"Zeros: {zeros}, Ones: {ones}, Bias: {bias:.4f}")

# 4) Histogram over byte values
plt.hist(data, bins=16)
plt.title("Raspberry Pi 5 TRNG Byte Histogram")
plt.xlabel("Byte value")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("trng_hist.png")
print("Saved histogram to trng_hist.png")
