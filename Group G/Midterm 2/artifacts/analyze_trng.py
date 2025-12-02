import numpy as np
import matplotlib.pyplot as plt

# Load hex values
data = np.loadtxt("trng_output.txt", dtype=str)
nums = np.array([int(x,16) for x in data], dtype=np.uint32)

# Convert 32-bit numbers → bits
bits = np.unpackbits(nums.view(np.uint8))

# Histogram of bits
plt.hist(bits, bins=2)
plt.title("Bit Distribution (0/1)")
plt.savefig("bit_hist.png")
plt.close()

# Histogram of bytes
bytes_arr = nums.view(np.uint8)
plt.hist(bytes_arr, bins=256)
plt.title("Byte Distribution (0-255)")
plt.savefig("byte_hist.png")
plt.close()

# Print statistics
print("Mean:", np.mean(bits))
print("Variance:", np.var(bits))
