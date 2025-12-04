import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("histogram.csv")

plt.bar(df["value"], df["count"])
plt.xlabel("Byte value (0–255)")
plt.ylabel("Frequency")
plt.title("TRNG Byte Histogram")
plt.tight_layout()
plt.savefig("trng_histogram.png", dpi=300)
plt.show()
