#!/usr/bin/env python3
import sys, pandas as pd, numpy as np, matplotlib.pyplot as plt

df = pd.read_csv(sys.argv[1] if len(sys.argv) > 1 else "data.csv")
tcol = "Transmit Start Time (since epoch as ms)"
df["t"]   = pd.to_datetime(df[tcol], unit="ms")

x = np.sort(df["Latency (ms)"].dropna()); y = np.arange(1, len(x)+1) / len(x)
plt.figure(); plt.plot(x, y); plt.xlabel("Latency (ms)"); plt.ylabel("CDF"); plt.title("Latency CDF"); plt.grid(True)

for col, lab in [("Throughput (bytes per second)", "Throughput (bps)"), ("Frames per Second", "FPS")]:
    plt.figure(); plt.plot(df["t"], df[col]); plt.xlabel("Time"); plt.ylabel(lab); plt.title(f"{lab} vs Time"); plt.grid(True); plt.gcf().autofmt_xdate()

plt.show()

