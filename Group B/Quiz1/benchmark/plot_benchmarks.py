# ~/ece4301/benchmarks_aes_only/plot_benchmarks.py
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

base = Path(__file__).resolve().parent
df = pd.read_csv(base / "benchmarks_combined.csv")

requested = ["AES-128","AES-256","SHA256","SHA512"]
present = [a for a in requested if (df["algorithm"] == a).any()]

if not present:
    print("No matching algorithms found in CSV; nothing to plot.")
    raise SystemExit(0)

def plot_one(y_col, y_label, title, outfile, logy=False):
    plt.figure()
    any_points = False
    for algo in present:
        d = df[df["algorithm"] == algo].copy()
        if d.empty:
            continue
        d = d.sort_values("block_size_bytes")
        # Keep only strictly-positive values for log axes
        d = d[(d["block_size_bytes"] > 0) & (d[y_col] > 0)]
        if d.empty:
            continue
        any_points = True
        plt.plot(d["block_size_bytes"], d[y_col], marker="o", label=algo)

    if not any_points:
        print(f"Skipped {outfile}: no positive data to plot.")
        return

    plt.xscale("log")
    if logy:
        plt.yscale("log")

    plt.xlabel("Block size (bytes)")
    plt.ylabel(y_label)
    plt.title(title)
    plt.grid(True, which="both", linestyle="--", alpha=0.5)
    plt.legend()
    plt.tight_layout()
    plt.savefig(base / outfile, dpi=220)
    print(f"Saved {outfile}")

plot_one(
    y_col="throughput_MBps",
    y_label="Throughput (MB/s)",
    title="Throughput vs Block Size (Pi 5, OpenSSL)",
    outfile="throughput_vs_blocksize.png",
    logy=False,
)

plot_one(
    y_col="latency_ns_per_block",
    y_label="Latency (ns per block)",
    title="Latency vs Block Size (Pi 5, OpenSSL)",
    outfile="latency_vs_blocksize.png",
    logy=True,
)
