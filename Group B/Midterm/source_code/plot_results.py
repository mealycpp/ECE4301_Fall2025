#!/usr/bin/env python3
"""
Compare ECDH vs RSA video encryption metrics.

Usage:
    python3 plot_results.py
"""

import os
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# --- Paths ---
ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

ecdh_path = RESULTS_DIR / "steady_ecdh.csv"
rsa_path = RESULTS_DIR / "steady_rsa.csv"

# --- Load CSVs ---
def load_csv(path):
    df = pd.read_csv(path)  # your CSV already has headers

    # --- Handle timestamp parsing ---
    def parse_time(val):
        try:
            s = str(val).strip()
            if s.endswith("Z"):
                s = s[:-1]  # remove Z suffix
            t = float(s)
            if t > 1e12:  # nanoseconds → seconds
                t /= 1e9
            return pd.to_datetime(t, unit="s", utc=True)
        except Exception:
            return pd.NaT

    # detect 'ts' or 'timestamp' column name
    ts_col = "ts" if "ts" in df.columns else "timestamp"
    df["timestamp"] = df[ts_col].apply(parse_time)

    # only receiver data
    df = df[df["role"] == "receiver"].copy()

    # --- Ensure numeric types for all key metrics ---
    numeric_cols = [
        "fps",
        "goodput_mbps",
        "latency_ms_p50",
        "latency_ms_p95",
        "cpu_pct",
        "mem_mb",
        "temp_c",
        "drops",
        "tag_fail",
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


print("📊 Loading CSV files...")
ecdh = load_csv(ecdh_path)
rsa = load_csv(rsa_path)
print(f"ECDH samples: {len(ecdh)}, RSA samples: {len(rsa)}")

# --- Plot helper ---
def plot_metric(metric, ylabel, title, filename):
    plt.figure(figsize=(8, 4))
    plt.plot(ecdh["timestamp"], ecdh[metric], label="ECDH", linewidth=2)
    plt.plot(rsa["timestamp"], rsa[metric], label="RSA", linewidth=2, linestyle="--")
    plt.title(title)
    plt.xlabel("Time")
    plt.ylabel(ylabel)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    outfile = RESULTS_DIR / filename
    plt.savefig(outfile, dpi=150)
    plt.close()
    print(f"✅ Saved {outfile.name}")

# --- Generate plots ---
plot_metric("fps", "Frames per Second", "FPS Over Time", "fps_comparison.png")
plot_metric("goodput_mbps", "Goodput (Mb/s)", "Throughput Comparison", "throughput_comparison.png")
plot_metric("latency_ms_p50", "Latency p50 (ms)", "Median Latency Comparison", "latency_p50.png")
plot_metric("latency_ms_p95", "Latency p95 (ms)", "Tail Latency Comparison", "latency_p95.png")
plot_metric("cpu_pct", "CPU (%)", "CPU Usage Comparison", "cpu_comparison.png")
plot_metric("temp_c", "Temperature (°C)", "Temperature Comparison", "temp_comparison.png")

# --- Summary table ---
summary = pd.DataFrame({
    "metric": ["fps", "goodput_mbps", "latency_ms_p50", "latency_ms_p95", "cpu_pct", "temp_c"],
    "ECDH_mean": [ecdh[m].mean() for m in ["fps", "goodput_mbps", "latency_ms_p50", "latency_ms_p95", "cpu_pct", "temp_c"]],
    "RSA_mean": [rsa[m].mean() for m in ["fps", "goodput_mbps", "latency_ms_p50", "latency_ms_p95", "cpu_pct", "temp_c"]],
})

summary["RSA_vs_ECDH_ratio"] = summary["RSA_mean"] / summary["ECDH_mean"]
summary_file = RESULTS_DIR / "summary.csv"
summary.to_csv(summary_file, index=False)
print(f"✅ Summary saved to {summary_file.name}")

print("\n🎯 Done! All plots and summary saved to:")
print(f"   {RESULTS_DIR}")

