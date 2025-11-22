#!/usr/bin/env python3
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import csv
from collections import defaultdict, OrderedDict

def mean(xs): return sum(xs)/len(xs) if xs else float('nan')

def read_rust_csv(path):
    rows=[]
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                rows.append({
                    "algo": row["algo"].strip(),
                    "build": row["build"].strip(),
                    "size": int(row["size_bytes"]),
                    "mibps": float(row["mib_per_s"]),
                })
            except Exception:
                # skip duplicate headers or malformed rows
                continue
    return rows

def read_engine_csv(path):
    eng = defaultdict(dict)  # eng[algo][size]=mibps
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                algo = row["algo"].strip()
                size = int(row["size_bytes"])
                mib  = float(row["mib_per_s"])
                eng[algo][size] = mib
            except Exception:
                continue
    return eng

def agg(rows, algo, build):
    buckets=defaultdict(list)
    for r in rows:
        if r["algo"]==algo and r["build"]==build:
            buckets[r["size"]].append(r["mibps"])
    xs=sorted(buckets)
    return OrderedDict((x, mean(buckets[x])) for x in xs)

def plot_algo(name, soft_map, accel_map, eng_map, out_png):
    xs = sorted(set(soft_map.keys()) | set(accel_map.keys()) | set(eng_map.keys()))
    ys_s = [soft_map.get(x, float("nan"))  for x in xs]
    ys_a = [accel_map.get(x, float("nan")) for x in xs]
    ys_e = [eng_map.get(x, float("nan"))   for x in xs]

    plt.figure()
    plt.title(f"{name.upper()} throughput vs size")
    plt.xlabel("Size (bytes, log2)")
    plt.ylabel("MiB/s")
    plt.xscale("log", base=2)
    plt.plot(xs, ys_s, marker="o", label="Rust-soft")
    plt.plot(xs, ys_a, marker="o", label="Rust-accel")
    plt.plot(xs, ys_e, marker="o", label="Engine")
    plt.grid(True, which="both", linewidth=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)

# --- main ---
soft = read_rust_csv("rust_soft.csv")
acc  = read_rust_csv("rust_accel.csv")
eng  = read_engine_csv("engine.csv")

soft_sha1   = agg(soft, "sha1", "soft")
accel_sha1  = agg(acc,  "sha1", "accel")
soft_sha256  = agg(soft, "sha256", "soft")
accel_sha256 = agg(acc,  "sha256", "accel")

plot_algo("sha1",   soft_sha1,  accel_sha1,  eng.get("sha1", {}),   "plot_sha1.png")
plot_algo("sha256", soft_sha256, accel_sha256, eng.get("sha256", {}), "plot_sha256.png")

print("Wrote plot_sha1.png and plot_sha256.png")
