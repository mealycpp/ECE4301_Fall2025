#!/usr/bin/env python3
import re, csv, math, sys
from collections import defaultdict, OrderedDict
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---------- helpers ----------
def mean(xs): return sum(xs)/len(xs) if xs else float('nan')

def read_rust_csv(path):
    rows = []
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                size = int(row["size_bytes"])
                mibps = float(row["mib_per_s"])
            except (KeyError, ValueError, TypeError):
                # Skip duplicate header lines or malformed rows
                continue
            rows.append({
                "algo": row.get("algo", "").strip(),
                "build": row.get("build", "").strip(),
                "size": size,
                "mibps": mibps,
            })
    return rows

# OpenSSL `speed` parsing (best-effort across versions):
# We expect a "Doing ... on <size> bytes" line followed (or later) by a
# throughput line with a "<number>k" token (k = *1000* bytes/sec in OpenSSL output).
# We'll map the last seen <size> to the next seen speed.
doing_re  = re.compile(r"(?:Doing .* on (\d+)\s+(?:bytes|size blocks))|(?:---- bytes=(\d+) ----)", re.I)
speedk_re = re.compile(r"\bevp\b[^\n]*?([\d.]+)\s*k\b", re.I)
bps_re    = re.compile(r"bytes per second:\s*([\d.]+)", re.I)

def parse_engine_txt(path):
    size_for_next = None
    results = []  # (size_bytes, mib_per_s)
    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = doing_re.search(line)
            if m:
                size_for_next = int(m.group(1) or m.group(2))
                continue
            # Prefer the 'evp ... k' line
            m = speedk_re.search(line)
            if m and size_for_next:
                kbps = float(m.group(1)) * 1000.0   # 'k' means *1000* bytes/s in OpenSSL
                mibps = kbps / (1024.0*1024.0)
                results.append((size_for_next, mibps))
                size_for_next = None
                continue
            # Fallback 'bytes per second: NNN' format (rare)
            m = bps_re.search(line)
            if m and size_for_next:
                bps = float(m.group(1))
                mibps = bps / (1024.0*1024.0)
                results.append((size_for_next, mibps))
                size_for_next = None
                continue
    # Keep the last measurement per size
    last = {}
    for sz, v in results:
        last[sz] = v
    return last

# ---------- load data ----------
soft = read_rust_csv("rust_soft.csv")
acc  = read_rust_csv("rust_accel.csv")

eng_sha1   = parse_engine_txt("engine_openssl_sha1.txt")
eng_sha256 = parse_engine_txt("engine_openssl_sha256.txt")

# Write engine.csv
with open("engine.csv","w",newline="") as f:
    w = csv.writer(f)
    w.writerow(["algo","size_bytes","mib_per_s"])
    for sz,v in sorted(eng_sha1.items()):
        w.writerow(["sha1", sz, f"{v:.6f}"])
    for sz,v in sorted(eng_sha256.items()):
        w.writerow(["sha256", sz, f"{v:.6f}"])

# Aggregate Rust means
def agg(rows, algo, build):
    buckets=defaultdict(list)
    for r in rows:
        if r["algo"]==algo and r["build"]==build:
            buckets[r["size"]].append(r["mibps"])
    xs=sorted(buckets)
    return OrderedDict((x, mean(buckets[x])) for x in xs)

agg_soft_sha1   = agg(soft, "sha1", "soft")
agg_accel_sha1  = agg(acc,  "sha1", "accel")
agg_soft_sha256  = agg(soft, "sha256", "soft")
agg_accel_sha256 = agg(acc,  "sha256", "accel")

# Combine to a single CSV (agg.csv)
sizes = sorted(set(list(agg_soft_sha1.keys())+list(agg_accel_sha1.keys())+
                   list(eng_sha1.keys())))
with open("agg.csv","w",newline="") as f:
    w = csv.writer(f); w.writerow(
        ["algo","size_bytes","rust_soft_mibps","rust_accel_mibps","engine_mibps"])
    for algo, s_soft, s_acc, s_eng in [
        ("sha1", agg_soft_sha1,  agg_accel_sha1,  eng_sha1),
        ("sha256", agg_soft_sha256, agg_accel_sha256, eng_sha256)
    ]:
        for sz in sorted(set(list(s_soft.keys())+list(s_acc.keys())+list(s_eng.keys()))):
            w.writerow([
                algo, sz,
                f"{s_soft.get(sz, float('nan')):.6f}" if sz in s_soft else "",
                f"{s_acc.get(sz, float('nan')):.6f}"  if sz in s_acc else "",
                f"{s_eng.get(sz, float('nan')):.6f}"  if sz in s_eng else "",
            ])

# Speedup table (accel/soft)
with open("speedups.csv","w",newline="") as f:
    w = csv.writer(f); w.writerow(["algo","size_bytes","accel_over_soft"])
    for algo, s_soft, s_acc in [
        ("sha1", agg_soft_sha1, agg_accel_sha1),
        ("sha256", agg_soft_sha256, agg_accel_sha256)
    ]:
        for sz in sorted(set(s_soft.keys()) & set(s_acc.keys())):
            spd = s_acc[sz] / s_soft[sz] if s_soft[sz] else float('nan')
            w.writerow([algo, sz, f"{spd:.3f}"])

# ---------- plots ----------
def plot_algo(name, soft_map, accel_map, eng_map, out_png):
    xs = sorted(set(soft_map.keys()) | set(accel_map.keys()) | set(eng_map.keys()))
    ys_soft  = [soft_map.get(x, float('nan')) for x in xs]
    ys_accel = [accel_map.get(x, float('nan')) for x in xs]
    ys_eng   = [eng_map.get(x, float('nan')) for x in xs]

    plt.figure()
    plt.title(f"{name.upper()} throughput vs size")
    plt.xlabel("Size (bytes, log2)")
    plt.ylabel("MiB/s")
    plt.xscale("log", base=2)
    plt.plot(xs, ys_soft,  marker="o", label="Rust-soft")
    plt.plot(xs, ys_accel, marker="o", label="Rust-accel")
    plt.plot(xs, ys_eng,   marker="o", label="Engine")
    plt.grid(True, which="both", linewidth=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)

plot_algo("sha1",   agg_soft_sha1,  agg_accel_sha1,  eng_sha1,   "plot_sha1.png")
plot_algo("sha256", agg_soft_sha256, agg_accel_sha256, eng_sha256, "plot_sha256.png")

print("Wrote: engine.csv, agg.csv, speedups.csv, plot_sha1.png, plot_sha256.png")
