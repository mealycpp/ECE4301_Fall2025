#!/usr/bin/env python3
import argparse, csv, statistics as stats
from collections import defaultdict
import matplotlib.pyplot as plt

# CSV format you actually have:
# algo,size_bytes,trial,mb_per_s,bytes,elapsed_ms

def load_rust(path):
    rows = []
    with open(path, newline='') as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append({
                'algo': row['algo'],
                'size': int(row['size_bytes']),
                'mbps': float(row['mb_per_s'])
            })
    return rows

def load_engine(path):
    rows = []
    with open(path, newline='') as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append({
                'algo': row['algo'],
                'size': int(row['size_bytes']),
                'mbps': float(row['mb_per_s'])
            })
    return rows


def summarize(rows):
    # mean MB/s by (algo, size)
    agg = defaultdict(list)
    for x in rows:
        agg[(x['algo'], x['size'])].append(x['mbps'])
    out = {}
    for k, v in agg.items():
        out[k] = (stats.mean(v), stats.pstdev(v) if len(v) > 1 else 0.0)
    return out


def plot_one(algo, sizes, series, outfile):
    plt.figure()
    for name, data in series.items():
        ys = [data.get(s, float('nan')) for s in sizes]
        plt.plot(sizes, ys, marker='o', label=name)
    plt.xscale('log', base=2)
    plt.xlabel('Message size (bytes)')
    plt.ylabel('Throughput (MB/s)')
    plt.title(f'{algo.upper()} throughput vs size (Pi 5)')
    plt.grid(True, which='both', linestyle=':')
    plt.legend()
    plt.tight_layout()
    plt.savefig(outfile, dpi=180)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rust-soft', required=True)
    ap.add_argument('--rust-accel', required=True)
    ap.add_argument('--engine', required=True)
    ap.add_argument('--out-dir', required=True)
    args = ap.parse_args()

    rsoft = summarize(load_rust(args.rust_soft))
    raccel = summarize(load_rust(args.rust_accel))
    eng = summarize(load_engine(args.engine))

    sizes = sorted({s for (_, s) in list(rsoft.keys()) + list(raccel.keys()) + list(eng.keys())})

    for algo in ['sha1', 'sha256']:
        series = {
            'Rust-soft': {s: rsoft.get((algo, s), (float('nan'), 0))[0] for s in sizes},
            'Rust-accel': {s: raccel.get((algo, s), (float('nan'), 0))[0] for s in sizes},
            'Engine': {s: eng.get((algo, s), (float('nan'), 0))[0] for s in sizes},
        }
        plot_one(algo, sizes, series, f"{args.out_dir}/{algo}_throughput.png")


if __name__ == '__main__':
    main()
