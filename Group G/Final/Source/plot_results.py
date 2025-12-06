import sys

from pathlib import Path

import pandas as pd

import numpy as np

import matplotlib.pyplot as plt

if len(sys.argv) < 2:

    print("Usage: python plot_results.py <results.csv>")

    sys.exit(1)

csv = Path(sys.argv[1])

df = pd.read_csv(csv)

df['throughput_MBps'] = df['bytes_hashed'] / (df['elapsed_ns'] / 1e9) / (1024*1024)

df['latency_us'] = df['elapsed_ns'] / 1000.0

grouped = df.groupby(['algorithm','impl','message_size'])['throughput_MBps'].agg(['median','mean','std','count']).reset_index()

print(grouped.head(20))

plt.figure(figsize=(10,6))

labels = []

for (alg, impl), sub in df.groupby(['algorithm','impl']):

    m = sub.groupby('message_size')['throughput_MBps'].median().reset_index()

    plt.plot(m['message_size'], m['throughput_MBps'], marker='o')

    labels.append(f"{alg}-{impl}")

plt.xscale('log', base=2)

plt.yscale('log')

plt.xlabel('message size (bytes)')

plt.ylabel('throughput (MB/s)')

plt.title('Median throughput vs message size')

plt.legend(labels, fontsize='small')

plt.grid(True, which='both', ls='--', lw=0.5)

plt.tight_layout()

plt.savefig('throughput_vs_size.png', dpi=200)

plt.close()

plt.figure(figsize=(10,6))

labels=[]

for (alg, impl), sub in df.groupby(['algorithm','impl']):

    m = sub.groupby('message_size')['latency_us'].median().reset_index()

    plt.plot(m['message_size'], m['latency_us'], marker='o')

    labels.append(f"{alg}-{impl}")

plt.xscale('log', base=2)

plt.yscale('log')

plt.xlabel('message size (bytes)')

plt.ylabel('latency (us)')

plt.title('Median latency vs message size')

plt.legend(labels, fontsize='small')

plt.grid(True, which='both', ls='--', lw=0.5)

plt.tight_layout()

plt.savefig('latency_vs_size.png', dpi=200)

plt.close()

for size in [16, 256, 4096, 65536]:

    sub = df[df['message_size'] == size]

    if sub.empty: continue

    plt.figure(figsize=(10,6))

    sub['algimpl'] = sub['algorithm'] + "-" + sub['impl']

    order = sorted(sub['algimpl'].unique())

    data = [sub[sub['algimpl']==o]['throughput_MBps'].values for o in order]

    plt.boxplot(data, labels=order, showfliers=False)

    plt.title(f"Throughput distribution for message size = {size} bytes")

    plt.ylabel('throughput (MB/s)')

    plt.xticks(rotation=45, ha='right')

    plt.tight_layout()

    plt.savefig(f'boxplot_{size}.png', dpi=200)

    plt.close()

print("Plots saved: throughput_vs_size.png, latency_vs_size.png, boxplot_*.png")