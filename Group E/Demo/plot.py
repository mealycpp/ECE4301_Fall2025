import pandas as pd
import matplotlib.pyplot as plt
import os

CSV = "results.csv"
if not os.path.exists(CSV):
    raise SystemExit("results.csv not found. Run ./run_bench.sh first.")

# Read robustly
df = pd.read_csv(CSV, dtype=str, on_bad_lines="skip")
if 'impl' not in df.columns:
    df = pd.read_csv(CSV, dtype=str, on_bad_lines="skip", engine="python")
if 'impl' not in df.columns:
    raise SystemExit("CSV missing 'impl' column.")

# Clean & coerce
df = df[df['impl'] != 'impl']
num_cols = ['total_mb','chunk_kb','elapsed_s','throughput_MBps','utime_us','stime_us']
for c in num_cols:
    df[c] = pd.to_numeric(df[c], errors='coerce')
df = df.dropna(subset=['total_mb','chunk_kb','throughput_MBps'])
df['total_mb'] = df['total_mb'].astype(int)
df['chunk_kb'] = df['chunk_kb'].astype(int)
df['impl'] = df['impl'].str.lower().str.strip()
df['op'] = df['op'].str.lower().str.strip()

# Throughput by op & total
totals = sorted(df['total_mb'].unique())
ops = sorted(df['op'].unique())

for op in ops:
    for t in totals:
        d = df[(df['op']==op) & (df['total_mb']==t)]
        if d.empty: continue
        piv = d.pivot_table(index='chunk_kb', columns='impl', values='throughput_MBps', aggfunc='mean')
        ax = piv.sort_index().plot(kind='bar')
        ax.set_title(f"Throughput vs Chunk Size (op={op}, total={t} MB)")
        ax.set_xlabel("Chunk Size (KB)")
        ax.set_ylabel("Throughput (MB/s)")
        ax.legend(title="Implementation")
        plt.tight_layout()
        plt.savefig(f"throughput_{op}_total_{t}.png")
        plt.clf()

# CPU time by op & impl
df['cpu_ms'] = (df['utime_us'].fillna(0) + df['stime_us'].fillna(0)) / 1000.0
cpu = df.groupby(['op','impl'])['cpu_ms'].mean().unstack('impl')
ax = cpu.plot(kind='bar')
ax.set_title("Average CPU Time (ms) by Operation and Implementation")
ax.set_xlabel("Operation")
ax.set_ylabel("CPU Time (ms)")
plt.tight_layout()
plt.savefig("cpu_time_avg_by_op.png")
print("Saved plots for ops:", [f"throughput_{op}_total_{t}.png" for op in ops for t in totals] + ["cpu_time_avg_by_op.png"])
