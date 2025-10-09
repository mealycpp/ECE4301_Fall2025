import os, re, csv, glob, pathlib

BASE = pathlib.Path(__file__).resolve().parent
RAW  = BASE / "raw"
OUT  = BASE / "benchmarks_combined.csv"

# --- Regex patterns for OpenSSL outputs ---
HDR_RE  = re.compile(r'^\s*type\s+(.*)$', re.I)
SIZE_RE = re.compile(r'(\d+)\s*bytes', re.I)
ROW_RE  = re.compile(r'^\s*([A-Za-z0-9_\-]+)\s+(.+)$')
LINE_RE = re.compile(r'^\s*([A-Za-z0-9_\-]+)\s+(\d+)\s+bytes\s+([0-9.]+)k', re.I)

def clean_name(name: str) -> str:
    """Normalize algorithm labels."""
    name = name.lower()
    if 'aes' in name:
        if '128' in name:
            return 'AES-128'
        elif '256' in name:
            return 'AES-256'
    if 'sha256' in name:
        return 'SHA256'
    if 'sha512' in name:
        return 'SHA512'
    return name.upper()

def parse_table_style(lines):
    sizes = []
    rows  = []
    for line in lines:
        m = HDR_RE.match(line)
        if m:
            sizes = [int(s) for s in SIZE_RE.findall(m.group(1))]
            continue
        m = ROW_RE.match(line)
        if m and sizes:
            algo = clean_name(m.group(1))
            cols = m.group(2).split()[:len(sizes)]
            vals = []
            for v in cols:
                v = v.rstrip('kK')
                try:
                    vals.append(float(v))
                except ValueError:
                    vals.append(0.0)
            for sz, kbps in zip(sizes, vals):
                bps = kbps * 1000.0
                mbps = bps / (1024.0 * 1024.0) if bps > 0 else 0.0
                latency_ns = (sz / bps) * 1e9 if bps > 0 else 0.0
                rows.append([algo, sz, mbps, latency_ns])
    return rows

def parse_per_line_style(lines):
    rows = []
    for line in lines:
        m = LINE_RE.match(line)
        if not m:
            continue
        algo, bsz, kbps = m.groups()
        algo = clean_name(algo)
        bsz  = int(bsz)
        bps  = float(kbps) * 1000.0
        mbps = bps / (1024.0 * 1024.0) if bps > 0 else 0.0
        latency_ns = (bsz / bps) * 1e9 if bps > 0 else 0.0
        rows.append([algo, bsz, mbps, latency_ns])
    return rows

all_rows = []
for p in sorted(RAW.glob("*.txt")):
    if p.name.startswith(("perf_", "system_info")):
        continue
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        lines = [ln.rstrip("\n") for ln in f]
    r = parse_table_style(lines)
    if not r:
        r = parse_per_line_style(lines)
    all_rows.extend(r)

with OUT.open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["algorithm","block_size_bytes","throughput_MBps","latency_ns_per_block"])
    w.writerows(all_rows)

print(f"Wrote {OUT} with {len(all_rows)} rows")
