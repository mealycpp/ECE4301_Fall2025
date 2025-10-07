#!/usr/bin/env python3
"""
SHA-256 timing demo (Pi 5 / OpenSSL-backed hashlib)
- One-shot hash of a tiny message (good for latency).
- 3s streaming hash with 16 KB chunks (good for throughput & per-call latency).
"""

import hashlib
import time
import os
import sys

# --- Config ---
PLAINTEXT = b"Hi this is plaintext"  # 21 bytes (same as your AES example)
STREAM_BLOCK = 16_384                 # 16 KB chunk size
STREAM_SECS = 3.0                     # ~3 seconds

def openssl_version_text() -> str:
    # Best effort: show which OpenSSL Python is linked against
    try:
        import hashlib as _h
        if hasattr(_h, "openssl_version"):
            return _h.openssl_version
    except Exception:
        pass
    try:
        import ssl
        return ssl.OPENSSL_VERSION
    except Exception:
        return "(could not determine OpenSSL version)"

def fmt_bps(bps: float) -> str:
    if bps >= 1e9:
        return f"{bps/1e9:.3f} GB/s ({bps/1e6:.1f} MB/s)"
    if bps >= 1e6:
        return f"{bps/1e6:.1f} MB/s"
    if bps >= 1e3:
        return f"{bps/1e3:.1f} kB/s"
    return f"{bps:.0f} B/s"

def main():
    print("== SHA-256 timing (hashlib/OpenSSL) ==\n")
    print("OpenSSL:", openssl_version_text())
    print()

    # ---------- One-shot (latency focus) ----------
    t0 = time.perf_counter()
    h = hashlib.sha256()          # setup context
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    h.update(PLAINTEXT)           # hash tiny message
    digest = h.digest()           # finalize
    t3 = time.perf_counter()

    setup_time = t1 - t0
    hash_time  = t3 - t2
    total_time = t3 - t0
    tiny_tp    = len(PLAINTEXT) / hash_time  # bytes/sec (noisy for tiny inputs)

    print("== One-shot (21-byte message) ==")
    print("plaintext:           ", PLAINTEXT.decode("utf-8"))
    print("digest (hex):        ", digest.hex())
    print(f"setup latency:        {setup_time*1e6:.2f} µs")
    print(f"hash latency:         {hash_time*1e6:.2f} µs  (execution time)")
    print(f"total latency:        {total_time*1e6:.2f} µs  (setup + hash)")
    print(f"throughput (tiny):    {fmt_bps(tiny_tp)}")
    print()

    # ---------- Streaming (throughput focus) ----------
    buf = b"\x00" * STREAM_BLOCK
    total = 0
    calls = 0

    h2 = hashlib.sha256()
    start = time.perf_counter()
    deadline = start + STREAM_SECS

    while True:
        now = time.perf_counter()
        if now >= deadline:
            break
        h2.update(buf)
        total += STREAM_BLOCK
        calls += 1

    digest2 = h2.digest()
    end = time.perf_counter()
    elapsed = end - start
    bps = total / elapsed
    per_call_latency = elapsed / calls if calls else float("nan")

    print("== Streaming (SHA-256) ==")
    print(f"elapsed:              {elapsed:.3f} s")
    print(f"bytes processed:      {total:,}")
    print(f"throughput:           {fmt_bps(bps)}")
    print(f"per-call latency:     {per_call_latency*1e6:.2f} µs per {STREAM_BLOCK}B update()")
    print(f"calls made:           {calls}")
    print("digest (hex):        ", digest2.hex())

if __name__ == "__main__":
    main()
