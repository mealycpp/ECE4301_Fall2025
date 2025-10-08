# 🔐 Raspberry Pi 5 AES Crypto Engine Benchmark

This benchmark evaluates **AES-128-CBC encryption performance** on the Raspberry Pi 5 (8 GB) using two different implementations:

1. **Software AES (`soft`)** — Pure C implementation without ARMv8 crypto intrinsics  
2. **Hardware AES (`afalg`)** — Linux Crypto API using **AF_ALG** (`cbc(aes)`) offloaded to the Pi 5’s ARMv8 crypto engine

---

## ⚙️ System Configuration

| Component | Details |
|------------|----------|
| **Device** | Raspberry Pi 5 (8 GB) |
| **CPU** | Quad-core Cortex-A76 @ 2.4 GHz |
| **OS** | Raspberry Pi OS Bookworm 64-bit |
| **Kernel** | 6.6 or later (with `aes-arm64-ce` support) |
| **Compiler** | GCC 12.2, flags: `-O3 -march=armv8-a -mtune=cortex-a76` |
| **Crypto Driver** | `aes-arm64-ce` via AF_ALG |
| **Test Sizes** | 64 MB, 128 MB, 256 MB |
| **Chunk Sizes** | 4 KB, 16 KB, 64 KB, 256 KB, 1024 KB |
| **Metrics** | Elapsed s · Throughput MB/s · CPU user/sys time µs |

---

## 🧪 Methodology

Each test encrypts a random buffer using **AES-128-CBC**.  
Two paths were benchmarked:

- **Software path (`soft`)** — Uses a pure C AES-128 implementation that does not call ARMv8 crypto instructions.
- **Hardware path (`afalg`)** — Uses the Linux kernel crypto API (`AF_ALG`) to offload encryption to the Pi 5’s ARMv8 AES engine through the kernel driver `aes-arm64-ce`.

For each configuration:
- Total data sizes: 64 MB, 128 MB, 256 MB  
- Chunk sizes: 4 KB → 1024 KB  
- Measured metrics: elapsed time (s), throughput (MB/s), and CPU time (µs)

Results were written to `results.csv` and plotted using `plot.py`.

---

## 📊 Results

### Throughput vs Chunk Size (64 MB)
![Throughput 64MB](throughput_total_64.png)

### Throughput vs Chunk Size (128 MB)
![Throughput 128MB](throughput_total_128.png)

### Throughput vs Chunk Size (256 MB)
![Throughput 256MB](throughput_total_256.png)

### Average CPU Time (ms) by Implementation
![CPU Time](cpu_time_avg.png)

---

## 🧠 Interpretation

**1. Throughput Trends**
- The hardware AES (`afalg`) reaches up to **~2 GB/s**, roughly **35–40× faster** than the software implementation.
- The software AES (`soft`) peaks near **50–70 MB/s** and is bottlenecked by CPU compute time.
- Throughput stabilizes for chunk sizes ≥ 64 KB, meaning syscall and IV-setup overheads become negligible.
- Identical throughput curves across 64 MB, 128 MB, 256 MB totals indicate **consistent per-MB performance** (total size scales linearly with time).

**2. CPU Usage**
- Average CPU time for the software path is ~2600 ms, while the AF_ALG hardware path averages ~100 ms.  
  → **~25× lower CPU utilization**.
- This confirms that encryption is being offloaded to the Pi 5’s ARM Crypto Extensions, freeing CPU cycles for other tasks.

**3. Hardware Verification**
- `/proc/crypto` lists `aes-arm64-ce`, confirming kernel-level hardware acceleration is active.
- AF_ALG’s performance matches expected ARMv8 AES engine throughput.

---

## 🧩 Summary Table (Representative 128 MB Run)

| Impl | Chunk Size (KB) | Throughput (MB/s) | Relative Speed |
|------|-----------------|-------------------|----------------|
| **soft** | 64 | ~60 MB/s | 1× |
| **afalg** | 64 | ~1900 MB/s | **≈ 31× faster** |
| **soft** | 1024 | ~63 MB/s | 1× |
| **afalg** | 1024 | ~2100 MB/s | **≈ 33× faster** |

---

## 🧾 Conclusion

The **Raspberry Pi 5’s hardware AES engine** (accessed via AF_ALG) provides a dramatic boost in performance and efficiency:

- Up to **2 GB/s** sustained throughput  
- **~30–40×** faster than software AES  
- **~25×** less CPU time  

For any cryptographic workload on the Pi 5, enabling the hardware crypto engine (via **AF_ALG**, **OpenSSL**, or **/dev/crypto**) is strongly recommended for maximum efficiency.

---

📁 *Files produced:*
- `results.csv` — raw data  
- `throughput_total_64.png`, `128.png`, `256.png` — throughput plots  
- `cpu_time_avg.png` — CPU usage comparison  
- `benchmarks.md` — this summary document
