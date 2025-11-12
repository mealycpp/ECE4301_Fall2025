# Secure Video Streaming for Raspberry Pi 5

End-to-end encrypted video streaming system with hardware-accelerated cryptography for Raspberry Pi 5.

## Features

- **Dual Key Establishment**: RSA-2048/3072 (key transport) and ECDH-P256 (key agreement)
- **Hardware Acceleration**: ARMv8 Crypto Extensions (AES, PMULL, SHA)
- **AES-128-GCM**: Authenticated encryption with proper nonce management
- **Automatic Rekeying**: Configurable intervals (default: 10 minutes or 2^20 frames)
- **Comprehensive Metrics**: Energy, latency, throughput, CPU, memory, temperature
- **Group Support**: 3+ node group key distribution protocols
- **Production-Ready**: Written entirely in Rust with zero unsafe code

## Architecture

```
┌─────────────┐                           ┌─────────────┐
│   Sender    │                           │  Receiver   │
│   (Pi-A)    │                           │   (Pi-B)    │
├─────────────┤                           ├─────────────┤
│  Camera     │                           │   Display   │
│  Capture    │                           │   Render    │
└──────┬──────┘                           └──────▲──────┘
       │                                         │
       │  1. Key Establishment                   │
       │     (RSA or ECDH)                       │
       ├────────────────────────────────────────►│
       │                                         │
       │  2. Encrypted Video Frames              │
       │     [Header][AES-GCM Ciphertext]        │
       ├────────────────────────────────────────►│
       │                                         │
       │  3. Periodic Rekey                      │
       │     (every 10 min or 2^20 frames)       │
       ├────────────────────────────────────────►│
       │                                         │
```

## Hardware Requirements

- 2× Raspberry Pi 5 (3+ for group extension)
- Pi Camera or USB camera on each node
- Wired Ethernet connection (recommended)
- Power measurement: USB-C inline meter or INA219 HAT
- MicroSD cards (32GB+, Class 10)

## Software Dependencies

### System Packages

```bash
sudo apt update
sudo apt install -y \
    clang pkg-config libssl-dev \
    gstreamer1.0-tools gstreamer1.0-libav \
    gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
    gstreamer1.0-gl
```

### Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup default stable
```

## Installation

```bash
# Clone repository
git clone <repo-url>
cd rpi-secure-stream

# Build with hardware acceleration
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Or use the configured .cargo/config.toml (already set)
cargo build --release
```

## Usage

### Print Configuration & Verify Hardware Acceleration

```bash
./target/release/stream --print-config
```

Expected output:
```
=== ARMv8 Crypto Extensions Detection ===
AES:   ACTIVE ✓
PMULL: ACTIVE ✓
SHA1:  ACTIVE ✓
SHA2:  ACTIVE ✓
=========================================
```

### Run Benchmark

```bash
./target/release/bench
```

This encrypts 256MB of data and reports throughput. Expected: >200 MB/s with hardware acceleration.

### Two-Node Streaming

**On Receiver (Pi-B):**
```bash
./target/release/stream \
    --mode receiver \
    --mechanism ecdh \
    --host 0.0.0.0 \
    --port 8443 \
    --node-id pi-b
```

**On Sender (Pi-A):**
```bash
./target/release/stream \
    --mode sender \
    --mechanism ecdh \
    --host <pi-b-ip> \
    --port 8443 \
    --node-id pi-a \
    --video-source camera
```

### Compare RSA vs ECDH

**RSA-2048:**
```bash
# Receiver
./target/release/stream --mode receiver --mechanism rsa --rsa-bits 2048

# Sender
./target/release/stream --mode sender --mechanism rsa --rsa-bits 2048 --host <receiver-ip>
```

**ECDH-P256:**
```bash
# Receiver
./target/release/stream --mode receiver --mechanism ecdh

# Sender
./target/release/stream --mode sender --mechanism ecdh --host <receiver-ip>
```

### Options for video stream source

#To send with the Pi camera
./target/release/stream --mode sender --mechanism ecdh --host <receiver-ip> --video-source libcamera

#To send with USB
./target/release/stream --mode sender --mechanism ecdh --host <receiver-ip> --video-source v4l2 --video-device /dev/video0

#To simulate a feed (rather than falling back onto sim)
./target/release/s


### Advanced Options

```bash
./target/release/stream --help

Options:
  --mode <MODE>              Operating mode: sender or receiver
  --mechanism <MECHANISM>    Key establishment: rsa or ecdh [default: ecdh]
  --host <HOST>              Host address [default: 0.0.0.0]
  --port <PORT>              Port number [default: 8443]
  --node-id <NODE_ID>        Node identifier [default: node-1]
  --video-source <SOURCE>    Video source: camera or file path [default: camera]
  --rekey-interval <SECS>    Rekey interval in seconds [default: 600]
  --rsa-bits <BITS>          RSA key size: 2048 or 3072 [default: 2048]
  --print-config             Print configuration and exit
```

Example: Stream ECC at a specific resolution
# 720p @ 30fps
```bash
./target/release/stream --mode sender --mechanism ecdh --host <receiver-ip> --video-source v4l2 --video-width 1280 --video-height 720 --video-fps 30
```

## Output Files

After running, the following CSV files are generated:

- `handshake_rsa.csv` - RSA handshake metrics
- `handshake_ecdh.csv` - ECDH handshake metrics
- `steady_stream.csv` - Per-sample streaming metrics (CPU, memory, FPS, latency)
- `power_samples.csv` - Power measurements (voltage, current, watts)

### CSV Schemas

**handshake_*.csv:**
```
ts_start, ts_end, mechanism, bytes_tx, bytes_rx, cpu_avg, mem_mb, energy_j, success
```

**steady_stream.csv:**
```
ts, fps, goodput_mbps, latency_ms, cpu_pct, mem_mb, temp_c, drops, tag_failures
```

**power_samples.csv:**
```
ts, volts, amps, watts, phase, node_id
```

## Group Extension (3+ Nodes)

### Leader-Distributed Protocol

The leader generates a group key and securely distributes it to all members via pairwise ECDH channels.

**Run Leader:**
```bash
./target/release/group-leader \
    --node-id leader \
    --members pi-1:192.168.1.101:8443,pi-2:192.168.1.102:8443,pi-3:192.168.1.103:8443
```

**Run Members:**
```bash
# On each member Pi
./target/release/group-member \
    --node-id pi-1 \
    --listen 0.0.0.0:8443
```

##Two options for streaming mode: Broadcast or Relay

**Broadcast Mode**
Run two instances of this code from the sender:
#To Pi-2
```bash
./target/release/stream
  --mode sender --mechanism group --host 192.168.1.102 --port 8443 --video-source v4l2 --video-device /dev/video0 --group-key-file group_key.bin
```
#To Pi-3
```bash
./target/release/stream
  --mode sender --mechanism group --host 192.168.1.102 --port 8443 --video-source v4l2 --video-device /dev/video0 --group-key-file group_key.bin
```

For receivers:
#Metrics only, Pi-2 example
```bash
./target/release/stream --mode receiver --mechanism group --port 8443 --group-key-file group_key.bin
```
#With display, Pi-3 example
```bash
./target/release/stream --mode receiver --mechanism group --port 8444 --display --group-key-file group_key.bin
```

**Relay mode**
Sender:
```bash
./target/release/stream --mode sender --mechanism group --host 192.168.1.102 --port 8443 --video-source v4l2 --group-key-file group_key.bin
```

Receivers:

#Pi-2 as relay
```bash
./target/release/stream --mode relay --mechanism group --host 0.0.0.0 --port 8443 --relay-host 192.168.1.103 --relay-port 8444 --group-key-file group_key.bin
```

#Pi-3 as receiver with video display
```bash
./target/release/stream --mode receiver --mechanism group --port 8444 --display --group-key-file group_key.bin
```

### Scaling Analysis

The system automatically generates scaling predictions based on measured data:

```bash
./target/release/analyze-scaling \
    --measured group_metrics_n3.csv \
    --predict-max 10 \
    --output scaling_analysis.csv
```

This produces predictions for N=4..10 based on N=3 measurements.

## Performance Optimization

### CPU Governor

```bash
# Set to performance mode
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### Thermal Management

```bash
# Monitor temperature
watch -n 1 cat /sys/class/thermal/thermal_zone0/temp

# Ensure adequate cooling (heatsink + fan recommended)
```

### Network Tuning

```bash
# Increase socket buffers
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
```

## Security Guarantees

✓ Hardware TRNG via `/dev/urandom` (getrandom syscall)  
✓ Unique nonces per frame (96-bit: random base + 32-bit counter)  
✓ Authenticated encryption (AES-GCM with AAD)  
✓ Forward secrecy (ephemeral keys per session)  
✓ Automatic rekeying (prevents nonce exhaustion)  
✓ Key material wiped on drop (zeroize)  
✓ No plaintext key storage

## Troubleshooting

### Hardware Acceleration Not Detected

```bash
# Verify CPU features
grep -i features /proc/cpuinfo | head -1

# Should include: aes pmull sha1 sha2

# Check compilation flags
RUSTFLAGS="-C target-cpu=native" cargo build --release --verbose
```

### Low Throughput

1. Check CPU governor: `cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor`
2. Monitor thermal throttling: `vcgencmd measure_temp`
3. Verify hardware acceleration: `./target/release/bench`
4. Check network: `iperf3` between nodes

### GCM Tag Failures

- Clock skew: Ensure NTP is running (`sudo systemctl status systemd-timesyncd`)
- Packet corruption: Check network cables and switch
- Key mismatch: Verify both nodes completed handshake successfully

## Testing

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration

# Benchmark
cargo bench
```

## Project Structure

```
rpi-secure-stream/
├── .cargo/
│   └── config.toml          # Build configuration with target-cpu=native
├── crates/
│   ├── crypto/              # Cryptography primitives
│   │   ├── src/
│   │   │   └── lib.rs       # RSA, ECDH, AES-GCM, nonce management
│   │   └── Cargo.toml
│   ├── metrics/             # Performance metrics collection
│   │   ├── src/
│   │   │   └── lib.rs       # CPU, memory, power, latency tracking
│   │   └── Cargo.toml
│   ├── stream/              # Main streaming application
│   │   ├── src/
│   │   │   └── main.rs      # Sender/receiver implementation
│   │   └── Cargo.toml
│   ├── bench/               # AES-GCM benchmark tool
│   │   ├── src/
│   │   │   └── main.rs      # Hardware acceleration verification
│   │   └── Cargo.toml
│   └── group/               # Group key establishment
│       ├── src/
│       │   └── lib.rs       # Leader-distributed and Tree-ECDH
│       └── Cargo.toml
├── Cargo.toml               # Workspace configuration
├── README.md                # This file
└── HW_ACCEL.md             # Hardware acceleration proof
```

## License

MIT License - See LICENSE file for details

## References

- [ARMv8 Crypto Extensions](https://developer.arm.com/documentation/ddi0487/latest/)
- [AES-GCM Spec (NIST SP 800-38D)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [ECDH (RFC 7748)](https://datatracker.ietf.org/doc/html/rfc7748)
- [RSA OAEP (RFC 8017)](https://datatracker.ietf.org/doc/html/rfc8017)
- [GStreamer Documentation](https://gstreamer.freedesktop.org/documentation/)
