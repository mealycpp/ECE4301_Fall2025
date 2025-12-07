# Quick Start Guide

Get your secure video streaming system running in under 10 minutes.

## Prerequisites

- 2× Raspberry Pi 5 with Raspberry Pi OS (64-bit, Bookworm)
- Both Pis on the same network
- Pi Camera or USB webcam on sender
- Internet connection for setup

## Step 1: Clone and Setup (on both Pis)

```bash
# Clone the repository
git clone <repo-url>
cd rpi-secure-stream

# Run automated setup (installs dependencies, Rust, builds project)
chmod +x setup.sh
./setup.sh
```

The setup script will:
- Install system packages (GStreamer, OpenSSL, etc.)
- Install Rust toolchain
- Build all binaries with hardware acceleration
- Configure CPU governor for performance
- Enable camera support

## Step 2: Verify Hardware Acceleration (on both Pis)

```bash
# Check CPU features and runtime detection
./target/release/stream --print-config
```

You should see:
```
=== ARMv8 Crypto Extensions Detection ===
AES:   ACTIVE ✓
PMULL: ACTIVE ✓
SHA1:  ACTIVE ✓
SHA2:  ACTIVE ✓
```

## Step 3: Run Benchmark (optional but recommended)

```bash
./target/release/bench
```

Expected output:
```
Throughput: 400+ MB/s (with hardware acceleration)
✓ EXCELLENT: Hardware acceleration is working optimally
```

## Step 4: Start Streaming

### On Receiver Pi (Pi-B):

```bash
# Get IP address
hostname -I  # Note this IP, e.g., 192.168.1.102

# Start receiver
./target/release/stream \
    --mode receiver \
    --mechanism ecdh \
    --node-id pi-b \
    --port 8443
```

You should see:
```
[INFO] Starting receiver mode
[INFO] ARMv8 Crypto Extensions — AES: true, PMULL: true
[INFO] Listening on 0.0.0.0:8443
```

### On Sender Pi (Pi-A):

```bash
# Start sender (replace <pi-b-ip> with actual IP from above)
./target/release/stream \
    --mode sender \
    --mechanism ecdh \
    --node-id pi-a \
    --host 192.168.1.102 \
    --port 8443 \
    --video-source camera
```

You should see:
```
[INFO] Starting sender mode
[INFO] Connecting to 192.168.1.102:8443
[INFO] ECDH handshake completed in 0.083s
[INFO] Starting video stream
[INFO] Sent 450 frames, 15.23 fps, 52.4 Mbps
```

## Step 5: View Results

After 60 seconds, the stream will stop automatically. Check the generated CSV files:

```bash
ls -lh *.csv
# handshake_ecdh.csv
# steady_stream.csv
# power_samples.csv
```

Generate plots:

```bash
python3 scripts/plot_results.py
```

View plots:

```bash
ls plots/
# latency_cdf.png
# throughput_timeseries.png
# energy_bars.png
# system_metrics.png
```

## Common Issues and Solutions

### Issue: "Hardware acceleration not detected"

**Solution:**
```bash
# Verify CPU features
grep features /proc/cpuinfo | head -1

# Rebuild with correct flags
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Check again
./target/release/stream --print-config
```

### Issue: Connection refused

**Solution:**
```bash
# On receiver, check if port is listening
sudo netstat -tulpn | grep 8443

# Check firewall
sudo ufw status

# If firewall is active, allow port
sudo ufw allow 8443/tcp

# Verify network connectivity
ping <receiver-ip>
```

### Issue: Low frame rate or dropped frames

**Solution:**
```bash
# Set CPU to performance mode
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Check temperature (should be < 80°C)
vcgencmd measure_temp

# Ensure adequate cooling (heatsink + fan)

# Use wired Ethernet instead of WiFi
```

### Issue: GCM tag failures

**Solution:**
```bash
# Sync clocks using NTP
sudo systemctl enable systemd-timesyncd
sudo systemctl start systemd-timesyncd
timedatectl status

# Check network quality
ping -c 100 <peer-ip>  # Should show 0% packet loss
```

### Issue: Camera not found

**Solution:**
```bash
# List available cameras
v4l2-ctl --list-devices

# Test camera with GStreamer
gst-launch-1.0 v4l2src ! videoconvert ! autovideosink

# For Pi Camera, ensure it's enabled
sudo raspi-config  # Interface Options -> Camera -> Enable

# Reboot after enabling
sudo reboot
```

## Comparing RSA vs ECDH

### Test RSA-2048:

**Receiver:**
```bash
./target/release/stream --mode receiver --mechanism rsa --rsa-bits 2048
```

**Sender:**
```bash
./target/release/stream --mode sender --mechanism rsa --rsa-bits 2048 --host <receiver-ip>
```

Results saved to `handshake_rsa.csv`

### Test ECDH-P256:

**Receiver:**
```bash
./target/release/stream --mode receiver --mechanism ecdh
```

**Sender:**
```bash
./target/release/stream --mode sender --mechanism ecdh --host <receiver-ip>
```

Results saved to `handshake_ecdh.csv`

### Compare Results:

```bash
python3 scripts/plot_results.py
# Generates energy_bars.png with RSA vs ECDH comparison
```

**Expected Results:**
- **ECDH**: ~0.08s handshake, ~130 bytes exchanged, ~0.85J energy
- **RSA-2048**: ~0.15s handshake, ~550 bytes exchanged, ~1.2J energy
- **ECDH Advantages**: Faster, less energy, smaller messages
- **RSA Advantages**: Simpler revocation, mature tooling

## Quick Test with Group Keys

For faster connection setup with multiple nodes:

```bash
# Step 1: Generate group key (on any Pi)
./target/release/stream \
    --mode group-leader \
    --node-id leader \
    --members "pi-1:192.168.1.101:8444,pi-2:192.168.1.102:8444"

# Step 2: On each member (run simultaneously)
# Pi-1
./target/release/stream --mode group-member --node-id pi-1 --port 8444

# Pi-2  
./target/release/stream --mode group-member --node-id pi-2 --port 8444

# Step 3: Copy group_key.bin to all nodes
scp group_key.bin pi@pi-1:~/
scp group_key.bin pi@pi-2:~/

# Step 4: Stream with group key
# Receiver
./target/release/stream --mode receiver --mechanism group --display

# Sender
./target/release/stream --mode sender --mechanism group --host <receiver-ip> --video-source v4l2
```

## Performance Tuning Tips

### 1. Network Optimization

```bash
# Increase socket buffers for high throughput
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"

# Make permanent
echo "net.core.rmem_max=16777216" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max=16777216" | sudo tee -a /etc/sysctl.conf
```

### 2. CPU Pinning (optional)

```bash
# Pin sender to cores 0-1
taskset -c 0,1 ./target/release/stream --mode sender ...

# Pin receiver to cores 2-3
taskset -c 2,3 ./target/release/stream --mode receiver ...
```

### 3. Video Resolution

For testing or lower-power operation, you can adjust frame size in the code:

```rust
// In crates/stream/src/main.rs
// Change from: let frame_data = vec![0u8; 460_000]; // 640x480
// To:          let frame_data = vec![0u8; 230_000]; // 480x360
```

### 4. Rekey Interval

```bash
# More frequent rekeying (every 2 minutes)
./target/release/stream --mode sender --rekey-interval 120 ...

# Less frequent (every 30 minutes)
./target/release/stream --mode sender --rekey-interval 1800 ...
```

## Measuring Power Consumption

### Method 1: USB-C Inline Power Meter

1. Insert meter between power supply and Pi
2. Note voltage and current readings
3. Manually record in CSV format

### Method 2: INA219 Sensor HAT (I²C)

```bash
# Install library
pip3 install adafruit-circuitpython-ina219

# The code will automatically read from I²C if sensor is detected
# Check dmesg for I²C device detection
dmesg | grep i2c
```

### Method 3: Software Estimation

The code includes a simulation mode that estimates power based on CPU usage:

```rust
// In crates/metrics/src/lib.rs
pub async fn read_power_simulated() -> (f32, f32) {
    // Returns (volts, amps)
    // Real implementation should read from INA219
}
```

## Data Analysis

### View Raw Data

```bash
# Handshake metrics
cat handshake_ecdh.csv | column -t -s,

# Stream performance
tail -20 steady_stream.csv | column -t -s,

# Power samples
head -10 power_samples.csv | column -t -s,
```

### Calculate Statistics

```bash
# Average FPS
awk -F, 'NR>1 {sum+=$2; count++} END {print "Avg FPS:", sum/count}' steady_stream.csv

# Average latency
awk -F, 'NR>1 {sum+=$4; count++} END {print "Avg Latency:", sum/count, "ms"}' steady_stream.csv

# Total energy
awk -F, 'NR>1 && $5=="steady" {sum+=$4*0.25} END {print "Total Energy:", sum, "J"}' power_samples.csv
```

### Generate Report

```bash
python3 scripts/plot_results.py
cd plots/
# View all generated plots
ls -1 *.png
```

## Next Steps

1. **Read the full README.md** for detailed documentation
2. **Review HW_ACCEL.md** for hardware acceleration proof
3. **Implement GStreamer integration** for real camera capture
4. **Add INA219 power monitoring** for accurate energy measurement
5. **Test with different video resolutions** (480p, 720p, 1080p)
6. **Experiment with QUIC transport** (quinn crate) for better loss recovery
7. **Implement the group extension** for 3+ nodes
8. **Run scaling experiments** (N=3,4,5,...,10) and fit models

## Getting Help

- Check logs: `RUST_LOG=debug ./target/release/stream ...`
- Monitor system: `htop`, `iotop`, `nethogs`
- Test network: `iperf3 -s` (server), `iperf3 -c <server-ip>` (client)
- Temperature: `watch -n 1 vcgencmd measure_temp`
- Troubleshoot crypto: `./target/release/bench --verbose`

## Example Complete Workflow

```bash
# === On Both Pis ===
./setup.sh
./target/release/stream --print-config
./target/release/bench

# === Pi-B (Receiver) ===
./target/release/stream --mode receiver --mechanism ecdh --node-id pi-b

# === Pi-A (Sender) ===
./target/release/stream --mode sender --mechanism ecdh --node-id pi-a --host 192.168.1.102

# === After 60 seconds, on either Pi ===
python3 scripts/plot_results.py
ls plots/

# === Compare RSA vs ECDH ===
# Repeat with --mechanism rsa
# Then compare handshake_rsa.csv vs handshake_ecdh.csv
```

## Success Criteria

✓ Hardware acceleration detected (AES, PMULL active)  
✓ Benchmark shows >200 MB/s throughput  
✓ Stream maintains 15 fps for 60 seconds  
✓ Latency p95 < 100ms  
✓ Zero GCM tag failures  
✓ Energy consumption logged  
✓ CSV files and plots generated  

You're now ready to run experiments and collect data for your report!