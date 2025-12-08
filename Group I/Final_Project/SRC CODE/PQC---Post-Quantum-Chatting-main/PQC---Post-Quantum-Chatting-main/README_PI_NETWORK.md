# PQC Chat - Raspberry Pi 5 Network Setup

This guide provides complete instructions for setting up PQC Chat across 3 Raspberry Pi 5s connected via ethernet switch with static IP addresses.

## Quick Start

1. **Configure static network on all Pis** (see [NETWORK_SETUP.md](NETWORK_SETUP.md))
2. **Deploy the application on each Pi**:
   ```bash
   # On each Pi, clone and build the project
   git clone https://github.com/Vervion/PQC---Post-Quantum-Chatting.git
   cd PQC---Post-Quantum-Chatting
   
   # Run the deployment script (auto-detects role based on IP)
   sudo ./scripts/deploy_pi_network.sh
   ```

## Network Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Pi 1 (Server)   │    │ Pi 2 (Client)   │    │ Pi 3 (Client)   │
│ 192.168.10.101  │◄──►│ 192.168.10.102  │    │ 192.168.10.103  │
│ pqc-server      │    │ pqc-client1     │◄──►│ pqc-client2     │
│                 │    │                 │    │                 │
│ Runs:           │    │ Runs:           │    │ Runs:           │
│ - pqc-server    │    │ - pqc-enhanced-gui       │    │ - pqc-enhanced-gui       │
│ - Signaling     │    │ - Audio/Video   │    │ - Audio/Video   │
│ - Certificate   │    │   capture       │    │   capture       │
│   management    │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Step-by-Step Setup

### 1. Network Configuration

Follow the detailed instructions in [NETWORK_SETUP.md](NETWORK_SETUP.md) to configure static IP addresses:
- **Pi 1 (Server)**: 192.168.10.101
- **Pi 2 (Client 1)**: 192.168.10.102  
- **Pi 3 (Client 2)**: 192.168.10.103

### 2. Install Dependencies

On **all three Pis**, install required dependencies:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install system dependencies
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libasound2-dev \
    libv4l-dev \
    libxkbcommon-dev \
    libwayland-dev \
    libxrandr-dev \
    libxcursor-dev \
    libxi-dev \
    libxinerama-dev \
    libgl1-mesa-dev
```

### 3. Clone and Build

On **all three Pis**:

```bash
# Clone the repository
git clone https://github.com/Vervion/PQC---Post-Quantum-Chatting.git
cd PQC---Post-Quantum-Chatting

# Build the project
cargo build --release
```

### 4. Deploy Application

#### Option A: Automatic Deployment (Recommended)

Run the deployment script on each Pi. It will auto-detect the role based on IP address:

```bash
sudo ./scripts/deploy_pi_network.sh
```

#### Option B: Manual Deployment

**On Pi 1 (Server - 192.168.10.101):**
```bash
sudo ./scripts/deploy_pi_network.sh server
```

**On Pi 2 (Client 1 - 192.168.10.102):**
```bash
sudo ./scripts/deploy_pi_network.sh client1
```

**On Pi 3 (Client 2 - 192.168.10.103):**
```bash
sudo ./scripts/deploy_pi_network.sh client2
```

## Starting the Chat System

### 1. Start the Server (Pi 1)

The server should start automatically after deployment. If needed:

```bash
# Check server status
sudo systemctl status pqc-chat-server

# Start server manually
sudo systemctl start pqc-chat-server

# View server logs
sudo journalctl -u pqc-chat-server -f
```

### 2. Start Clients (Pi 2 & Pi 3)

On each client Pi:

```bash
# Start the GUI application (installed by the deploy script)
/opt/pqc-chat/bin/pqc-enhanced-gui

# Or run from the project directory (developer build)
./target/release/pqc-enhanced-gui
```

## Configuration Files

The deployment creates these configuration files:

- **Server (Pi 1)**: `/etc/pqc-chat/server.toml`
- **Client 1 (Pi 2)**: `/etc/pqc-chat/client.toml` (points to Pi-Client-1)
- **Client 2 (Pi 3)**: `/etc/pqc-chat/client.toml` (points to Pi-Client-2)

## Port Configuration

The system uses these ports:
- **8443**: HTTPS signaling (encrypted control messages)
- **10000**: UDP audio stream
- **10001**: UDP video stream

Make sure these ports are not blocked by any firewall.

## Troubleshooting

### Network Issues

```bash
# Test network connectivity from any Pi
ping 192.168.10.101  # Server
ping 192.168.10.102  # Client 1  
ping 192.168.10.103  # Client 2

# Test specific ports (from client Pis)
nc -zv 192.168.10.101 8443  # Test signaling port
```

### Server Issues

```bash
# Check server logs
sudo journalctl -u pqc-chat-server -n 50

# Restart server
sudo systemctl restart pqc-chat-server

# Check if ports are listening
sudo netstat -tlnp | grep -E ":(8443|10000|10001)"
```

### Client Issues

```bash
# Run client with debug output
RUST_LOG=debug /opt/pqc-chat/bin/pqc-enhanced-gui

# Check client configuration
cat /etc/pqc-chat/client.toml
```

### Certificate Issues

If TLS certificates are causing problems:

```bash
# Regenerate certificates on server
cd /path/to/PQC---Post-Quantum-Chatting
sudo ./scripts/generate_certs.sh

# Restart server after certificate regeneration
sudo systemctl restart pqc-chat-server
```

### Audio/Video Issues

```bash
# List available cameras
v4l2-ctl --list-devices

# List audio devices  
arecord -l

# Test camera
ffplay /dev/video0

# Test audio recording
arecord -f cd -t wav -d 5 test.wav && aplay test.wav
```

## Performance Optimization

For optimal performance on Raspberry Pi 5:

1. **GPU Memory Split**: Increase GPU memory to at least 128MB:
   ```bash
   sudo raspi-config
   # Advanced Options → Memory Split → 128
   ```

2. **Disable unnecessary services**:
   ```bash
   sudo systemctl disable bluetooth
   sudo systemctl disable wifi
   # (if using ethernet only)
   ```

3. **Monitor CPU/Memory usage**:
   ```bash
   htop
   # Watch for CPU usage during video chat
   ```

## Security Notes

- The system uses TLS certificates for signaling encryption
- Consider changing default ports if deploying on a network with other services
- The static IP configuration assumes a private network segment
- Kyber post-quantum cryptography is used for key exchange

## Hardware Requirements

- **Raspberry Pi 5** (4GB+ RAM recommended)
- **USB Camera** or **Raspberry Pi Camera Module**
- **USB Microphone** or **Audio HAT**
- **Ethernet cables** (Cat 5e or better)
- **Ethernet switch** (unmanaged is sufficient)

## Audio Quality & Latency Improvements

### Recent Optimizations (Dec 6, 2025)

The audio subsystem has been optimized for low-latency, high-quality transmission on Raspberry Pi 5:

**Changes Made:**
- **Reduced playback buffer**: From 200ms → 80ms (lower perceived latency)
- **Bounded command queue**: Switched from unbounded to bounded channel (size 32) to prevent audio packet backlog
- **Non-blocking sends**: Audio capture now uses `try_send()` to drop packets when the queue is full, avoiding unbounded delays

**Why:** Audio was being sent over TCP (signaling channel) with unbounded buffering. This caused:
- Long delays before hearing the remote person
- Grainy/static audio artifacts from queued backlog
- Excessive latency on Raspberry Pi hardware

With these fixes:
- Latency reduced by ~120ms (from 200ms to 80ms buffer)
- Audio packets dropped gracefully when network is slow (better than queuing)
- More responsive real-time feel

### Testing Audio Quality

#### Quick Test (All Pis)

```bash
# Terminal 1 - On Pi 1 (Server):
sudo systemctl start pqc-chat-server
sudo journalctl -u pqc-chat-server -f  # Monitor server logs

# Terminal 2 - On Pi 2 (Client 1):
RUST_LOG=debug /opt/pqc-chat/bin/pqc-enhanced-gui

# Terminal 3 - On Pi 3 (Client 2):
RUST_LOG=debug /opt/pqc-chat/bin/pqc-enhanced-gui
```

#### What to Observe

1. **Startup**: Both clients should connect and show "Connected to server" status
2. **Room Creation**: Create a room on one client, join from the other
3. **Audio Call**: Click the 🎤 button to start audio (runs at 48kHz mono)
4. **Quality Metrics**:
   - ✅ Audio heard within ~100–150ms (was 300ms+)
   - ✅ Minimal static/grain (no longer layered backlog)
   - ✅ Clear voice transmission
5. **Debug Output**: Watch stderr for:
   ```
   DEBUG: Audio from <sender>: N samples, pushed M, max_amp=X.XX
   WARNING: Buffer full, dropped Y samples
   ```

#### If Audio Quality is Still Poor

**Symptom: Frequent "dropped samples" warnings**
- Increase the command queue capacity (too many packets being sent)
- Edit `src/gui/enhanced_main.rs` line ~199:
  ```rust
  let (command_sender, command_receiver) = mpsc::channel(64);  // was 32
  ```
- Rebuild: `cargo build --release && sudo ./scripts/deploy_pi_network.sh`

**Symptom: Still hearing lag/delay**
- Lower the playback buffer further (if hardware can handle it)
- Edit `src/audio.rs` line ~35:
  ```rust
  const PLAYBACK_BUFFER_MS: usize = 50;  // was 80 (more aggressive, may underrun)
  ```
- Rebuild and redeploy

**Symptom: Audio has clicks/pops (underruns)**
- Increase the playback buffer
- Edit `src/audio.rs` line ~35:
  ```rust
  const PLAYBACK_BUFFER_MS: usize = 100;  // was 80
  ```
- Rebuild and redeploy

#### Audio Device Configuration

If audio is not working at all:

```bash
# On client Pi, list audio devices
arecord -l   # Input devices
aplay -l     # Output devices

# Check current configuration
cat /etc/pqc-chat/client.toml | grep -A 5 "\[audio\]"

# Test audio I/O manually
arecord -f cd -t wav -d 3 test.wav && aplay test.wav
```

The system defaults to:
- **Sample Rate**: 48 kHz (CD quality)
- **Channels**: 1 (mono for low bandwidth)
- **Transport**: Raw f32 samples over TLS signaling (TCP)

**Note**: For production deployments with better latency, consider:
- Implementing UDP-based media transport (see `src/media.rs` stubs)
- Adding Opus encoding/decoding (compression + better bandwidth efficiency)
- Using DTLS-SRTP for secure real-time media

## Next Steps

After successful deployment:
1. Test basic connectivity between all Pis
2. Start a video chat session from both clients
3. Verify audio and video quality (use the Audio Testing section above)
4. Monitor performance and adjust settings if needed

For advanced configuration and troubleshooting, see the individual configuration files in the `config/` directory.