# Quick Start: Audio Testing on Raspberry Pi Network

This guide walks you through testing the audio improvements on your 3-Pi setup.

## Prerequisites

- All 3 Pis deployed with `sudo ./scripts/deploy_pi_network.sh`
- Network is stable (verify with `ping 192.168.10.101` from clients)
- Audio devices connected (USB mic/speakers or audio HAT)

## Test Procedure

### Step 1: Start the Server (Pi 1 - 192.168.10.101)

On **Pi 1**, in a terminal:

```bash
cd ~/PQC---Post-Quantum-Chatting
sudo systemctl restart pqc-chat-server
sudo journalctl -u pqc-chat-server -f
```

You should see:
```
pqc-server: Listening on 0.0.0.0:8443 for signaling
```

### Step 2: Launch Client 1 (Pi 2 - 192.168.10.102)

On **Pi 2**, in a terminal:

```bash
cd ~/PQC---Post-Quantum-Chatting
RUST_LOG=debug /opt/pqc-chat/bin/pqc-enhanced-gui
```

**In the GUI:**
- Server: `192.168.10.101`
- Port: `8443`
- Username: `Pi2-User`
- Click **Connect**
- Wait for "Connected to server" ✅

### Step 3: Launch Client 2 (Pi 3 - 192.168.10.103)

On **Pi 3**, in a terminal:

```bash
cd ~/PQC---Post-Quantum-Chatting
RUST_LOG=debug /opt/pqc-chat/bin/pqc-enhanced-gui
```

**In the GUI:**
- Server: `192.168.10.101`
- Port: `8443`
- Username: `Pi3-User`
- Click **Connect**
- Wait for "Connected to server" ✅

### Step 4: Create a Room

On **Pi 2 (Client 1)**:
- Enter **Room Name**: `TestAudioRoom`
- Click **Create Room**
- Wait for "Created room" ✅

On **Pi 3 (Client 2)**:
- Click **Rooms** to refresh
- Select **TestAudioRoom** from the list
- Click **Join Room**
- You should see "Joined room" and the participants list ✅

### Step 5: Start Audio Call

On **Pi 2 (Client 1)**:
- Click the **🎤 (Audio Call)** button
- You should see "Audio call started - speak now!" ✅
- Watch the debug output for:
  ```
  DEBUG: Audio from Pi3-User: 960 samples, pushed 960, max_amp=0.0015
  ```

On **Pi 3 (Client 2)**:
- Click the **🎤 (Audio Call)** button
- You should see "Audio call started - speak now!" ✅

### Step 6: Test Audio Quality

1. **Speak on Pi 2** → Listen on Pi 3
   - You should hear audio within **100–150ms** (was 300ms before fixes)
   - Audio should be clear, not grainy or staticy
   
2. **Speak on Pi 3** → Listen on Pi 2
   - Confirm audio travels both directions
   - Listen for clicks/pops (underruns) or dropouts

### Step 7: Monitor for Issues

**Watch the terminal output on both clients for:**

```
WARNING: Buffer full, dropped N samples
```

- **Few warnings** (< 5/minute) = Good, network keeping up
- **Many warnings** (> 10/minute) = Queue too small, increase to 64 (see below)

## Expected Results

### ✅ Good Audio
- Hearing the other person within 100–150ms
- Clear voice, no static or grain
- Occasional "dropped sample" messages (1–5 per minute) is normal

### ⚠️ Degraded Audio
- Still hearing lag > 200ms → Lower buffer (see Adjustments)
- Frequent clicking/popping → Increase buffer
- Constant "Buffer full" warnings → Increase queue size

## Adjustments

### If You See Many "Buffer full" Warnings

Edit `/home/iliketrains2314/PQC-Post-Quantum-Chatting-12-6/src/gui/enhanced_main.rs` around line 199:

```rust
// Change from:
let (command_sender, command_receiver) = mpsc::channel(32);

// To:
let (command_sender, command_receiver) = mpsc::channel(64);
```

Then rebuild:
```bash
cd ~/PQC---Post-Quantum-Chatting
cargo build --release
sudo ./scripts/deploy_pi_network.sh
```

### If Latency Still Feels High

Edit `/home/iliketrains2314/PQC-Post-Quantum-Chatting-12-6/src/audio.rs` around line 35:

```rust
// Change from:
const PLAYBACK_BUFFER_MS: usize = 80;

// To (more aggressive):
const PLAYBACK_BUFFER_MS: usize = 50;
```

Then rebuild and redeploy.

### If You Hear Clicks/Pops (Underruns)

Edit the same file, increase buffer:

```rust
// Change from:
const PLAYBACK_BUFFER_MS: usize = 80;

// To (more stable):
const PLAYBACK_BUFFER_MS: usize = 120;
```

Then rebuild and redeploy.

## Troubleshooting

### "Connection failed" Error

```bash
# From a client Pi, test network:
ping 192.168.10.101
nc -zv 192.168.10.101 8443
```

If ping fails → Network issue, check `NETWORK_SETUP.md`  
If port 8443 fails → Server not running or crashed

### No Audio Heard

1. Check audio devices exist:
   ```bash
   arecord -l
   aplay -l
   ```

2. Test audio manually:
   ```bash
   arecord -f cd -t wav -d 3 test.wav && aplay test.wav
   ```

3. Check GUI debug output for "Audio call started"

4. Verify both clients are in the same room

### Audio is Very Garbled

- Likely overrun/underrun (buffer mismatch)
- Try increasing `PLAYBACK_BUFFER_MS` to 100–150ms
- Rebuild and test again

## What Changed (Under the Hood)

**Dec 6, 2025 Audio Optimizations:**

1. **Bounded command queue** (size 32):
   - Prevents unbounded backlog of audio packets
   - Drops packets when queue is full (good for latency)

2. **Reduced playback buffer** (200ms → 80ms):
   - Cuts perceived latency by ~120ms
   - Still safe on Raspberry Pi 5 hardware

3. **Non-blocking sends** from CPAL audio thread:
   - Uses `try_send()` instead of `send()`
   - Avoids blocking the capture thread

These changes prioritize **low latency** over **perfect audio delivery** — you'll get responsive calls at the cost of an occasional dropped packet, which is better than hearing everything 300ms late.

## Next Steps

1. Run this test on all 3 Pis
2. Note the latency you observe
3. If unsatisfied, adjust buffer/queue and retest
4. For production, consider UDP-based media transport and Opus encoding (see `README_PI_NETWORK.md`)

Good luck! 🎤
