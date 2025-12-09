# Quick Reference Card - 3 Pi Setup

## 🔑 Phase 1: Group Key Setup (One-Time)

### Order: Members First, Then Leader

```bash
# Pi2 & Pi3 (Start FIRST - they listen)
./target/release/stream --mode group-member --node-id pi-2 --port 9000

# Pi1 (Start LAST - it connects)
./target/release/stream --mode group-leader \
  --members pi-2:192.168.1.102:9000,pi-3:192.168.1.103:9000
```

**Result:** All Pis have `group_key.bin`

---

## 🎥 Phase 2: Video Streaming

### Order: Receivers First, Then Sender

### Setup A: Broadcast (1 → Many)
```bash
# Pi2 & Pi3 (Start FIRST)
Pi2: ./target/release/stream --mode receiver --mechanism group --port 8443
Pi3: ./target/release/stream --mode receiver --mechanism group --port 8444 --display

# Pi1 (Start LAST - run twice for 2 streams)
./target/release/stream --mode sender --mechanism group --host 192.168.1.102 --port 8443
./target/release/stream --mode sender --mechanism group --host 192.168.1.103 --port 8444
```

### Setup B: Relay Chain (1 → 2 → 3)
```bash
# Pi3 (Start FIRST)
./target/release/stream --mode receiver --mechanism group --port 8444 --display

# Pi2 (Start SECOND)
./target/release/stream --mode relay --mechanism group --port 8443 \
  --relay-host 192.168.1.103 --relay-port 8444

# Pi1 (Start LAST)
./target/release/stream --mode sender --mechanism group --host 192.168.1.102 --port 8443
```

---

## 📊 All Modes Cheat Sheet

| Mode | What It Does | Required Args |
|------|--------------|---------------|
| `group-leader` | Generates & distributes group key | `--members` |
| `group-member` | Receives group key from leader | `--port` |
| `sender` | Captures & sends encrypted video | `--host`, `--port` |
| `receiver` | Receives & decrypts video | `--port` |
| `relay` | Decrypt, re-encrypt, forward | `--port`, `--relay-host`, `--relay-port` |

---

## 🔧 Common Flags

```bash
--mode <MODE>              # sender, receiver, relay, group-leader, group-member
--mechanism <MECH>         # ecdh, rsa, group
--host <IP>                # Target IP (sender/relay)
--port <PORT>              # Listen/connect port
--video-source <SRC>       # camera, v4l2, libcamera
--video-device <DEV>       # /dev/video0
--display                  # Show video (receiver only)
--simulate                 # Fake video data
--group-key-file <PATH>    # group_key.bin (default)
--node-id <ID>             # Identifier for metrics
```

---

## 🚨 Common Issues

| Problem | Solution |
|---------|----------|
| "Connection refused" | Start receiver/member FIRST, sender/leader LAST |
| "Tag mismatch" | Verify same `group_key.bin` on all Pis (`sha256sum`) |
| "Camera not found" | Check `ls /dev/video*` or use `--simulate` |
| "Display failed" | Run `export DISPLAY=:0` |
| "Members required" | Need `--members` for `group-leader` mode |

---

## 📈 Typical Timeline

```
0:00 - Start Pi2, Pi3 as group-member (they wait)
0:05 - Start Pi1 as group-leader (distributes key)
0:10 - All have group_key.bin ✓
0:15 - Start Pi2, Pi3 as receiver (they wait) 
0:20 - Start Pi1 as sender (connects & streams)
1:20 - Stream ends (60s default), check metrics
```

---

## 🔄 Quick Reset

```bash
# Stop all processes
killall stream

# Clear old keys
rm group_key.bin

# Start fresh from Phase 1
```
