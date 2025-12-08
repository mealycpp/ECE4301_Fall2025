# Ultra-Low Latency Audio Configuration

## Changes Made for Minimum Delay

### 1. Reduced Packet Size: 5ms (was 10ms)
```rust
const BUFFER_SIZE: usize = 240;  // 5ms at 48kHz
```
**Impact**: Audio is sent more frequently = faster transmission

### 2. Reduced Playback Buffer: 60ms (was 100ms)
```rust
const PLAYBACK_BUFFER_MS: usize = 60;  // 60ms buffer
```
**Impact**: Less audio queued = lower delay

### 3. Zero Prefill
```rust
// NO prefill - start immediately to minimize latency
// First packet may glitch but subsequent audio will be real-time
```
**Impact**: No startup delay, audio starts playing immediately

### 4. Aggressive Buffer Management (30% threshold)
```rust
if buffer_percent > 30 {
    // Skip packet if buffer is >30% full
    // 30% of 60ms = ~18ms buffered
}
```
**Impact**: Keeps latency under 20ms by dropping packets when accumulating

### 5. Immediate Packet Sending
```rust
// Send data as soon as we get any
for sample in data {
    audio_buffer.push(*sample);
    if audio_buffer.len() >= BUFFER_SIZE {
        callback(chunk);  // Send immediately
    }
}
```
**Impact**: No waiting to accumulate data before sending

## Expected Latency Breakdown (OPTIMIZED)

| Component | Latency | Notes |
|-----------|---------|-------|
| Capture | 5ms | Very small buffer |
| Encoding | <1ms | Simple byte conversion |
| Network | 5-15ms | LAN only (same subnet) |
| Playback buffer | 5-18ms | Aggressive 30% limit |
| **Total** | **15-39ms** | Typical: ~20-25ms |

### Previous Configuration
- Total: 30-86ms (typical 40-60ms)

### Current Configuration  
- Total: 15-39ms (typical 20-25ms)
- **~50% latency reduction!**

## Trade-offs

### Pros ✅
- **Ultra-low latency**: ~20-25ms feels almost instantaneous
- **Real-time feel**: Like talking in person
- **Aggressive packet dropping**: Prioritizes current audio over old

### Cons ⚠️
- **More packet drops**: On any network congestion
- **Potential audio glitches**: If Pi is under heavy load
- **Less jitter tolerance**: Needs very stable network

## Network Requirements

**CRITICAL**: This configuration assumes:
- Both Pis on **same LAN** (same switch/router)
- Network latency **< 10ms**
- No other heavy network traffic
- Stable connection (no packet loss)

## Testing

Run audio test and observe debug output:

**Good (low latency)**:
```
DEBUG: Audio from xxx: 240 samples, pushed 240, buffer 15% (9ms), max_amp=0.0124
```

**Buffer building up (will drop next packet)**:
```
DEBUG: Audio from xxx: 240 samples, pushed 240, buffer 35% (21ms), max_amp=0.0124
WARNING: Buffer 35% full (21ms audio queued), skipping packet for real-time
```

## If You Experience Issues

### Audio cutting out frequently
**Cause**: Network too slow or unstable  
**Fix**: Increase `PLAYBACK_BUFFER_MS` to 100 and threshold to 50%

### Still too much latency
**Cause**: Network delay between Pis  
**Fix**: Check network with `ping` - should be <5ms

### Audio quality poor
**Cause**: Packet size too small causing overhead  
**Fix**: Increase `BUFFER_SIZE` to 480 (10ms)

## Verification Commands

```bash
# Check network latency between Pis
ping -c 10 192.168.10.XXX

# Should see:
# rtt min/avg/max = 1.xxx/2.xxx/5.xxx ms
# If avg > 10ms, network is too slow for ultra-low latency

# Monitor audio in real-time
/opt/pqc-chat/bin/pqc-enhanced-gui 2>&1 | grep -E "DEBUG|WARNING"
```

## Summary

These changes prioritize **latency over reliability**:
- Smaller buffers = less delay
- Aggressive dropping = stay real-time
- No prefill = instant start
- 5ms packets = faster transmission

**Perfect for**: LAN with stable connection  
**Not good for**: Internet or wireless connections with jitter
