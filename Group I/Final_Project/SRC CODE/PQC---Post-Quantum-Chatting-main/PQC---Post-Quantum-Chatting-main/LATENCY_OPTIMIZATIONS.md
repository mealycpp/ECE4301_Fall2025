# Audio Latency Optimizations

## Problem
Audio had noticeable delay - speaking would take time before the listener heard it.

## Root Causes
1. **Large audio buffer**: 2-second ring buffer (96,000 samples)
2. **Large capture chunks**: 20ms packets (960 samples)
3. **Prefill delay**: 40ms of silence added before playback
4. **No buffer management**: Old audio accumulated causing increasing delay

## Solutions Implemented

### 1. Reduced Buffer Size (200ms → was 2 seconds)
**File**: `src/audio.rs` line 152
```rust
// Before: 2 seconds = 96,000 samples
let ring_buffer = HeapRb::<f32>::new(SAMPLE_RATE as usize * 2);

// After: 200ms = 9,600 samples
let ring_buffer = HeapRb::<f32>::new(SAMPLE_RATE as usize / 5);
```
**Impact**: Reduces maximum possible latency from 2000ms → 200ms

### 2. Smaller Capture Chunks (10ms → was 20ms)
**File**: `src/audio.rs` line 28
```rust
// Before: 20ms chunks
const BUFFER_SIZE: usize = 960;  // 20ms at 48kHz

// After: 10ms chunks
const BUFFER_SIZE: usize = 480;  // 10ms at 48kHz
```
**Impact**: Faster packet transmission, 10ms less base latency

### 3. Minimal Prefill (5ms → was 40ms)
**File**: `src/audio.rs` line 156
```rust
// Before: 40ms prefill
for _ in 0..(BUFFER_SIZE * 2) {

// After: 5ms prefill
for _ in 0..(BUFFER_SIZE / 2) {
```
**Impact**: 35ms less startup delay

### 4. Buffer Overflow Protection
**File**: `src/gui/enhanced_main.rs` line 414-420
- If buffer fills up, new audio stops being queued
- Prevents infinite latency accumulation
- Keeps audio "real-time" by dropping old data when needed

## Expected Latency Breakdown

| Component | Latency | Notes |
|-----------|---------|-------|
| Capture | 10ms | Buffer fill time |
| Encoding | <1ms | Simple byte conversion |
| Network | 5-20ms | LAN, depends on congestion |
| Playback prefill | 5ms | Initial buffer |
| Playback buffer | 10-50ms | Jitter absorption |
| **Total** | **30-86ms** | Typical: ~40-60ms |

### Before Optimizations
- Base latency: 60ms
- Buffer accumulation: up to 2000ms
- **Total: 60-2000ms+**

### After Optimizations
- Base latency: 30ms
- Maximum buffer: 200ms
- **Total: 30-200ms** (typically 40-60ms)

## Testing
Run two GUI instances and speak. You should now hear:
- **Immediate response** (~40-60ms delay)
- **No accumulating delay** over time
- **Slight audio drops** if network is congested (this is intentional - keeps latency low)

## Future Improvements (Optional)
1. **Adaptive jitter buffer**: Automatically adjust buffer size based on network conditions
2. **Opus codec**: 6-12 kbps audio with built-in FEC (Forward Error Correction)
3. **WebRTC-style buffering**: More sophisticated packet loss concealment
4. **QoS markers**: Prioritize audio packets in network stack

## Trade-offs
✅ **Much lower latency**: 40-60ms typical (was 60-2000ms)
✅ **Real-time feel**: Like phone call
⚠️ **Possible audio dropouts**: If network lags, audio may skip (better than delay)
⚠️ **Less jitter tolerance**: Needs stable LAN connection

For Raspberry Pi on LAN: These trade-offs are excellent!
