# Audio Call Testing Guide

## ✅ Audio Implementation Complete!

The audio call feature is now fully implemented and ready to test.

## 🎯 What to Test

### Test 1: Local Audio (Single Machine)
1. **Run GUI**: `/opt/pqc-chat/bin/pqc-enhanced-gui`
2. **Connect** to server (192.168.10.101:8443)
3. **Join a room** (e.g., "test")
4. **Click "📞 Start Call"**
5. **Check status messages** - Should see "🎤 Audio call started - speak now!"
6. **Speak into microphone** - Audio is being captured and sent
7. **Click "📞 End Call"** - Should see "🔇 Audio call ended"

### Test 2: Two-Way Audio (Two Machines)
**On Machine 1 (Your Pi):**
1. Run GUI: `/opt/pqc-chat/bin/pqc-enhanced-gui`
2. Connect to server
3. Join room "audiotest"
4. Click "📞 Start Call"

**On Machine 2 (Friend's Pi):**
1. Run GUI: `/opt/pqc-chat/bin/pqc-enhanced-gui`
2. Connect to server
3. Join room "audiotest"
4. Click "📞 Start Call"

**Both machines should now be able to:**
- Hear each other speak
- See status messages when audio starts/stops
- Have low-latency voice chat (~20-40ms)

## 🔍 What to Look For

### ✅ Success Indicators:
- Status message: "🎤 Audio call started - speak now!"
- No error messages
- Can hear yourself (if on same machine) or friend (if on different machines)
- Low latency (immediate response)
- Clear audio quality

### ❌ Problem Indicators:
- Error message: "❌ Failed to create audio manager"
- Error message: "❌ Failed to start playback"
- Error message: "❌ Failed to start capture"
- No audio being received
- Choppy or delayed audio

## 🐛 Troubleshooting

### Problem: No audio captured
```bash
# Check microphone
arecord -l

# Test microphone
arecord -d 3 /tmp/test.wav
aplay /tmp/test.wav

# Check ALSA mixer
alsamixer
```

### Problem: No audio playback
```bash
# Check speakers
aplay -l

# Test speakers
speaker-test -t wav -c 1
```

### Problem: "Failed to create audio manager"
```bash
# Reinstall ALSA libraries
sudo apt-get install --reinstall libasound2-dev

# Check if another application is using audio
lsof /dev/snd/*
```

### Problem: Feedback/echo
- **Use headphones** instead of speakers
- Reduce speaker volume
- Keep microphone away from speakers

### Problem: Choppy audio
- Check network latency: `ping 192.168.10.101`
- Close other bandwidth-heavy applications
- Ensure both machines are on same LAN
- Check CPU usage: `htop`

## 📊 Expected Performance

### Audio Quality:
- **Sample Rate**: 48kHz
- **Channels**: Mono
- **Bit Depth**: 32-bit float
- **Latency**: 20-40ms on LAN
- **Bandwidth**: ~384 kbps per participant

### System Resources:
- **CPU**: <1% per audio stream
- **Memory**: ~10MB per active call
- **Network**: 384 kbps per sender

## 🎤 Audio Flow

```
Machine 1 (You)                     Server                      Machine 2 (Friend)
===============                     ======                      =================
Microphone                                                      
    ↓                                                           
Capture (48kHz)                                                 
    ↓                                                           
Convert to bytes                                                
    ↓                                                           
SendAudioData ────────────────────→ Receive                     
                                        ↓                       
                                    Broadcast                   
                                        ↓                       
                                  AudioDataReceived ──────────→ Receive
                                                                    ↓
                                                               Convert to samples
                                                                    ↓
                                                               Playback (48kHz)
                                                                    ↓
                                                               Speakers/Headset
```

## 🧪 Test Scenarios

### Scenario 1: Quick Test
1. Both users join same room
2. Both click "Start Call"
3. User 1 says "Testing, one, two, three"
4. User 2 confirms they heard it
5. User 2 responds "Confirmed, I hear you"
6. User 1 confirms they heard it
7. Both click "End Call"

### Scenario 2: Multi-Party Test (3+ users)
1. All users join same room
2. All click "Start Call"
3. Users take turns speaking
4. Verify everyone can hear everyone

### Scenario 3: Connection Quality Test
1. Start call between two users
2. Have continuous conversation for 5 minutes
3. Check for:
   - Audio dropouts
   - Latency increase
   - Quality degradation

### Scenario 4: Stress Test
1. Multiple rooms with audio calls
2. Monitor server CPU/memory
3. Check for performance degradation

## 📝 Test Results Log

Copy this template to record your tests:

```
Date: __________
Tester: __________

Test 1: Local Audio
[ ] Started call successfully
[ ] Heard audio feedback
[ ] Stopped call successfully
Notes: _________________________________

Test 2: Two-Way Audio
Machine 1: __________
Machine 2: __________
[ ] Both started calls
[ ] Machine 1 heard Machine 2
[ ] Machine 2 heard Machine 1
[ ] Low latency (<100ms)
[ ] Good audio quality
Notes: _________________________________

Issues Found:
_________________________________
_________________________________
```

## 🎉 Success Criteria

Audio calls are working if:
✅ Both users can start/stop calls
✅ Audio is transmitted in both directions
✅ Latency is acceptable (<100ms)
✅ Audio quality is clear
✅ No crashes or errors
✅ System resources reasonable

## 🚀 Next Steps After Testing

Once audio works:
1. Consider adding **Opus compression** (reduce bandwidth)
2. Add **echo cancellation** (prevent feedback)
3. Add **noise suppression** (cleaner audio)
4. Add **volume controls** (adjust levels)
5. Add **audio device selection** (choose mic/speakers)
6. Add **mute button** (quick audio toggle)

## 📞 Quick Commands

```bash
# Run GUI
/opt/pqc-chat/bin/pqc-enhanced-gui

# Check audio hardware
./test_audio.sh

# Monitor audio
alsamixer

# Check server logs
sudo journalctl -u pqc-chat-server -f

# Monitor network
iftop

# Monitor CPU
htop
```

Happy testing! 🎤🎧
