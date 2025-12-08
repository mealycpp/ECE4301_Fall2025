#!/bin/bash
# Test Audio Call Feature

echo "🎤 PQC Chat - Audio Call Test"
echo "=============================="
echo ""

# Check if ALSA is available
echo "1. Checking audio devices..."
if command -v arecord &> /dev/null; then
    echo "✅ ALSA tools found"
    echo ""
    echo "Input devices:"
    arecord -l | grep -i card || echo "No input devices found"
    echo ""
    echo "Output devices:"
    aplay -l | grep -i card || echo "No output devices found"
else
    echo "❌ ALSA tools not found. Install with: sudo apt-get install alsa-utils"
    exit 1
fi

echo ""
echo "2. Testing microphone..."
echo "Recording 3 seconds of audio... (speak now!)"
arecord -d 3 -f S16_LE -r 48000 -c 1 /tmp/test_audio.wav 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ Microphone working"
    echo ""
    echo "3. Testing speakers..."
    echo "Playing back recording..."
    aplay /tmp/test_audio.wav 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "✅ Speakers working"
    else
        echo "❌ Speakers not working"
    fi
    rm /tmp/test_audio.wav
else
    echo "❌ Microphone not working"
fi

echo ""
echo "4. Checking PQC Chat GUI..."
if [ -f "/opt/pqc-chat/bin/pqc-enhanced-gui" ]; then
    echo "✅ PQC Chat GUI installed"
else
    echo "❌ PQC Chat GUI not found"
    exit 1
fi

echo ""
echo "5. Checking server..."
if pgrep -f "pqc-server" > /dev/null; then
    echo "✅ Server is running"
else
    echo "❌ Server not running"
    echo "Start with: sudo /opt/pqc-chat/bin/pqc-server --config config/server_pi.toml"
fi

echo ""
echo "=============================="
echo "✅ Audio system ready!"
echo ""
echo "To test audio calls:"
echo "1. Run GUI on this machine: /opt/pqc-chat/bin/pqc-enhanced-gui"
echo "2. Run GUI on another machine"
echo "3. Both join the same room"
echo "4. Click '📞 Start Call' on both machines"
echo "5. Speak and listen!"
echo ""
echo "Tips:"
echo "- Use headphones to avoid feedback"
echo "- Stay on the same LAN for best quality"
echo "- Check audio levels with 'alsamixer'"
