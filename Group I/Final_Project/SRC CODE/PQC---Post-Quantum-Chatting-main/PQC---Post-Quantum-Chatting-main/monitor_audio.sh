#!/bin/bash
# Monitor audio call activity

echo "🎤 Monitoring Audio Call Activity"
echo "=================================="
echo ""
echo "Watching for:"
echo "  - Audio device access"
echo "  - Audio processes"
echo "  - Network audio traffic"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Monitor ALSA device access
echo "📊 Current audio processes:"
lsof /dev/snd/* 2>/dev/null | grep pqc || echo "No PQC audio activity yet"

echo ""
echo "🔊 Audio devices in use:"
fuser -v /dev/snd/* 2>&1 | grep pqc || echo "No devices in use by PQC yet"

echo ""
echo "💾 Memory usage:"
ps aux | grep pqc-enhanced-gui | grep -v grep | head -1

echo ""
echo "🌐 Network connections:"
netstat -tnp 2>/dev/null | grep pqc-enhanced-gui || echo "No network connections yet"

echo ""
echo "=================================="
echo "Now try starting a call in the GUI and run this script again!"
