#!/bin/bash
# Verify audio call is working

echo "🔍 Audio Call Diagnostics"
echo "=========================="
echo ""

# Check if GUI is running
GUI_PID=$(pgrep -f pqc-enhanced-gui)
if [ -z "$GUI_PID" ]; then
    echo "❌ GUI not running"
    exit 1
fi
echo "✅ GUI running (PIDs: $GUI_PID)"

# Check audio device usage
echo ""
echo "🎤 Audio device usage:"
lsof /dev/snd/* 2>/dev/null | grep pqc-enhanced-gui | while read line; do
    echo "  ✅ $line"
done || echo "  ⚠️  No audio devices in use (call may not be active)"

# Check for ALSA processes
echo ""
echo "🔊 ALSA processes:"
ps aux | grep -E "pqc-enhanced-gui.*ALSA" | grep -v grep || echo "  Check with: ps aux | grep pqc-enhanced-gui"

# Memory check
echo ""
echo "💾 Memory usage per GUI instance:"
ps aux | grep pqc-enhanced-gui | grep -v grep | awk '{print "  Instance: " $2 " - " $4 "% RAM (" $6 " KB)"}'

# Check audio mixer levels
echo ""
echo "🎚️  Audio levels:"
amixer sget Master 2>/dev/null | grep -E "Playback|Mono:" || echo "  Master volume unknown"
amixer sget Capture 2>/dev/null | grep -E "Playback|Capture:" || echo "  Capture volume unknown"

# Sample audio data sizes (if logs available)
echo ""
echo "📊 Recent audio activity (last 5 seconds):"
echo "  Run with: journalctl --user -u pqc-enhanced-gui -f"
echo "  Or check terminal output for 'DEBUG: Playing audio' messages"

echo ""
echo "=========================="
echo "Quick Test:"
echo "  1. Start call in both GUIs"
echo "  2. Speak into microphone"
echo "  3. Check if you hear yourself from other GUI"
echo ""
echo "If audio is too quiet:"
echo "  amixer set Master 80%"
echo "  amixer set Capture 80%"
