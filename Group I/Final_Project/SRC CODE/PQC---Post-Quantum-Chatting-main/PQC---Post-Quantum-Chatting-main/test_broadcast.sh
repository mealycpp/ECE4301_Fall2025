#!/bin/bash

# Test script to verify live broadcasting functionality

echo "🧪 Testing PQC Chat Live Broadcasting"
echo "====================================="

# Kill any existing clients
pkill -f pqc-interactive 2>/dev/null
pkill -f pqc-client 2>/dev/null

echo "📡 Starting server log monitoring..."
# Start monitoring server logs in background
sudo journalctl -u pqc-chat-server -f > /tmp/server_logs &
SERVER_LOG_PID=$!

sleep 2

echo "🚀 Starting Client 1..."
# Start first client in background
(
    sleep 2
    echo "create TestRoom"
    sleep 2
    echo "join TestRoom"
    sleep 5
    echo "leave" 
    sleep 2
    echo "quit"
) | ./target/release/pqc-interactive --config config/server_client_pi.toml --username Client1 > /tmp/client1_output 2>&1 &
CLIENT1_PID=$!

sleep 3

echo "🚀 Starting Client 2..." 
# Start second client in background  
(
    sleep 2
    echo "rooms"
    sleep 2
    echo "join TestRoom"
    sleep 5
    echo "quit"
) | ./target/release/pqc-interactive --config config/client1_pi.toml --username Client2 > /tmp/client2_output 2>&1 &
CLIENT2_PID=$!

echo "⏳ Waiting for clients to interact..."
sleep 15

echo "🛑 Stopping clients..."
kill $CLIENT1_PID $CLIENT2_PID 2>/dev/null
kill $SERVER_LOG_PID 2>/dev/null

echo ""
echo "📋 CLIENT 1 OUTPUT:"
echo "==================="
cat /tmp/client1_output

echo ""
echo "📋 CLIENT 2 OUTPUT:"
echo "==================="
cat /tmp/client2_output

echo ""
echo "📋 SERVER LOGS:"
echo "==============="
cat /tmp/server_logs | tail -20

echo ""
echo "🔍 Looking for broadcast messages in server logs..."
grep -i "broadcasting\|participant.*joined\|participant.*left" /tmp/server_logs || echo "❌ No broadcast messages found"

# Cleanup
rm -f /tmp/client1_output /tmp/client2_output /tmp/server_logs