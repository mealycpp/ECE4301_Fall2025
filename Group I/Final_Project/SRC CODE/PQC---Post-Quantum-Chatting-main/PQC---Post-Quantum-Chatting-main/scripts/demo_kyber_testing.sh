#!/bin/bash
# Quick Demo - Kyber Performance Testing
# 
# This script demonstrates the Kyber testing tools with a simple workflow

set -e

# Create organized results directory structure
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BASE_RESULTS_DIR="./results"
RESULTS_DIR="$BASE_RESULTS_DIR/kyber_demo_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"

echo "🔐 PQC Chat - Kyber Performance Testing Demo"
echo "============================================"
echo "📁 Results directory: $BASE_RESULTS_DIR/"
echo "📁 This test saved to: $RESULTS_DIR/"
echo ""

# Check if server is running
if ! systemctl is-active --quiet pqc-chat-server; then
    echo "⚠️ Starting PQC server..."
    sudo systemctl start pqc-chat-server
    sleep 3
fi

# Verify server is actually listening on the expected port
echo "🔍 Checking server connectivity..."
if ! ss -tln | grep -q ":8443 "; then
    echo "❌ Server not listening on port 8443. Checking what's running..."
    echo "Listening ports:"
    ss -tln | grep LISTEN
    echo ""
    echo "Server status:"
    systemctl status pqc-chat-server --no-pager
    exit 1
fi

echo "✅ Server is running and listening on port 8443"
echo ""

# Build the test client if needed
if [[ ! -f "./target/release/pqc-kyber-test" ]]; then
    echo "🔨 Building Kyber test client..."
    cargo build --release --bin pqc-kyber-test
    echo "✅ Build complete"
    echo ""
fi

echo "🧪 Running Kyber performance tests..."
echo ""

# Test 1: Quick single connection
echo "📊 Test 1: Single Connection Timing"
echo "-----------------------------------"
./target/release/pqc-kyber-test --server 127.0.0.1 --port 8443 --attempts 1 --verbose --username demo_user_$(date +%s) | tee "$RESULTS_DIR/test1_single_connection.log"
echo ""

# Test 2: Multiple attempts for statistics
echo "📊 Test 2: Statistical Analysis (5 attempts)"
echo "--------------------------------------------"
./target/release/pqc-kyber-test --server 127.0.0.1 --port 8443 --attempts 5 --username stats_test_$(date +%s) | tee "$RESULTS_DIR/test2_statistical_analysis.log"
echo ""

# Test 3: JSON output for analysis
echo "📊 Test 3: JSON Data Export"
echo "---------------------------"
json_file="$RESULTS_DIR/test3_json_data.json"
./target/release/pqc-kyber-test --server 127.0.0.1 --port 8443 --attempts 3 --json --username json_test_$(date +%s) > "$json_file"
echo "✅ JSON results saved to: $json_file"
echo ""

# Show JSON results summary
echo "📋 Results Summary:"
echo "-------------------"
summary_output=$(python3 -c "
import json
try:
    with open('$json_file') as f:
        data = json.load(f)
    summary = f'''✅ Success Rate: {data[\"success_rate\"]:.1f}%
⏱️  Average Total Time: {data[\"summary\"][\"avg_total_duration_ms\"]:.1f}ms
🔐 Average Kyber KeyGen: {data[\"summary\"][\"avg_kyber_keygen_ms\"]:.1f}ms  
🔐 Average Kyber Exchange: {data[\"summary\"][\"avg_kyber_exchange_ms\"]:.1f}ms
📊 Min/Max Total: {data[\"summary\"][\"min_total_duration_ms\"]}ms / {data[\"summary\"][\"max_total_duration_ms\"]}ms'''
    print(summary)
    # Save summary to file
    with open('$RESULTS_DIR/summary.txt', 'w') as f:
        f.write(summary)
except Exception as e:
    print(f'❌ Error reading results: {e}')
" 2>/dev/null || echo "⚠️ Python analysis unavailable")

echo "$summary_output"

# Test 4: Server log analysis
echo "📊 Test 4: Server Log Analysis"
echo "------------------------------"
echo "Capturing recent server logs..."
journalctl -u pqc-chat-server --since "1 minute ago" > "$RESULTS_DIR/server_logs.txt" 2>/dev/null || echo "⚠️ Server logs not accessible"

# Save system information
echo "💻 Test 5: System Information"
echo "-----------------------------"
{
    echo "=== System Information ==="
    echo "Date: $(date)"
    echo "Hostname: $(hostname)"
    echo "CPU: $(lscpu | grep 'Model name' | cut -d':' -f2 | xargs)"
    echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}')"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo ""
    echo "=== Network Configuration ==="
    ip addr show | grep -E "(inet |UP,BROADCAST)"
    echo ""
    echo "=== PQC Server Status ==="
    systemctl status pqc-chat-server --no-pager || echo "Server status unavailable"
} > "$RESULTS_DIR/system_info.txt"

echo "✅ System information saved"

# Create README for results directory
cat > "$RESULTS_DIR/README.md" << EOF
# Kyber Performance Test Results

Test conducted on: $(date)
Duration: ~30 seconds (demo test)

## Files in this directory:

- **test1_single_connection.log**: Single connection timing test with verbose output
- **test2_statistical_analysis.log**: Multiple connection test for statistical analysis  
- **test3_json_data.json**: Raw JSON timing data for further analysis
- **summary.txt**: Quick summary of key performance metrics
- **server_logs.txt**: Server-side logs during testing period
- **system_info.txt**: System configuration and status information
- **README.md**: This file

## Key Metrics Summary:

$(cat "$RESULTS_DIR/summary.txt" 2>/dev/null || echo "Summary not available")

## Usage:

- Import JSON data: \`python3 -c "import json; data = json.load(open('test3_json_data.json'))"\`
- View logs: \`less test1_single_connection.log\`  
- Analyze timing: See avg_kyber_* fields in JSON data

EOF

echo ""
echo "🎉 Demo completed!"
echo ""
echo "📁 All results saved to: $RESULTS_DIR/"
echo "📁 View all results: ls -la $BASE_RESULTS_DIR/"
echo "   📄 README.md - Overview and instructions"
echo "   📊 test*_*.log - Human-readable test outputs"
echo "   🔬 test3_json_data.json - Raw data for analysis"
echo "   📋 summary.txt - Key performance metrics"
echo "   📝 server_logs.txt - Server-side logs"
echo "   💻 system_info.txt - System configuration"
echo ""
echo "📚 For more advanced testing, see:"
echo "   - KYBER_TESTING_GUIDE.md"
echo "   - ./scripts/kyber_test.sh"
echo "   - ./scripts/kyber_performance_logger.py"