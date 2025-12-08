#!/bin/bash
# Quick Kyber Performance Test Script
# 
# This script runs automated tests to measure Kyber key exchange
# performance and generates timing reports.

set -e

# Configuration
SERVER_IP="${1:-127.0.0.1}"
TEST_DURATION="${2:-30}"
BASE_RESULTS_DIR="./results"
OUTPUT_DIR="$BASE_RESULTS_DIR/kyber_test_$(date +%Y%m%d_%H%M%S)"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔐 PQC Chat Kyber Performance Test${NC}"
echo "========================================"
echo "Server IP: $SERVER_IP"
echo "Test Duration: ${TEST_DURATION}s"
echo "Output Directory: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to measure connection time
measure_connection_time() {
    local client_name="$1"
    local start_time=$(date +%s.%N)
    
    log "Starting connection test for $client_name"
    
    # Run client with timing and capture output
    timeout 10s /opt/pqc-chat/bin/pqc-client \
        --server "$SERVER_IP" \
        --port 8444 \
        --username "test_${client_name}_${TIMESTAMP}" \
        > "$OUTPUT_DIR/client_${client_name}_${TIMESTAMP}.log" 2>&1 || true
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    
    log "Connection test completed for $client_name in ${duration}s"
    echo "$duration" > "$OUTPUT_DIR/timing_${client_name}_${TIMESTAMP}.txt"
}

# Function to analyze server logs for Kyber metrics
analyze_kyber_logs() {
    log "Analyzing server logs for Kyber performance..."
    
    local log_file="$OUTPUT_DIR/server_analysis_${TIMESTAMP}.txt"
    local since_time=$(date -d "1 minute ago" '+%Y-%m-%d %H:%M:%S')
    
    echo "=== Kyber Key Exchange Analysis ===" > "$log_file"
    echo "Analysis Time: $(date)" >> "$log_file"
    echo "Analyzing logs since: $since_time" >> "$log_file"
    echo "" >> "$log_file"
    
    # Extract Kyber-related log entries
    journalctl -u pqc-chat-server --since "$since_time" | \
        grep -i "kyber\|key.exchange" >> "$log_file" 2>/dev/null || \
        echo "No Kyber logs found" >> "$log_file"
    
    echo "" >> "$log_file"
    
    # Count successful exchanges
    local kyber_count=$(journalctl -u pqc-chat-server --since "$since_time" | \
        grep -c "Kyber key exchange completed" 2>/dev/null || echo "0")
    
    echo "Successful Kyber Exchanges: $kyber_count" >> "$log_file"
    
    # Extract timing information if available
    echo "" >> "$log_file"
    echo "=== Connection Timings ===" >> "$log_file"
    journalctl -u pqc-chat-server --since "$since_time" | \
        grep -E "Connected|login|participant" >> "$log_file" 2>/dev/null || \
        echo "No timing logs found" >> "$log_file"
    
    log "Server log analysis saved to $log_file"
}

# Function to test multiple concurrent connections
test_concurrent_connections() {
    local num_connections="${1:-3}"
    
    log "Testing $num_connections concurrent connections for Kyber exchange timing"
    
    local pids=()
    
    # Start multiple clients simultaneously
    for i in $(seq 1 $num_connections); do
        (measure_connection_time "concurrent_$i") &
        pids+=($!)
        sleep 0.5  # Small delay to avoid overwhelming
    done
    
    # Wait for all clients to complete
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    log "Concurrent connection test completed"
}

# Function to generate summary report
generate_summary() {
    local summary_file="$OUTPUT_DIR/kyber_summary_${TIMESTAMP}.txt"
    
    echo "PQC Chat Kyber Performance Summary" > "$summary_file"
    echo "===================================" >> "$summary_file"
    echo "Test Date: $(date)" >> "$summary_file"
    echo "Server: $SERVER_IP" >> "$summary_file"
    echo "Test Duration: ${TEST_DURATION}s" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Connection timing summary
    echo "Connection Timing Results:" >> "$summary_file"
    echo "--------------------------" >> "$summary_file"
    
    local total_time=0
    local count=0
    
    for timing_file in "$OUTPUT_DIR"/timing_*_${TIMESTAMP}.txt; do
        if [[ -f "$timing_file" ]]; then
            local time=$(cat "$timing_file")
            local client_name=$(basename "$timing_file" | sed "s/timing_\(.*\)_${TIMESTAMP}.txt/\1/")
            
            echo "  $client_name: ${time}s" >> "$summary_file"
            total_time=$(echo "$total_time + $time" | bc)
            ((count++))
        fi
    done
    
    if [[ $count -gt 0 ]]; then
        local avg_time=$(echo "scale=3; $total_time / $count" | bc)
        echo "" >> "$summary_file"
        echo "Average Connection Time: ${avg_time}s" >> "$summary_file"
        echo "Total Connections Tested: $count" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    
    # System information
    echo "System Information:" >> "$summary_file"
    echo "-------------------" >> "$summary_file"
    echo "CPU: $(lscpu | grep 'Model name' | cut -d':' -f2 | xargs)" >> "$summary_file"
    echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}')" >> "$summary_file"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)" >> "$summary_file"
    
    log "Summary report generated: $summary_file"
    
    # Display summary on console
    echo -e "\n${GREEN}=== PERFORMANCE SUMMARY ===${NC}"
    cat "$summary_file" | tail -n +4
}

# Main test execution
main() {
    log "Starting Kyber performance testing..."
    
    # Check if server is running
    if ! systemctl is-active --quiet pqc-chat-server; then
        echo -e "${YELLOW}⚠️ Warning: pqc-chat-server is not running${NC}"
        echo "Starting server..."
        sudo systemctl start pqc-chat-server
        sleep 3
    fi
    
    # Check server connectivity
    if ! ping -c 1 -W 1 "$SERVER_IP" > /dev/null 2>&1; then
        echo -e "${RED}❌ Error: Cannot reach server at $SERVER_IP${NC}"
        exit 1
    fi
    
    log "Server is reachable, starting tests..."
    
    # Run tests
    echo -e "${YELLOW}🧪 Running single connection test...${NC}"
    measure_connection_time "single"
    
    echo -e "${YELLOW}🧪 Running concurrent connection test...${NC}"
    test_concurrent_connections 3
    
    echo -e "${YELLOW}📊 Analyzing server logs...${NC}"
    analyze_kyber_logs
    
    echo -e "${YELLOW}📋 Generating summary report...${NC}"
    generate_summary
    
    log "All tests completed successfully!"
    
    echo -e "\n${GREEN}✅ Test Results Available:${NC}"
    echo "  - Raw logs: $OUTPUT_DIR/"
    echo "  - Summary: $OUTPUT_DIR/kyber_summary_${TIMESTAMP}.txt"
    echo "  - Server analysis: $OUTPUT_DIR/server_analysis_${TIMESTAMP}.txt"
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v bc &> /dev/null; then
        missing_deps+=("bc")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}❌ Missing dependencies: ${missing_deps[*]}${NC}"
        echo "Install with: sudo apt install ${missing_deps[*]}"
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_dependencies
    main "$@"
fi