# Kyber Performance Testing Guide

This guide provides comprehensive tools for testing and analyzing Kyber key exchange performance in the PQC Chat system. These tools are designed to generate detailed reports for research and performance analysis.

## Available Tools

### 1. Kyber Performance Logger (`scripts/kyber_performance_logger.py`)
A comprehensive Python script that monitors system performance during Kyber operations.

**Features:**
- Real-time monitoring of Kyber key exchanges
- System resource usage tracking (CPU, memory)
- Network latency measurements
- Connection event logging
- JSON and human-readable report generation

**Usage:**
```bash
# Basic usage (60 second test)
python3 scripts/kyber_performance_logger.py

# Extended test with custom parameters
python3 scripts/kyber_performance_logger.py --duration 300 --server 192.168.10.101 --output detailed_report.json

# Generate human-readable report from existing JSON
python3 scripts/kyber_performance_logger.py --readable --output detailed_report.json
```

**Requirements:**
```bash
pip install psutil
```

### 2. Quick Kyber Test Script (`scripts/kyber_test.sh`)
A bash script for quick performance testing and timing measurements.

**Features:**
- Single and concurrent connection testing
- Connection timing measurements
- Server log analysis
- Automated report generation
- System information collection

**Usage:**
```bash
# Make executable
chmod +x scripts/kyber_test.sh

# Basic test (localhost, 30 seconds)
./scripts/kyber_test.sh

# Custom server and duration
./scripts/kyber_test.sh 192.168.10.101 60

# Results saved to ./kyber_test_results/
```

**Requirements:**
```bash
sudo apt install bc  # For calculations
```

### 3. Kyber Test Client (`pqc-kyber-test`)
A specialized Rust client that provides precise timing measurements for Kyber operations.

**Features:**
- Microsecond-precision timing
- Detailed breakdown of connection phases
- JSON output for data analysis
- Multiple connection attempts
- Statistical summaries

**Build and Usage:**
```bash
# Build the test client
cargo build --release --bin pqc-kyber-test

# Single connection test
./target/release/pqc-kyber-test --server 127.0.0.1 --username test_user

# Multiple attempts with detailed output
./target/release/pqc-kyber-test --attempts 10 --verbose --username load_test

# JSON output for analysis
./target/release/pqc-kyber-test --attempts 5 --json > kyber_timing_results.json

# Stress test with delays
./target/release/pqc-kyber-test --attempts 20 --delay 2 --server 192.168.10.101
```

## Test Scenarios

### Scenario 1: Basic Performance Baseline
Establish baseline Kyber performance metrics.

```bash
# Start server monitoring
python3 scripts/kyber_performance_logger.py --duration 120 --output baseline_test.json &

# Run test client
./target/release/pqc-kyber-test --attempts 10 --verbose --username baseline_user

# Wait for monitoring to complete, then generate report
python3 scripts/kyber_performance_logger.py --readable --output baseline_test.json
```

### Scenario 2: Load Testing
Test Kyber performance under concurrent connections.

```bash
# Quick load test
./scripts/kyber_test.sh 127.0.0.1 60

# Or detailed load test with concurrent clients
for i in {1..5}; do
  ./target/release/pqc-kyber-test --attempts 3 --username "load_test_$i" --json > "load_test_$i.json" &
done
wait  # Wait for all background jobs to complete
```

### Scenario 3: Network Latency Impact
Test how network conditions affect Kyber performance.

```bash
# Test localhost (baseline)
./target/release/pqc-kyber-test --attempts 5 --server 127.0.0.1 --json > localhost_results.json

# Test remote server
./target/release/pqc-kyber-test --attempts 5 --server 192.168.10.101 --json > remote_results.json

# Compare results
echo "Localhost vs Remote Kyber Performance:"
echo "======================================"
python3 -c "
import json
with open('localhost_results.json') as f: local = json.load(f)
with open('remote_results.json') as f: remote = json.load(f)
print(f'Localhost avg: {local[\"summary\"][\"avg_total_duration_ms\"]:.1f}ms')
print(f'Remote avg: {remote[\"summary\"][\"avg_total_duration_ms\"]:.1f}ms')
print(f'Difference: {remote[\"summary\"][\"avg_total_duration_ms\"] - local[\"summary\"][\"avg_total_duration_ms\"]:.1f}ms')
"
```

## Report Analysis

### Key Metrics to Monitor

1. **Kyber Key Generation Time**: Time to generate Kyber1024 keypair
   - Expected: 0.1-2ms on modern hardware
   - Concern if: >5ms consistently

2. **Kyber Exchange Time**: Time for encapsulation/decapsulation
   - Expected: 0.1-1ms on modern hardware  
   - Concern if: >3ms consistently

3. **Total Connection Time**: End-to-end connection establishment
   - Expected: 10-50ms on LAN
   - Concern if: >100ms on LAN

4. **Success Rate**: Percentage of successful Kyber exchanges
   - Expected: 100% under normal conditions
   - Concern if: <99% without network issues

### Sample Report Output

```
🔐 Kyber Key Exchange Performance:
  Total Exchanges: 15
  Successful: 15
  Success Rate: 100.0%

⏱️  TIMING AVERAGES (successful attempts only)
================================================
TCP Connect:         2.3 ms
TLS Handshake:       12.7 ms
Kyber Key Gen:       0.8 ms
Kyber Exchange:      1.2 ms
Login:               2.1 ms
Total Average:       19.1 ms
Total Min:           15 ms
Total Max:           24 ms

💻 System Performance:
  Average CPU: 3.2%
  Peak CPU: 8.7%
  Average Memory: 45.3%
  Peak Memory: 47.8%

🌐 Network Performance:
  Average Latency: 0.8ms
  Min Latency: 0.6ms
  Max Latency: 1.2ms
  Packet Loss Rate: 0.0%
```

## Troubleshooting

### Common Issues

1. **Permission Denied for systemd logs**:
   ```bash
   sudo usermod -a -G systemd-journal $USER
   # Log out and back in
   ```

2. **Missing Dependencies**:
   ```bash
   # Python dependencies
   pip install psutil

   # System dependencies
   sudo apt install bc python3-pip
   ```

3. **Server Not Running**:
   ```bash
   sudo systemctl start pqc-chat-server
   sudo systemctl status pqc-chat-server
   ```

4. **Build Errors**:
   ```bash
   cargo clean
   cargo build --release
   ```

### Performance Expectations

| Environment | TCP Connect | TLS Handshake | Kyber KeyGen | Kyber Exchange | Total |
|-------------|-------------|---------------|--------------|----------------|-------|
| Localhost   | <1ms        | 5-15ms        | <1ms         | <2ms           | 10-25ms |
| LAN (1Gbps) | 1-3ms       | 8-20ms        | <1ms         | <2ms           | 15-35ms |
| Pi-to-Pi    | 2-5ms       | 10-25ms       | 1-3ms        | 1-4ms          | 20-50ms |

## Data Export

All tools generate structured data suitable for further analysis:

```bash
# Combine multiple JSON reports
python3 -c "
import json, glob
all_data = []
for file in glob.glob('*.json'):
    with open(file) as f:
        data = json.load(f)
        if 'metrics' in data:
            all_data.extend(data['metrics'])
combined = {'combined_metrics': all_data}
with open('combined_analysis.json', 'w') as f:
    json.dump(combined, f, indent=2)
print('Combined analysis saved to combined_analysis.json')
"
```

## Integration with Research

These tools generate data in formats suitable for:
- Academic papers (timing statistics, success rates)
- Performance benchmarks (comparison data)
- Security analysis (key exchange patterns)
- System optimization (bottleneck identification)

Export data to CSV for spreadsheet analysis:
```bash
python3 -c "
import json, csv
with open('kyber_timing_results.json') as f:
    data = json.load(f)
with open('kyber_analysis.csv', 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=['attempt_number', 'total_duration_ms', 'kyber_keygen_duration_ms', 'kyber_exchange_duration_ms', 'success'])
    writer.writeheader()
    writer.writerows(data['metrics'])
print('Data exported to kyber_analysis.csv')
"
```