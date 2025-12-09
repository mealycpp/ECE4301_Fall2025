# Kyber Performance Test Results

Test conducted on: Sun  7 Dec 06:35:29 GMT 2025
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

✅ Success Rate: 100.0%
⏱️  Average Total Time: 28.3ms
🔐 Average Kyber KeyGen: 0.0ms  
🔐 Average Kyber Exchange: 0.0ms
📊 Min/Max Total: 28ms / 29ms

## Usage:

- Import JSON data: `python3 -c "import json; data = json.load(open('test3_json_data.json'))"`
- View logs: `less test1_single_connection.log`  
- Analyze timing: See avg_kyber_* fields in JSON data

