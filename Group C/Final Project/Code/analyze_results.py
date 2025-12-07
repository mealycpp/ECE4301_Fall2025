#!/usr/bin/env python3
"""
ASCON Benchmark Results Analyzer and Visualizer

This script analyzes CSV output from the ASCON benchmark suite and generates
comparison charts and performance reports.

Usage:
    python3 analyze_results.py <csv_file1> [csv_file2] ...
    python3 analyze_results.py --dir results/
    python3 analyze_results.py --compare-platforms results/*.csv
"""

import sys
import csv
import os
import argparse
from collections import defaultdict
from typing import List, Dict, Tuple

try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not installed. Plotting disabled.")
    print("Install with: pip3 install matplotlib")

class BenchmarkResult:
    """Represents a single benchmark result"""
    def __init__(self, row: Dict[str, str]):
        self.msg_size = int(row['msg_size'])
        self.ad_size = int(row['ad_size'])
        
        # Encryption metrics
        self.enc_time_median_us = float(row['enc_time_median_us'])
        self.enc_time_mean_us = float(row['enc_time_mean_us'])
        self.enc_time_stddev_us = float(row['enc_time_stddev_us'])
        self.enc_cycles_median = float(row['enc_cycles_median'])
        self.enc_cycles_per_byte = float(row['enc_cycles_per_byte'])
        self.enc_throughput_mbps = float(row['enc_throughput_mbps'])
        
        # Decryption metrics
        self.dec_time_median_us = float(row['dec_time_median_us'])
        self.dec_time_mean_us = float(row['dec_time_mean_us'])
        self.dec_time_stddev_us = float(row['dec_time_stddev_us'])
        self.dec_cycles_median = float(row['dec_cycles_median'])
        self.dec_cycles_per_byte = float(row['dec_cycles_per_byte'])
        self.dec_throughput_mbps = float(row['dec_throughput_mbps'])

class BenchmarkDataset:
    """Represents all results from a single CSV file"""
    def __init__(self, filename: str):
        self.filename = filename
        self.metadata = {}
        self.results: List[BenchmarkResult] = []
        self._load()
    
    def _load(self):
        """Load CSV file and parse results"""
        with open(self.filename, 'r') as f:
            # Parse metadata from comments
            for line in f:
                line = line.strip()
                if line.startswith('#'):
                    if ':' in line:
                        key, value = line[1:].split(':', 1)
                        self.metadata[key.strip()] = value.strip()
                elif line and not line.startswith('#'):
                    # Start of CSV data
                    f.seek(0)  # Reset to beginning
                    break
            
            # Skip comment lines
            for line in f:
                if not line.startswith('#'):
                    # Found header line
                    reader = csv.DictReader([line] + list(f))
                    for row in reader:
                        try:
                            self.results.append(BenchmarkResult(row))
                        except (ValueError, KeyError) as e:
                            print(f"Warning: Could not parse row: {e}")
                    break
    
    def get_platform_name(self) -> str:
        """Get a readable platform name"""
        model = self.metadata.get('Model', 'Unknown')
        hardware = self.metadata.get('Hardware', '')
        
        # Extract Pi model
        if 'Zero W' in model:
            return 'Pi Zero W'
        elif 'Pi 5' in model:
            return 'Pi 5'
        elif 'Pi 4' in model:
            return 'Pi 4'
        elif 'Pi 3' in model:
            if '3 B+' in model:
                return 'Pi 3 B+'
            return 'Pi 3'
        elif 'Pi 2' in model:
            return 'Pi 2'
        elif hardware:
            return hardware
        else:
            # Use filename as fallback
            return os.path.basename(self.filename).replace('.csv', '')
    
    def get_cpu_freq_mhz(self) -> float:
        """Get CPU frequency in MHz"""
        freq_str = self.metadata.get('CPU Frequency', '0 kHz')
        try:
            khz = float(freq_str.split()[0])
            return khz / 1000.0
        except (ValueError, IndexError):
            return 0.0

def print_summary(datasets: List[BenchmarkDataset]):
    """Print text summary of results"""
    print("\n" + "=" * 80)
    print("ASCON Benchmark Summary")
    print("=" * 80 + "\n")
    
    for dataset in datasets:
        print(f"Platform: {dataset.get_platform_name()}")
        print(f"  Model:     {dataset.metadata.get('Model', 'Unknown')}")
        print(f"  CPU:       {dataset.get_cpu_freq_mhz():.1f} MHz")
        print(f"  Governor:  {dataset.metadata.get('Governor', 'Unknown')}")
        print()
        
        # Find 1KB result
        for result in dataset.results:
            if result.msg_size == 1024:
                print(f"  1KB Message Performance:")
                print(f"    Encryption:  {result.enc_throughput_mbps:7.2f} MB/s  "
                      f"({result.enc_cycles_per_byte:5.1f} cycles/byte)")
                print(f"    Decryption:  {result.dec_throughput_mbps:7.2f} MB/s  "
                      f"({result.dec_cycles_per_byte:5.1f} cycles/byte)")
                break
        print()

def print_detailed_comparison(datasets: List[BenchmarkDataset]):
    """Print detailed comparison table"""
    if len(datasets) < 2:
        return
    
    print("\n" + "=" * 80)
    print("Cross-Platform Comparison")
    print("=" * 80 + "\n")
    
    # Header
    print(f"{'Message Size':<15}", end='')
    for dataset in datasets:
        platform = dataset.get_platform_name()
        print(f"{platform:>20}", end='')
    print()
    print("-" * (15 + 20 * len(datasets)))
    
    # Get all message sizes
    msg_sizes = sorted(set(r.msg_size for dataset in datasets for r in dataset.results))
    
    # Encryption throughput
    print("\nEncryption Throughput (MB/s):")
    for size in msg_sizes:
        print(f"{size:>6} bytes     ", end='')
        for dataset in datasets:
            result = next((r for r in dataset.results if r.msg_size == size), None)
            if result:
                print(f"{result.enc_throughput_mbps:>19.2f}", end='')
            else:
                print(f"{'N/A':>19}", end='')
        print()
    
    # Cycles per byte
    print("\nEncryption (Cycles/Byte):")
    for size in msg_sizes:
        print(f"{size:>6} bytes     ", end='')
        for dataset in datasets:
            result = next((r for r in dataset.results if r.msg_size == size), None)
            if result:
                print(f"{result.enc_cycles_per_byte:>19.1f}", end='')
            else:
                print(f"{'N/A':>19}", end='')
        print()
    
    print()

def plot_throughput_comparison(datasets: List[BenchmarkDataset], output_dir: str):
    """Plot throughput vs message size"""
    if not HAS_MATPLOTLIB:
        return
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    for dataset in datasets:
        platform = dataset.get_platform_name()
        msg_sizes = [r.msg_size for r in dataset.results]
        enc_throughput = [r.enc_throughput_mbps for r in dataset.results]
        dec_throughput = [r.dec_throughput_mbps for r in dataset.results]
        
        ax1.plot(msg_sizes, enc_throughput, marker='o', label=platform, linewidth=2)
        ax2.plot(msg_sizes, dec_throughput, marker='s', label=platform, linewidth=2)
    
    # Encryption plot
    ax1.set_xlabel('Message Size (bytes)', fontsize=12)
    ax1.set_ylabel('Throughput (MB/s)', fontsize=12)
    ax1.set_title('ASCON Encryption Throughput', fontsize=14, fontweight='bold')
    ax1.set_xscale('log', base=2)
    ax1.grid(True, alpha=0.3)
    ax1.legend()
    
    # Decryption plot
    ax2.set_xlabel('Message Size (bytes)', fontsize=12)
    ax2.set_ylabel('Throughput (MB/s)', fontsize=12)
    ax2.set_title('ASCON Decryption Throughput', fontsize=14, fontweight='bold')
    ax2.set_xscale('log', base=2)
    ax2.grid(True, alpha=0.3)
    ax2.legend()
    
    plt.tight_layout()
    output_file = os.path.join(output_dir, 'throughput_comparison.png')
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()

def plot_cycles_per_byte(datasets: List[BenchmarkDataset], output_dir: str):
    """Plot cycles per byte vs message size"""
    if not HAS_MATPLOTLIB:
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    for dataset in datasets:
        platform = dataset.get_platform_name()
        msg_sizes = [r.msg_size for r in dataset.results]
        cycles_per_byte = [r.enc_cycles_per_byte for r in dataset.results]
        
        ax.plot(msg_sizes, cycles_per_byte, marker='o', label=platform, linewidth=2)
    
    ax.set_xlabel('Message Size (bytes)', fontsize=12)
    ax.set_ylabel('Cycles per Byte', fontsize=12)
    ax.set_title('ASCON Encryption Efficiency', fontsize=14, fontweight='bold')
    ax.set_xscale('log', base=2)
    ax.grid(True, alpha=0.3)
    ax.legend()
    
    plt.tight_layout()
    output_file = os.path.join(output_dir, 'cycles_per_byte.png')
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()

def plot_performance_bars(datasets: List[BenchmarkDataset], output_dir: str):
    """Plot bar chart for 1KB message performance"""
    if not HAS_MATPLOTLIB:
        return
    
    platforms = []
    enc_throughput = []
    dec_throughput = []
    
    for dataset in datasets:
        platforms.append(dataset.get_platform_name())
        result = next((r for r in dataset.results if r.msg_size == 1024), None)
        if result:
            enc_throughput.append(result.enc_throughput_mbps)
            dec_throughput.append(result.dec_throughput_mbps)
        else:
            enc_throughput.append(0)
            dec_throughput.append(0)
    
    x = np.arange(len(platforms))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    bars1 = ax.bar(x - width/2, enc_throughput, width, label='Encryption', 
                   color='#2E86AB', alpha=0.8)
    bars2 = ax.bar(x + width/2, dec_throughput, width, label='Decryption',
                   color='#A23B72', alpha=0.8)
    
    ax.set_xlabel('Platform', fontsize=12)
    ax.set_ylabel('Throughput (MB/s)', fontsize=12)
    ax.set_title('ASCON Performance @ 1KB Message', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(platforms, rotation=45, ha='right')
    ax.legend()
    ax.grid(True, axis='y', alpha=0.3)
    
    # Add value labels on bars
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.1f}',
                       ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    output_file = os.path.join(output_dir, 'performance_bars_1kb.png')
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()

def generate_html_report(datasets: List[BenchmarkDataset], output_dir: str):
    """Generate HTML report with embedded charts"""
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASCON Benchmark Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1, h2, h3 { color: #2c3e50; }
        .platform-card {
            background: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric { 
            display: inline-block;
            margin: 10px 20px 10px 0;
            font-size: 14px;
        }
        .metric-label {
            color: #7f8c8d;
            font-weight: bold;
        }
        .metric-value {
            color: #2c3e50;
            font-size: 18px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #3498db;
            color: white;
        }
        tr:hover { background-color: #f5f5f5; }
        .chart-container {
            background: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            text-align: center;
        }
        .chart-container img {
            max-width: 100%;
            height: auto;
        }
    </style>
</head>
<body>
    <h1>ASCON Benchmark Results</h1>
    <p>Generated: """ + __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
"""
    
    # Platform summaries
    for dataset in datasets:
        platform = dataset.get_platform_name()
        html_content += f"""
    <div class="platform-card">
        <h2>{platform}</h2>
        <div class="metric">
            <span class="metric-label">Model:</span>
            <span class="metric-value">{dataset.metadata.get('Model', 'Unknown')}</span>
        </div>
        <div class="metric">
            <span class="metric-label">CPU Frequency:</span>
            <span class="metric-value">{dataset.get_cpu_freq_mhz():.1f} MHz</span>
        </div>
        <div class="metric">
            <span class="metric-label">Governor:</span>
            <span class="metric-value">{dataset.metadata.get('Governor', 'Unknown')}</span>
        </div>
"""
        
        # 1KB performance
        result_1kb = next((r for r in dataset.results if r.msg_size == 1024), None)
        if result_1kb:
            html_content += f"""
        <h3>1KB Message Performance</h3>
        <div class="metric">
            <span class="metric-label">Encryption:</span>
            <span class="metric-value">{result_1kb.enc_throughput_mbps:.2f} MB/s</span>
        </div>
        <div class="metric">
            <span class="metric-label">Cycles/Byte:</span>
            <span class="metric-value">{result_1kb.enc_cycles_per_byte:.1f}</span>
        </div>
"""
        
        html_content += "    </div>\n"
    
    # Embed charts
    if HAS_MATPLOTLIB:
        html_content += """
    <h2>Performance Charts</h2>
    <div class="chart-container">
        <img src="throughput_comparison.png" alt="Throughput Comparison">
    </div>
    <div class="chart-container">
        <img src="cycles_per_byte.png" alt="Cycles per Byte">
    </div>
    <div class="chart-container">
        <img src="performance_bars_1kb.png" alt="1KB Performance">
    </div>
"""
    
    html_content += """
</body>
</html>
"""
    
    output_file = os.path.join(output_dir, 'benchmark_report.html')
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"✓ Saved: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Analyze and visualize ASCON benchmark results'
    )
    parser.add_argument('files', nargs='*', help='CSV files to analyze')
    parser.add_argument('--dir', help='Directory containing CSV files')
    parser.add_argument('--output', '-o', default='analysis',
                       help='Output directory for charts (default: analysis)')
    parser.add_argument('--no-plots', action='store_true',
                       help='Skip generating plots')
    
    args = parser.parse_args()
    
    # Collect CSV files
    csv_files = []
    if args.dir:
        if os.path.isdir(args.dir):
            csv_files = [os.path.join(args.dir, f) 
                        for f in os.listdir(args.dir) if f.endswith('.csv')]
    
    csv_files.extend(args.files)
    
    if not csv_files:
        print("Error: No CSV files specified")
        print("\nUsage:")
        print("  python3 analyze_results.py file1.csv file2.csv")
        print("  python3 analyze_results.py --dir results/")
        return 1
    
    # Load datasets
    print(f"Loading {len(csv_files)} result file(s)...")
    datasets = []
    for f in csv_files:
        if os.path.exists(f):
            try:
                datasets.append(BenchmarkDataset(f))
                print(f"✓ Loaded: {f}")
            except Exception as e:
                print(f"✗ Failed to load {f}: {e}")
        else:
            print(f"✗ File not found: {f}")
    
    if not datasets:
        print("Error: No valid datasets loaded")
        return 1
    
    # Print text summaries
    print_summary(datasets)
    if len(datasets) > 1:
        print_detailed_comparison(datasets)
    
    # Generate plots
    if not args.no_plots:
        os.makedirs(args.output, exist_ok=True)
        print(f"\nGenerating visualizations in {args.output}/...")
        
        plot_throughput_comparison(datasets, args.output)
        plot_cycles_per_byte(datasets, args.output)
        plot_performance_bars(datasets, args.output)
        generate_html_report(datasets, args.output)
        
        print(f"\n✓ Analysis complete! Open {args.output}/benchmark_report.html")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
