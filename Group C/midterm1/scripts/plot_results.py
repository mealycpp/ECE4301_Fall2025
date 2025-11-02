#!/usr/bin/env python3
"""
Plot results from secure video streaming experiments.
Generates: latency CDF, throughput time-series, energy bars, scaling curves.
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
import sys

# Set publication-quality defaults
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 11
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 14
plt.rcParams['legend.fontsize'] = 10
plt.rcParams['figure.dpi'] = 150

def plot_latency_cdf(csv_path, output_path='plots/latency_cdf.png'):
    """Plot cumulative distribution function of latency."""
    df = pd.read_csv(csv_path)
    
    if 'latency_ms' not in df.columns or df['latency_ms'].isna().all():
        print(f"Warning: No latency data in {csv_path}")
        return
    
    latencies = df['latency_ms'].dropna().values
    latencies_sorted = np.sort(latencies)
    cdf = np.arange(1, len(latencies_sorted) + 1) / len(latencies_sorted)
    
    fig, ax = plt.subplots()
    ax.plot(latencies_sorted, cdf * 100, linewidth=2, color='#2E86AB')
    ax.axvline(np.percentile(latencies, 50), color='#A23B72', 
               linestyle='--', label=f'p50: {np.percentile(latencies, 50):.1f} ms')
    ax.axvline(np.percentile(latencies, 95), color='#F18F01', 
               linestyle='--', label=f'p95: {np.percentile(latencies, 95):.1f} ms')
    
    ax.set_xlabel('Latency (ms)')
    ax.set_ylabel('Cumulative Probability (%)')
    ax.set_title('End-to-End Latency Distribution')
    ax.grid(True, alpha=0.3)
    ax.legend()
    
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, bbox_inches='tight')
    print(f"Saved: {output_path}")
    plt.close()

def plot_throughput_timeseries(csv_path, output_path='plots/throughput_timeseries.png'):
    """Plot throughput and FPS over time."""
    df = pd.read_csv(csv_path)
    
    if 'ts' not in df.columns:
        print(f"Warning: No timestamp data in {csv_path}")
        return
    
    df['ts'] = pd.to_datetime(df['ts'])
    df['elapsed_s'] = (df['ts'] - df['ts'].iloc[0]).dt.total_seconds()
    
    fig, (ax1, ax2) = plt.subplots(2, 1, sharex=True, figsize=(10, 8))
    
    # Throughput
    ax1.plot(df['elapsed_s'], df['goodput_mbps'], linewidth=1.5, color='#2E86AB')
    ax1.set_ylabel('Throughput (Mbps)')
    ax1.set_title('Encrypted Video Stream Performance')
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim(bottom=0)
    
    # Frame rate
    ax2.plot(df['elapsed_s'], df['fps'], linewidth=1.5, color='#A23B72')
    ax2.axhline(15, color='#F18F01', linestyle='--', label='Target: 15 fps')
    ax2.set_xlabel('Time (seconds)')
    ax2.set_ylabel('Frame Rate (fps)')
    ax2.grid(True, alpha=0.3)
    ax2.legend()
    ax2.set_ylim(bottom=0)
    
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, bbox_inches='tight')
    print(f"Saved: {output_path}")
    plt.close()

def plot_energy_comparison(handshake_files, steady_csv, output_path='plots/energy_bars.png'):
    """Plot energy consumption for handshake and steady-state."""
    energy_data = []
    
    # Handshake energy
    for mech, filepath in handshake_files.items():
        if Path(filepath).exists():
            df = pd.read_csv(filepath)
            if not df.empty and 'energy_j' in df.columns:
                energy_data.append({
                    'Phase': f'Handshake\n({mech})',
                    'Energy (J)': df['energy_j'].iloc[0]
                })
    
    # Steady-state energy (compute from power samples)
    if Path(steady_csv).exists():
        df_power = pd.read_csv('power_samples.csv')
        df_steady = df_power[df_power['phase'] == 'steady']
        
        if len(df_steady) > 1:
            df_steady['ts'] = pd.to_datetime(df_steady['ts'])
            times = df_steady['ts'].values
            watts = df_steady['watts'].values
            
            # Trapezoidal integration
            energy_j = 0.0
            for i in range(len(times) - 1):
                dt = (pd.Timestamp(times[i + 1]) - pd.Timestamp(times[i])).total_seconds()
                avg_power = (watts[i] + watts[i + 1]) / 2
                energy_j += avg_power * dt
            
            energy_data.append({
                'Phase': 'Steady-State\n(60s stream)',
                'Energy (J)': energy_j
            })
    
    if not energy_data:
        print("Warning: No energy data found")
        return
    
    df_plot = pd.DataFrame(energy_data)
    
    fig, ax = plt.subplots(figsize=(8, 6))
    colors = ['#2E86AB', '#A23B72', '#F18F01']
    bars = ax.bar(df_plot['Phase'], df_plot['Energy (J)'], 
                   color=colors[:len(df_plot)], edgecolor='black', linewidth=1.2)
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.1f} J',
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    ax.set_ylabel('Energy Consumption (Joules)')
    ax.set_title('Energy Cost by Phase')
    ax.grid(True, axis='y', alpha=0.3)
    ax.set_ylim(bottom=0)
    
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, bbox_inches='tight')
    print(f"Saved: {output_path}")
    plt.close()

def plot_scaling_analysis(csv_path, output_path='plots/scaling_curve.png'):
    """Plot energy and latency scaling for group protocols."""
    if not Path(csv_path).exists():
        print(f"Warning: {csv_path} not found")
        return
    
    df = pd.read_csv(csv_path)
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    protocols = df['protocol'].unique()
    colors = {'leader-distributed': '#2E86AB', 'tree-ecdh': '#A23B72'}
    markers = {'leader-distributed': 'o', 'tree-ecdh': 's'}
    
    for protocol in protocols:
        df_proto = df[df['protocol'] == protocol]
        df_measured = df_proto[df_proto['measured'] == True]
        df_predicted = df_proto[df_proto['measured'] == False]
        
        color = colors.get(protocol, '#333333')
        marker = markers.get(protocol, 'o')
        
        # Energy plot
        ax1.plot(df_measured['n_members'], df_measured['energy_j'], 
                marker=marker, markersize=10, linewidth=0, 
                label=f'{protocol} (measured)', color=color)
        ax1.plot(df_predicted['n_members'], df_predicted['energy_j'], 
                linestyle='--', linewidth=2, alpha=0.7, color=color)
        
        # Latency plot
        ax2.plot(df_measured['n_members'], df_measured['latency_s'] * 1000, 
                marker=marker, markersize=10, linewidth=0,
                label=f'{protocol} (measured)', color=color)
        ax2.plot(df_predicted['n_members'], df_predicted['latency_s'] * 1000, 
                linestyle='--', linewidth=2, alpha=0.7, color=color)
    
    ax1.set_xlabel('Number of Group Members (N)')
    ax1.set_ylabel('Handshake Energy (J)')
    ax1.set_title('Energy Scaling')
    ax1.grid(True, alpha=0.3)
    ax1.legend()
    
    ax2.set_xlabel('Number of Group Members (N)')
    ax2.set_ylabel('Handshake Latency (ms)')
    ax2.set_title('Latency Scaling')
    ax2.grid(True, alpha=0.3)
    ax2.legend()
    
    plt.suptitle('Group Key Establishment Scaling Analysis', fontsize=16, y=1.02)
    
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, bbox_inches='tight')
    print(f"Saved: {output_path}")
    plt.close()

def plot_cpu_memory(csv_path, output_path='plots/system_metrics.png'):
    """Plot CPU and memory usage over time."""
    df = pd.read_csv(csv_path)
    
    if 'ts' not in df.columns:
        print(f"Warning: No timestamp data in {csv_path}")
        return
    
    df['ts'] = pd.to_datetime(df['ts'])
    df['elapsed_s'] = (df['ts'] - df['ts'].iloc[0]).dt.total_seconds()
    
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, sharex=True, figsize=(10, 10))
    
    # CPU usage
    ax1.plot(df['elapsed_s'], df['cpu_pct'], linewidth=1.5, color='#2E86AB')
    ax1.set_ylabel('CPU Usage (%)')
    ax1.set_title('System Resource Utilization')
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim(0, 100)
    
    # Memory usage
    ax2.plot(df['elapsed_s'], df['mem_mb'], linewidth=1.5, color='#A23B72')
    ax2.set_ylabel('Memory (MB)')
    ax2.grid(True, alpha=0.3)
    ax2.set_ylim(bottom=0)
    
    # Temperature
    ax3.plot(df['elapsed_s'], df['temp_c'], linewidth=1.5, color='#F18F01')
    ax3.axhline(80, color='red', linestyle='--', alpha=0.5, label='Throttle threshold')
    ax3.set_xlabel('Time (seconds)')
    ax3.set_ylabel('Temperature (°C)')
    ax3.grid(True, alpha=0.3)
    ax3.legend()
    ax3.set_ylim(30, 90)
    
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, bbox_inches='tight')
    print(f"Saved: {output_path}")
    plt.close()

def main():
    print("Generating plots from CSV data...")
    
    # Create plots directory
    Path('plots').mkdir(exist_ok=True)
    
    # Generate all plots
    if Path('steady_stream.csv').exists():
        plot_latency_cdf('steady_stream.csv')
        plot_throughput_timeseries('steady_stream.csv')
        plot_cpu_memory('steady_stream.csv')
    else:
        print("Warning: steady_stream.csv not found")
    
    # Energy comparison
    handshake_files = {
        'RSA': 'handshake_rsa.csv',
        'ECDH': 'handshake_ecdh.csv'
    }
    plot_energy_comparison(handshake_files, 'power_samples.csv')
    
    # Scaling analysis (if available)
    if Path('scaling_analysis.csv').exists():
        plot_scaling_analysis('scaling_analysis.csv')
    
    print("\nAll plots generated successfully!")
    print("Output directory: plots/")

if __name__ == '__main__':
    main()