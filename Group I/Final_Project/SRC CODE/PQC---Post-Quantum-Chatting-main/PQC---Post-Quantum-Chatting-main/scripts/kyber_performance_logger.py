#!/usr/bin/env python3
"""
Kyber Performance Logger
========================

Monitors PQC Chat system performance and generates detailed reports on:
- Kyber key exchange timings and efficiency
- Connection establishment metrics
- Audio transmission performance
- System resource usage
- Network latency measurements

Usage:
    python3 kyber_performance_logger.py [--duration SECONDS] [--output FILE] [--server IP]
"""

import argparse
import json
import time
import subprocess
import threading
import queue
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
import psutil
import statistics

class KyberPerformanceLogger:
    def __init__(self, output_file="kyber_performance_report.json", server_ip="127.0.0.1"):
        # Ensure results directory exists
        import os
        results_dir = "./results"
        os.makedirs(results_dir, exist_ok=True)
        
        # If output_file is just a filename, put it in results directory
        if not output_file.startswith('./') and not output_file.startswith('/'):
            self.output_file = os.path.join(results_dir, output_file)
        else:
            self.output_file = output_file
        self.server_ip = server_ip
        self.metrics = {
            "test_session": {
                "start_time": None,
                "end_time": None,
                "duration_seconds": 0
            },
            "kyber_exchanges": [],
            "connection_metrics": [],
            "audio_metrics": [],
            "system_metrics": [],
            "network_metrics": [],
            "summary": {}
        }
        self.log_queue = queue.Queue()
        self.running = False
        
    def start_logging(self, duration_seconds=60):
        """Start performance logging for specified duration"""
        print(f"🔐 Starting Kyber Performance Logger for {duration_seconds}s")
        print(f"📊 Output file: {self.output_file}")
        print(f"🌐 Server IP: {self.server_ip}")
        
        self.metrics["test_session"]["start_time"] = datetime.now().isoformat()
        self.running = True
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self._monitor_server_logs),
            threading.Thread(target=self._monitor_client_logs),
            threading.Thread(target=self._monitor_system_metrics),
            threading.Thread(target=self._monitor_network_metrics),
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        # Run for specified duration
        time.sleep(duration_seconds)
        
        self.running = False
        self.metrics["test_session"]["end_time"] = datetime.now().isoformat()
        self.metrics["test_session"]["duration_seconds"] = duration_seconds
        
        # Generate summary
        self._generate_summary()
        
        # Save results
        self._save_report()
        
        print(f"✅ Performance logging completed. Report saved to {self.output_file}")
    
    def _monitor_server_logs(self):
        """Monitor server logs for Kyber key exchange events"""
        try:
            # Monitor systemd journal for server logs
            proc = subprocess.Popen(
                ["journalctl", "-u", "pqc-chat-server", "-f", "--since", "now"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            while self.running and proc.poll() is None:
                line = proc.stdout.readline()
                if line:
                    self._parse_server_log_line(line.strip())
                    
        except Exception as e:
            print(f"⚠️ Server log monitoring error: {e}")
    
    def _monitor_client_logs(self):
        """Monitor client application logs"""
        # This would monitor RUST_LOG output from GUI applications
        # For now, we'll simulate or capture from known log patterns
        pass
    
    def _monitor_system_metrics(self):
        """Monitor CPU, memory, and system resource usage"""
        while self.running:
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                
                metric = {
                    "timestamp": datetime.now().isoformat(),
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "memory_used_mb": memory.used // (1024 * 1024),
                    "memory_available_mb": memory.available // (1024 * 1024)
                }
                
                # Check for PQC processes
                pqc_processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        if 'pqc' in proc.info['name'].lower():
                            pqc_processes.append({
                                "pid": proc.info['pid'],
                                "name": proc.info['name'],
                                "cpu_percent": proc.info['cpu_percent'],
                                "memory_percent": proc.info['memory_percent']
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                metric["pqc_processes"] = pqc_processes
                self.metrics["system_metrics"].append(metric)
                
                time.sleep(5)  # Sample every 5 seconds
                
            except Exception as e:
                print(f"⚠️ System metrics error: {e}")
                break
    
    def _monitor_network_metrics(self):
        """Monitor network latency to server"""
        while self.running:
            try:
                # Ping server to measure latency
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", self.server_ip],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    # Parse ping output for latency
                    ping_match = re.search(r'time=(\d+\.?\d*)', result.stdout)
                    if ping_match:
                        latency_ms = float(ping_match.group(1))
                        
                        metric = {
                            "timestamp": datetime.now().isoformat(),
                            "latency_ms": latency_ms,
                            "packet_loss": 0
                        }
                        self.metrics["network_metrics"].append(metric)
                else:
                    # Packet loss
                    metric = {
                        "timestamp": datetime.now().isoformat(),
                        "latency_ms": None,
                        "packet_loss": 1
                    }
                    self.metrics["network_metrics"].append(metric)
                
                time.sleep(2)  # Ping every 2 seconds
                
            except Exception as e:
                print(f"⚠️ Network metrics error: {e}")
                time.sleep(2)
    
    def _parse_server_log_line(self, line):
        """Parse server log lines for Kyber-related events"""
        timestamp_str = datetime.now().isoformat()
        
        # Detect Kyber key exchange completion
        kyber_match = re.search(r'Kyber key exchange completed for (\w+)', line)
        if kyber_match:
            participant_id = kyber_match.group(1)
            
            exchange = {
                "timestamp": timestamp_str,
                "participant_id": participant_id,
                "status": "completed",
                "operation": "server_side_complete"
            }
            self.metrics["kyber_exchanges"].append(exchange)
            print(f"🔐 Kyber exchange completed for {participant_id}")
        
        # Detect connection events
        login_match = re.search(r'User (\w+) logged in as (.+)', line)
        if login_match:
            participant_id = login_match.group(1)
            username = login_match.group(2)
            
            connection = {
                "timestamp": timestamp_str,
                "participant_id": participant_id,
                "username": username,
                "event": "login_success"
            }
            self.metrics["connection_metrics"].append(connection)
            print(f"👤 User login: {username}")
        
        # Detect audio transmission events
        audio_match = re.search(r'Broadcasting audio to room (\w+)', line)
        if audio_match:
            room_id = audio_match.group(1)
            
            audio = {
                "timestamp": timestamp_str,
                "room_id": room_id,
                "event": "audio_broadcast"
            }
            self.metrics["audio_metrics"].append(audio)
    
    def _generate_summary(self):
        """Generate performance summary statistics"""
        summary = {
            "kyber_performance": {
                "total_exchanges": len(self.metrics["kyber_exchanges"]),
                "successful_exchanges": len([e for e in self.metrics["kyber_exchanges"] if e["status"] == "completed"]),
                "success_rate": 0,
                "average_time_between_exchanges": None
            },
            "connection_performance": {
                "total_connections": len(self.metrics["connection_metrics"]),
                "unique_users": len(set(c["username"] for c in self.metrics["connection_metrics"]))
            },
            "audio_performance": {
                "total_audio_events": len(self.metrics["audio_metrics"]),
                "active_rooms": len(set(a["room_id"] for a in self.metrics["audio_metrics"]))
            },
            "system_performance": {},
            "network_performance": {}
        }
        
        # Kyber success rate
        if summary["kyber_performance"]["total_exchanges"] > 0:
            summary["kyber_performance"]["success_rate"] = (
                summary["kyber_performance"]["successful_exchanges"] / 
                summary["kyber_performance"]["total_exchanges"] * 100
            )
        
        # System performance averages
        if self.metrics["system_metrics"]:
            cpu_values = [m["cpu_percent"] for m in self.metrics["system_metrics"]]
            memory_values = [m["memory_percent"] for m in self.metrics["system_metrics"]]
            
            summary["system_performance"] = {
                "avg_cpu_percent": statistics.mean(cpu_values),
                "max_cpu_percent": max(cpu_values),
                "avg_memory_percent": statistics.mean(memory_values),
                "max_memory_percent": max(memory_values),
                "total_samples": len(cpu_values)
            }
        
        # Network performance
        if self.metrics["network_metrics"]:
            latencies = [m["latency_ms"] for m in self.metrics["network_metrics"] if m["latency_ms"] is not None]
            packet_losses = [m["packet_loss"] for m in self.metrics["network_metrics"]]
            
            if latencies:
                summary["network_performance"] = {
                    "avg_latency_ms": statistics.mean(latencies),
                    "min_latency_ms": min(latencies),
                    "max_latency_ms": max(latencies),
                    "packet_loss_rate": sum(packet_losses) / len(packet_losses) * 100,
                    "total_samples": len(self.metrics["network_metrics"])
                }
        
        self.metrics["summary"] = summary
    
    def _save_report(self):
        """Save performance report to JSON file"""
        with open(self.output_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)
    
    def generate_human_readable_report(self):
        """Generate a human-readable report for presentations"""
        if not Path(self.output_file).exists():
            print(f"❌ Report file {self.output_file} not found. Run logging first.")
            return
        
        with open(self.output_file, 'r') as f:
            data = json.load(f)
        
        report_file = self.output_file.replace('.json', '_readable.txt')
        
        with open(report_file, 'w') as f:
            f.write("PQC Chat - Kyber Performance Report\n")
            f.write("=" * 40 + "\n\n")
            
            # Test session info
            session = data["test_session"]
            f.write(f"Test Duration: {session['duration_seconds']} seconds\n")
            f.write(f"Start Time: {session['start_time']}\n")
            f.write(f"End Time: {session['end_time']}\n\n")
            
            # Kyber performance
            kyber = data["summary"]["kyber_performance"]
            f.write("🔐 Kyber Key Exchange Performance:\n")
            f.write(f"  Total Exchanges: {kyber['total_exchanges']}\n")
            f.write(f"  Successful: {kyber['successful_exchanges']}\n")
            f.write(f"  Success Rate: {kyber['success_rate']:.1f}%\n\n")
            
            # Connection performance
            conn = data["summary"]["connection_performance"]
            f.write("🔌 Connection Performance:\n")
            f.write(f"  Total Connections: {conn['total_connections']}\n")
            f.write(f"  Unique Users: {conn['unique_users']}\n\n")
            
            # System performance
            if "system_performance" in data["summary"]:
                sys_perf = data["summary"]["system_performance"]
                f.write("💻 System Performance:\n")
                f.write(f"  Average CPU: {sys_perf['avg_cpu_percent']:.1f}%\n")
                f.write(f"  Peak CPU: {sys_perf['max_cpu_percent']:.1f}%\n")
                f.write(f"  Average Memory: {sys_perf['avg_memory_percent']:.1f}%\n")
                f.write(f"  Peak Memory: {sys_perf['max_memory_percent']:.1f}%\n\n")
            
            # Network performance
            if "network_performance" in data["summary"]:
                net_perf = data["summary"]["network_performance"]
                f.write("🌐 Network Performance:\n")
                f.write(f"  Average Latency: {net_perf['avg_latency_ms']:.1f}ms\n")
                f.write(f"  Min Latency: {net_perf['min_latency_ms']:.1f}ms\n")
                f.write(f"  Max Latency: {net_perf['max_latency_ms']:.1f}ms\n")
                f.write(f"  Packet Loss Rate: {net_perf['packet_loss_rate']:.1f}%\n\n")
            
            # Audio performance
            audio = data["summary"]["audio_performance"]
            f.write("🎤 Audio Performance:\n")
            f.write(f"  Total Audio Events: {audio['total_audio_events']}\n")
            f.write(f"  Active Rooms: {audio['active_rooms']}\n")
        
        print(f"📋 Human-readable report saved to {report_file}")

def main():
    parser = argparse.ArgumentParser(description="Kyber Performance Logger for PQC Chat")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds (default: 60)")
    parser.add_argument("--output", default="kyber_performance_report.json", help="Output JSON file")
    parser.add_argument("--server", default="127.0.0.1", help="Server IP address")
    parser.add_argument("--readable", action="store_true", help="Generate human-readable report from existing JSON")
    
    args = parser.parse_args()
    
    logger = KyberPerformanceLogger(args.output, args.server)
    
    if args.readable:
        logger.generate_human_readable_report()
    else:
        try:
            logger.start_logging(args.duration)
            # Also generate human-readable version
            logger.generate_human_readable_report()
        except KeyboardInterrupt:
            print("\n🛑 Logging interrupted by user")
            logger.running = False

if __name__ == "__main__":
    main()