use anyhow::Result;
use chrono::{DateTime, Utc};
use csv::Writer;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use sysinfo::System;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMetrics {
    pub ts_start: DateTime<Utc>,
    pub ts_end: DateTime<Utc>,
    pub mechanism: String,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub cpu_avg: f32,
    pub mem_mb: f64,
    pub energy_j: f64,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMetrics {
    pub ts: DateTime<Utc>,
    pub fps: f32,
    pub goodput_mbps: f32,
    pub latency_ms: f32,
    pub cpu_pct: f32,
    pub mem_mb: f64,
    pub temp_c: f32,
    pub drops: u64,
    pub tag_failures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerSample {
    pub ts: DateTime<Utc>,
    pub volts: f32,
    pub amps: f32,
    pub watts: f32,
    pub phase: String,
    pub node_id: String,
}

pub struct MetricsCollector {
    system: Arc<RwLock<System>>,
    node_id: String,
    power_samples: Arc<RwLock<Vec<PowerSample>>>,
    stream_metrics: Arc<RwLock<Vec<StreamMetrics>>>,
}

impl MetricsCollector {
    pub fn new(node_id: String) -> Self {
        Self {
            system: Arc::new(RwLock::new(System::new_all())),
            node_id,
            power_samples: Arc::new(RwLock::new(Vec::new())),
            stream_metrics: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Start collecting system metrics in the background
    pub fn start_collection(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(250));
            
            loop {
                interval.tick().await;
                
                let mut sys = self.system.write().await;
                sys.refresh_cpu();
                sys.refresh_memory();
                
                // CPU usage (global) - sysinfo 0.30+ has direct methods
                let cpu_usage: f32 = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() 
                    / sys.cpus().len() as f32;
                
                // Memory usage
                let mem_mb = sys.used_memory() as f64 / (1024.0 * 1024.0);
                
                // Temperature (RPi5 thermal zone)
                let temp_c = read_temperature().unwrap_or(0.0);
                
                drop(sys); // Release lock
                
                let metrics = StreamMetrics {
                    ts: Utc::now(),
                    fps: 0.0, // Updated by stream handler
                    goodput_mbps: 0.0, // Updated by stream handler
                    latency_ms: 0.0, // Updated by stream handler
                    cpu_pct: cpu_usage,
                    mem_mb,
                    temp_c,
                    drops: 0,
                    tag_failures: 0,
                };
                
                self.stream_metrics.write().await.push(metrics);
            }
        })
    }
    
    /// Record a power sample
    pub async fn record_power(&self, volts: f32, amps: f32, phase: String) {
        let sample = PowerSample {
            ts: Utc::now(),
            volts,
            amps,
            watts: volts * amps,
            phase,
            node_id: self.node_id.clone(),
        };
        
        self.power_samples.write().await.push(sample);
    }
    
    /// Update stream statistics
    pub async fn update_stream_stats(&self, fps: f32, goodput_mbps: f32, latency_ms: f32) {
        if let Some(last) = self.stream_metrics.write().await.last_mut() {
            last.fps = fps;
            last.goodput_mbps = goodput_mbps;
            last.latency_ms = latency_ms;
        }
    }
    
    /// Record dropped frames
    pub async fn record_drop(&self) {
        if let Some(last) = self.stream_metrics.write().await.last_mut() {
            last.drops += 1;
        }
    }
    
    /// Record GCM tag failure
    pub async fn record_tag_failure(&self) {
        if let Some(last) = self.stream_metrics.write().await.last_mut() {
            last.tag_failures += 1;
        }
    }
    
    /// Write handshake metrics to CSV
    pub fn write_handshake_csv<P: AsRef<Path>>(
        metrics: &[HandshakeMetrics],
        path: P,
    ) -> Result<()> {
        let mut writer = Writer::from_path(path)?;
        for m in metrics {
            writer.serialize(m)?;
        }
        writer.flush()?;
        Ok(())
    }
    
    /// Write stream metrics to CSV
    pub async fn write_stream_csv<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let metrics = self.stream_metrics.read().await;
        let mut writer = Writer::from_path(path)?;
        for m in metrics.iter() {
            writer.serialize(m)?;
        }
        writer.flush()?;
        Ok(())
    }
    
    /// Write power samples to CSV
    pub async fn write_power_csv<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let samples = self.power_samples.read().await;
        let mut writer = Writer::from_path(path)?;
        for s in samples.iter() {
            writer.serialize(s)?;
        }
        writer.flush()?;
        Ok(())
    }
    
    /// Calculate energy consumption (Joules) using trapezoidal integration
    pub async fn calculate_energy(&self, phase: Option<&str>) -> f64 {
        let samples = self.power_samples.read().await;
        
        let filtered: Vec<_> = if let Some(p) = phase {
            samples.iter().filter(|s| s.phase == p).collect()
        } else {
            samples.iter().collect()
        };
        
        if filtered.len() < 2 {
            return 0.0;
        }
        
        let mut energy = 0.0_f64;
        for i in 0..filtered.len() - 1 {
            let dt = (filtered[i + 1].ts - filtered[i].ts).num_milliseconds() as f64 / 1000.0;
            let avg_power = (filtered[i].watts + filtered[i + 1].watts) / 2.0;
            energy += avg_power as f64 * dt;
        }
        
        energy
    }
    
    /// Get latency statistics (mean, p50, p95)
    pub async fn get_latency_stats(&self) -> (f32, f32, f32) {
        let metrics = self.stream_metrics.read().await;
        
        if metrics.is_empty() {
            return (0.0, 0.0, 0.0);
        }
        
        let mut latencies: Vec<f32> = metrics.iter().map(|m| m.latency_ms).collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let mean = latencies.iter().sum::<f32>() / latencies.len() as f32;
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[(latencies.len() * 95) / 100];
        
        (mean, p50, p95)
    }
}

/// Read CPU temperature from RPi5 thermal zone
fn read_temperature() -> Result<f32> {
    let temp_str = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp")?;
    let temp_millidegrees: i32 = temp_str.trim().parse()?;
    Ok(temp_millidegrees as f32 / 1000.0)
}

/// Simulate power reading (replace with actual INA219 implementation)
pub async fn read_power_simulated() -> (f32, f32) {
    // Placeholder: returns (volts, amps)
    // In real implementation, read from INA219 via I2C using rppal crate
    (5.0, 2.0) // ~10W typical for RPi5 under load
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_energy_calculation() {
        let collector = MetricsCollector::new("test".to_string());
        
        // Add some power samples
        collector.record_power(5.0, 2.0, "test".to_string()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        collector.record_power(5.0, 2.5, "test".to_string()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        collector.record_power(5.0, 2.0, "test".to_string()).await;
        
        let energy = collector.calculate_energy(Some("test")).await;
        assert!(energy > 0.0);
    }
}