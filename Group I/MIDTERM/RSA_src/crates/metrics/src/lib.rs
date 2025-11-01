//! Metrics crate: CSV logging for handshake, energy, throughput, latency, system stats, and loss/errors.
//! Creates per-metric CSV files under provided log directory.

use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use csv::Writer;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use sysinfo::{CpuExt, System, SystemExt};

fn iso_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn filename_ts() -> String {
    Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

fn create_writer(dir: &str, prefix: &str) -> Writer<File> {
    let _ = std::fs::create_dir_all(dir);
    let filename = format!("{}/{}-{}.csv", dir, prefix, filename_ts());
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open(&filename)
        .expect("failed to open metrics file");
    csv::WriterBuilder::new().has_headers(true).from_writer(file)
}

fn create_writer_with_role(base_dir: &str, role: &str, prefix: &str) -> Writer<File> {
    let dir = format!("{}/{}", base_dir, role);
    let _ = std::fs::create_dir_all(&dir);
    let filename = format!("{}/{}-{}.csv", dir, prefix, filename_ts());
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open(&filename)
        .expect("failed to open metrics file");
    csv::WriterBuilder::new().has_headers(true).from_writer(file)
}

#[derive(Clone)]
pub struct Metrics {
    handshake_w: Arc<Mutex<Writer<File>>>,
    energy_w: Arc<Mutex<Writer<File>>>,
    energy_samples_w: Arc<Mutex<Writer<File>>>,
    throughput_w: Arc<Mutex<Writer<File>>>,
    latency_w: Arc<Mutex<Writer<File>>>,
    sys_w: Arc<Mutex<Writer<File>>>,
    loss_w: Arc<Mutex<Writer<File>>>,
    sys: Arc<Mutex<System>>,
    latency_samples: Arc<Mutex<VecDeque<f64>>>,
    role: String,
}

impl Metrics {
    pub fn new(log_dir: &str) -> Result<Self> {
        Self::new_with_role(log_dir, "")
    }

    pub fn new_with_role(log_dir: &str, role: &str) -> Result<Self> {
        let (handshake_w, energy_w, energy_samples_w, throughput_w, latency_w, sys_w, loss_w) = 
            if role.is_empty() {
                // Original single-folder structure for backward compatibility
                (
                    Arc::new(Mutex::new(create_writer(log_dir, "handshake"))),
                    Arc::new(Mutex::new(create_writer(log_dir, "energy_summary"))),
                    Arc::new(Mutex::new(create_writer(log_dir, "energy_samples"))),
                    Arc::new(Mutex::new(create_writer(log_dir, "throughput"))),
                    Arc::new(Mutex::new(create_writer(log_dir, "latency"))),
                    Arc::new(Mutex::new(create_writer(log_dir, "system"))),
                    Arc::new(Mutex::new(create_writer(log_dir, "loss_errors"))),
                )
            } else {
                // New role-based folder structure
                (
                    Arc::new(Mutex::new(create_writer_with_role(log_dir, role, "handshake"))),
                    Arc::new(Mutex::new(create_writer_with_role(log_dir, role, "energy_summary"))),
                    Arc::new(Mutex::new(create_writer_with_role(log_dir, role, "energy_samples"))),
                    Arc::new(Mutex::new(create_writer_with_role(log_dir, role, "throughput"))),
                    Arc::new(Mutex::new(create_writer_with_role(log_dir, role, "latency"))),
                    Arc::new(Mutex::new(create_writer_with_role(log_dir, role, "system"))),
                    Arc::new(Mutex::new(create_writer_with_role(log_dir, role, "loss_errors"))),
                )
            };

        let mut sys = System::new_all();
        sys.refresh_all();
        Ok(Self {
            handshake_w,
            energy_w,
            energy_samples_w,
            throughput_w,
            latency_w,
            sys_w,
            loss_w,
            sys: Arc::new(Mutex::new(sys)),
            latency_samples: Arc::new(Mutex::new(VecDeque::new())),
            role: role.to_string(),
        })
    }

    pub fn log_handshake(
        &self,
        algo: &str,
        duration_s: f64,
        bytes_exchanged: usize,
        failed: bool,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct H<'a> {
            ts: String,
            algo: &'a str,
            duration_s: f64,
            bytes_exchanged: usize,
            failed: bool,
        }
        let rec = H {
            ts: iso_now(),
            algo,
            duration_s,
            bytes_exchanged,
            failed,
        };
        let mut w = self.handshake_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;
        Ok(())
    }

    pub fn log_energy_summary(
        &self,
        name: &str,
        joules: f64,
        duration_s: f64,
        avg_power_w: f64,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct E<'a> {
            ts: String,
            name: &'a str,
            joules: f64,
            duration_s: f64,
            avg_power_w: f64,
        }
        let rec = E {
            ts: iso_now(),
            name,
            joules,
            duration_s,
            avg_power_w,
        };
        let mut w = self.energy_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;
        Ok(())
    }

    pub fn log_energy_sample(
        &self,
        timestamp_s: f64,
        volts: f64,
        amps: f64,
        sampling_freq_hz: Option<f64>,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct S {
            ts_iso: String,
            sample_ts_s: f64,
            volts: f64,
            amps: f64,
            sampling_freq_hz: Option<f64>,
        }
        let rec = S {
            ts_iso: iso_now(),
            sample_ts_s: timestamp_s,
            volts,
            amps,
            sampling_freq_hz,
        };
        let mut w = self.energy_samples_w.lock().unwrap();
        w.serialize(rec)?;
        Ok(())
    }

    pub fn compute_energy_from_samples(samples: &[(f64, f64, f64)]) -> (f64, f64) {
        if samples.len() < 2 {
            return (0.0, 0.0);
        }
        let mut energy = 0.0f64;
        let mut total_time = 0.0f64;
        for w in samples.windows(2) {
            let (t0, v0, a0) = w[0];
            let (t1, v1, a1) = w[1];
            let dt = (t1 - t0).max(0.0);
            let p0 = v0 * a0;
            let p1 = v1 * a1;
            energy += 0.5 * (p0 + p1) * dt;
            total_time += dt;
        }
        let avg_power = if total_time > 0.0 { energy / total_time } else { 0.0 };
        (energy, avg_power)
    }

    pub fn log_throughput(
        &self,
        mbps: f64,
        fps: f64,
        bytes_sent: usize,
        interval_s: f64,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct T {
            ts: String,
            mbps: f64,
            fps: f64,
            bytes_sent: usize,
            interval_s: f64,
        }
        let rec = T {
            ts: iso_now(),
            mbps,
            fps,
            bytes_sent,
            interval_s,
        };
        let mut w = self.throughput_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;
        Ok(())
    }

    pub fn log_latency_frame(&self, frame_id: u64, frame_ts_sender: f64, recv_ts: f64) -> Result<()> {
        #[derive(Serialize)]
        struct L {
            ts: String,
            frame_id: u64,
            sender_ts_s: f64,
            recv_ts_s: f64,
            latency_s: f64,
        }
        let latency = (recv_ts - frame_ts_sender).max(0.0);
        let rec = L {
            ts: iso_now(),
            frame_id,
            sender_ts_s: frame_ts_sender,
            recv_ts_s: recv_ts,
            latency_s: latency,
        };
        let mut w = self.latency_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;

        // Collect latency sample for aggregation
        let mut samples = self.latency_samples.lock().unwrap();
        samples.push_back(latency);
        // Keep only recent samples (e.g., last 1000)
        if samples.len() > 1000 {
            samples.pop_front();
        }

        Ok(())
    }

    pub fn latency_stats(latencies: &mut [f64]) -> (f64, f64, f64) {
        if latencies.is_empty() {
            return (0.0, 0.0, 0.0);
        }
        let sum: f64 = latencies.iter().sum();
        let mean = sum / (latencies.len() as f64);
        latencies.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p50 = percentile(latencies, 50.0);
        let p95 = percentile(latencies, 95.0);
        (mean, p50, p95)
    }

    pub fn log_latency_aggregate(&self, name: &str, mean: f64, p50: f64, p95: f64, samples: usize) -> Result<()> {
        #[derive(Serialize)]
        struct LA<'a> {
            ts: String,
            name: &'a str,
            mean_s: f64,
            p50_s: f64,
            p95_s: f64,
            samples: usize,
        }
        let rec = LA {
            ts: iso_now(),
            name,
            mean_s: mean,
            p50_s: p50,
            p95_s: p95,
            samples,
        };
        let mut w = self.latency_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;
        Ok(())
    }

    /// Calculate and log aggregate latency statistics from collected samples
    pub fn log_latency_stats_periodic(&self) -> Result<()> {
        let mut samples = self.latency_samples.lock().unwrap();
        if samples.len() < 10 {
            // Need at least 10 samples for meaningful statistics
            return Ok(());
        }

        // Convert VecDeque to Vec for statistics calculation
        let mut latencies: Vec<f64> = samples.iter().copied().collect();
        let sample_count = latencies.len();

        // Calculate statistics
        let (mean, p50, p95) = Self::latency_stats(&mut latencies);

        // Log aggregate statistics
        let role_suffix = if self.role.is_empty() { "" } else { &format!("_{}", self.role) };
        let name = format!("aggregate{}", role_suffix);
        self.log_latency_aggregate(&name, mean, p50, p95, sample_count)?;

        // Clear samples after aggregation
        samples.clear();

        Ok(())
    }

    pub fn sample_system(&self) -> Result<()> {
        let mut sys = self.sys.lock().unwrap();
        sys.refresh_memory();
        sys.refresh_cpu();
        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        let cpu_usage = if sys.cpus().is_empty() {
            0.0
        } else {
            sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / (sys.cpus().len() as f32)
        };
        let temp_c = read_thermal_zone_temp().unwrap_or(f64::NAN);

        #[derive(Serialize)]
        struct S {
            ts: String,
            cpu_pct: f32,
            total_mem_kb: u64,
            used_mem_kb: u64,
            temp_c: f64,
        }
        let rec = S {
            ts: iso_now(),
            cpu_pct: cpu_usage,
            total_mem_kb: total_mem,
            used_mem_kb: used_mem,
            temp_c,
        };
        let mut w = self.sys_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;
        Ok(())
    }

    pub fn log_loss_errors(
        &self,
        drops: usize,
        gcm_tag_failures: usize,
        retransmissions: usize,
        recv_errors: usize,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct E {
            ts: String,
            drops: usize,
            gcm_tag_failures: usize,
            retransmissions: usize,
            recv_errors: usize,
        }
        let rec = E {
            ts: iso_now(),
            drops,
            gcm_tag_failures,
            retransmissions,
            recv_errors,
        };
        let mut w = self.loss_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;
        Ok(())
    }

    pub fn flush_all(&self) -> Result<()> {
        self.handshake_w.lock().unwrap().flush()?;
        self.energy_w.lock().unwrap().flush()?;
        self.energy_samples_w.lock().unwrap().flush()?;
        self.throughput_w.lock().unwrap().flush()?;
        self.latency_w.lock().unwrap().flush()?;
        self.sys_w.lock().unwrap().flush()?;
        self.loss_w.lock().unwrap().flush()?;
        Ok(())
    }
}

fn read_thermal_zone_temp() -> Option<f64> {
    let path = Path::new("/sys/class/thermal/thermal_zone0/temp");
    if path.exists() {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(milli) = s.trim().parse::<f64>() {
                return Some(milli / 1000.0);
            }
        }
    }
    None
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = p / 100.0 * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = rank - (lo as f64);
        sorted[lo] * (1.0 - frac) + sorted[hi] * frac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instantiate_metrics_and_log_sample() {
        let m = Metrics::new("target/metrics_test_logs").expect("create metrics");
        m.log_handshake("RSA", 0.12, 512, false).unwrap();
        m.log_throughput(12.34, 30.0, 1024, 1.0).unwrap();
        m.log_loss_errors(0, 0, 0, 0).unwrap();
        // flush to ensure no panic
        m.flush_all().unwrap();
    }
}