//! Lightweight metrics logger for the rpi secure streaming project.
//!
//! This crate provides a `Metrics` type that logs handshake, energy,
//! throughput, latency and system statistics into CSV files. It's
//! intentionally small and synchronous so the rest of the project can
//! call it from any thread.

use anyhow::Result;
use chrono::{DateTime, Utc};
use csv::Writer;
use serde::Serialize;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufWriter, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};
use sysinfo::{CpuExt, System, SystemExt};

#[derive(Clone)]
pub struct Metrics {
    _out_dir: String,
    handshake_w: Arc<Mutex<Writer<BufWriter<File>>>>,
    energy_w: Arc<Mutex<Writer<BufWriter<File>>>>,
    energy_samples_w: Arc<Mutex<Writer<BufWriter<File>>>>,
    throughput_w: Arc<Mutex<Writer<BufWriter<File>>>>,
    latency_w: Arc<Mutex<Writer<BufWriter<File>>>>,
    system_w: Arc<Mutex<Writer<BufWriter<File>>>>,
    errors_w: Arc<Mutex<Writer<BufWriter<File>>>>,
    // in-memory latency samples for summary computation
    latencies_ms: Arc<Mutex<Vec<f64>>>,
}

#[derive(Serialize)]
struct HandshakeRecord {
    timestamp: DateTime<Utc>,
    method: String, // "RSA" or "ECDH"
    duration_s: f64,
    bytes_sent: u64,
    bytes_received: u64,
    success: bool,
    failure_reason: Option<String>,
    peer: Option<String>,
}

#[derive(Serialize)]
struct EnergyRecord {
    timestamp: DateTime<Utc>,
    context: String, // e.g., "handshake" or "60s_stream"
    joules: f64,
    sampling_hz: f64,
    sample_count: usize,
}

#[derive(Serialize, Clone)]
pub struct EnergySample {
    timestamp: DateTime<Utc>,
    voltage_v: f64,
    current_a: f64,
}

#[derive(Serialize)]
struct ThroughputRecord {
    timestamp: DateTime<Utc>,
    duration_s: f64,
    encrypted_goodput_mbps: f64,
    frames: u64,
    fps: f64,
}

#[derive(Serialize)]
struct LatencySummary {
    timestamp: DateTime<Utc>,
    count: usize,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
}

#[derive(Serialize)]
struct SystemRecord {
    timestamp: DateTime<Utc>,
    cpu_usage_percent: f32,
    total_memory_bytes: u64,
    used_memory_bytes: u64,
    temp_c: Option<f64>,
}

#[derive(Serialize)]
struct ErrorRecord {
    timestamp: DateTime<Utc>,
    drops: u64,
    gcm_tag_failures: u64,
    retransmissions: u64,
}

impl Metrics {
    /// Create a new Metrics instance that writes CSV files under `out_dir`.
    pub fn new<P: AsRef<Path>>(out_dir: P) -> Result<Self> {
        let out_dir = out_dir.as_ref();
        create_dir_all(out_dir)?;

        // helper to open a csv writer
        let open_writer = |name: &str| -> Result<Writer<BufWriter<File>>> {
            let path = out_dir.join(name);
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            Ok(Writer::from_writer(BufWriter::new(file)))
        };

        let handshake_w = Arc::new(Mutex::new(open_writer("handshake.csv")?));
        let energy_w = Arc::new(Mutex::new(open_writer("energy_summary.csv")?));
        let energy_samples_w = Arc::new(Mutex::new(open_writer("energy_samples.csv")?));
        let throughput_w = Arc::new(Mutex::new(open_writer("throughput.csv")?));
        let latency_w = Arc::new(Mutex::new(open_writer("latency.csv")?));
        let system_w = Arc::new(Mutex::new(open_writer("system.csv")?));
        let errors_w = Arc::new(Mutex::new(open_writer("errors.csv")?));

        Ok(Metrics {
            _out_dir: out_dir.to_string_lossy().into_owned(),
            handshake_w,
            energy_w,
            energy_samples_w,
            throughput_w,
            latency_w,
            system_w,
            errors_w,
            latencies_ms: Arc::new(Mutex::new(Vec::with_capacity(1024))),
        })
    }

    /// Record a handshake event (RSA or ECDH).
    pub fn record_handshake(
        &self,
        method: &str,
        duration: std::time::Duration,
        bytes_sent: u64,
        bytes_received: u64,
        success: bool,
        failure_reason: Option<String>,
        peer: Option<String>,
    ) -> Result<()> {
        // normalize duration to seconds (f64) internally
        let duration_s = duration.as_secs_f64();
        let rec = HandshakeRecord {
            timestamp: Utc::now(),
            method: method.to_string(),
            duration_s,
            bytes_sent,
            bytes_received,
            success,
            failure_reason,
            peer,
        };

        let mut w = self.handshake_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;
        Ok(())
    }

    /// Record energy samples and a summary row. `samples` should be ordered in time.
    /// `sampling_hz` is the sample rate in Hz (best-effort). The function will write
    /// individual samples to `energy_samples.csv` and a summary with computed joules
    /// to `energy_summary.csv`.
    pub fn record_energy_samples(&self, context: &str, samples: &[EnergySample], sampling_hz: f64) -> Result<()> {
        // write raw samples
        {
            let mut w = self.energy_samples_w.lock().unwrap();
            for s in samples {
                w.serialize(s)?;
            }
            w.flush()?;
        }

        // compute joules using trapezoidal integration of power = V * I
        let joules = compute_energy_joules(samples);
        let summary = EnergyRecord {
            timestamp: Utc::now(),
            context: context.to_string(),
            joules,
            sampling_hz,
            sample_count: samples.len(),
        };
        let mut w = self.energy_w.lock().unwrap();
        w.serialize(summary)?;
        w.flush()?;
        Ok(())
    }

    /// Record throughput over a measured period.
    /// `encrypted_goodput_mbps` - actual payload sent per second in megabits per second.
    pub fn record_throughput(&self, duration_s: f64, encrypted_goodput_mbps: f64, frames: u64) -> Result<()> {
        let rec = ThroughputRecord {
            timestamp: Utc::now(),
            duration_s,
            encrypted_goodput_mbps,
            frames,
            fps: if duration_s > 0.0 { frames as f64 / duration_s } else { 0.0 },
        };
        let mut w = self.throughput_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;
        Ok(())
    }

    /// Record a single per-frame latency sample in milliseconds.
    /// The project should stamp frames with the sender timestamp (UTC or monotonic) before encryption.
    pub fn record_frame_latency_ms(&self, latency_ms: f64) -> Result<()> {
        // Filter out implausible samples (negative, NaN/Inf, or extremely large)
        if !latency_ms.is_finite() || latency_ms < 0.0 || latency_ms > 10_000.0 {
            // ignore outlier
            return Ok(());
        }

        {
            let mut lat = self.latencies_ms.lock().unwrap();
            lat.push(latency_ms);
            // keep memory bounded; cap to last 100k samples
            let len = lat.len();
            if len > 100_000 {
                let remove = len - 100_000;
                lat.drain(0..remove);
            }
        }
        Ok(())
    }

    /// Compute summary statistics (mean, p50, p95) and write to latency CSV.
    pub fn write_latency_summary(&self) -> Result<()> {
        let (count, mean, p50, p95) = {
            let lat_guard = self.latencies_ms.lock().unwrap();
            let mut copy = lat_guard.clone();
            copy.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let count = copy.len();
            if count == 0 {
                (0usize, 0.0f64, 0.0f64, 0.0f64)
            } else {
                let sum: f64 = copy.iter().sum();
                let mean = sum / count as f64;
                let p50 = percentile(&copy, 50.0);
                let p95 = percentile(&copy, 95.0);
                (count, mean, p50, p95)
            }
        };

        let rec = LatencySummary {
            timestamp: Utc::now(),
            count,
            mean_ms: mean,
            p50_ms: p50,
            p95_ms: p95,
        };
        let mut w = self.latency_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;

        // Clear samples so future summaries are per-interval and not cumulative
        {
            let mut lat_guard = self.latencies_ms.lock().unwrap();
            lat_guard.clear();
        }

        Ok(())
    }

    /// Snapshot system stats: CPU usage, memory, temperature (best-effort).
    pub fn record_system_snapshot(&self) -> Result<()> {
        use std::{thread, time};
        let mut sys = System::new_all();
        sys.refresh_cpu();
        sys.refresh_memory();
        // Wait 500ms for sysinfo to update CPU usage
        thread::sleep(time::Duration::from_millis(500));
        sys.refresh_cpu();
        let cpu = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32;
        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        let temp = read_cpu_temp().ok();

        // Only log if cpu usage is nonzero
        if cpu > 0.0 {
            let rec = SystemRecord {
                timestamp: Utc::now(),
                cpu_usage_percent: cpu,
                total_memory_bytes: total_mem * 1024, // sysinfo returns KB
                used_memory_bytes: used_mem * 1024,
                temp_c: temp,
            };
            let mut w = self.system_w.lock().unwrap();
            w.serialize(rec)?;
            w.flush()?;
        }
        Ok(())
    }

    /// Record loss/error counters.
    pub fn record_errors(&self, drops: u64, gcm_tag_failures: u64, retransmissions: u64) -> Result<()> {
        let rec = ErrorRecord {
            timestamp: Utc::now(),
            drops,
            gcm_tag_failures,
            retransmissions,
        };
        let mut w = self.errors_w.lock().unwrap();
        w.serialize(rec)?;
        w.flush()?;
        Ok(())
    }

    /// Helper to produce an 8-byte little-endian sender timestamp (nanoseconds since UNIX_EPOCH).
    /// Call this right before encryption and put into your frame header.
    pub fn make_sender_timestamp_bytes() -> [u8; 8] {
        let now = Utc::now();
        let ns = now.timestamp_nanos() as u64;
        ns.to_le_bytes()
    }

    /// Helper to parse sender timestamp bytes that were embedded in a frame header by `make_sender_timestamp_bytes`.
    /// Returns a DateTime<Utc> on success.
    pub fn parse_sender_timestamp_bytes(bytes: [u8; 8]) -> Option<DateTime<Utc>> {
        let ns = u64::from_le_bytes(bytes);
        // treat as signed i128 to support negative? we'll assume positive
        let secs = (ns / 1_000_000_000) as i64;
        let rem_ns = (ns % 1_000_000_000) as u32;
        Some(DateTime::<Utc>::from_utc(chrono::NaiveDateTime::from_timestamp_opt(secs, rem_ns)?, Utc))
    }
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
        let w = rank - lo as f64;
        sorted[lo] * (1.0 - w) + sorted[hi] * w
    }
}

fn compute_energy_joules(samples: &[EnergySample]) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    // convert DateTime to seconds since epoch as f64
    let mut joules = 0.0;
    for w in samples.windows(2) {
        let a = &w[0];
        let b = &w[1];
        let ta = a.timestamp.timestamp_nanos() as f64 / 1e9;
        let tb = b.timestamp.timestamp_nanos() as f64 / 1e9;
        let dt = tb - ta;
        if dt <= 0.0 {
            continue;
        }
        let pa = a.voltage_v * a.current_a;
        let pb = b.voltage_v * b.current_a;
        let p_avg = 0.5 * (pa + pb);
        joules += p_avg * dt;
    }
    joules
}

fn read_cpu_temp() -> Result<f64> {
    // typical Raspberry Pi path
    let mut f = File::open("/sys/class/thermal/thermal_zone0/temp")?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let raw: f64 = s.trim().parse()?;
    // usually in millidegrees
    Ok(raw / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_metrics_and_write() {
        let dir = tempfile::tempdir().unwrap();
        let m = Metrics::new(dir.path()).unwrap();
    m.record_handshake("ECDH", std::time::Duration::from_secs_f64(0.012), 128, 256, true, None, None).unwrap();
        let samples = vec![
            EnergySample { timestamp: Utc::now(), voltage_v: 5.0, current_a: 0.5 },
            EnergySample { timestamp: Utc::now(), voltage_v: 5.0, current_a: 0.52 },
        ];
        m.record_energy_samples("handshake", &samples, 100.0).unwrap();
        m.record_throughput(1.0, 12.3, 30).unwrap();
        m.record_frame_latency_ms(10.0).unwrap();
        m.write_latency_summary().unwrap();
        m.record_system_snapshot().unwrap();
        m.record_errors(0, 0, 0).unwrap();
    }
}