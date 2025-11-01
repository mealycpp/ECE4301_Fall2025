use chrono::{Utc, SecondsFormat};
use csv::Writer;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::fs::{create_dir_all, OpenOptions};
use std::sync::Arc;
use std::time::{SystemTime, Duration};
use tokio::sync::Mutex;
use sysinfo::{System, SystemExt, CpuExt};
use std::fmt;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// Metrics logging utilities (CSV) used by leader and member.
///
/// Files produced:
/// - handshake_ecdh.csv  (ts_start, ts_end, mech, bytes_tx, bytes_rx, cpu_avg, mem_mb, energy_j)
/// - throughput.csv
/// - latency.csv
/// - steady_stream.csv   (ts, fps, goodput_mbps, latency_ms_p50, cpu_pct, mem_mb, temp_c, drops, tag_fail)
/// - sys.csv
/// - loss.csv
/// - runtime_features.csv (ts, aes, pmull, node_id)
static FEATURE_LOGGED: AtomicBool = AtomicBool::new(false);

pub fn log_arm_crypto_support() {
    if FEATURE_LOGGED.swap(true, Ordering::SeqCst) { return; }
    #[cfg(target_arch = "aarch64")]
    {
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        eprintln!("ARMv8 Crypto Extensions — AES: {}, PMULL: {}", aes, pmull);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        eprintln!("ARMv8 feature detection not available on this arch");
    }
}

fn iso_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn read_temp_c() -> Option<f32> {
    if let Ok(s) = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp") {
        if let Ok(milli) = s.trim().parse::<f32>() {
            return Some(milli / 1000.0);
        }
    }
    None
}

#[derive(Clone)]
pub struct MetricsLogger {
    out_dir: PathBuf,
    handshake_w: Arc<Mutex<Writer<std::io::BufWriter<std::fs::File>>>>,
    handshake_ecdh_w: Arc<Mutex<Writer<std::io::BufWriter<std::fs::File>>>>,
    throughput_w: Arc<Mutex<Writer<std::io::BufWriter<std::fs::File>>>>,
    latency_w: Arc<Mutex<Writer<std::io::BufWriter<std::fs::File>>>>,
    steady_w: Arc<Mutex<Writer<std::io::BufWriter<std::fs::File>>>>,
    sys_w: Arc<Mutex<Writer<std::io::BufWriter<std::fs::File>>>>,
    loss_w: Arc<Mutex<Writer<std::io::BufWriter<std::fs::File>>>>,
    runtime_w: Arc<Mutex<Writer<std::io::BufWriter<std::fs::File>>>>,
}

#[derive(Serialize)]
struct HandshakeRow {
    ts: String,
    role: String,
    duration_s: f64,
    bytes_exchanged: u64,
    success: bool,
    note: String,
}

#[derive(Serialize)]
struct HandshakeEcdhRow {
    ts_start: String,
    ts_end: String,
    mech: String,
    bytes_tx: u64,
    bytes_rx: u64,
    cpu_avg: f32,
    mem_mb: u64,
    energy_j: f64,
}

#[derive(Serialize)]
struct ThroughputRow {
    ts: String,
    duration_s: f64,
    bytes_encrypted: u64,
    mbps: f64,
    fps: f64,
}

#[derive(Serialize)]
struct LatencyRow {
    ts: String,
    sender_ts_iso: String,
    recv_ts_iso: String,
    latency_s: f64,
    frame_counter: u32,
    size_bytes: usize,
    success: bool,
}

#[derive(Serialize)]
struct SteadyRow {
    ts: String,
    fps: f32,
    goodput_mbps: f64,
    latency_ms_p50: f64,
    cpu_pct: f32,
    mem_mb: u64,
    temp_c: Option<f32>,
    drops: u64,
    tag_fail: u64,
}

#[derive(Serialize)]
struct SysRow {
    ts: String,
    cpu_percent: f32,
    total_mem_kb: u64,
    used_mem_kb: u64,
    temp_c: Option<f32>,
}

#[derive(Serialize)]
struct LossRow {
    ts: String,
    event: String,
    count: u64,
    note: String,
}

#[derive(Serialize)]
struct RuntimeRow {
    ts: String,
    aes: bool,
    pmull: bool,
    node_id: String,
}

impl MetricsLogger {
    /// Create a new logger writing CSV files into out_dir (creates directory)
    pub async fn new<P: AsRef<Path>>(out_dir: P) -> anyhow::Result<Self> {
        let out_dir = out_dir.as_ref().to_path_buf();
        create_dir_all(&out_dir)?;

        let h = open_csv(&out_dir.join("handshake.csv"), &["ts","role","duration_s","bytes_exchanged","success","note"])?;
        let he = open_csv(&out_dir.join("handshake_ecdh.csv"), &["ts_start","ts_end","mech","bytes_tx","bytes_rx","cpu_avg","mem_mb","energy_j"])?;
        let t = open_csv(&out_dir.join("throughput.csv"), &["ts","duration_s","bytes_encrypted","mbps","fps"])?;
        let l = open_csv(&out_dir.join("latency.csv"), &["ts","sender_ts_iso","recv_ts_iso","latency_s","frame_counter","size_bytes","success"])?;
        let s = open_csv(&out_dir.join("steady_stream.csv"), &["ts","fps","goodput_mbps","latency_ms_p50","cpu_pct","mem_mb","temp_c","drops","tag_fail"])?;
        let sys = open_csv(&out_dir.join("sys.csv"), &["ts","cpu_percent","total_mem_kb","used_mem_kb","temp_c"])?;
        let lo = open_csv(&out_dir.join("loss.csv"), &["ts","event","count","note"])?;
        let rt = open_csv(&out_dir.join("runtime_features.csv"), &["ts","aes","pmull","node_id"])?;

        Ok(MetricsLogger {
            out_dir,
            handshake_w: Arc::new(Mutex::new(h)),
            handshake_ecdh_w: Arc::new(Mutex::new(he)),
            throughput_w: Arc::new(Mutex::new(t)),
            latency_w: Arc::new(Mutex::new(l)),
            steady_w: Arc::new(Mutex::new(s)),
            sys_w: Arc::new(Mutex::new(sys)),
            loss_w: Arc::new(Mutex::new(lo)),
            runtime_w: Arc::new(Mutex::new(rt)),
        })
    }

    pub async fn log_handshake(&self, role: &str, duration: Duration, bytes_exchanged: u64, success: bool, note: &str) -> anyhow::Result<()> {
        let row = HandshakeRow {
            ts: iso_now(),
            role: role.to_string(),
            duration_s: duration.as_secs_f64(),
            bytes_exchanged,
            success,
            note: note.to_string(),
        };
        let mut w = self.handshake_w.lock().await;
        w.serialize(row)?;
        w.flush()?;
        Ok(())
    }

    /// New detailed handshake logging for ECDH-style handshakes
    pub async fn log_handshake_ecdh(&self, ts_start: SystemTime, ts_end: SystemTime, mech: &str, bytes_tx: u64, bytes_rx: u64, cpu_avg: f32, mem_mb: u64, energy_j: f64) -> anyhow::Result<()> {
        let row = HandshakeEcdhRow {
            ts_start: chrono::DateTime::<Utc>::from(ts_start).to_rfc3339_opts(SecondsFormat::Secs, true),
            ts_end: chrono::DateTime::<Utc>::from(ts_end).to_rfc3339_opts(SecondsFormat::Secs, true),
            mech: mech.to_string(),
            bytes_tx,
            bytes_rx,
            cpu_avg,
            mem_mb,
            energy_j,
        };
        let mut w = self.handshake_ecdh_w.lock().await;
        w.serialize(row)?;
        w.flush()?;
        Ok(())
    }

    pub async fn log_throughput(&self, duration: Duration, bytes_encrypted: u64, fps: f32) -> anyhow::Result<()> {
        let mbps = (bytes_encrypted as f64 * 8.0) / (1024.0*1024.0) / duration.as_secs_f64();
        let row = ThroughputRow {
            ts: iso_now(),
            duration_s: duration.as_secs_f64(),
            bytes_encrypted,
            mbps,
            fps: fps as f64,
        };
        let mut w = self.throughput_w.lock().await;
        w.serialize(row)?;
        w.flush()?;
        Ok(())
    }

    pub async fn log_latency(&self, sender_ts_iso: &str, recv_instant: SystemTime, frame_counter: u32, size_bytes: usize, success: bool) -> anyhow::Result<()> {
        let recv_iso = chrono::DateTime::<Utc>::from(recv_instant).to_rfc3339_opts(SecondsFormat::Secs, true);
        let sender_dt = chrono::DateTime::parse_from_rfc3339(sender_ts_iso).map_err(|e| anyhow::anyhow!(e))?;
        // convert parsed sender to Utc to match recv_iso semantics
        let sender_utc = sender_dt.with_timezone(&Utc);
        let recv_dt = chrono::DateTime::parse_from_rfc3339(&recv_iso)?;
        let recv_utc = recv_dt.with_timezone(&Utc);
        let latency = (recv_utc - sender_utc).to_std().map(|d| d.as_secs_f64()).unwrap_or(0.0);
        let row = LatencyRow {
            ts: iso_now(),
            sender_ts_iso: sender_ts_iso.to_string(),
            recv_ts_iso: recv_iso,
            latency_s: latency,
            frame_counter,
            size_bytes,
            success,
        };
        let mut w = self.latency_w.lock().await;
        w.serialize(row)?;
        w.flush()?;
        Ok(())
    }

    pub async fn log_steady_stream(&self, fps: f32, goodput_mbps: f64, latency_ms_p50: f64, cpu_pct: f32, mem_mb: u64, temp_c: Option<f32>, drops: u64, tag_fail: u64) -> anyhow::Result<()> {
        let row = SteadyRow {
            ts: iso_now(),
            fps,
            goodput_mbps,
            latency_ms_p50,
            cpu_pct,
            mem_mb,
            temp_c,
            drops,
            tag_fail,
        };
        let mut w = self.steady_w.lock().await;
        w.serialize(row)?;
        w.flush()?;
        Ok(())
    }

    pub async fn log_sys_sample(&self) -> anyhow::Result<()> {
        let mut sys = System::new();
        sys.refresh_cpu();
        sys.refresh_memory();
        let cpu_percent = sys.global_cpu_info().cpu_usage();
        let total_mem_kb = sys.total_memory();
        let used_mem_kb = sys.used_memory();
        let temp = read_temp_c();
        let row = SysRow {
            ts: iso_now(),
            cpu_percent,
            total_mem_kb,
            used_mem_kb,
            temp_c: temp,
        };
        let mut w = self.sys_w.lock().await;
        w.serialize(row)?;
        w.flush()?;
        Ok(())
    }

    pub fn spawn_periodic_sys_sampler(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let logger = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = logger.log_sys_sample().await {
                    eprintln!("sys sample log error: {:?}", e);
                }
                tokio::time::sleep(interval).await;
            }
        })
    }

    pub async fn log_loss(&self, event: &str, count: u64, note: &str) -> anyhow::Result<()> {
        let row = LossRow {
            ts: iso_now(),
            event: event.to_string(),
            count,
            note: note.to_string(),
        };
        let mut w = self.loss_w.lock().await;
        w.serialize(row)?;
        w.flush()?;
        Ok(())
    }

    /// Log runtime features (one-shot) — records AES/PMULL detection and node id
    pub async fn log_runtime_features(&self, node_id: &str) -> anyhow::Result<()> {
        #[cfg(target_arch = "aarch64")]
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        #[cfg(not(target_arch = "aarch64"))]
        let aes = false;
        #[cfg(target_arch = "aarch64")]
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        #[cfg(not(target_arch = "aarch64"))]
        let pmull = false;

        let row = RuntimeRow {
            ts: iso_now(),
            aes,
            pmull,
            node_id: node_id.to_string(),
        };
        let mut w = self.runtime_w.lock().await;
        w.serialize(row)?;
        w.flush()?;
        Ok(())
    }
}

fn open_csv(path: &Path, headers: &[&str]) -> anyhow::Result<Writer<std::io::BufWriter<std::fs::File>>> {
    let file = OpenOptions::new().create(true).append(true).read(true).open(path)?;
    let meta = file.metadata()?;
    let mut writer = Writer::from_writer(std::io::BufWriter::new(file));
    if meta.len() == 0 {
        writer.write_record(headers)?;
        writer.flush()?;
    }
    Ok(writer)
}

impl fmt::Debug for MetricsLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsLogger").finish()
    }
}
