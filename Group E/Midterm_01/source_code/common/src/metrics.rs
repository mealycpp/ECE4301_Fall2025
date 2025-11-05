use serde::Serialize;
use std::{
    fs::OpenOptions,
    time::{Duration, Instant},
};
use sysinfo::{System, RefreshKind, CpuRefreshKind, MemoryRefreshKind};

/// Point-in-time system snapshot.
#[derive(Debug, Clone, Copy)]
pub struct SysSnapshot {
    pub cpu_pct: f32,
    pub mem_mb: f32,
    pub temp_c: Option<f32>,
}

/// Lightweight system sampler (CPU/MEM/TEMP).
pub struct SysSampler {
    sys: System,
    last_cpu_refresh: Instant,
}

impl SysSampler {
    pub fn new() -> Self {
        // sysinfo 0.30 requires explicit MemoryRefreshKind.
        let sys = System::new_with_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything()),
        );
        Self {
            sys,
            last_cpu_refresh: Instant::now() - Duration::from_secs(2),
        }
    }

    /// Sample CPU (with ~750ms min refresh), memory, and temperature.
    pub fn sample(&mut self) -> SysSnapshot {
        if self.last_cpu_refresh.elapsed() >= Duration::from_millis(750) {
            self.sys.refresh_cpu();
            self.last_cpu_refresh = Instant::now();
        }
        self.sys.refresh_memory();

        let cpu_pct = self.sys.global_cpu_info().cpu_usage();
        // used_memory() is bytes in recent sysinfo; convert to MB.
        let mem_mb = (self.sys.used_memory() as f32) / (1024.0 * 1024.0);
        let temp_c = read_cpu_temp_c();

        SysSnapshot { cpu_pct, mem_mb, temp_c }
    }
}

fn read_cpu_temp_c() -> Option<f32> {
    // RPi typically exposes thermal_zone0 as millidegrees C.
    let path = "/sys/class/thermal/thermal_zone0/temp";
    if let Ok(s) = std::fs::read_to_string(path) {
        if let Ok(mdeg) = s.trim().parse::<i32>() {
            return Some(mdeg as f32 / 1000.0);
        }
    }
    None
}

/// Keeps track of bytes/frames over ~1s windows to compute Mb/s and FPS.
pub struct RateMeter {
    last_t: Instant,
    last_bytes: u64,
    last_frames: u64,
}

impl RateMeter {
    pub fn new() -> Self {
        Self {
            last_t: Instant::now(),
            last_bytes: 0,
            last_frames: 0,
        }
    }

    /// Provide cumulative totals; returns (Mb/s, fps) once >= ~1s elapsed.
    pub fn tick(&mut self, total_bytes: u64, total_frames: u64) -> Option<(f32, f32)> {
        let now = Instant::now();
        let dt = now.duration_since(self.last_t).as_secs_f32();
        if dt < 0.95 {
            return None;
        }

        let dbytes = (total_bytes - self.last_bytes) as f32;
        let dframes = (total_frames - self.last_frames) as f32;

        self.last_t = now;
        self.last_bytes = total_bytes;
        self.last_frames = total_frames;

        let mbps = (dbytes * 8.0) / (1_000_000.0 * dt);
        let fps = dframes / dt;
        Some((mbps, fps))
    }
}

/// Row schema for steady-stream CSV logging.
#[derive(Serialize)]
pub struct SteadyRow {
    pub ts: String,
    pub node: String,
    pub goodput_mbps: f32,
    pub fps: f32,
    pub cpu_pct: f32,
    pub mem_mb: f32,
    pub temp_c: Option<f32>,
    pub drops: u32,
    pub tag_fail: u32,
}

/// Simple CSV appender for steady-stream metrics.
pub struct CsvLogger {
    wtr: csv::Writer<std::fs::File>,
}

impl CsvLogger {
    pub fn open_append(path: &str) -> anyhow::Result<Self> {
        // Ensure parent directory exists.
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let wtr = csv::WriterBuilder::new()
            .has_headers(true)
            .from_writer(file);
        Ok(Self { wtr })
    }

    pub fn write_row(&mut self, row: &SteadyRow) -> anyhow::Result<()> {
        self.wtr.serialize(row)?;
        self.wtr.flush()?;
        Ok(())
    }
}

/// ISO-8601 wallclock timestamp (UTC, ms precision).
pub fn ts_iso() -> String {
    use chrono::{SecondsFormat, Utc};
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Pretty one-line stderr logger for live stats.
pub fn log_line(node: &str, mbps: f32, fps: f32, snap: SysSnapshot) {
    let t = snap
        .temp_c
        .map(|v| format!("{v:.1}°C"))
        .unwrap_or_else(|| "-".into());
    eprintln!(
        "[{}] {:>6.2} Mb/s  {:>5.1} fps  CPU {:>5.1}%  MEM {:>6.1} MB  TEMP {}",
        node, mbps, fps, snap.cpu_pct, snap.mem_mb, t
    );
}
