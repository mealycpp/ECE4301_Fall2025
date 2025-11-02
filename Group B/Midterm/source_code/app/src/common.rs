use std::fs::OpenOptions;
use std::io::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

// ---------------- Frame header ----------------

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FrameHeader {
    pub seq: u32,   // monotonically increasing
    pub ts_ns: u64, // sender monotonic nanoseconds
}

impl FrameHeader {
    pub const BYTES: usize = 12;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut b = [0u8; Self::BYTES];
        b[..4].copy_from_slice(&self.seq.to_be_bytes());
        b[4..12].copy_from_slice(&self.ts_ns.to_be_bytes());
        b
    }

    pub fn from_slice(s: &[u8]) -> Option<FrameHeader> {
        if s.len() < Self::BYTES {
            return None;
        }
        let mut u4 = [0u8; 4];
        let mut u8 = [0u8; 8];
        u4.copy_from_slice(&s[..4]);
        u8.copy_from_slice(&s[4..12]);
        Some(FrameHeader {
            seq: u32::from_be_bytes(u4),
            ts_ns: u64::from_be_bytes(u8),
        })
    }
}

// A monotonic origin for ts_ns
pub fn now_monotonic_ns(origin: Instant) -> u64 {
    origin.elapsed().as_nanos() as u64
}

pub fn now_iso8601() -> String {
    let st = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    let secs = st.as_secs() as i64;
    let nanos = st.subsec_nanos();
    format!("{secs}.{nanos:09}Z")
}

// ---------------- Metrics ----------------

#[derive(Serialize)]
pub struct SteadyRow<'a> {
    pub ts: &'a str,
    pub role: &'a str, // "sender" | "receiver"
    pub fps: f32,
    pub goodput_mbps: f32,
    pub latency_ms_p50: f32,
    pub latency_ms_p95: f32,
    pub cpu_pct: f32,
    pub mem_mb: f32,
    pub temp_c: f32,
    pub drops: u64,
    pub tag_fail: u64,
}

pub struct Metrics {
    sys: System,
    role: &'static str,
    csv_path: String,
    buf_frames: u64,
    buf_bytes: u64,
    latencies_ns: Vec<u32>,
    drops: u64,
    tag_fail: u64,
}

impl Metrics {
    pub fn new(role: &'static str, csv_path: &str) -> Self {
        let sys = System::new_with_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything()),
        );

        // Ensure CSV header
        if !std::path::Path::new(csv_path).exists() {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(csv_path)
                .unwrap();
            let header = "ts,role,fps,goodput_mbps,latency_ms_p50,latency_ms_p95,cpu_pct,mem_mb,temp_c,drops,tag_fail\n";
            let _ = f.write_all(header.as_bytes());
        }

        Self {
            sys,
            role,
            csv_path: csv_path.to_string(),
            buf_frames: 0,
            buf_bytes: 0,
            latencies_ns: Vec::with_capacity(256),
            drops: 0,
            tag_fail: 0,
        }
    }

    pub fn add_frame(&mut self, bytes: usize) {
        self.buf_frames += 1;
        self.buf_bytes += bytes as u64;
    }

    pub fn add_latency_ns(&mut self, ns: u64) {
        let v = ns.min(u32::MAX as u64) as u32;
        self.latencies_ns.push(v);
        if self.latencies_ns.len() > 512 {
            self.latencies_ns.drain(..self.latencies_ns.len() - 512);
        }
    }

    pub fn inc_drop(&mut self) {
        self.drops += 1;
    }

    pub fn inc_tag_fail(&mut self) {
        self.tag_fail += 1;
    }

    pub fn sample_and_flush(&mut self) {
        self.sys.refresh_cpu();
        self.sys.refresh_memory();

        let cpu_pct = self.sys.global_cpu_info().cpu_usage();
        let mem_mb = (self.sys.used_memory() as f32) / (1024.0 * 1024.0);
        let temp_c = read_temp_c();

        let fps = self.buf_frames as f32 * 4.0;
        let goodput_mbps = (self.buf_bytes as f32 * 4.0) * 8.0 / 1_000_000.0;

        let (p50, p95) = percentiles_ms(&mut self.latencies_ns);

        let row = SteadyRow {
            ts: &now_iso8601(),
            role: self.role,
            fps,
            goodput_mbps,
            latency_ms_p50: p50,
            latency_ms_p95: p95,
            cpu_pct,
            mem_mb,
            temp_c,
            drops: self.drops,
            tag_fail: self.tag_fail,
        };

        let line = format!(
            "{},{},{:.2},{:.2},{:.2},{:.2},{:.1},{:.1},{:.1},{},{}\n",
            row.ts,
            row.role,
            row.fps,
            row.goodput_mbps,
            row.latency_ms_p50,
            row.latency_ms_p95,
            row.cpu_pct,
            row.mem_mb,
            row.temp_c,
            row.drops,
            row.tag_fail
        );

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.csv_path)
            .unwrap();
        let _ = f.write_all(line.as_bytes());

        self.buf_frames = 0;
        self.buf_bytes = 0;
    }
}

fn read_temp_c() -> f32 {
    if let Ok(s) = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp") {
        if let Ok(v) = s.trim().parse::<i32>() {
            return v as f32 / 1000.0;
        }
    }
    f32::NAN
}

fn percentiles_ms(lat_ns: &mut Vec<u32>) -> (f32, f32) {
    if lat_ns.is_empty() {
        return (f32::NAN, f32::NAN);
    }
    lat_ns.sort_unstable();

    let len = lat_ns.len();
    let idx50 = ((len as f32) * 0.50).floor() as usize;
    let idx95 = ((len as f32) * 0.95).floor() as usize;
    let idx95 = idx95.min(len - 1); // ensure within bounds

    let p50 = lat_ns[idx50] as f32 / 1_000_000.0;
    let p95 = lat_ns[idx95] as f32 / 1_000_000.0;
    (p50, p95)
}


// ---------------- Rekey Control Frame ----------------

pub const CTRL_REKEY_FLAG: u8 = 0xA5;
pub const CTRL_REKEY_SALT_LEN: usize = 16;

pub fn pack_rekey_control(salt16: [u8; 16]) -> [u8; 17] {
    let mut b = [0u8; 17];
    b[0] = CTRL_REKEY_FLAG;
    b[1..].copy_from_slice(&salt16);
    b
}

pub fn parse_control(buf: &[u8]) -> Option<[u8; 16]> {
    if buf.len() == 1 + CTRL_REKEY_SALT_LEN && buf[0] == CTRL_REKEY_FLAG {
        let mut s = [0u8; 16];
        s.copy_from_slice(&buf[1..]);
        return Some(s);
    }
    None
}
