use std::fs;
use std::time::{Duration, Instant};

#[derive(Default, Clone, Copy)]
pub struct SysSample {
    pub cpu_total: u64,
    pub cpu_idle: u64,
    pub mem_total_kb: u64,
    pub mem_free_kb: u64,
    pub temp_c: f32,
}

pub fn read_sample() -> SysSample {
    let mut s = SysSample::default();

    // /proc/stat for CPU
    if let Ok(txt) = fs::read_to_string("/proc/stat") {
        if let Some(line) = txt.lines().find(|l| l.starts_with("cpu ")) {
            // cpu  user nice system idle iowait irq softirq steal guest guest_nice
            let nums: Vec<u64> = line.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
            if nums.len() >= 4 {
                s.cpu_total = nums.iter().take(8).sum(); // up to steal
                s.cpu_idle = nums[3] + nums.get(4).copied().unwrap_or(0); // idle + iowait
            }
        }
    }

    // /proc/meminfo
    if let Ok(txt) = fs::read_to_string("/proc/meminfo") {
        for line in txt.lines() {
            if line.starts_with("MemTotal:") { s.mem_total_kb = line.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0); }
            if line.starts_with("MemAvailable:") { s.mem_free_kb = line.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0); }
        }
    }

    // temperature (RPi)
    if let Ok(txt) = fs::read_to_string("/sys/class/thermal/thermal_zone0/temp") {
        if let Ok(milli) = txt.trim().parse::<i64>() { s.temp_c = milli as f32 / 1000.0; }
    }

    s
}

pub fn cpu_pct(a: SysSample, b: SysSample) -> f32 {
    let total = b.cpu_total.saturating_sub(a.cpu_total) as f32;
    let idle  = b.cpu_idle.saturating_sub(a.cpu_idle) as f32;
    if total <= 0.0 { 0.0 } else { (1.0 - idle / total) * 100.0 }
}

pub fn mem_mb(s: SysSample) -> f32 {
    // simple: MemUsed ~= MemTotal - MemAvailable
    let used_kb = s.mem_total_kb.saturating_sub(s.mem_free_kb);
    used_kb as f32 / 1024.0
}

/// Sample CPU% over a short window for handshake
pub fn cpu_pct_over(dur: Duration) -> f32 {
    let a = read_sample();
    std::thread::sleep(dur);
    let b = read_sample();
    cpu_pct(a, b)
}
