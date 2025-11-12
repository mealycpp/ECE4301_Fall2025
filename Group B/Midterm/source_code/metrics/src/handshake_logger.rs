use chrono::Utc;
use csv::Writer;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::time::Instant;
use sysinfo::System;

pub struct HandshakeMetrics {
    pub mech: String,      // "RSA" or "ECDH"
    pub bytes_tx: usize,
    pub bytes_rx: usize,
    pub energy_j: f64,     // fill in later when power data added
}

pub fn log_handshake(metrics: HandshakeMetrics, csv_path: &str, start: Instant) -> std::io::Result<()> {
    let ts_start = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    let ts_end = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let mut sys = System::new_all();
    sys.refresh_all();
    let cpu_avg = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32;
    let mem_mb = sys.used_memory() as f64 / 1024.0;

    let path = Path::new(csv_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_exists = path.exists();
    let mut writer = Writer::from_writer(
        OpenOptions::new().append(true).create(true).open(csv_path)?
    );

    if !file_exists {
        writer.write_record(&[
            "ts_start",
            "ts_end",
            "duration_ms",
            "mech",
            "bytes_tx",
            "bytes_rx",
            "cpu_avg",
            "mem_mb",
            "energy_j",
        ])?;
    }

    writer.write_record(&[
        ts_start,
        ts_end,
        format!("{:.2}", duration_ms),
        metrics.mech,
        metrics.bytes_tx.to_string(),
        metrics.bytes_rx.to_string(),
        format!("{:.2}", cpu_avg),
        format!("{:.2}", mem_mb),
        format!("{:.4}", metrics.energy_j),
    ])?;

    writer.flush()?;
    Ok(())
}
