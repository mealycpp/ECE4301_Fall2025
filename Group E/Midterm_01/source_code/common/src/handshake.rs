use serde::Serialize;
use std::{
    fs::OpenOptions,
    time::Instant,
};
use csv;
use anyhow::Result;

use crate::metrics::{SysSampler, ts_iso};

#[derive(Serialize)]
pub struct HandshakeRow {
    pub ts_start: String,
    pub ts_end: String,
    pub mech: String,      // "ecdh" or "rsa"
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub cpu_avg: f32,
    pub mem_mb: f32,
    pub energy_j: f32,     // keep 0.0 unless you integrate power for HS
}

/// Minimal recorder; call add_tx/add_rx around your handshake I/O,
/// then finish_and_write() once the handshake completes.
pub struct HandshakeRecorder {
    path: String,
    mech: String,
    start_wall: String,
    start_instant: Instant,
    bytes_tx: u64,
    bytes_rx: u64,
    sampler: SysSampler,
    start_cpu: f32,
}

impl HandshakeRecorder {
    pub fn new(csv_path: &str, mech: &str) -> Result<Self> {
        // Ensure parent dir exists
        if let Some(parent) = std::path::Path::new(csv_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut sampler = SysSampler::new();
        let start_cpu = sampler.sample().cpu_pct;

        Ok(Self {
            path: csv_path.to_string(),
            mech: mech.to_string(),
            start_wall: ts_iso(),
            start_instant: Instant::now(),
            bytes_tx: 0,
            bytes_rx: 0,
            sampler,
            start_cpu,
        })
    }

    #[inline] pub fn add_tx(&mut self, n: usize) { self.bytes_tx += n as u64; }
    #[inline] pub fn add_rx(&mut self, n: usize) { self.bytes_rx += n as u64; }

    pub fn finish_and_write(&mut self) -> Result<()> {
        // End sample
        let snap_end = self.sampler.sample();
        let cpu_avg = (self.start_cpu + snap_end.cpu_pct) / 2.0;

        let row = HandshakeRow {
            ts_start: self.start_wall.clone(),
            ts_end: ts_iso(),
            mech: self.mech.clone(),
            bytes_tx: self.bytes_tx,
            bytes_rx: self.bytes_rx,
            cpu_avg,
            mem_mb: snap_end.mem_mb,
            energy_j: 0.0,
        };

        let file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        let mut wtr = csv::WriterBuilder::new().has_headers(true).from_writer(file);
        wtr.serialize(row)?;
        wtr.flush()?;
        Ok(())
    }
}
