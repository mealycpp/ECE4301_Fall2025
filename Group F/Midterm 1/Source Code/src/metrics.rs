use csv::Writer;
use sysinfo::System;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use std::{fs::File, time::Duration};

fn now() -> String { OffsetDateTime::now_utc().format(&Rfc3339).unwrap() }

pub struct Logs {
    pub handshake: Writer<File>,
    pub throughput: Writer<File>,
    pub latency: Writer<File>,
    pub errors: Writer<File>,
    pub energy: Writer<File>,
}

impl Logs {
    pub fn open(prefix:&str) -> Self {
        let mk = |n| Writer::from_path(format!("{prefix}_{n}.csv")).unwrap();
        Self{
            handshake: mk("handshake"),
            throughput: mk("throughput"),
            latency: mk("latency"),
            errors: mk("errors"),
            energy: mk("energy"),
        }
    }
}

pub async fn sys_task(out_path: &'static str) {
    let mut w = Writer::from_path(out_path).expect("open sys csv");
    let mut sys = System::new_all();
    loop {
        sys.refresh_all();
        let cpu = sys.global_cpu_info().cpu_usage(); // works without traits in 0.30
        let mem = sys.used_memory();
        let temp = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp")
            .ok().and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or_default();
        let _ = w.write_record(&[now(), format!("{cpu:.2}"), mem.to_string(), temp.to_string()]);
        let _ = w.flush();
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub fn log_handshake(w:&mut Writer<File>, mech:&str, bytes:usize, secs:f64, ok:bool) {
    let _ = w.write_record(&[now(), mech.to_string(), bytes.to_string(), format!("{secs:.4}"), ok.to_string()]);
    let _ = w.flush();
}
pub fn log_latency(w:&mut Writer<File>, seq:u64, e2e_ms:f64) {
    let _ = w.write_record(&[now(), seq.to_string(), format!("{e2e_ms:.3}")]);
    let _ = w.flush();
}
pub fn log_throughput(w:&mut Writer<File>, mbps:f64, fps:f64) {
    let _ = w.write_record(&[now(), format!("{mbps:.3}"), format!("{fps:.1}")]);
    let _ = w.flush();
}
pub fn log_error(w:&mut Writer<File>, what:&str) {
    let _ = w.write_record(&[now(), what.to_string()]);
    let _ = w.flush();
}
