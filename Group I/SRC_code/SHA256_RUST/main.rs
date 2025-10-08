use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const MESSAGE: &[u8] = b"Hi this is plaintext"; // 21 bytes
const STREAM_BLOCK: usize = 16 * 1024;          // 16 KB per update
const STREAM_SECS: f64 = 3.0;                   // ~3 seconds

fn fmt_bps(bps: f64) -> String {
    if bps >= 1e9 { format!("{:.3} GB/s ({:.1} MB/s)", bps/1e9, bps/1e6) }
    else if bps >= 1e6 { format!("{:.1} MB/s", bps/1e6) }
    else if bps >= 1e3 { format!("{:.1} kB/s", bps/1e3) }
    else { format!("{:.0} B/s", bps) }
}

fn main() {
    // ---------- One-shot (latency focus) ----------
    let t0 = Instant::now();
    let mut h = Sha256::new();   // setup context
    let t1 = Instant::now();

    let t2 = Instant::now();
    h.update(MESSAGE);           // hash tiny message
    let digest = h.finalize();   // finalize
    let t3 = Instant::now();

    let setup_time   = (t1 - t0).as_secs_f64();
    let hash_time    = (t3 - t2).as_secs_f64();
    let total_time   = (t3 - t0).as_secs_f64();
    let tiny_tp_bps  = (MESSAGE.len() as f64) / hash_time;

    println!("== One-shot (21-byte message) ==");
    println!("plaintext:            {}", String::from_utf8_lossy(MESSAGE));
    println!("digest (hex):         {}", hex::encode(digest));
    println!("setup latency:        {:.2} µs", setup_time * 1e6);
    println!("hash latency:         {:.2} µs  (execution time)", hash_time * 1e6);
    println!("total latency:        {:.2} µs  (setup + hash)", total_time * 1e6);
    println!("throughput (tiny):    {}", fmt_bps(tiny_tp_bps));
    println!();

    // ---------- Streaming (throughput focus) ----------
    let mut buf = vec![0u8; STREAM_BLOCK];
    let mut total: usize = 0;
    let mut calls: u64 = 0;

    let mut h2 = Sha256::new();
    let start = Instant::now();
    let deadline = start + Duration::from_secs_f64(STREAM_SECS);

    while Instant::now() < deadline {
        h2.update(&buf);
        total += buf.len();
        calls += 1;
    }
    let digest2 = h2.finalize();
    let elapsed = (Instant::now() - start).as_secs_f64();
    let bps = (total as f64) / elapsed;
    let per_call_latency = elapsed / (calls as f64);

    println!("== Streaming (SHA-256, software-only) ==");
    println!("elapsed:              {:.3} s", elapsed);
    println!("bytes processed:      {}", total);
    println!("throughput:           {}", fmt_bps(bps));
    println!("per-call latency:     {:.2} µs per {}B update()", per_call_latency * 1e6, STREAM_BLOCK);
    println!("calls made:           {}", calls);
    println!("digest (hex):         {}", hex::encode(digest2));
}
