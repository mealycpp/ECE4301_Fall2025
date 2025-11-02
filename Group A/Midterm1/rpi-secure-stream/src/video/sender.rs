use crate::net::aead_stream::Aes128GcmStream;
use crate::net::transport::{tcp_connect_with_retry, WireMsg, FLAG_FRAME, FLAG_REKEY};
use anyhow::Result;
use bytes::Bytes;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::time::Duration;

const REKEY_EVERY_FRAMES: u64 = 900; // ~30s @ 30fps

pub struct Sender {
    pub aead: Aes128GcmStream,
    pub pipeline: gst::Pipeline,   // ← keep the pipeline
    pub sink: AppSink,
    pub width: i32,
    pub height: i32,
    pub fps: i32,
}

impl Sender {
    pub fn new(
        aead: Aes128GcmStream,
        pipeline: gst::Pipeline,    // ← take it in
        sink: AppSink,
        width: i32,
        height: i32,
        fps: i32,
    ) -> Self {
        Self { aead, pipeline, sink, width, height, fps }
    }

        pub async fn run(mut self, leader_addr: &str) -> Result<()> {
            eprintln!("[sender] connecting to {leader_addr} ...");
            let mut conn = tcp_connect_with_retry(leader_addr, Duration::from_secs(20)).await?;
            eprintln!("[sender] connected to {leader_addr}");

            // === NEW: send bootstrap REKEY for seq=0 ===
            let mut key0 = [0u8; 16];
            let mut nb0  = [0u8; 12];
            OsRng.fill_bytes(&mut key0);
            OsRng.fill_bytes(&mut nb0);

            let mut p0 = Vec::with_capacity(8 + 16 + 12);
            p0.extend_from_slice(&0u64.to_be_bytes());   // next_seq = 0
            p0.extend_from_slice(&key0);
            p0.extend_from_slice(&nb0);

            let ts0 = gst::SystemClock::obtain().time().map(|t| t.nseconds()).unwrap_or(0) as u64;
            let msg0 = WireMsg {
                flags: FLAG_REKEY,
                ts_ns: ts0,
                seq: 0,
                pt_len: 0,
                payload: Bytes::from(p0),
            };
            msg0.write_to(&mut conn).await?;
            self.aead.rekey(key0, nb0)?;                 // switch locally
            eprintln!("[sender] bootstrap REKEY sent (seq=0)");
        


                self.aead.rekey(key, nb)?;
            }

            let sample_opt = self.sink.try_pull_sample(gst::ClockTime::from_mseconds(500));
            let Some(sample) = sample_opt else {
                // No frame for 500ms; log once per 2s so we know camera is idle
                if last_log.elapsed() > std::time::Duration::from_secs(2) {
                    eprintln!("[sender] waiting for frames (no sample in 500ms)...");
                    last_log = std::time::Instant::now();
                }
                continue;
            };

            let buffer = sample.buffer().ok_or_else(|| anyhow::anyhow!("appsink sample had no buffer"))?;
            let map = buffer.map_readable().map_err(|_| anyhow::anyhow!("appsink map_readable failed"))?;
            let pt = map.as_slice();
            let pt_len = pt.len() as u32;

            let ts = clock.time().map(|t| t.nseconds()).unwrap_or(0) as u64;
            let ct = self.aead.encrypt_frame(seq, pt, pt_len)?;

            let msg = WireMsg {
                flags: FLAG_FRAME,
                ts_ns: ts,
                seq,
                pt_len,
                payload: Bytes::from(ct),
            };
            msg.write_to(&mut conn).await?;

            frames_since_log += 1;
            if last_log.elapsed() > std::time::Duration::from_secs(1) {
                eprintln!("[sender] tx fps≈{} (seq={})", frames_since_log, seq);
                frames_since_log = 0;
                last_log = std::time::Instant::now();
            }

            seq = seq.wrapping_add(1);
        }
    }

}
