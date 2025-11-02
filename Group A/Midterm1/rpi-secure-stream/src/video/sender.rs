use crate::net::aead_stream::Aes128GcmStream;
use crate::net::transport::{tcp_connect_with_retry, WireMsg, FLAG_FRAME, FLAG_REKEY};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::time::Duration;

const REKEY_EVERY_FRAMES: u64 = 900; // ~30s @30fps

pub struct Sender {
    pub aead: Aes128GcmStream,
    pub pipeline: gst::Pipeline,
    pub sink: AppSink,
    pub width: i32,
    pub height: i32,
    pub fps: i32,
}

impl Sender {
    pub fn new(
        aead: Aes128GcmStream,
        pipeline: gst::Pipeline,
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

        // === bootstrap REKEY at seq=0 ===
        let mut key0 = [0u8; 16];
        let mut nb0  = [0u8; 12];
        OsRng.fill_bytes(&mut key0);
        OsRng.fill_bytes(&mut nb0);

        let mut p0 = Vec::with_capacity(8 + 16 + 12);
        p0.extend_from_slice(&0u64.to_be_bytes());   // next_seq = 0
        p0.extend_from_slice(&key0);
        p0.extend_from_slice(&nb0);

        let ts0 = gst::SystemClock::obtain().time().map(|t| t.nseconds()).unwrap_or(0) as u64;
        let msg0 = WireMsg { flags: FLAG_REKEY, ts_ns: ts0, seq: 0, pt_len: 0, payload: Bytes::from(p0) };
        msg0.write_to(&mut conn).await?;
        self.aead.rekey_at(key0, nb0, 0)?;
        eprintln!("[sender] bootstrap REKEY sent (seq=0)");
        // wait a moment for receiver to apply key
        tokio::time::sleep(Duration::from_millis(150)).await;

        // === start GStreamer pipeline ===
       self.pipeline.set_state(gst::State::Playing)?;
        let (_cur, new, _pend) = self
            .pipeline
            .state(gst::ClockTime::from_seconds(3))
            .map_err(|_| anyhow!("camera pipeline failed to preroll"))?;
        eprintln!("[sender] pipeline state: {:?}", new);


        let mut seq: u64 = 0;
        let clock = gst::SystemClock::obtain();
        let mut last_log = std::time::Instant::now();
        let mut frames_since_log = 0usize;

        loop {
            // === periodic REKEY ===
            if seq > 0 && seq % REKEY_EVERY_FRAMES == 0 {
                let next_seq = seq;
                let mut key = [0u8; 16];
                let mut nb  = [0u8; 12];
                OsRng.fill_bytes(&mut key);
                OsRng.fill_bytes(&mut nb);

                let mut p = Vec::with_capacity(8 + 16 + 12);
                p.extend_from_slice(&next_seq.to_be_bytes());
                p.extend_from_slice(&key);
                p.extend_from_slice(&nb);

                let ts = clock.time().map(|t| t.nseconds()).unwrap_or(0) as u64;
                let msg = WireMsg { flags: FLAG_REKEY, ts_ns: ts, seq: next_seq, pt_len: 0, payload: Bytes::from(p) };
                msg.write_to(&mut conn).await?;
                eprintln!("[sender] REKEY at seq={next_seq}");
                self.aead.rekey_at(key, nb, next_seq)?;
            }

            // === pull frame ===
            let sample_opt = self.sink.try_pull_sample(gst::ClockTime::from_mseconds(500));
            let sample = match sample_opt {
                Some(s) => s,
                None => {
                    if last_log.elapsed() > std::time::Duration::from_secs(2) {
                        eprintln!("[sender] waiting for frames...");
                        last_log = std::time::Instant::now();
                    }
                    continue;
                }
            };

            let buffer = sample
                .buffer()
                .ok_or_else(|| anyhow!("appsink sample had no buffer"))?;
            let map = buffer
                .map_readable()
                .map_err(|_| anyhow!("appsink buffer map_readable failed"))?;
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
            if let Err(e) = msg.write_to(&mut conn).await {
                eprintln!("[sender] write error at seq={seq}: {e}");
                break;
            }

            frames_since_log += 1;
            if last_log.elapsed() > std::time::Duration::from_secs(1) {
                eprintln!("[sender] tx fps≈{} (seq={})", frames_since_log, seq);
                frames_since_log = 0;
                last_log = std::time::Instant::now();
            }

            seq = seq.wrapping_add(1);
        }

        self.pipeline.set_state(gst::State::Null)?;
        Ok(())
    }
}
