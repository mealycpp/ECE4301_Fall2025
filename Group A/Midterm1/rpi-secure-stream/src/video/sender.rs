// src/video/sender.rs
use crate::net::aead_stream::Aes128GcmStream;                // ← was crate::aead_stream
use crate::net::transport::{tcp_connect, WireMsg, FLAG_FRAME}; // ← was crate::transport
use anyhow::Result;
use bytes::Bytes;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
// (You can delete this; we don't use Duration/Instant here)
// use std::time::{Duration, Instant};

pub struct Sender {
    pub aead: Aes128GcmStream,
    pub sink: AppSink,
    pub width: i32,
    pub height: i32,
    pub fps: i32,
}

impl Sender {
    pub fn new(aead: Aes128GcmStream, sink: AppSink, width: i32, height: i32, fps: i32) -> Self {
        Self { aead, sink, width, height, fps }
    }

    pub async fn run(mut self, leader_addr: &str) -> Result<()> {
        let mut conn = tcp_connect(leader_addr).await?;

        // Start pipeline
        let pipeline = self.sink.parent().unwrap().downcast::<gst::Pipeline>().unwrap();
        pipeline.set_state(gst::State::Playing)?;

        let mut seq: u64 = 0;
        let clock = gst::SystemClock::obtain();

        loop {
            // Use try_pull_sample with a timeout (e.g., 2s)
            let sample_opt = self.sink.try_pull_sample(gst::ClockTime::from_seconds(2));
            let sample = match sample_opt {
                Some(s) => s,
                None => continue, // no frame in timeout window; keep looping
            };

            let buffer = sample.buffer().ok_or_else(|| anyhow::anyhow!("no buffer"))?;
            let map = buffer.map_readable().map_err(|_| anyhow::anyhow!("map failed"))?;

            // ClockTime is Option<ClockTime>; get nanoseconds if present
            let ts = clock.time().map(|t| t.nseconds()).unwrap_or(0) as u64;

            // Encrypt the raw frame (I420)
            let pt = map.as_slice();
            let ct = self.aead.encrypt_frame(seq, pt)?;

            let msg = WireMsg {
                flags: FLAG_FRAME,
                ts_ns: ts,
                payload: Bytes::from(ct),
            };
            msg.write_to(&mut conn).await?;

            seq = seq.wrapping_add(1);
        }
        // (unreachable normally; if you add a break, remember to set to Null)
        // pipeline.set_state(gst::State::Null)?;
        // Ok(())
    }
}
