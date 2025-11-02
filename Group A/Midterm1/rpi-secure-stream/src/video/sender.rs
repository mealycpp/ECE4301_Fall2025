use crate::net::aead_stream::Aes128GcmStream;
use crate::net::transport::{tcp_connect, WireMsg, FLAG_FRAME, FLAG_REKEY};
use anyhow::Result;
use bytes::Bytes;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use rand::rngs::OsRng;
use rand::RngCore;

const REKEY_EVERY_FRAMES: u64 = 900; // ~30s @ 30fps

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
            // Rekey boundary: send control message that tells receiver the *next* seq to start with.
            if seq > 0 && seq % REKEY_EVERY_FRAMES == 0 {
                let next_seq = seq; // apply new key starting at this upcoming frame index

                // TODO: wrap with RSA/ECDH before shipping!
                let mut key = [0u8; 16];
                let mut nb  = [0u8; 12];
                OsRng.fill_bytes(&mut key);
                OsRng.fill_bytes(&mut nb);

                // payload = [u64 next_seq][key[16]][nonce_base[12]]
                let mut p = Vec::with_capacity(8 + 16 + 12);
                p.extend_from_slice(&next_seq.to_be_bytes());
                p.extend_from_slice(&key);
                p.extend_from_slice(&nb);

                let ts = clock.time().map(|t| t.nseconds()).unwrap_or(0) as u64;
                let msg = WireMsg {
                    flags: FLAG_REKEY,
                    ts_ns: ts,
                    seq: next_seq, // for logging; not used by decrypt
                    pt_len: 0,
                    payload: Bytes::from(p),
                };
                msg.write_to(&mut conn).await?;

                // Switch locally *after* sending control (so receiver can catch up)
                self.aead.rekey(key, nb)?;
            }

            // Pull one frame
            let sample_opt = self.sink.try_pull_sample(gst::ClockTime::from_mseconds(500));
            let sample = match sample_opt {
                Some(s) => s,
                None => continue,
            };
            let buffer = sample.buffer().ok_or_else(|| anyhow::anyhow!("no buffer"))?;
            let map = buffer.map_readable().map_err(|_| anyhow::anyhow!("map failed"))?;
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

            seq = seq.wrapping_add(1);
        }
    }
}
