use crate::net::aead_stream::Aes128GcmStream;
use crate::net::transport::{tcp_connect_with_retry, WireMsg, FLAG_FRAME, FLAG_REKEY, FLAG_CAPS, FLAG_PING};


use anyhow::{anyhow, Result};
use bytes::Bytes;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::time::Duration;

// ==== CONFIG: where to load the receiver's RSA public key (PEM) ====
const KEY_PATH_RECEIVER_PUB: &str = "/home/pi/.ece4301/receiver_pub.pem";

const REKEY_EVERY_FRAMES: u64 = 900; // ~30s @30fps

// RSA-OAEP-256
use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use sha2::Sha256;

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

    fn now_ns() -> u64 {
        gst::SystemClock::obtain().time().map(|t| t.nseconds()).unwrap_or(0) as u64
    }

    fn load_receiver_pub() -> Result<RsaPublicKey> {
        let pem = std::fs::read_to_string(KEY_PATH_RECEIVER_PUB)
            .map_err(|e| anyhow!("read receiver pubkey {}: {}", KEY_PATH_RECEIVER_PUB, e))?;
        Ok(RsaPublicKey::from_public_key_pem(&pem)?)
    }

    /// Build and send CAPs control message so receiver can match the stream caps.
    async fn send_caps(&self, conn: &mut tokio::net::TcpStream) -> Result<()> {
        let mut p = Vec::with_capacity(16);
        p.extend_from_slice(&(self.width as u32).to_be_bytes());
        p.extend_from_slice(&(self.height as u32).to_be_bytes());
        p.extend_from_slice(&(self.fps as u32).to_be_bytes()); // fps_num
        p.extend_from_slice(&1u32.to_be_bytes());              // fps_den = 1
        let msg = WireMsg { flags: FLAG_CAPS, ts_ns: Self::now_ns(), seq: 0, pt_len: 0, payload: Bytes::from(p) };
        msg.write_to(conn).await
    }

    /// Send RSA-OAEP bootstrap/periodic REKEY for `next_seq`.
    async fn send_rekey_rsa(&mut self, conn: &mut tokio::net::TcpStream, next_seq: u64) -> Result<()> {
        let mut key = [0u8; 16];
        let mut nb  = [0u8; 12];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nb);

        // Wrap (key||nonce_base) with receiver's RSA public key
        let mut secret = [0u8; 28];
        secret[..16].copy_from_slice(&key);
        secret[16..].copy_from_slice(&nb);

        let pk = Self::load_receiver_pub()?;
        let label = Oaep::new::<Sha256>();
        let wrapped = pk.encrypt(&mut OsRng, label, &secret)
            .map_err(|e| anyhow!("RSA-OAEP wrap failed: {e}"))?;

        // payload: [u64 next_seq][u16 alg_id=1][u16 wrap_len][wrap...]
        let mut p = Vec::with_capacity(8 + 2 + 2 + wrapped.len());
        p.extend_from_slice(&next_seq.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes()); // alg_id=1: RSA-OAEP-256
        p.extend_from_slice(&(wrapped.len() as u16).to_be_bytes());
        p.extend_from_slice(&wrapped);

        let msg = WireMsg { flags: FLAG_REKEY, ts_ns: Self::now_ns(), seq: next_seq, pt_len: 0, payload: Bytes::from(p) };
        msg.write_to(conn).await?;

        // swap locally
        self.aead.rekey_at(key, nb, next_seq)?;
        Ok(())
    }

        pub async fn run(mut self, leader_addr: &str) -> Result<()> {
        eprintln!("[sender] start role=sender addr={leader_addr} w={} h={} fps={}", self.width, self.height, self.fps);
        let mut conn = tcp_connect_with_retry(leader_addr, Duration::from_secs(20)).await?;
        eprintln!("[sender] TCP connected, nodelay set");

        // --- Sanity: tell receiver our caps
        self.send_caps(&mut conn).await?;
        eprintln!("[sender] sent CAPS");

        // --- Handshake: REKEY(seq=0) via RSA-OAEP
        self.send_rekey_rsa(&mut conn, 0).await?;
        eprintln!("[sender] sent REKEY(seq=0) RSA-OAEP");
        tokio::time::sleep(Duration::from_millis(150)).await;

        // --- Optional: heartbeat PING (helps confirm transport)
        for i in 0..3 {
            let msg = WireMsg {
                flags: FLAG_PING,
                ts_ns: Self::now_ns(),
                seq: i,
                pt_len: 0,
                payload: Bytes::new(),
            };
            msg.write_to(&mut conn).await?;
            eprintln!("[sender] PING seq={i} sent");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // --- Start pipeline
        self.pipeline.set_state(gst::State::Playing)?;
        let (res, new, _pending) = self.pipeline.state(gst::ClockTime::from_seconds(3));
        if let Err(_e) = res {
            return Err(anyhow!("camera pipeline failed to preroll"));
        }
        eprintln!("[sender] pipeline state: {:?}", new);

        let mut seq: u64 = 0;
        let mut last_log = std::time::Instant::now();
        let mut frames_since_log = 0usize;

        loop {
            // Guard + periodic rekey
            if self.aead.need_rekey(seq) || (seq > 0 && seq % REKEY_EVERY_FRAMES == 0) {
                let next_seq = seq;
                self.send_rekey_rsa(&mut conn, next_seq).await?;
                eprintln!("[sender] REKEY at seq={next_seq}");
            }

            // Pull frame
            let Some(sample) = self.sink.try_pull_sample(gst::ClockTime::from_mseconds(500)) else {
                if last_log.elapsed() > std::time::Duration::from_secs(2) {
                    eprintln!("[sender] waiting for frames...");
                    last_log = std::time::Instant::now();
                }
                continue;
            };
            let buffer = sample.buffer().ok_or_else(|| anyhow!("appsink sample had no buffer"))?;
            let map = buffer.map_readable().map_err(|_| anyhow!("appsink buffer map_readable failed"))?;
            let pt = map.as_slice();
            let pt_len = pt.len() as u32;

            let ct = self.aead.encrypt_frame(seq, pt, pt_len)?;

            let msg = WireMsg {
                flags: FLAG_FRAME,
                ts_ns: Self::now_ns(),
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
                eprintln!("[sender] TX fps≈{} (last seq={})", frames_since_log, seq);
                frames_since_log = 0;
                last_log = std::time::Instant::now();
            }

            seq = seq.wrapping_add(1);
        }

        self.pipeline.set_state(gst::State::Null)?;
        Ok(())
    }

}
