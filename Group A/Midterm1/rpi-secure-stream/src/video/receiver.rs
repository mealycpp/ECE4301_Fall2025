use crate::net::aead_stream::Aes128GcmStream;
use crate::net::transport::{tcp_bind, WireMsg, FLAG_FRAME, FLAG_REKEY};
use anyhow::Result;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use tokio::net::TcpListener;

pub struct Receiver {
    pub aead: Aes128GcmStream,
    pub pipeline: gst::Pipeline,   // ← keep the pipeline
    pub src: AppSrc,
    pub width: i32,
    pub height: i32,
}

impl Receiver {
    pub fn new(aead: Aes128GcmStream, pipeline: gst::Pipeline, src: AppSrc, width: i32, height: i32) -> Self {
        Self { aead, pipeline, src, width, height }
    }

    pub async fn run(mut self, bind_addr: &str) -> Result<()> {
        let listener: TcpListener = tcp_bind(bind_addr).await?;
        let (mut stream, _addr) = listener.accept().await?;

        self.pipeline.set_state(gst::State::Playing)?;

        let mut expect_seq: u64 = 0;
        let mut expect_seq: u64 = 0;
let mut has_key = false;

loop {
    let msg = match WireMsg::read_from(&mut stream).await {
        Ok(m) => m,
        Err(e) => { eprintln!("[receiver] stream closed/error: {e}"); break; }
    };

    if (msg.flags & FLAG_REKEY) != 0 {
        if msg.payload.len() != 8 + 16 + 12 {
            eprintln!("[receiver] bad REKEY payload: {}", msg.payload.len());
            continue;
        }
        let next_seq = u64::from_be_bytes(msg.payload[..8].try_into().unwrap());
        let mut key = [0u8; 16];
        let mut nb  = [0u8; 12];
        key.copy_from_slice(&msg.payload[8..24]);
        nb.copy_from_slice(&msg.payload[24..36]);

        self.aead.rekey_at(key, nb, next_seq)?; // ← set base_seq
        expect_seq = next_seq;
        has_key = true;
        eprintln!("[receiver] REKEY to seq={next_seq}");
        continue;
    }

    if (msg.flags & FLAG_FRAME) == 0 { continue; }

    if !has_key {
        eprintln!("[receiver] dropping frame seq={} (no key yet)", msg.seq);
        continue;
    }

    let pt = match self.aead.decrypt_frame(msg.seq, &msg.payload, msg.pt_len) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[receiver] decrypt failed at seq={} : {e}", msg.seq);
            continue;
        }
    };

            let mut buffer = gst::Buffer::with_size(pt.len()).unwrap();
            {
                let bufref = buffer.make_mut();
                let mut map = bufref.map_writable().map_err(|_| anyhow::anyhow!("map_writable failed"))?;
                map.as_mut_slice().copy_from_slice(&pt);
            }
            self.src.push_buffer(buffer)?;

            if msg.seq != expect_seq {
                eprintln!("[receiver] seq jump: got {}, expect {}", msg.seq, expect_seq);
                expect_seq = msg.seq;
            }
            expect_seq = expect_seq.wrapping_add(1);

            frames_since_log += 1;
            if last_log.elapsed() > std::time::Duration::from_secs(1) {
                eprintln!("[receiver] rx fps≈{} (last seq={})", frames_since_log, msg.seq);
                frames_since_log = 0;
                last_log = std::time::Instant::now();
            }
        }


        self.pipeline.set_state(gst::State::Null)?;
        Ok(())
    }
}
