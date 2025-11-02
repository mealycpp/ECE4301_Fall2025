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

        loop {
            let msg = match WireMsg::read_from(&mut stream).await {
                Ok(m) => m,
                Err(_) => break,
            };

            if (msg.flags & FLAG_REKEY) != 0 {
                if msg.payload.len() != 8 + 16 + 12 { continue; }
                let next_seq = u64::from_be_bytes(msg.payload[..8].try_into().unwrap());
                let mut key = [0u8; 16];
                let mut nb  = [0u8; 12];
                key.copy_from_slice(&msg.payload[8..24]);
                nb.copy_from_slice(&msg.payload[24..36]);

                expect_seq = next_seq;
                self.aead.rekey(key, nb)?;
                continue;
            }

            if (msg.flags & FLAG_FRAME) == 0 { continue; }

            let pt = self.aead.decrypt_frame(msg.seq, &msg.payload, msg.pt_len)?;

            let mut buffer = gst::Buffer::with_size(pt.len()).unwrap();
            {
                let bufref = buffer.make_mut();
                let mut map = bufref.map_writable().map_err(|_| anyhow::anyhow!("map_writable failed"))?;
                map.as_mut_slice().copy_from_slice(&pt);
            }
            self.src.push_buffer(buffer)?;

            if msg.seq != expect_seq {
                // (optional) log reordering or loss
                expect_seq = msg.seq;
            }
            expect_seq = expect_seq.wrapping_add(1);
        }

        self.pipeline.set_state(gst::State::Null)?;
        Ok(())
    }
}
