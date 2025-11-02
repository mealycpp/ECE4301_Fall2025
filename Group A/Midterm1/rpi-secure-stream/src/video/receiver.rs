// src/video/receiver.rs
use crate::net::aead_stream::Aes128GcmStream;                 // ← was crate::aead_stream
use crate::net::transport::{tcp_bind, WireMsg, FLAG_FRAME};    // ← was crate::transport
use anyhow::Result;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use tokio::net::TcpListener;

pub struct Receiver {
    pub aead: Aes128GcmStream,
    pub src: AppSrc,
    pub width: i32,
    pub height: i32,
}

impl Receiver {
    pub fn new(aead: Aes128GcmStream, src: AppSrc, width: i32, height: i32) -> Self {
        Self { aead, src, width, height }
    }

    pub async fn run(mut self, bind_addr: &str) -> Result<()> {
        let listener: TcpListener = tcp_bind(bind_addr).await?;
        let (mut stream, _addr) = listener.accept().await?;

        let pipeline = self.src.parent().unwrap().downcast::<gst::Pipeline>().unwrap();
        pipeline.set_state(gst::State::Playing)?;

        let mut expected_seq: u64 = 0;

        loop {
            let msg = match WireMsg::read_from(&mut stream).await {
                Ok(m) => m,
                Err(_) => break,
            };
            if msg.flags & FLAG_FRAME == 0 { continue; }

            // Plain I420 size (YUV 4:2:0): width*height*1.5
            let frame_size = (self.width * self.height * 3 / 2) as u32;

            let pt = self.aead.decrypt_frame(expected_seq, &msg.payload, frame_size)?;
            expected_seq = expected_seq.wrapping_add(1);

            let mut buffer = gst::Buffer::with_size(pt.len()).unwrap();
            {
                // Ensure we have a unique, writable buffer ref
                let bufref = buffer.make_mut(); // returns &mut gst::BufferRef
                let mut map = bufref
                    .map_writable()
                    .map_err(|_| anyhow::anyhow!("buffer map_writable failed"))?;
                map.as_mut_slice().copy_from_slice(&pt);
            }
            self.src.push_buffer(buffer)?;
        }

        pipeline.set_state(gst::State::Null)?;
        Ok(())
    }
}
