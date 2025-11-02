use crate::net::aead_stream::Aes128GcmStream;
use crate::net::transport::{tcp_bind, WireMsg, FLAG_FRAME, FLAG_REKEY, FLAG_CAPS, FLAG_PING};
use anyhow::{anyhow, Result};
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use tokio::net::TcpListener;
use crate::logutil::append_csv; 
use chrono::Utc;
use dirs;


// ==== CONFIG: where to load the receiver's RSA private key (PEM) ====
fn key_path_receiver_priv() -> std::path::PathBuf {
    let mut p = dirs::home_dir().expect("no home dir");
    p.push(".ece4301/receiver_priv.pem");
    p
}


// RSA-OAEP-256
use rsa::{pkcs8::DecodePrivateKey, Oaep, RsaPrivateKey};
use sha2::Sha256;

pub struct Receiver {
    pub aead: Aes128GcmStream,
    pub pipeline: gst::Pipeline,
    pub src: AppSrc,
    pub width: i32,
    pub height: i32,
}

fn now_ns() -> u64 {
    gst::SystemClock::obtain()
        .time()
        .map(|t| t.nseconds())
        .unwrap_or(0) as u64
}


impl Receiver {
    pub fn new(aead: Aes128GcmStream, pipeline: gst::Pipeline, src: AppSrc, width: i32, height: i32) -> Self {
        Self { aead, pipeline, src, width, height }
    }

    fn load_receiver_priv() -> Result<RsaPrivateKey> {
        let pem = std::fs::read_to_string(key_path_receiver_priv())
                .map_err(|e| anyhow!("read receiver privkey: {e}"))?;

        Ok(RsaPrivateKey::from_pkcs8_pem(&pem)?)
    }

    

    fn rebuild_caps(&mut self, width: i32, height: i32, fps: i32) -> Result<()> {
        self.pipeline.set_state(gst::State::Null)?;

        let caps = gst::Caps::builder("video/x-raw")
            .field("format", "I420")
            .field("width", width)
            .field("height", height)
            .field("framerate", gst::Fraction::new(fps, 1))
            .build();

        self.src.set_caps(Some(&caps));

        self.pipeline.set_state(gst::State::Playing)?;
        let (res, new, _pend) = self.pipeline.state(gst::ClockTime::from_seconds(3));
        if let Err(_e) = res {
            return Err(anyhow!("receiver pipeline failed to preroll"));
        }
        eprintln!("[receiver] caps set w={} h={} fps={}", width, height, fps);
        self.width = width;
        self.height = height;
        Ok(())
    }


        pub async fn run(mut self, bind_addr: &str) -> Result<()> {
            let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
            let rx_log = "data/stream_rx.csv".to_string();
            let rekey_log = "data/rekey_rx.csv".to_string();


            eprintln!("[receiver] start role=receiver bind={bind_addr} (default w={} h={} fps=?)", self.width, self.height);
            let listener: TcpListener = tcp_bind(bind_addr).await?;
            eprintln!("[receiver] listening...");
            let (mut stream, addr) = listener.accept().await?;
            eprintln!("[receiver] TCP accepted from {}", addr);

            // Start the pipeline in case caps don't change; we may rebuild later on CAPS
            self.pipeline.set_state(gst::State::Playing)?;
            let (res, new, _pend) = self.pipeline.state(gst::ClockTime::from_seconds(3));

            if let Err(_e) = res {
                return Err(anyhow!("receiver pipeline failed to preroll"));
            }
            eprintln!("[receiver] pipeline state: {:?}", new);

            let mut expect_seq: u64 = 0;
            let mut has_key = false;
            let mut last_log = std::time::Instant::now();
            let mut frames_since_log: usize = 0;

            let sk = Self::load_receiver_priv()?; // RSA private key
            
            let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
            let log_dir = dirs::home_dir().unwrap().join(".ece4301").join("logs").join(&ts);
            std::fs::create_dir_all(&log_dir).ok();
            let rx_log    = log_dir.join("stream_rx.csv").display().to_string();
            let rekey_log = log_dir.join("rekey_rx.csv").display().to_string();
            eprintln!("[receiver] CSV logs -> {}", log_dir.display());

            loop {
                let msg = match WireMsg::read_from(&mut stream).await {
                    Ok(m) => m,
                    Err(e) => { eprintln!("[receiver] stream closed/error: {e}"); break; }
                };

                if (msg.flags & FLAG_PING) != 0 {
                    eprintln!("[receiver] PING seq={} received", msg.seq);
                    continue;
                }

                if (msg.flags & FLAG_CAPS) != 0 {
                    eprintln!("[receiver] CAPS received ({} bytes)", msg.payload.len());
                    if msg.payload.len() != 16 {
                        eprintln!("[receiver] bad CAPS payload ({})", msg.payload.len());
                        continue;
                    }
                    let w = i32::from_be_bytes(msg.payload[0..4].try_into().unwrap());
                    let h = i32::from_be_bytes(msg.payload[4..8].try_into().unwrap());
                    let fps_num = u32::from_be_bytes(msg.payload[8..12].try_into().unwrap());
                    let fps_den = u32::from_be_bytes(msg.payload[12..16].try_into().unwrap());
                    let fps = (fps_num as i32) / (fps_den as i32);
                    if let Err(e) = self.rebuild_caps(w, h, fps) {
                        eprintln!("[receiver] CAPS apply failed: {e}");
                    } else {
                        eprintln!("[receiver] CAPS applied w={} h={} fps={}", w, h, fps);
                    }
                    has_key = false; // wait for REKEY
                    continue;
                }

                if (msg.flags & FLAG_REKEY) != 0 {
                    eprintln!("[receiver] REKEY received ({} bytes)", msg.payload.len());
                    if msg.payload.len() < 12 {
                        eprintln!("[receiver] bad REKEY header ({})", msg.payload.len());
                        continue;
                    }
                    let next_seq = u64::from_be_bytes(msg.payload[0..8].try_into().unwrap());
                    let alg_id   = u16::from_be_bytes(msg.payload[8..10].try_into().unwrap());
                    let wrap_len = u16::from_be_bytes(msg.payload[10..12].try_into().unwrap()) as usize;
                    if msg.payload.len() != 12 + wrap_len {
                        eprintln!("[receiver] REKEY size mismatch: {} vs {}", msg.payload.len(), 12 + wrap_len);
                        continue;
                    }
                    match alg_id {
                        1 => { // RSA-OAEP-256
                            let wrapped = &msg.payload[12..];
                            let label = Oaep::new::<Sha256>();
                            let secret = match sk.decrypt(label, wrapped) {
                                Ok(s) => s,
                                Err(e) => { eprintln!("[receiver] RSA-OAEP unwrap failed: {e}"); continue; }
                            };
                            if secret.len() != 28 {
                                eprintln!("[receiver] REKEY secret wrong size: {}", secret.len());
                                continue;
                            }
                            let mut key = [0u8;16];
                            let mut nb  = [0u8;12];
                            key.copy_from_slice(&secret[..16]);
                            nb.copy_from_slice(&secret[16..28]);

                            if let Err(e) = self.aead.rekey_at(key, nb, next_seq) {
                                eprintln!("[receiver] rekey_at failed: {e}");
                                continue;
                            }
                            expect_seq = next_seq;
                            has_key = true;
                            eprintln!("[receiver] REKEY applied at seq={next_seq}");
                            append_csv(&rekey_log, &format!("{},{}", now_ns(), next_seq));
                            

                        }
                        _ => eprintln!("[receiver] unknown REKEY alg_id={alg_id}"),
                    }
                    continue;
                }

                if (msg.flags & FLAG_FRAME) == 0 {
                    eprintln!("[receiver] unknown/ignored flags={:#x}", msg.flags);
                    continue;
                }

                if !has_key {
                    eprintln!("[receiver] drop frame seq={} (no key yet)", msg.seq);
                    continue;
                }

                if msg.seq < expect_seq {
                    eprintln!("[receiver] replay/late frame: got {}, expect {}", msg.seq, expect_seq);
                    continue;
                } else if msg.seq > expect_seq {
                    eprintln!("[receiver] seq jump: got {}, expect {}", msg.seq, expect_seq);
                    // still try to decrypt
                }

                let pt = match self.aead.decrypt_frame(msg.seq, &msg.payload, msg.pt_len) {
                    Ok(p) => p,
                    Err(e) => { eprintln!("[receiver] decrypt failed at seq={} : {e}", msg.seq); continue; }
                };

                let mut buffer = gst::Buffer::with_size(pt.len()).unwrap();
                {
                    let bufref = buffer.make_mut();
                    let mut map = bufref.map_writable().map_err(|_| anyhow::anyhow!("map_writable failed"))?;
                    map.as_mut_slice().copy_from_slice(&pt);
                }
                if let Err(e) = self.src.push_buffer(buffer) {
                    eprintln!("[receiver] push_buffer failed: {e}");
                    append_csv(
                        &rx_log,
                        &format!("{},{},{},{}", 
                            now_ns(),        // timestamp
                            msg.seq,         // seq number
                            msg.pt_len,      // plaintext size
                            msg.payload.len()// ciphertext size
                        )
                    );

                    continue;
                }

                expect_seq = msg.seq.wrapping_add(1);

                frames_since_log += 1;
                if last_log.elapsed() > std::time::Duration::from_secs(1) {
                    eprintln!("[receiver] RX fps≈{} (last seq={})", frames_since_log, msg.seq);
                    frames_since_log = 0;
                    last_log = std::time::Instant::now();
                }
            }

            self.pipeline.set_state(gst::State::Null)?;
            Ok(())
        }

}
