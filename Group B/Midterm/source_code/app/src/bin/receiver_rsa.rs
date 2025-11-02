use std::sync::{Arc, Mutex};
use anyhow::Result;
use clap::Parser;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Instant, Duration};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};

use keying::rsa::{rsa_generate, rsa_pub_to_der, rsa_unwrap_aes_key};
use app::common::{FrameHeader, Metrics, now_monotonic_ns};
use metrics::handshake_logger::{log_handshake, HandshakeMetrics};

// ✅ Helper: preview bytes as hex
fn hex_preview(label: &str, seq: u32, data: &[u8]) {
    let preview_len = data.len().min(32);
    let hex_str = data[..preview_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!("{}[seq={seq}]: {}", label, hex_str);
}

#[derive(Parser, Debug)]
#[command(name = "receiver_rsa")]
#[command(about = "RSA-OAEP → AES-GCM decrypt → display + metrics", long_about=None)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:7000")]
    listen: String,
}

fn main() -> Result<()> {
    gst::init()?;
    let args = Args::parse();

    let pipeline = gst::parse::launch(
        "appsrc name=src is-live=true format=3 do-timestamp=true \
         ! h264parse config-interval=1 ! avdec_h264 ! videoconvert ! autovideosink sync=false",
    )?
    .downcast::<gst::Pipeline>()
    .unwrap();

    let appsrc: AppSrc = pipeline
        .by_name("src").unwrap()
        .dynamic_cast::<AppSrc>().unwrap();

    appsrc.set_caps(Some(
        &gst::Caps::builder("video/x-h264")
            .field("stream-format", "byte-stream")
            .field("alignment", "au")
            .build(),
    ));

    pipeline.set_state(gst::State::Playing)?;
    let listener = TcpListener::bind(&args.listen)?;
    println!("Listening on {}", args.listen);
    let (mut stream, addr) = listener.accept()?;
    println!("Client connected from {addr}");

    // --- RSA handshake ---
    let start = Instant::now();
    let (sk, pk) = rsa_generate(2048);
    let pub_der = rsa_pub_to_der(&pk);
    let l = pub_der.len() as u32;
    stream.write_all(&l.to_be_bytes())?;
    stream.write_all(&pub_der)?;

    let mut lb = [0u8; 4];
    stream.read_exact(&mut lb)?;
    let wrapped_len = u32::from_be_bytes(lb) as usize;
    let mut wrapped = vec![0u8; wrapped_len];
    stream.read_exact(&mut wrapped)?;
    let mut nonce_base = [0u8; 8];
    stream.read_exact(&mut nonce_base)?;

    let aes_key = rsa_unwrap_aes_key(&sk, &wrapped);
    let cipher = Aes128Gcm::new_from_slice(&aes_key)?;
    eprintln!("receiver_rsa: AES-128 key (first 8): {:02x?}", &aes_key[..8]);

    // ✅ Log RSA handshake
    log_handshake(
        HandshakeMetrics {
            mech: "RSA".into(),
            bytes_tx: pub_der.len(),
            bytes_rx: wrapped.len(),
            energy_j: 0.0,
        },
        "results/handshake_rsa.csv",
        start,
    )?;

    let metrics = Arc::new(Mutex::new(Metrics::new("receiver", "results/steady_rsa.csv")));
    let origin = Instant::now();

    {
        let m = Arc::clone(&metrics);
        thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(250));
            if let Ok(mut mm) = m.lock() {
                mm.sample_and_flush();
            }
        });
    }

    let appsrc_clone = appsrc.clone();
    let metrics_clone = Arc::clone(&metrics);

    thread::spawn(move || -> Result<()> {
        loop {
            let mut lenb = [0u8; 4];
            if stream.read_exact(&mut lenb).is_err() {
                println!("receiver_rsa: connection closed");
                break;
            }
            let total_len = u32::from_be_bytes(lenb) as usize;
            if total_len < 12 {
                eprintln!("receiver_rsa: bad frame");
                break;
            }

            let mut buf = vec![0u8; total_len];
            stream.read_exact(&mut buf)?;

            let nonce_bytes = &buf[..12];
            let ct = &buf[12..];

            // ✅ Show ciphertext from sender
            hex_preview("RCV", 0, ct);

            let mut nonce_arr = [0u8; 12];
            nonce_arr.copy_from_slice(nonce_bytes);
            let nonce = Nonce::from(nonce_arr);

            let pt = match cipher.decrypt(&nonce, ct) {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("receiver_rsa: decrypt failed");
                    if let Ok(mut mm) = metrics_clone.lock() {
                        mm.inc_tag_fail();
                    }
                    continue;
                }
            };

            if pt.len() < FrameHeader::BYTES {
                continue;
            }

            let hdr = FrameHeader::from_slice(&pt[..FrameHeader::BYTES]).unwrap();
            let au = &pt[FrameHeader::BYTES..];

            // ✅ Show decrypted payload
            hex_preview("DEC", hdr.seq, au);

            let now_ns = now_monotonic_ns(origin);
            let lat_ns = now_ns.saturating_sub(hdr.ts_ns);

            let gst_buf = gst::Buffer::from_mut_slice(au.to_vec());
            if let Err(e) = appsrc_clone.push_buffer(gst_buf) {
                eprintln!("receiver_rsa: appsrc push error: {e}");
                if let Ok(mut mm) = metrics_clone.lock() {
                    mm.inc_drop();
                }
                continue;
            }

            if let Ok(mut mm) = metrics_clone.lock() {
                mm.add_frame(ct.len());
                mm.add_latency_ns(lat_ns);
            }
        }
        Ok(())
    });

    let bus = pipeline.bus().unwrap();
    for msg in bus.iter_timed(gst::ClockTime::NONE) {
        use gst::MessageView;
        if let MessageView::Error(err) = msg.view() {
            eprintln!("GStreamer error: {}", err.error());
            break;
        }
    }

    pipeline.set_state(gst::State::Null)?;
    Ok(())
}
