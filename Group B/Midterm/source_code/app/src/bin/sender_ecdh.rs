use anyhow::Result;
use clap::Parser;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSinkCallbacks};

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

use keying::{gen_ecdh_keypair, finish_ecdh};
use metrics::handshake_logger::{log_handshake, HandshakeMetrics};
use app::common::{
    FrameHeader, now_monotonic_ns, Metrics, pack_rekey_control,
    CTRL_REKEY_SALT_LEN,
};

#[derive(Parser, Debug)]
#[command(name = "sender_ecdh")]
#[command(about = "Camera → H264 → AES-GCM (ECDH key exchange) → TCP", long_about=None)]
struct Args {
    #[arg(long, value_name = "IP:PORT")]
    dest: String,
    #[arg(long, default_value_t = 640)]
    width: u32,
    #[arg(long, default_value_t = 480)]
    height: u32,
    #[arg(long, default_value_t = 15)]
    fps: u32,
    #[arg(long, default_value_t = 600)]
    rekey_secs: u64,
}

// ✅ Helper: pretty-print the first 32 bytes of data
fn hex_preview(label: &str, seq: u32, data: &[u8]) {
    let preview_len = data.len().min(32);
    let hex_str = data[..preview_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!("{}[seq={seq}]: {}", label, hex_str);
}

fn log_arm_crypto_support() {
    #[cfg(target_arch = "aarch64")]
    {
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        eprintln!("ARMv8 Crypto Extensions — AES: {aes}, PMULL: {pmull}");
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        eprintln!("ARMv8 Crypto Extensions — not aarch64 target; skipping detection");
    }
}

fn hkdf_rekey(old_key: &[u8;16], salt16: &[u8;16]) -> [u8;16] {
    let hk = Hkdf::<Sha256>::new(Some(salt16), old_key);
    let mut out = [0u8;16];
    hk.expand(b"ECE4301-midterm-2025-rekey", &mut out).unwrap();
    out
}

fn main() -> Result<()> {
    let args = Args::parse();
    gst::init()?;
    log_arm_crypto_support();

    let stream = TcpStream::connect(&args.dest)?;
    stream.set_nodelay(true)?;
    let stream = Arc::new(Mutex::new(stream));

    // --- ECDH handshake ---
    let start = Instant::now();
    let (pub_a, secret_a) = gen_ecdh_keypair();
    let (aes_key, nonce_base, bytes_tx, bytes_rx) = {
        let mut g = stream.lock().unwrap();
        let la = pub_a.len() as u32;
        g.write_all(&la.to_be_bytes())?;
        g.write_all(&pub_a)?;
        let mut lb = [0u8; 4];
        g.read_exact(&mut lb)?;
        let len_b = u32::from_be_bytes(lb) as usize;
        let mut peer_b = vec![0u8; len_b];
        g.read_exact(&mut peer_b)?;
        let key = finish_ecdh(&secret_a, &peer_b);
        eprintln!("sender_ecdh: AES-128 key (first 8): {:02x?}", &key[..8]);
        let mut nb = [0u8; 8];
        OsRng.fill_bytes(&mut nb);
        g.write_all(&nb)?;
        g.flush()?;
        (key, nb, pub_a.len(), len_b)
    };

    // ✅ Log handshake metrics
    let elapsed_ms = start.elapsed().as_millis();
    log_handshake(
        HandshakeMetrics {
            mech: "ECDH".into(),
            bytes_tx,
            bytes_rx,
            energy_j: 0.0,
        },
        "results/handshake_ecdh.csv",
        start,
    )?;
    eprintln!("HANDSHAKE_ECDH complete — key exchanged in {elapsed_ms} ms");

    let cipher = Aes128Gcm::new_from_slice(&aes_key).expect("cipher");
    let shared = Arc::new((Mutex::new(aes_key), Mutex::new(cipher), nonce_base));
    let origin = Instant::now();
    let metrics = Arc::new(Mutex::new(Metrics::new("sender", "results/steady_ecdh.csv")));

    // metrics thread
    {
        let m = Arc::clone(&metrics);
        thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(250));
            if let Ok(mut mm) = m.lock() {
                mm.sample_and_flush();
            }
        });
    }

    // optional rekey
    if args.rekey_secs > 0 {
        let stream_rk = Arc::clone(&stream);
        let shared_rk = Arc::clone(&shared);
        thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(args.rekey_secs));
            let mut salt = [0u8; CTRL_REKEY_SALT_LEN];
            OsRng.fill_bytes(&mut salt);
            let ctrl = pack_rekey_control(salt);
            let mut g = stream_rk.lock().unwrap();
            let total_len = ctrl.len() as u32;
            let _ = g.write_all(&total_len.to_be_bytes());
            let _ = g.write_all(&ctrl);
            let _ = g.flush();
            drop(g);
            let (ref key_lock, ref cipher_lock, _nb) = *shared_rk;
            let mut k = key_lock.lock().unwrap();
            let new_key = hkdf_rekey(&*k, &salt);
            *k = new_key;
            let mut c = cipher_lock.lock().unwrap();
            *c = Aes128Gcm::new_from_slice(&new_key).unwrap();
            eprintln!("sender_ecdh: rekey applied");
        });
    }

    let launch = format!(
        "libcamerasrc ! video/x-raw,format=NV12,width={w},height={h},framerate={f}/1 \
         ! videoconvert ! x264enc tune=zerolatency speed-preset=ultrafast bitrate=1200 \
         ! video/x-h264,stream-format=byte-stream,alignment=au \
         ! appsink name=appsink emit-signals=true sync=false max-buffers=1 drop=true",
        w = args.width, h = args.height, f = args.fps
    );

    let pipeline = gst::parse::launch(&launch)?
        .downcast::<gst::Pipeline>()
        .expect("not a pipeline");

    let appsink: AppSink = pipeline
        .by_name("appsink")
        .expect("appsink not found")
        .dynamic_cast::<AppSink>()
        .expect("appsink wrong type");

    let stream_cb = Arc::clone(&stream);
    let shared_cb = Arc::clone(&shared);
    let metrics_cb = Arc::clone(&metrics);
    let mut counter: u32 = 0;

    appsink.set_callbacks(
        AppSinkCallbacks::builder()
            .new_sample(move |sink| -> Result<gst::FlowSuccess, gst::FlowError> {
                let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;
                let map = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;
                let au = map.as_slice();

                let hdr = FrameHeader { seq: counter, ts_ns: now_monotonic_ns(origin) };
                counter = counter.wrapping_add(1);

                // ✅ Raw data print
                hex_preview("RAW", hdr.seq, au);

                let mut pt = Vec::with_capacity(FrameHeader::BYTES + au.len());
                pt.extend_from_slice(&hdr.to_bytes());
                pt.extend_from_slice(au);

                let (ref _key_lock, ref cipher_lock, base) = *shared_cb;
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..8].copy_from_slice(&base);
                nonce_bytes[8..].copy_from_slice(&counter.to_be_bytes());
                let nonce = Nonce::from(nonce_bytes);

                let ct = {
                    let c = cipher_lock.lock().unwrap();
                    c.encrypt(&nonce, pt.as_ref()).map_err(|_| gst::FlowError::Error)?
                };

                // ✅ Encrypted data print
                hex_preview("ENC", hdr.seq, &ct);

                let mut g = stream_cb.lock().unwrap();
                let total_len = (12 + ct.len()) as u32;
                g.write_all(&total_len.to_be_bytes()).map_err(|_| gst::FlowError::Error)?;
                g.write_all(&nonce_bytes).map_err(|_| gst::FlowError::Error)?;
                g.write_all(&ct).map_err(|_| gst::FlowError::Error)?;

                if let Ok(mut mm) = metrics_cb.lock() {
                    mm.add_frame(ct.len());
                }

                Ok(gst::FlowSuccess::Ok)
            })
            .build()
    );

    pipeline.set_state(gst::State::Playing)?;
    let bus = pipeline.bus().expect("no bus");
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
