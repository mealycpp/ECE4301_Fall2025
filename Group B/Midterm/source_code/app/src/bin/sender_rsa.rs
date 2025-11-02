use std::sync::{Arc, Mutex};
use anyhow::Result;
use clap::Parser;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSinkCallbacks};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Instant, Duration};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};

use keying::rsa::{rsa_pub_from_der, rsa_wrap_aes_key, sample_session_material};
use app::common::{FrameHeader, now_monotonic_ns, Metrics};
use metrics::handshake_logger::{log_handshake, HandshakeMetrics};

#[derive(Parser, Debug)]
#[command(name = "sender_rsa")]
#[command(about = "Camera → H264 → AES-GCM (RSA-OAEP key wrap) → TCP", long_about=None)]
struct Args {
    #[arg(long, value_name = "IP:PORT")]
    dest: String,
    #[arg(long, default_value_t = 640)]
    width: u32,
    #[arg(long, default_value_t = 480)]
    height: u32,
    #[arg(long, default_value_t = 15)]
    fps: u32,
}

// static FRAME_CT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ✅ Helper: hex preview for raw/encrypted data
fn hex_preview(label: &str, seq: u32, data: &[u8]) {
    let preview_len = data.len().min(32);
    let hex_str = data[..preview_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!("{}[seq={seq}]: {}", label, hex_str);
}

fn main() -> Result<()> {
    gst::init()?;
    let args = Args::parse();

    // --- TCP connect ---
    let stream = TcpStream::connect(&args.dest)?;
    stream.set_nodelay(true)?;
    let stream = Arc::new(Mutex::new(stream));

    // --- RSA handshake ---
    let start = Instant::now();
    let (aes_key, nonce_base) = sample_session_material();

    let (_pub_der, wrapped_key) = {
        let mut g = stream.lock().unwrap();

        // 1️⃣ Receive receiver's RSA public key (DER)
        let mut lb = [0u8; 4];
        g.read_exact(&mut lb)?;
        let der_len = u32::from_be_bytes(lb) as usize;
        let mut der = vec![0u8; der_len];
        g.read_exact(&mut der)?;

        // 2️⃣ Wrap AES session key
        let rpk = rsa_pub_from_der(&der);
        let wrapped = rsa_wrap_aes_key(&rpk, &aes_key);

        // 3️⃣ Send wrapped AES key + nonce base
        let wl = wrapped.len() as u32;
        g.write_all(&wl.to_be_bytes())?;
        g.write_all(&wrapped)?;
        g.write_all(&nonce_base)?;
        g.flush()?;

        (der, wrapped)
    };

    // ✅ Log RSA handshake
    log_handshake(
        HandshakeMetrics {
            mech: "RSA".into(),
            bytes_tx: wrapped_key.len(),
            bytes_rx: 0,
            energy_j: 0.0,
        },
        "results/handshake_rsa.csv",
        start,
    )?;

    eprintln!(
        "HANDSHAKE_RSA complete — key exchanged in {} ms",
        (Instant::now() - start).as_millis()
    );

    // --- Encryption setup ---
    let cipher = Aes128Gcm::new_from_slice(&aes_key)?;
    let origin = Instant::now();
    let metrics = Arc::new(Mutex::new(Metrics::new("sender", "results/steady_rsa.csv")));

    // --- Metrics thread ---
    {
        let m = Arc::clone(&metrics);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(250));
            if let Ok(mut mm) = m.lock() {
                mm.sample_and_flush();
            }
        });
    }

    // --- GStreamer pipeline ---
    let launch = format!(
        "libcamerasrc ! \
         video/x-raw,format=NV12,width={w},height={h},framerate={f}/1 ! \
         videoconvert ! \
         x264enc tune=zerolatency speed-preset=ultrafast bitrate=1200 key-int-max={gop} ! \
         video/x-h264,stream-format=byte-stream,alignment=au ! \
         appsink name=appsink emit-signals=true sync=false max-buffers=1 drop=true",
        w = args.width, h = args.height, f = args.fps, gop = args.fps * 2
    );

    let pipeline = gst::parse::launch(&launch)?
        .downcast::<gst::Pipeline>()
        .expect("pipeline");

    let appsink: AppSink = pipeline
        .by_name("appsink").unwrap()
        .dynamic_cast::<AppSink>().unwrap();

    let stream_cb = Arc::clone(&stream);
    let cipher_cb = cipher;
    let metrics_cb: Arc<Mutex<Metrics>> = Arc::clone(&metrics);
    let mut counter: u32 = 0;

    appsink.set_callbacks(
        AppSinkCallbacks::builder()
            .new_sample(move |sink| -> Result<gst::FlowSuccess, gst::FlowError> {
                let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;
                let map = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;
                let au = map.as_slice();

                // Header + timestamp
                let hdr = FrameHeader { seq: counter, ts_ns: now_monotonic_ns(origin) };
                counter = counter.wrapping_add(1);

                // ✅ Print raw frame bytes
                hex_preview("RAW", hdr.seq, au);

                let mut pt = Vec::with_capacity(FrameHeader::BYTES + au.len());
                pt.extend_from_slice(&hdr.to_bytes());
                pt.extend_from_slice(au);

                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..8].copy_from_slice(&nonce_base);
                nonce_bytes[8..].copy_from_slice(&counter.to_be_bytes());
                let nonce = Nonce::from(nonce_bytes);

                let ct = cipher_cb.encrypt(&nonce, pt.as_ref()).map_err(|_| gst::FlowError::Error)?;

                // ✅ Print encrypted bytes
                hex_preview("ENC", hdr.seq, &ct);

                let mut g = stream_cb.lock().unwrap();
                let total_len = (12 + ct.len()) as u32;
                g.write_all(&total_len.to_be_bytes()).unwrap();
                g.write_all(&nonce_bytes).unwrap();
                g.write_all(&ct).unwrap();

                if let Ok(mut mm) = metrics_cb.lock() {
                    mm.add_frame(ct.len());
                }

                Ok(gst::FlowSuccess::Ok)
            })
            .build(),
    );

    pipeline.set_state(gst::State::Playing)?;
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
