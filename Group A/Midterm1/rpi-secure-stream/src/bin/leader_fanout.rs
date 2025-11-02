use anyhow::{anyhow, Result};
use bytes::Bytes;
use clap::Parser;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep};
use rpi_secure_stream::logutil::append_csv;
use chrono::Utc;



use rpi_secure_stream::net::aead_stream::Aes128GcmStream;
use rpi_secure_stream::net::transport::{
    tcp_connect_with_retry, WireMsg, FLAG_CAPS, FLAG_FRAME, FLAG_REKEY
};
use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use sha2::Sha256;

/// ===== Adjust if needed: where public keys for listeners are stored =====
/// For demo: one shared receiver_pub.pem used for all listeners (group key wrapped identically).
const KEY_PATH_RECEIVER_PUB: &str = "/home/pi/.ece4301/receiver_pub.pem";

#[derive(Parser, Debug)]
struct Args {
    /// Multiple --listener ip:port entries (one per listener)
    #[arg(long = "listener")]
    listeners: Vec<String>,

    #[arg(long, default_value = "/dev/video0")]
    device: String,
    #[arg(long, default_value_t = 640)]
    width: i32,
    #[arg(long, default_value_t = 480)]
    height: i32,
    #[arg(long, default_value_t = 15)]
    fps: i32,
}

struct Conn {
    addr: String,
    tcp: TcpStream,
    aead: Aes128GcmStream,
    has_key: bool,
}

fn now_ns() -> u64 {
    gst::SystemClock::obtain().time().map(|t| t.nseconds()).unwrap_or(0) as u64
}

fn load_receiver_pub() -> Result<RsaPublicKey> {
    let pem = std::fs::read_to_string(KEY_PATH_RECEIVER_PUB)
        .map_err(|e| anyhow!("read receiver pubkey {}: {}", KEY_PATH_RECEIVER_PUB, e))?;
    Ok(RsaPublicKey::from_public_key_pem(&pem)?)
}

/// sender-side pipeline (queues + drop=true)
fn make_sender_pipeline(device: &str, w: i32, h: i32, fps: i32)
    -> Result<(gst::Pipeline, AppSink)>
{
    rpi_secure_stream::video::gst_init_once()?;

    let desc = format!(
        "v4l2src device={device} do-timestamp=true !
         queue max-size-buffers=5 leaky=downstream !
         videoconvert !
         video/x-raw,format=I420,width={w},height={h},framerate={fps}/1 !
         queue max-size-buffers=5 leaky=downstream !
         appsink name=sink sync=false max-buffers=2 drop=true emit-signals=false"
    );

    let pipeline = gst::parse::launch(&desc)?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow!("not a pipeline"))?;

    let sink = pipeline
        .by_name("sink").ok_or_else(|| anyhow!("appsink not found"))?
        .downcast::<AppSink>()
        .map_err(|_| anyhow!("appsink downcast failed"))?;

    Ok((pipeline, sink))
}

async fn send_caps(conn: &mut TcpStream, w: i32, h: i32, fps: i32) -> Result<()> {
    let mut p = Vec::with_capacity(16);
    p.extend_from_slice(&(w as u32).to_be_bytes());
    p.extend_from_slice(&(h as u32).to_be_bytes());
    p.extend_from_slice(&(fps as u32).to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes()); // denom
    let msg = WireMsg { flags: FLAG_CAPS, ts_ns: now_ns(), seq: 0, pt_len: 0, payload: Bytes::from(p) };
    msg.write_to(conn).await
}

/// Send REKEY(seq=next_seq) using **group key** wrapped once per listener (RSA-OAEP-256)
async fn send_rekey_all(conns: &mut [Conn], next_seq: u64, rekey_log: &str) -> Result<()> {
    // generate new group key
    let mut key = [0u8; 16];
    let mut nb  = [0u8; 12];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nb);

    // common plaintext (key||nonce_base)
    let mut secret = [0u8; 28];
    secret[..16].copy_from_slice(&key);
    secret[16..].copy_from_slice(&nb);

    let pk = load_receiver_pub()?;
    let label = Oaep::new::<Sha256>();

    for c in conns.iter_mut() {
    let wrapped = pk.encrypt(&mut OsRng, Oaep::new::<Sha256>(), &secret)
        .map_err(|e| anyhow!("RSA-OAEP wrap to {} failed: {e}", c.addr))?;
    // ...
    



        let mut p = Vec::with_capacity(8 + 2 + 2 + wrapped.len());
        p.extend_from_slice(&next_seq.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes()); // alg_id=1
        p.extend_from_slice(&(wrapped.len() as u16).to_be_bytes());
        p.extend_from_slice(&wrapped);

        let msg = WireMsg { flags: FLAG_REKEY, ts_ns: now_ns(), seq: next_seq, pt_len: 0, payload: Bytes::from(p) };
        if let Err(e) = msg.write_to(&mut c.tcp).await {
            eprintln!("[fanout] rekey to {} failed: {e}", c.addr);
            continue;
        }
        // swap locally
        if let Err(e) = c.aead.rekey_at(key, nb, next_seq) {
            eprintln!("[fanout] local rekey_at {} failed: {e}", c.addr);
            append_csv(&rekey_log, &format!("{},{},{}", now_ns(), next_seq, c.addr));

            continue;
        }
        c.has_key = true;
        eprintln!("[fanout] REKEY applied for {}", c.addr);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let tx_log    = "data/stream_tx.csv".to_string();
    let rekey_log = "data/rekey_tx.csv".to_string();    

    if args.listeners.is_empty() {
        return Err(anyhow!("provide at least one --listener ip:port"));
    }
    eprintln!("[fanout] listeners: {:?}", args.listeners);

    // Build video pipeline
    let (pipeline, sink) = make_sender_pipeline(&args.device, args.width, args.height, args.fps)?;
    pipeline.set_state(gst::State::Playing)?;
    let (res, new, _) = pipeline.state(gst::ClockTime::from_seconds(3));
    if let Err(_) = res { return Err(anyhow!("camera failed to preroll")); }
    eprintln!("[fanout] pipeline: {:?}", new);

    // Connect to all listeners
    let mut conns: Vec<Conn> = Vec::new();
    for addr in &args.listeners {
        match tcp_connect_with_retry(addr, Duration::from_secs(10)).await {
            Ok(mut tcp) => {
                let _ = tcp.set_nodelay(true);
                // neutral AEAD until rekey
                let aead = Aes128GcmStream::new([0u8;16], [0u8;12])?;
                // send CAPS
                if let Err(e) = send_caps(&mut tcp, args.width, args.height, args.fps).await {
                    eprintln!("[fanout] CAPS to {} failed: {e}", addr);
                }
                conns.push(Conn { addr: addr.clone(), tcp, aead, has_key: false });
            }
            Err(e) => eprintln!("[fanout] connect {} failed: {e}", addr),
        }
    }
    if conns.is_empty() {
        return Err(anyhow!("no listeners connected"));
    }

    // Bootstrap rekey at seq=0 for all
    send_rekey_all(&mut conns, 0, &rekey_log).await?;
    sleep(Duration::from_millis(150)).await;

    let mut seq: u64 = 0;
    let mut last = Instant::now();
    let mut tx_frames = 0usize;

    loop {
        // Periodic/group rekey every ~30s @15fps OR guard against wrap
        let need_guard = conns.iter().any(|c| c.aead.need_rekey(seq));
        if need_guard || (seq > 0 && seq % 450 == 0) { // 450 ≈ 30s @15fps
            send_rekey_all(&mut conns, seq, &rekey_log).await?;
        }

        // Pull one frame
        let Some(sample) = sink.try_pull_sample(gst::ClockTime::from_mseconds(500)) else {
            if last.elapsed() > Duration::from_secs(2) {
                eprintln!("[fanout] waiting for frames...");
                last = Instant::now();
            }
            continue;
        };
        let buffer = match sample.buffer() {
            Some(b) => b,
            None => continue,
        };
        let map = match buffer.map_readable() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let pt = map.as_slice();
        let pt_len = pt.len() as u32;

        // Encrypt/sent per listener that has a key
        for c in conns.iter_mut() {
            if !c.has_key { continue; }
            match c.aead.encrypt_frame(seq, pt, pt_len) {
                Ok(ct) => {
                    let ct_len = ct.len();                   // <-- take length before move
                    let msg = WireMsg {
                        flags: FLAG_FRAME,
                        ts_ns: now_ns(),
                        seq,
                        pt_len,
                        payload: Bytes::from(ct),            // <-- ct moved here
                    };
                    if let Err(e) = msg.write_to(&mut c.tcp).await {
                        eprintln!("[fanout] write {} failed: {e}", c.addr);
                        c.has_key = false;
                    } else {
                        // per-frame TX CSV log (now using ct_len)
                        append_csv(
                            &tx_log,
                            &format!("{},{},{},{},{}",
                                now_ns(), seq, pt_len, ct_len, c.addr
                            )
                        );
                    }
                }
                Err(e) => eprintln!("[fanout] encrypt {} failed: {e}", c.addr),
            }

        }

        tx_frames += 1;
        if last.elapsed() > Duration::from_secs(1) {
            eprintln!("[fanout] TX fps≈{} (seq={}) to {} listeners", tx_frames, seq,
                      conns.iter().filter(|c| c.has_key).count());
            tx_frames = 0;
            last = Instant::now();
        }

        seq = seq.wrapping_add(1);
    }
}
