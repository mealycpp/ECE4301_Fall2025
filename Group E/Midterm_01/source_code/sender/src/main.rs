use anyhow::Result;
use clap::Parser;
use tokio::{net::TcpStream, io::AsyncWriteExt};

use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use tokio::sync::Mutex;

use common::{crypto::*, framing, video};
use common::crypto;
use common::metrics::{SysSampler, RateMeter, CsvLogger, SteadyRow, ts_iso, log_line};
use rand::RngCore;

#[derive(Parser, Debug)]
struct Args {
    /// Receiver address in host:port form (e.g. 192.168.1.100:5001)
    #[arg(long, default_value = "192.168.1.100:5001")]
    target: String,

    /// Key exchange mechanism: "ecdh" or "rsa"
    #[arg(long, default_value = "ecdh")]
    mech: String,

    /// Video capture settings: width,height,fps (e.g. 640,480,15)
    #[arg(long, default_value = "640,480,15")]
    whf: String,

    /// Enable periodic metrics logging to stderr
    #[arg(long, default_value_t = false)]
    log: bool,

    /// Optional CSV path for steady-stream metrics
    #[arg(long)]
    csv: Option<String>,

    /// Node label shown in logs/CSV
    #[arg(long, default_value = "sender")]
    node: String,
}

#[tokio::main(flavor="multi_thread")]
async fn main() -> Result<()> {
    crypto::log_arm_crypto_support();
    video::init_gst()?;

    let args = Args::parse();
    let parts: Vec<_> = args.whf.split(',').collect();
    let (w,h,fps) = (parts[0].parse::<i32>()?, parts[1].parse::<i32>()?, parts[2].parse::<i32>()?);

    let mut sock = TcpStream::connect(&args.target).await?;
    eprintln!("Connected to {}", args.target);

    // --- Key establishment ---
    let mut aead: AeadCtx;

    if args.mech == "ecdh" {
        // 1) Initiator: send (salt || my_pub)
        let st = ecdh_start();
        let payload = [&st.salt[..], &st.pub_bytes[..]].concat();
        let msg = framing::pack(framing::MsgKind::Handshake, 1, now_ns(), &payload);
        sock.write_all(&msg).await?;

        // 2) Responder reply: (responder_nonce_base || responder_pub)
        let (_,_,_,resp) = framing::read_one(&mut sock).await?;
        let (peer_nb_bytes, resp_pub) = resp.split_at(8);

        // 3) Finish ECDH and ADOPT the responder's nonce base
        let (mut ctx, _my_local_nb) = ecdh_finish(st, resp_pub, b"ECE4301-midterm-2025")?;
        let mut nb = [0u8;8];
        nb.copy_from_slice(peer_nb_bytes);
        ctx.set_nonce_base(nb);  // requires AeadCtx::set_nonce_base([u8;8])
        aead = ctx;

        // 4) Optional ACK
        let ack = framing::pack(framing::MsgKind::HandshakeResp, 0, now_ns(), peer_nb_bytes);
        sock.write_all(&ack).await?;
    } else {
        // RSA path: request receiver pub, wrap session key, send (nonce_base || wrapped)
        use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
        // Request receiver pub
        let req = framing::pack(framing::MsgKind::Handshake, 2, now_ns(), b"REQ_PUB");
        sock.write_all(&req).await?;
        let (_,_,_,pub_der) = framing::read_one(&mut sock).await?;
        let rpk = RsaPublicKey::from_public_key_der(&pub_der)?;
        // Make session key & nonce base
        let mut sk = [0u8;16]; rand::rngs::OsRng.fill_bytes(&mut sk);
        let mut nonce_base=[0u8;8]; rand::rngs::OsRng.fill_bytes(&mut nonce_base);
        let wrapped = rpk.encrypt(&mut rand::rngs::OsRng, rsa::Oaep::new::<sha2::Sha256>(), &sk)?;
        let payload = [&nonce_base[..], &wrapped[..]].concat();
        let msg2 = framing::pack(framing::MsgKind::HandshakeResp, 0, now_ns(), &payload);
        sock.write_all(&msg2).await?;
        aead = AeadCtx::new(sk, nonce_base);
    }
    eprintln!("Handshake complete.");

    // --- Metrics wiring (optional) ---
    let bytes_tx = Arc::new(AtomicU64::new(0));
    let frames_tx = Arc::new(AtomicU64::new(0));

    // CSV logger behind Arc<Mutex<...>> so it can be moved into the 'static task.
    let csv_logger: Option<Arc<Mutex<CsvLogger>>> = args.csv.as_ref().map(|path| {
        Arc::new(Mutex::new(CsvLogger::open_append(path).expect("open csv")))
    });

    if args.log || csv_logger.is_some() {
        let node = args.node.clone();
        let print_log = args.log;

        let bytes_tx_c = Arc::clone(&bytes_tx);
        let frames_tx_c = Arc::clone(&frames_tx);
        let csv_logger_c = csv_logger.clone();

        tokio::spawn(async move {
            let mut sys = SysSampler::new();
            let mut rate = RateMeter::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let snap = sys.sample();
                if let Some((mbps, fps)) =
                    rate.tick(bytes_tx_c.load(Ordering::Relaxed), frames_tx_c.load(Ordering::Relaxed))
                {
                    if print_log {
                        log_line(&node, mbps, fps, snap);
                    }
                    if let Some(logger_arc) = &csv_logger_c {
                        if let Ok(mut guard) = logger_arc.try_lock() {
                            let row = SteadyRow {
                                ts: ts_iso(),
                                node: node.clone(),
                                goodput_mbps: mbps,
                                fps,
                                cpu_pct: snap.cpu_pct,
                                mem_mb: snap.mem_mb,
                                temp_c: snap.temp_c,
                                drops: 0,
                                tag_fail: 0,
                            };
                            let _ = guard.write_row(&row);
                        }
                    }
                }
            }
        });
    }

    // --- Video capture & send loop ---
    let cap = video::make_sender_pipeline(w,h,fps)?;
    let mut seq: u64 = 0;
    loop {
        let h264 = match video::pull_h264_sample(&cap) {
            Ok(v)=>v, Err(_) => continue
        };
        let seq_bytes = seq.to_be_bytes();
        let ct = aead.encrypt(&seq_bytes, &h264)?;
        let payload = [&seq_bytes, &ct[..]].concat();
        let msg = framing::pack(framing::MsgKind::Data, 0, now_ns(), &payload);

        // update metrics counters *before* write
        bytes_tx.fetch_add(msg.len() as u64, Ordering::Relaxed);
        frames_tx.fetch_add(1, Ordering::Relaxed);

        sock.write_all(&msg).await?;
        seq = seq.wrapping_add(1);
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}
