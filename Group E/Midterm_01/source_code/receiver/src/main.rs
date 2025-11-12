use anyhow::Result;
use clap::Parser;
use tokio::{net::TcpListener, io::AsyncWriteExt};

use std::sync::{
    Arc,
    atomic::{AtomicU32, AtomicU64, Ordering}
};
use tokio::sync::Mutex;

use common::{crypto::*, framing, video};
use common::crypto;
use common::handshake::HandshakeRecorder;
use common::metrics::{SysSampler, RateMeter, CsvLogger, SteadyRow, ts_iso, log_line};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:5001")]
    bind: String,

    #[arg(long, default_value = "ecdh")]
    mech: String,

    /// Enable periodic metrics logging to stderr
    #[arg(long, default_value_t = false)]
    log: bool,

    /// Optional CSV path for steady-stream metrics
    #[arg(long)]
    csv: Option<String>,

    /// Node label shown in logs/CSV
    #[arg(long, default_value = "receiver")]
    node: String,

    /// Optional CSV to log per-frame latency rows
    #[arg(long)]
    frames_csv: Option<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    crypto::log_arm_crypto_support();
    video::init_gst()?;

    let args = Args::parse();
    let lis = TcpListener::bind(&args.bind).await?;
    eprintln!("Listening on {}", args.bind);
    let (mut sock, addr) = lis.accept().await?;
    eprintln!("Client: {addr}");

    // --- Handshake -> AEAD context
    let mut aead: AeadCtx;

    if args.mech == "ecdh" {
        let mut hs = HandshakeRecorder::new("data/handshake_ecdh.csv", "ecdh")?;

        // Expect initiator HS: (salt || pub)
        let (_, _, _, init) = framing::read_one(&mut sock).await?;
        hs.add_rx(init.len());
        let (salt, peer_pub) = init.split_at(32);

        // Responder: make ctx + send (nonce_base || my_pub)
        let (my_pub, ctx, nonce_base) =
            ecdh_responder(peer_pub, salt, b"ECE4301-midterm-2025")?;
        let out = [&nonce_base[..], &my_pub[..]].concat();
        let msg = framing::pack(framing::MsgKind::HandshakeResp, 0, now_ns(), &out);
        hs.add_tx(msg.len());
        sock.write_all(&msg).await?;

        // optional: read final ACK (nonce_base echo)
        if let Ok((_, _, _, ack)) = framing::read_one(&mut sock).await {
            hs.add_rx(ack.len());
        }
        aead = ctx;

        hs.finish_and_write()?;
    } else {
        // RSA: Provide public key to sender
        use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey};
        let mut hs = HandshakeRecorder::new("data/handshake_rsa.csv", "rsa")?;

        let mut rng = rand::rngs::OsRng;
        let sk = RsaPrivateKey::new(&mut rng, 2048)?;
        let pk = RsaPublicKey::from(&sk);
        let der = pk.to_public_key_der()?.as_bytes().to_vec();

        let (_, _, _, req) = framing::read_one(&mut sock).await?;
        hs.add_rx(req.len());
        assert_eq!(&req[..], b"REQ_PUB");

        let msg = framing::pack(framing::MsgKind::HandshakeResp, 0, now_ns(), &der);
        hs.add_tx(msg.len());
        sock.write_all(&msg).await?;

        let (_, _, _, payload) = framing::read_one(&mut sock).await?;
        hs.add_rx(payload.len());
        let (nonce_base, wrapped) = payload.split_at(8);
        let skey = rsa_unwrap(&sk, wrapped)?;
        let mut nb = [0u8; 8];
        nb.copy_from_slice(nonce_base);
        aead = AeadCtx::new(skey.try_into().unwrap(), nb);

        hs.finish_and_write()?;
    }

    eprintln!("Handshake complete.");

    // --- Metrics wiring (optional) ---
    let bytes_rx = Arc::new(AtomicU64::new(0));
    let frames_rx = Arc::new(AtomicU64::new(0));
    let drops     = Arc::new(AtomicU32::new(0));
    let tag_fail  = Arc::new(AtomicU32::new(0));

    // CSV logger behind Arc<Mutex<...>> so it can be moved into the 'static task.
    let csv_logger: Option<Arc<Mutex<CsvLogger>>> = args.csv.as_ref().map(|path| {
        Arc::new(Mutex::new(CsvLogger::open_append(path).expect("open csv")))
    });

    if args.log || csv_logger.is_some() {
        let node = args.node.clone();
        let print_log = args.log;

        let bytes_rx_c  = Arc::clone(&bytes_rx);
        let frames_rx_c = Arc::clone(&frames_rx);
        let drops_c     = Arc::clone(&drops);
        let tag_fail_c  = Arc::clone(&tag_fail);
        let csv_logger_c = csv_logger.clone();

        tokio::spawn(async move {
            let mut sys  = SysSampler::new();
            let mut rate = RateMeter::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let snap = sys.sample();
                if let Some((mbps, fps)) =
                    rate.tick(bytes_rx_c.load(Ordering::Relaxed), frames_rx_c.load(Ordering::Relaxed))
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
                                drops: drops_c.swap(0, Ordering::Relaxed),
                                tag_fail: tag_fail_c.swap(0, Ordering::Relaxed),
                            };
                            let _ = guard.write_row(&row);
                        }
                    } else {
                        // when only printing, reset counters each tick
                        let _ = drops_c.swap(0, Ordering::Relaxed);
                        let _ = tag_fail_c.swap(0, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    // --- Pipeline + receive loop
    let player = video::make_receiver_pipeline()?;

    // Optional per-frame latency CSV
    let mut frames_csv = if let Some(path) = &args.frames_csv {
        let mut w = csv::WriterBuilder::new().has_headers(true).from_path(path)?;
        w.write_record(&["ts", "node", "send_ts_ns", "recv_ts_ns", "latency_ms"])?;
        Some(w)
    } else { None };

    loop {
        let (kind, _flags, ts_sent_ns, payload) = match framing::read_one(&mut sock).await {
            Ok(v) => v,
            Err(_) => { drops.fetch_add(1, Ordering::Relaxed); continue; }
        };

        if kind != (common::framing::MsgKind::Data as u8) { continue; }
        if payload.len() < 8 { continue; }

        // Split AAD (seq) from ciphertext
        let (seqb, ct) = payload.split_at(8);

        match aead.decrypt(seqb, ct) {
            Ok(pt) => {
                // Count payload bytes + frame for rates
                bytes_rx.fetch_add(payload.len() as u64, Ordering::Relaxed);
                frames_rx.fetch_add(1, Ordering::Relaxed);

                let _ = video::push_h264_frame(&player, &pt);

                if let Some(w) = frames_csv.as_mut() {
                    let recv_ns = now_ns();
                    let lat_ms = (recv_ns as i128 - ts_sent_ns as i128) as f64 / 1.0e6;
                    w.write_record(&[
                        &common::metrics::ts_iso(),
                        &args.node,
                        &ts_sent_ns.to_string(),
                        &recv_ns.to_string(),
                        &format!("{:.3}", lat_ms),
                    ]).ok();
                    w.flush().ok();
                }
            }
            Err(_) => { tag_fail.fetch_add(1, Ordering::Relaxed); }
        }
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
