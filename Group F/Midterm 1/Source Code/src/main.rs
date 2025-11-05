mod crypto;
mod frame;
mod transport;
mod video;
mod metrics;
mod group;

use clap::{Parser, ValueEnum};
use crypto::{AeadState, NonceMgr, hkdf_expand_128_96, os_rand_maybe_mix};
use frame::{Frame, FLAG_HANDSHAKE, FLAG_VIDEO};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}, Mutex};
use tokio::sync::mpsc;
use time::OffsetDateTime;
use tracing::info;
use gstreamer::prelude::*; // for set_state, ElementExt

use std::time::Instant;

// Start timing before handshake
// ... your existing handshake code (send wrapped key, receive confirm) ...

//let hs_dur = hs_start.elapsed().as_secs_f64();
//let bytes_sent = f.payload.len(); // or total handshake bytes if you track them
//{
  //  let mut lg = logs.lock().unwrap();
    //metrics::log_handshake(&mut lg.handshake, "rsa2048", bytes_sent, hs_dur, true);
//}


#[derive(Copy, Clone, ValueEnum, Debug)]
enum Mode { Sender, Receiver, Leader }

#[derive(Copy, Clone, ValueEnum, Debug)]
enum Mech { Rsa2048, Rsa3072 }

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long, value_enum)]
    mode: Mode,
    #[arg(long, default_value = "0.0.0.0:5000")]
    addr: String,
    #[arg(long, value_enum, default_value_t = Mech::Rsa2048)]
    mech: Mech,
    #[arg(long)]
    print_config: bool,
}

fn print_config() {
    println!("Build flags: target-cpu=native (.cargo/config.toml)");
    if let Ok(c) = std::fs::read_to_string("/proc/cpuinfo") {
        if let Some(line) = c.lines().find(|l| l.to_lowercase().contains("features")) {
            println!("cpuinfo: {line}");
        }
    }
    #[cfg(target_arch="aarch64")] {
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        eprintln!("ARMv8 Crypto Extensions: AES={} PMULL={}", aes, pmull);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let a = Args::parse();
    if a.print_config { print_config(); }

    tokio::spawn(metrics::sys_task("run_sys.csv"));

    // shared logs for both sender and receiver
    let logs = Arc::new(Mutex::new(metrics::Logs::open("run")));

    match a.mode {
        Mode::Sender => run_sender(&a.addr, a.mech, Arc::clone(&logs)).await?,
        Mode::Receiver => run_receiver(&a.addr, a.mech, Arc::clone(&logs)).await?,
	Mode::Leader   => run_leader().await?,
    }
    Ok(())
}

async fn run_sender(dst:&str, mech:Mech, logs:Arc<Mutex<metrics::Logs>>) -> anyhow::Result<()> {
    video::init()?;
    let (pipeline, appsink) = video::build_sender_640x480()?;
    pipeline.set_state(gstreamer::State::Playing)?;

    let mut conn = transport::connect(dst).await?;
    info!("sender: connected {}", dst);

    let hs_start = Instant::now(); 

    let mut gk = [0u8;16]; os_rand_maybe_mix(&mut gk);
    let f = Frame{ flags:FLAG_HANDSHAKE, ts_ns: now_ns(), seq:0, payload: gk.to_vec() };
    transport::send(&mut conn, &f.encode()).await?;
    let hs_dur = hs_start.elapsed().as_secs_f64();
    {
        let mut lg = logs.lock().unwrap();
        metrics::log_handshake(&mut lg.handshake, "rsa2048", f.payload.len(), hs_dur, true);
    }

    let mut salt=[0u8;32]; os_rand_maybe_mix(&mut salt);
    let (key, base) = hkdf_expand_128_96(&gk, &salt);
    let aead = AeadState::new(key);
    let mut nmgr = NonceMgr::new(base);

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    appsink.set_callbacks(
        gstreamer_app::AppSinkCallbacks::builder()
            .new_sample(move |sink| {
                let sample = sink.pull_sample().unwrap();
                let buf = sample.buffer().unwrap();
                let map = buf.map_readable().unwrap();
                tx.send(map.as_ref().to_vec()).ok();
                Ok(gstreamer::FlowSuccess::Ok)
            })
            .build()
    );

    let seq = Arc::new(AtomicU64::new(0));
    let mut bytes_acc = 0usize;
    let mut frames = 0usize;
    let mut window_start = std::time::Instant::now();

    while let Some(h264) = rx.recv().await {
        let s = seq.fetch_add(1, Ordering::Relaxed);
        let ts_ns = now_ns();
        let clear = Frame{ flags: FLAG_VIDEO, ts_ns, seq: s, payload: h264 };
        let aad = clear.aad();
        let nonce = nmgr.next();
        let ct = aead.seal(nonce, &aad, &clear.payload)?;
        let enc = Frame{ payload: ct, ..clear }.encode();
        bytes_acc += enc.len(); frames += 1;
        transport::send(&mut conn, &enc).await?;

        if window_start.elapsed().as_secs_f64() >= 1.0 {
            let mbps = (bytes_acc as f64 * 8.0) / 1_000_000.0;
            let mut lg = logs.lock().unwrap();
            metrics::log_throughput(&mut lg.throughput, mbps, frames as f64);
            bytes_acc = 0; frames = 0; window_start = std::time::Instant::now();
        }

        if nmgr.near_limit() {
            info!("sender: nearing nonce limit (add rekey)");
        }
    }
    Ok(())
}

async fn run_receiver(bind:&str, _mech:Mech, logs:Arc<Mutex<metrics::Logs>>) -> anyhow::Result<()> {
    use gstreamer as gst;
    video::init()?;
    let (pipeline, appsrc) = video::build_receiver()?;
    pipeline.set_state(gst::State::Playing)?;
    info!("receiver: listening {}", bind);

    let aead_state: Arc<Mutex<Option<(AeadState, NonceMgr)>>> = Arc::new(Mutex::new(None));

    let handler: Arc<Mutex<Box<dyn FnMut(Vec<u8>) -> anyhow::Result<()> + Send>>> = {
        let st = aead_state.clone();
        let logs_arc = Arc::clone(&logs);

        Arc::new(Mutex::new(Box::new(move |buf: Vec<u8>| -> anyhow::Result<()> {
            let f = frame::Frame::decode(&buf[..]);

	    if f.flags & FLAG_HANDSHAKE != 0 {
		    eprintln!("receiver: HANDSHAKE frame received ({} bytes)", f.payload.len());

		    // --- Step 4: unwrap the leader’s RSA-OAEP payload ---
		    // generate or load our RSA keypair (normally load from disk)
		    use rsa::RsaPrivateKey;
		    let (my_priv, _my_pub) = crypto::rsa_generate(2048)?;
    
		    // unwrap salt || ciphertext into group key
		    let confirm = group::member_receive_wrap(&my_priv, &f.payload)?;
		    eprintln!("receiver: KEM confirm HMAC[0..8]={:x?}", &confirm[..8]);

		    // derive AES session key + nonce base from group key (shared)
		    let (key, nonce_base) = crypto::hkdf_expand_128_96(&confirm, b"ECE4301-midterm-2025");
		    eprintln!("receiver: derived AES key {:?} nonce base {:?}", &key[..4], &nonce_base[..4]);

		    // you could now initialize your AeadState + NonceMgr here
		    // *aead_state.lock().unwrap() = Some((AeadState::new(key), NonceMgr::new(nonce_base)));

		    return Ok(());
		}


            if f.flags & FLAG_VIDEO != 0 {
                if let Some((ref aead, ref mut nmgr)) = *st.lock().unwrap() {
                    let aad = f.aad();
                    let nonce = nmgr.next();
                    let pt = aead.open(nonce, &aad, &f.payload)?;
                    let gstbuf = gst::Buffer::from_mut_slice(pt);
                    appsrc.push_buffer(gstbuf).unwrap();

                    let now_ns = now_ns();
                    let e2e_ms = ((now_ns as i128 - f.ts_ns as i128) as f64) / 1_000_000.0;
                    let mut lg = logs_arc.lock().unwrap();
                    metrics::log_latency(&mut lg.latency, f.seq, e2e_ms);
                } else {
                    let mut lg = logs_arc.lock().unwrap();
                    metrics::log_error(&mut lg.errors, "video before handshake");
                }
            }
            Ok(())
        })))
    };

    transport::listen(bind, handler).await?;
    Ok(())
}

fn now_ns() -> u64 {
    OffsetDateTime::now_utc().unix_timestamp_nanos() as u64
}


async fn run_leader() -> anyhow::Result<()> {
    use rsa::RsaPublicKey;
    use crate::group;

    println!("Leader: starting group key distribution demo");

    // create our leader keypair
    let (_leader_priv, _leader_pub) = crypto::rsa_generate(2048)?;

    // example: two members at known IPs
    let member_addrs = vec![
        "192.168.0.181:5000".to_string(),
       // "192.168.0.183:5000".to_string(),
    ];

    // placeholder: in a real setup, you’d load actual member public keys
    // for now, reuse dummy keys locally (this just shows structure)
    let mut member_pubs: Vec<RsaPublicKey> = Vec::new();
    for _ in 0..member_addrs.len() {
        let (_priv, pubk) = crypto::rsa_generate(2048)?;
        member_pubs.push(pubk);
    }

    let (gk, _salts) = group::leader_distribute(member_addrs, member_pubs).await?;
    println!("Leader: distributed group key {:?} to members", gk);
    Ok(())
}

