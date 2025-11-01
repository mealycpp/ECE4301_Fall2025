use anyhow::{anyhow, Result};
use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit, Payload}, Nonce};
use clap::Parser;
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{time::{Instant, Duration, SystemTime}, sync::{Arc, Mutex}, thread};
use std::arch;
use zeroize::Zeroize;
use tokio::{
    net::TcpListener,
    io::{AsyncWriteExt, AsyncReadExt},
    sync::mpsc,
    task,
};
use gstreamer as gst;
use gstreamer_app as gst_app;
use gst::prelude::*;
use gst_app::AppSink;
use std::sync::atomic::{AtomicU32, Ordering};
use sysinfo::{System, SystemExt, CpuExt}; 

mod metrics;
use metrics::{MetricsLogger, log_arm_crypto_support};

#[derive(Parser, Debug)]
#[command(author, version, about = "Leader sender: ECDH + AES-GCM + MJPEG video stream (with rekey & metrics)")]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(long, default_value_t = 8080)]
    port: u16,
    #[arg(long, default_value = "/dev/video0")]
    video_dev: String,
    #[arg(long, default_value_t = 640)]
    width: i32,
    #[arg(long, default_value_t = 480)]
    height: i32,
    #[arg(long, default_value_t = 15)]
    fps: i32,
    #[arg(long, default_value_t = false)]
    print_config: bool,
    /// Metrics output directory
    #[arg(long, default_value = "metrics/leader")]
    metrics_dir: String,
    /// Queue capacity for capture->network (0 disables decoupling)
    #[arg(long, default_value_t = 4)]
    queue: usize,
}

const CONTEXT: &[u8] = b"ECE4301-midterm-2025";
const REKEY_FRAMES: u64 = 1 << 20;
const REKEY_INTERVAL: Duration = Duration::from_secs(10 * 60);

const F_ECDH_PUB: u8 = 0x20;
const F_NONCE_BASE: u8 = 0x21;
const F_ACK: u8 = 0x11;
const F_FRAME: u8 = 0x01;

struct KeyState {
    cipher: Aes128Gcm,
    nonce_base: [u8; 8],
    frames_sent: u64,
    started_at: Instant,
    counter: AtomicU32,
}

impl KeyState {
    fn needs_rekey(&self) -> bool {
        self.frames_sent >= REKEY_FRAMES || self.started_at.elapsed() >= REKEY_INTERVAL
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.print_config {
        println!("RUSTFLAGS={:?}", std::env::var("RUSTFLAGS").ok());
        #[cfg(target_arch = "aarch64")]
        {
            let aes = arch::is_aarch64_feature_detected!("aes");
            let pmull = arch::is_aarch64_feature_detected!("pmull");
            println!("runtime_features: aes={}, pmull={}", aes, pmull);
        }
        return Ok(());
    }

    // runtime feature log and metrics logger
    log_arm_crypto_support();

    let metrics = MetricsLogger::new(&args.metrics_dir).await?;
    let _sys_handle = metrics.spawn_periodic_sys_sampler(Duration::from_secs(5));
    // record runtime features to CSV
    metrics.log_runtime_features("leader").await.ok();

    let bind_addr = format!("{}:{}", args.host, args.port);
    println!("Binding TCP listener at {}", bind_addr);

    let listener = TcpListener::bind(&bind_addr).await?;
    println!("Waiting for member...");
    let (mut sock, peer_addr) = listener.accept().await?;
    sock.set_nodelay(true)?;
    println!("Member connected from {}", peer_addr);

    // Handshake instrumentation - record detailed handshake
    let hs_start = SystemTime::now();
    let hs_start_instant = Instant::now();
    let mut bytes_exchanged: u64 = 0;
    let mut bytes_tx_handshake: u64 = 0;
    let mut bytes_rx_handshake: u64 = 0;

    // send our ephemeral public
    let my_secret = EphemeralSecret::random(&mut OsRng);
    let my_public = EncodedPoint::from(PublicKey::from(&my_secret));
    send_pub_envelope(&mut sock, my_public.as_bytes()).await?;
    let sent_len = (4 + 1 + my_public.as_bytes().len()) as u64;
    bytes_exchanged += sent_len;
    bytes_tx_handshake += sent_len;

    // recv peer pub
    let peer_pub_bytes = read_envelope_payload(&mut sock).await?;
    let recv_len = (4 + peer_pub_bytes.len()) as u64;
    bytes_exchanged += recv_len;
    bytes_rx_handshake += recv_len;
    if peer_pub_bytes.is_empty() || peer_pub_bytes[0] != F_ECDH_PUB {
        metrics.log_handshake("leader", hs_start_instant.elapsed(), bytes_exchanged, false, "peer pub missing").await.ok();
        return Err(anyhow!("expected ECDH pub envelope"));
    }
    let peer_pub = PublicKey::from_sec1_bytes(&peer_pub_bytes[1..])?;
    let shared = my_secret.diffie_hellman(&peer_pub);
    let mut shared_ikm = shared.raw_secret_bytes().to_vec();

    // derive key + nonce & send salt envelope
    let (cipher, nonce_base, salt) = derive_key_from_ikm_and_salt(&shared_ikm)?;
    let salt_env_len = (4 + 1 + 4 + salt.len()) as u64;
    bytes_exchanged += salt_env_len;
    bytes_tx_handshake += salt_env_len;

    let ks = Arc::new(Mutex::new(KeyState {
        cipher,
        nonce_base,
        frames_sent: 0,
        started_at: Instant::now(),
        counter: AtomicU32::new(0),
    }));

    send_salt_envelope(&mut sock, &salt).await?;
    // wait for ACK
    wait_for_ack_and_validate(&mut sock, &ks).await?;
    // ACK read is inside wait_for_ack_and_validate — that function may account for bytes_rx_handshake if updated there.

    let hs_end = SystemTime::now();
    let hs_duration = hs_start_instant.elapsed();
    // minimal cpu/mem snapshot for handshake record
    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu();
    let cpu_avg = sys.global_cpu_info().cpu_usage();
    let mem_mb = sys.used_memory() / 1024; // used_memory() returns KB

    // log both simple and detailed handshake records
    metrics.log_handshake("leader", hs_duration, bytes_exchanged, true, "").await.ok();
    metrics.log_handshake_ecdh(hs_start, hs_end, "ECDH+HKDF+AES-GCM", bytes_tx_handshake, bytes_rx_handshake, cpu_avg, mem_mb, 0.0).await.ok();

    println!("Handshake complete; entering streaming loop.");

    // Setup GStreamer capture pipeline
    gst::init()?;
    let pipeline_desc = format!(
        "v4l2src device={dev} ! image/jpeg,width={w},height={h},framerate={fps}/1 \
         ! appsink name=sink emit-signals=false sync=false max-buffers=2 drop=true",
        dev = args.video_dev, w = args.width, h = args.height, fps = args.fps
    );
    let pipeline = gst::parse_launch(&pipeline_desc)?;
    let bin = pipeline.dynamic_cast::<gst::Bin>().map_err(|e| anyhow!("Pipeline cast failed: {:?}", e))?;
    let sink = bin.by_name("sink")
        .ok_or_else(|| anyhow!("appsink not found"))?
        .dynamic_cast::<AppSink>()
        .map_err(|e| anyhow!("appsink is not AppSink: {:?}", e))?;
    bin.set_state(gst::State::Playing)?;
    println!("Streaming MJPEG ...");

    // Optional channel between capture and network
    let (tx, mut rx) = if args.queue > 0 {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(args.queue);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    if let Some(tx) = tx.clone() {
        let sink_clone = sink.clone();
        let tx_clone = tx.clone();
        let fps_capture = args.fps;
        task::spawn_blocking(move || {
            loop {
                let timeout = gst::ClockTime::from_mseconds((1000 / fps_capture).max(10) as u64);
                match sink_clone.try_pull_sample(timeout) {
                    Some(sample) => {
                        if let Some(buffer) = sample.buffer() {
                            if let Ok(map) = buffer.map_readable() {
                                let slice = map.as_slice();
                                let mut v = Vec::with_capacity(slice.len());
                                v.extend_from_slice(slice);
                                match tx_clone.try_send(v) {
                                    Ok(_) => {}
                                    Err(_) => { /* drop frame */ }
                                }
                            }
                        }
                    }
                    None => {
                        thread::sleep(std::time::Duration::from_millis(2));
                        continue;
                    }
                }
            }
        });
    }

    // network + metrics window bookkeeping
    let ks_net = ks.clone();
    let mut window_frame_count: u64 = 0;
    let mut bytes_encrypted_window: u64 = 0;
    let mut window_start = Instant::now();
    let window_dur = Duration::from_secs(5);

    loop {
        let frame_bytes = if let Some(rx) = rx.as_mut() {
            match rx.recv().await {
                Some(b) => b,
                None => break,
            }
        } else {
            let sample = match sink.try_pull_sample(gst::ClockTime::from_mseconds(1000 / args.fps as u64)) {
                Some(s) => s,
                None => continue,
            };
            let buffer = sample.buffer().ok_or_else(|| anyhow!("no buffer"))?;
            let map = buffer.map_readable().map_err(|_| anyhow!("map_readable failed"))?;
            map.as_slice().to_vec()
        };

        let mut state = ks_net.lock().unwrap();
        let cipher = state.cipher.clone();
        let nonce_base = state.nonce_base;
        let ctr = state.counter.fetch_add(1, Ordering::SeqCst);
        let ts_ns = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos() as u64;

        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&nonce_base);
        nonce12[8..12].copy_from_slice(&ctr.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce12);

        let mut aad = [0u8; 16];
        aad[..8].copy_from_slice(&ts_ns.to_be_bytes());
        aad[8..12].copy_from_slice(&ctr.to_be_bytes());

        let ciphertext = match cipher.encrypt(nonce, Payload { msg: &frame_bytes, aad: &aad }) {
            Ok(ct) => ct,
            Err(_) => {
                metrics.log_loss("gcm_tag_failure", 1, "encrypt_failed").await.ok();
                continue;
            }
        };

        let len_u32 = u32::try_from(ciphertext.len()).unwrap_or(0);
        let mut header = Vec::with_capacity(13);
        header.extend_from_slice(&len_u32.to_be_bytes());
        header.push(F_FRAME);
        header.extend_from_slice(&ts_ns.to_be_bytes());

        if sock.write_all(&header).await.is_err() || sock.write_all(&ciphertext).await.is_err() {
            metrics.log_loss("send_failure", 1, "socket_write_failed").await.ok();
            println!("Connection closed.");
            break;
        }

        // bookkeeping
        window_frame_count = window_frame_count.wrapping_add(1);
        state.frames_sent = state.frames_sent.wrapping_add(1);
        bytes_encrypted_window += ciphertext.len() as u64;

        // periodic steady_stream logging (leader-side: fps & goodput; latency supplied by member via its own steady_stream rows)
        if window_start.elapsed() >= window_dur {
            let dur = window_start.elapsed();
            let fps = (window_frame_count as f32) / dur.as_secs_f32();
            let goodput_mbps = (bytes_encrypted_window as f64 * 8.0) / (1024.0*1024.0) / dur.as_secs_f64();

            // snapshot sys info for CPU/mem/temp
            let mut sys = System::new();
            sys.refresh_cpu();
            sys.refresh_memory();
            let cpu_pct = sys.global_cpu_info().cpu_usage();
            let mem_mb = sys.used_memory() / 1024;

            // leader doesn't compute latency_ms_p50 for receiver side; set 0.0 here and join offline if needed.
            let latency_ms_p50 = 0.0_f64;
            // for drops and tag_fail, you may aggregate loss.csv offline; we pass zeros here.
            metrics.log_steady_stream(fps, goodput_mbps, latency_ms_p50, cpu_pct, mem_mb, read_temp_c(), 0, 0).await.ok();

            // reset window
            bytes_encrypted_window = 0;
            window_frame_count = 0;
            window_start = Instant::now();
        }

        // rekey check
        if state.needs_rekey() {
            println!("Rekey triggered; performing rekey.");
            drop(state);
            perform_rekey_exchange(&mut sock, &ks_net).await?;
        }
    }

    bin.set_state(gst::State::Null)?;
    Ok(())
}

// helpers (envelope/crypto/rekey) - same style as earlier examples

async fn send_pub_envelope(sock: &mut tokio::net::TcpStream, pub_bytes: &[u8]) -> Result<()> {
    let payload_len = 1 + pub_bytes.len();
    let mut env = Vec::with_capacity(4 + payload_len);
    env.extend_from_slice(&(payload_len as u32).to_be_bytes());
    env.push(F_ECDH_PUB);
    env.extend_from_slice(pub_bytes);
    sock.write_all(&env).await?;
    Ok(())
}

async fn read_envelope_payload(sock: &mut tokio::net::TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await?;
    let env_len = u32::from_be_bytes(len_buf) as usize;
    let mut env = vec![0u8; env_len];
    sock.read_exact(&mut env).await?;
    Ok(env)
}

fn derive_key_from_ikm_and_salt(shared_ikm: &[u8]) -> Result<(Aes128Gcm, [u8;8], [u8;16])> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_ikm);
    let mut okm = [0u8; 16 + 8];
    hk.expand(CONTEXT, &mut okm).map_err(|_| anyhow!("HKDF expand failed"))?;
    let aes_key = &okm[..16];
    let mut nonce_base = [0u8;8];
    nonce_base.copy_from_slice(&okm[16..24]);
    let cipher = Aes128Gcm::new_from_slice(aes_key)?;
    okm.zeroize();
    Ok((cipher, nonce_base, salt))
}

async fn send_salt_envelope(sock: &mut tokio::net::TcpStream, salt: &[u8;16]) -> Result<()> {
    let mut salt_env = Vec::with_capacity(4 + 1 + 4 + salt.len());
    let payload_len = 1 + 4 + salt.len();
    salt_env.extend_from_slice(&(payload_len as u32).to_be_bytes());
    salt_env.push(F_NONCE_BASE);
    salt_env.extend_from_slice(&(salt.len() as u32).to_be_bytes());
    salt_env.extend_from_slice(&salt[..]);
    sock.write_all(&salt_env).await?;
    Ok(())
}

async fn wait_for_ack_and_validate(sock: &mut tokio::net::TcpStream, ks: &Arc<Mutex<KeyState>>) -> Result<()> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await?;
    let ack_msg_len = u32::from_be_bytes(len_buf) as usize;
    let mut ack_msg = vec![0u8; ack_msg_len];
    sock.read_exact(&mut ack_msg).await?;
    if ack_msg[0] != F_ACK {
        return Err(anyhow!("expected ACK flag from receiver"));
    }
    if ack_msg.len() < 1 + 4 {
        return Err(anyhow!("malformed ACK payload"));
    }
    let ack_cipher_len = u32::from_be_bytes(ack_msg[1..5].try_into().unwrap()) as usize;
    let ack_cipher = &ack_msg[5..5 + ack_cipher_len];

    let guard = ks.lock().unwrap();
    let mut ack_nonce12 = [0u8; 12];
    ack_nonce12[..8].copy_from_slice(&guard.nonce_base);
    ack_nonce12[8..12].copy_from_slice(&0u32.to_be_bytes());
    let ack_nonce = Nonce::from_slice(&ack_nonce12);
    let mut ack_aad = [0u8; 12];
    ack_aad[8..12].copy_from_slice(&(ack_cipher_len as u32).to_be_bytes());
    let ack_plain = guard.cipher.decrypt(ack_nonce, Payload { msg: ack_cipher, aad: &ack_aad })
        .map_err(|e| anyhow!("ack decrypt failed: {:?}", e))?;
    println!("Received decrypted ACK: {:?}", String::from_utf8_lossy(&ack_plain));
    Ok(())
}

async fn perform_rekey_exchange(sock: &mut tokio::net::TcpStream, ks: &Arc<Mutex<KeyState>>) -> Result<()> {
    let my_secret = EphemeralSecret::random(&mut OsRng);
    let my_public = EncodedPoint::from(PublicKey::from(&my_secret));
    send_pub_envelope(sock, my_public.as_bytes()).await?;

    let peer_pub_bytes = read_envelope_payload(sock).await?;
    if peer_pub_bytes.is_empty() || peer_pub_bytes[0] != F_ECDH_PUB {
        return Err(anyhow!("expected peer ECDH pub envelope during rekey"));
    }
    let peer_pub = PublicKey::from_sec1_bytes(&peer_pub_bytes[1..])?;

    let shared = my_secret.diffie_hellman(&peer_pub);
    let mut new_shared_vec = shared.raw_secret_bytes().to_vec();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let hk = Hkdf::<Sha256>::new(Some(&salt), &new_shared_vec);
    let mut okm = [0u8; 16 + 8];
    hk.expand(CONTEXT, &mut okm).map_err(|_| anyhow!("HKDF expand failed"))?;
    let new_aes_key = &okm[..16];
    let mut new_nonce_base = [0u8;8];
    new_nonce_base.copy_from_slice(&okm[16..24]);
    let new_cipher = Aes128Gcm::new_from_slice(new_aes_key)?;
    new_shared_vec.zeroize();
    okm.zeroize();

    send_salt_envelope(sock, &salt).await?;

    // wait for ACK encrypted with new key
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await?;
    let ack_msg_len = u32::from_be_bytes(len_buf) as usize;
    let mut ack_msg = vec![0u8; ack_msg_len];
    sock.read_exact(&mut ack_msg).await?;
    if ack_msg[0] != F_ACK { return Err(anyhow!("expected ACK")); }
    if ack_msg.len() < 1 + 4 {
        return Err(anyhow!("malformed ACK payload"));
    }
    let ack_cipher_len = u32::from_be_bytes(ack_msg[1..5].try_into().unwrap()) as usize;
    let ack_cipher = &ack_msg[5..5 + ack_cipher_len];

    let mut ack_nonce12 = [0u8; 12];
    ack_nonce12[..8].copy_from_slice(&new_nonce_base);
    ack_nonce12[8..12].copy_from_slice(&0u32.to_be_bytes());
    let ack_nonce = Nonce::from_slice(&ack_nonce12);
    let mut ack_aad = [0u8; 12];
    ack_aad[8..12].copy_from_slice(&(ack_cipher_len as u32).to_be_bytes());

    let ack_plain = new_cipher.decrypt(ack_nonce, Payload { msg: ack_cipher, aad: &ack_aad })
        .map_err(|e| anyhow!("rekey ACK decrypt failed: {:?}", e))?;
    println!("Rekey ACK decrypted: {:?}", String::from_utf8_lossy(&ack_plain));

    // swap in new key
    {
        let mut g = ks.lock().unwrap();
        g.cipher = new_cipher;
        g.nonce_base = new_nonce_base;
        g.counter.store(0, Ordering::SeqCst);
        g.frames_sent = 0;
        g.started_at = Instant::now();
    }

    salt.zeroize();
    Ok(())
}

fn read_temp_c() -> Option<f32> {
    if let Ok(s) = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp") {
        if let Ok(m) = s.trim().parse::<f32>() {
            return Some(m / 1000.0);
        }
    }
    None
}
