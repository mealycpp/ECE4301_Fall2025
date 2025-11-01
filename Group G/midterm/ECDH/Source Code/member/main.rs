use anyhow::{anyhow, Result};
use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit, Payload}, Nonce};
use clap::Parser;
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use rand::rngs::OsRng;
use sha2::Sha256;
use std::time::{Instant, Duration, SystemTime};
use zeroize::Zeroize;
use tokio::{
    net::TcpStream,
    io::{AsyncReadExt, AsyncWriteExt},
};
use gstreamer as gst;
use gstreamer_app as gst_app;
use gst::prelude::*;
use gst_app::AppSrc;
use sysinfo::{System, SystemExt, CpuExt};

mod metrics;
use metrics::{MetricsLogger, log_arm_crypto_support};

#[derive(Parser, Debug)]
#[command(author, version, about = "Member receiver: AES-GCM MJPEG live video player (with metrics)")]
struct Args {
    #[arg(long)]
    leader_ip: String,
    #[arg(long, default_value_t = 8080)]
    port: u16,
    #[arg(long, default_value_t = false)]
    print_config: bool,
    #[arg(long, default_value = "metrics/member")]
    metrics_dir: String,
}

const CONTEXT: &[u8] = b"ECE4301-midterm-2025";

const F_ECDH_PUB: u8 = 0x20;
const F_NONCE_BASE: u8 = 0x21;
const F_ACK: u8 = 0x11;
const F_FRAME: u8 = 0x01;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.print_config {
        println!("RUSTFLAGS={:?}", std::env::var("RUSTFLAGS").ok());
        #[cfg(target_arch = "aarch64")]
        {
            let aes = std::arch::is_aarch64_feature_detected!("aes");
            let pmull = std::arch::is_aarch64_feature_detected!("pmull");
            println!("runtime_features: aes={}, pmull={}", aes, pmull);
        }
        return Ok(());
    }

    log_arm_crypto_support();

    // metrics logger
    let metrics = MetricsLogger::new(&args.metrics_dir).await?;
    let _sys = metrics.spawn_periodic_sys_sampler(Duration::from_secs(5));
    metrics.log_runtime_features("member").await.ok();

    let addr = format!("{}:{}", args.leader_ip, args.port);
    println!("Connecting to leader at {}", addr);
    let mut sock = TcpStream::connect(&addr).await?;
    sock.set_nodelay(true)?;
    println!("Connected to leader.");

    // handshake - record detailed handshake metrics
    let hs_start = SystemTime::now();
    let hs_start_instant = Instant::now();
    let mut bytes_exchanged: u64 = 0;
    let mut bytes_tx_handshake: u64 = 0;
    let mut bytes_rx_handshake: u64 = 0;

    // receive leader pub envelope
    let leader_pub_env = read_envelope_payload(&mut sock).await?;
    bytes_exchanged += (4 + leader_pub_env.len()) as u64;
    bytes_rx_handshake += (4 + leader_pub_env.len()) as u64;
    if leader_pub_env.is_empty() || leader_pub_env[0] != F_ECDH_PUB {
        return Err(anyhow!("expected leader ECDH pub envelope"));
    }
    let leader_pub = PublicKey::from_sec1_bytes(&leader_pub_env[1..])?;

    // build ephemeral and send pub envelope
    let my_secret = EphemeralSecret::random(&mut OsRng);
    let my_public = EncodedPoint::from(PublicKey::from(&my_secret));
    send_pub_envelope(&mut sock, my_public.as_bytes()).await?;
    bytes_exchanged += (4 + 1 + my_public.as_bytes().len()) as u64;
    bytes_tx_handshake += (4 + 1 + my_public.as_bytes().len()) as u64;

    let shared = my_secret.diffie_hellman(&leader_pub);
    let mut ikm = shared.raw_secret_bytes().to_vec();

    // read salt envelope
    let salt_env = read_envelope_payload(&mut sock).await?;
    bytes_exchanged += (4 + salt_env.len()) as u64;
    bytes_rx_handshake += (4 + salt_env.len()) as u64;
    if salt_env.is_empty() || salt_env[0] != F_NONCE_BASE {
        return Err(anyhow!("expected salt envelope flag"));
    }
    let salt_len = u32::from_be_bytes(salt_env[1..5].try_into().unwrap()) as usize;
    let salt = &salt_env[5..5 + salt_len];

    // derive key/nonce and send ACK
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 16 + 8];
    hk.expand(CONTEXT, &mut okm).map_err(|_| anyhow!("HKDF expand failed"))?;
    let aes_key = okm[..16].to_vec();
    let mut nonce_base = [0u8; 8];
    nonce_base.copy_from_slice(&okm[16..24]);
    ikm.zeroize();
    okm.zeroize();
    let cipher = Aes128Gcm::new_from_slice(&aes_key)?;

    // build and send ACK (encrypted)
    let mut ack_plain = Vec::new();
    let ts_millis = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64;
    ack_plain.extend_from_slice(&ts_millis.to_be_bytes());
    ack_plain.extend_from_slice(b"OK");

    let mut ack_nonce12 = [0u8; 12];
    ack_nonce12[..8].copy_from_slice(&nonce_base);
    ack_nonce12[8..12].copy_from_slice(&0u32.to_be_bytes());
    let ack_nonce = Nonce::from_slice(&ack_nonce12);

    // Build aad for ACK (match leader expectation: last 4 bytes = ack_cipher_len as u32 BE)
    let mut ack_aad = [0u8; 12];

    let ack_cipher = {

        let first = cipher.encrypt(ack_nonce, Payload { msg: &ack_plain, aad: &[] })
            .map_err(|e| anyhow!("ack encrypt failed: {:?}", e))?;
        let len = first.len();
        ack_aad[8..12].copy_from_slice(&(len as u32).to_be_bytes());
        // now encrypt with the intended AAD
        cipher.encrypt(ack_nonce, Payload { msg: &ack_plain, aad: &ack_aad })
            .map_err(|e| anyhow!("ack encrypt failed: {:?}", e))?
    };

    let mut ack_env = Vec::with_capacity(4 + 1 + 4 + ack_cipher.len());
    let payload_len = 1 + 4 + ack_cipher.len();
    ack_env.extend_from_slice(&(payload_len as u32).to_be_bytes());
    ack_env.push(F_ACK);
    ack_env.extend_from_slice(&(ack_cipher.len() as u32).to_be_bytes());
    ack_env.extend_from_slice(&ack_cipher);
    sock.write_all(&ack_env).await?;
    bytes_exchanged += (4 + payload_len) as u64;
    bytes_tx_handshake += (4 + payload_len) as u64;

    let hs_end = SystemTime::now();
    let hs_duration = hs_start_instant.elapsed();
    // cpu/mem snapshot
    let mut sys = System::new();
    sys.refresh_cpu();
    sys.refresh_memory();
    let cpu_avg = sys.global_cpu_info().cpu_usage();
    let mem_mb = sys.used_memory() / 1024;

    metrics.log_handshake("member", hs_duration, bytes_exchanged, true, "").await.ok();
    metrics.log_handshake_ecdh(hs_start, hs_end, "ECDH+HKDF+AES-GCM", bytes_tx_handshake, bytes_rx_handshake, cpu_avg, mem_mb, 0.0).await.ok();

    println!("Handshake complete, entering receive loop...");

    // GStreamer + appsrc setup
    gst::init()?;
    let pipeline_desc = "appsrc name=src is-live=true format=time do-timestamp=true \
                         caps=image/jpeg,framerate=15/1 \
                         ! jpegparse ! avdec_mjpeg ! videoconvert ! autovideosink sync=false";
    let pipeline = gst::parse_launch(pipeline_desc)?;
    let pipeline = pipeline.dynamic_cast::<gst::Pipeline>()
        .map_err(|e| anyhow!("Pipeline cast failed: {:?}", e))?;

    let appsrc_elem = pipeline.by_name("src").ok_or_else(|| anyhow!("appsrc not found"))?;
    let appsrc = appsrc_elem
        .dynamic_cast::<AppSrc>()
        .map_err(|e| anyhow!("appsrc element is not an AppSrc: {:?}", e))?;

    pipeline.set_state(gst::State::Playing)?;
    println!("Pipeline ready — displaying live video.");

    // keep in-memory latency buffer for p50 per window
    let mut lat_buffer: Vec<f64> = Vec::new();
    let mut window_start = Instant::now();
    let window_dur = Duration::from_secs(5);
    let mut bytes_received_window: u64 = 0;

    let mut ctr: u32 = 0;

    loop {
        // read frame header or envelope
        let mut first4 = [0u8; 4];
        if sock.read_exact(&mut first4).await.is_err() {
            println!("Stream ended.");
            break;
        }
        let v = u32::from_be_bytes(first4) as usize;

        if v <= 65536 {
            // envelope
            let mut env = vec![0u8; v];
            if sock.read_exact(&mut env).await.is_err() { break; }
            if env.is_empty() { continue; }
            match env[0] {
                F_ECDH_PUB => continue,
                F_NONCE_BASE => continue,
                _ => continue,
            }
        } else {
            // frame header (we already read first4)
            let mut header = [0u8; 13];
            header[..4].copy_from_slice(&first4);
            if sock.read_exact(&mut header[4..]).await.is_err() { break; }
            let frame_len = u32::from_be_bytes(header[0..4].try_into()?) as usize;
            let _flags = header[4];
            let ts_ns = u64::from_be_bytes(header[5..13].try_into()?);

            let mut ciphertext = vec![0u8; frame_len];
            if sock.read_exact(&mut ciphertext).await.is_err() { break; }

            let mut nonce12 = [0u8; 12];
            nonce12[..8].copy_from_slice(&nonce_base);
            nonce12[8..12].copy_from_slice(&ctr.to_be_bytes());
            let nonce = Nonce::from_slice(&nonce12);

            let mut aad = [0u8; 16];
            aad[..8].copy_from_slice(&ts_ns.to_be_bytes());
            aad[8..12].copy_from_slice(&ctr.to_be_bytes());

            let recv_instant = SystemTime::now();
            match cipher.decrypt(nonce, Payload { msg: &ciphertext, aad: &aad }) {
                Ok(plaintext) => {
                    // push buffer to appsrc
                    let mut buffer = gst::Buffer::with_size(plaintext.len()).unwrap();
                    {
                        let buffer_mut = buffer.get_mut().ok_or_else(|| anyhow!("failed to get mutable buffer"))?;
                        let mut map = buffer_mut.map_writable().map_err(|_| anyhow!("map_writable failed"))?;
                        map.as_mut_slice().copy_from_slice(&plaintext);
                    }
                    {
                        let buffer_mut = buffer.get_mut().ok_or_else(|| anyhow!("failed to get mutable buffer"))?;
                        buffer_mut.set_pts(Some(gst::ClockTime::from_nseconds(ts_ns)));
                    }
                    if let Err(e) = appsrc.push_buffer(buffer) {
                        eprintln!("Push buffer error: {:?}", e);
                        break;
                    }

                    // compute latency and append to buffer for p50 agg
                    let sender_iso = chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH + Duration::from_nanos(ts_ns)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                    if let Ok(_) = metrics.log_latency(&sender_iso, recv_instant, ctr, plaintext.len(), true).await {
                        // store numeric latency for window-level p50
                        if let Ok(sender_dt_fixed) = chrono::DateTime::parse_from_rfc3339(&sender_iso) {
                            let sender_dt_utc = sender_dt_fixed.with_timezone(&chrono::Utc);
                            let recv_dt = chrono::DateTime::<chrono::Utc>::from(recv_instant);
                            if let Ok(lat_dur) = (recv_dt - sender_dt_utc).to_std() {
                                lat_buffer.push(lat_dur.as_secs_f64() * 1000.0); // ms
                            }
                        }
                    }

                    bytes_received_window += ciphertext.len() as u64;
                    if window_start.elapsed() >= window_dur {
                        let dur = window_start.elapsed();
                        let fps = if !lat_buffer.is_empty() { lat_buffer.len() as f32 / dur.as_secs_f32() } else { 0.0_f32 };
                        let latency_p50 = if lat_buffer.is_empty() { 0.0 } else {
                            lat_buffer.sort_by(|a,b| a.partial_cmp(b).unwrap());
                            let mid = lat_buffer.len()/2;
                            lat_buffer[mid]
                        };
                        // snapshot sys
                        let mut sys = System::new();
                        sys.refresh_cpu();
                        sys.refresh_memory();
                        let cpu_pct = sys.global_cpu_info().cpu_usage();
                        let mem_mb = sys.used_memory() / 1024;
                        let temp_c = read_temp_c();

                        metrics.log_steady_stream(fps, 0.0, latency_p50, cpu_pct, mem_mb, temp_c, 0, 0).await.ok();

                        // clear buffer and window
                        lat_buffer.clear();
                        bytes_received_window = 0;
                        window_start = Instant::now();
                    }
                }
                Err(_) => {
                    eprintln!("Decryption failed for frame at {}", ts_ns);
                    metrics.log_loss("gcm_tag_failure", 1, "decrypt_failed").await.ok();
                }
            }

            ctr = ctr.wrapping_add(1);
        }
    }

    pipeline.set_state(gst::State::Null)?;
    Ok(())
}

// helpers

async fn read_envelope_payload(sock: &mut tokio::net::TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await?;
    let env_len = u32::from_be_bytes(len_buf) as usize;
    let mut env = vec![0u8; env_len];
    sock.read_exact(&mut env).await?;
    Ok(env)
}

async fn send_pub_envelope(sock: &mut tokio::net::TcpStream, pub_bytes: &[u8]) -> Result<()> {
    let payload_len = 1 + pub_bytes.len();
    let mut env = Vec::with_capacity(4 + payload_len);
    env.extend_from_slice(&(payload_len as u32).to_be_bytes());
    env.push(F_ECDH_PUB);
    env.extend_from_slice(pub_bytes);
    sock.write_all(&env).await?;
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
