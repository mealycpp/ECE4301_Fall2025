use anyhow::{anyhow, Result};
use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit, Payload}, Nonce};
use clap::Parser;
use rand::rngs::OsRng;
use rsa::{pkcs8::EncodePublicKey, RsaPrivateKey, Oaep};
use sha2::Sha256;
use std::time::{Instant, Duration, SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::{
    net::TcpStream,
    io::{AsyncReadExt, AsyncWriteExt},
};
use sysinfo::{System, SystemExt, CpuExt};

use gstreamer as gst;
use gstreamer_app as gst_app;
use gst::prelude::*;

mod metrics;
use metrics::{MetricsLogger, log_arm_crypto_support};

#[derive(Parser, Debug)]
#[command(author, version, about = "Member receiver (verbose) with display")]
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

const F_RSA_PUB: u8 = 0x30;
const F_WRAP_KEY: u8 = 0x31;
const F_ACK: u8 = 0x11;
const F_FRAME: u8 = 0x01;

fn hex_prefix(b: &[u8]) -> String {
    b.iter().take(32).map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(" ")
}

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

    let metrics = MetricsLogger::new(&args.metrics_dir).await?;
    let _sys_handle = metrics.spawn_periodic_sys_sampler(Duration::from_secs(5));
    metrics.log_runtime_features("member").await.ok();

    // Initialize GStreamer
    gst::init()?;

    // Use parse_launch to create pipeline: appsrc (image/jpeg) -> jpegdec -> videoconvert -> autovideosink
    let pipeline_description = "appsrc name=src format=time is-live=true do-timestamp=true caps=\"image/jpeg,framerate=30/1\" ! jpegdec ! videoconvert ! autovideosink";
    let pipeline = gst::parse_launch(pipeline_description)?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow!("failed to downcast pipeline"))?;
    // Retrieve appsrc by name and cast to AppSrc
    let src_element = pipeline.by_name("src").ok_or_else(|| anyhow!("failed to find appsrc by name"))?;
    let appsrc = src_element
        .dynamic_cast::<gst_app::AppSrc>()
        .map_err(|_| anyhow!("appsrc cast failed"))?;
    // Start pipeline
    pipeline.set_state(gst::State::Playing)?;

    let addr = format!("{}:{}", args.leader_ip, args.port);
    println!("Connecting to leader at {}", addr);
    let mut sock = TcpStream::connect(&addr).await?;
    sock.set_nodelay(true)?;
    println!("Connected to leader.");

    // Handshake instrumentation
    let hs_start_time = SystemTime::now();
    let hs_start_instant = Instant::now();
    let mut bytes_exchanged: u64 = 0;
    let mut bytes_tx_handshake: u64 = 0;
    let mut bytes_rx_handshake: u64 = 0;

    // Generate fresh RSA keypair (3072)
    let bits = 3072;
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| anyhow!("RSA keygen failed: {:?}", e))?;
    let public_key = private_key.to_public_key();

    // Send public key DER envelope
    let pub_der = public_key.to_public_key_der().map_err(|e| anyhow!("pub export fail: {:?}", e))?;
    let pub_bytes = pub_der.as_ref();
    let mut pub_env = Vec::with_capacity(4 + 1 + pub_bytes.len());
    let payload_len = 1 + pub_bytes.len();
    pub_env.extend_from_slice(&(payload_len as u32).to_be_bytes());
    pub_env.push(F_RSA_PUB);
    pub_env.extend_from_slice(pub_bytes);
    sock.write_all(&pub_env).await?;
    bytes_exchanged += (4 + payload_len) as u64;
    bytes_tx_handshake += (4 + payload_len) as u64;

    // Receive wrapped AES key envelope
    let wrap_env = read_envelope_payload(&mut sock).await?;
    bytes_exchanged += (4 + wrap_env.len()) as u64;
    bytes_rx_handshake += (4 + wrap_env.len()) as u64;
    if wrap_env.is_empty() || wrap_env[0] != F_WRAP_KEY {
        return Err(anyhow!("expected wrapped key envelope"));
    }
    let wrapped = &wrap_env[1..];

    // Unwrap with RSA-OAEP-SHA256 using Oaep helper
    let decrypted = private_key.decrypt(Oaep::new::<Sha256>(), wrapped)
        .map_err(|e| anyhow!("rsa decrypt failed: {:?}", e))?;
    if decrypted.len() < 16 + 8 {
        return Err(anyhow!("wrapped blob too small"));
    }
    let aes_key = &decrypted[..16];
    let mut nonce_base = [0u8; 8];
    nonce_base.copy_from_slice(&decrypted[16..24]);

    // AES-GCM cipher
    let cipher = Aes128Gcm::new_from_slice(aes_key)?;

    // Send ACK encrypted as before
    let mut ack_plain = Vec::new();
    let ts_millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    ack_plain.extend_from_slice(&ts_millis.to_be_bytes());
    ack_plain.extend_from_slice(b"OK");
    let mut ack_nonce12 = [0u8; 12];
    ack_nonce12[..8].copy_from_slice(&nonce_base);
    ack_nonce12[8..12].copy_from_slice(&0u32.to_be_bytes());
    let ack_nonce = Nonce::from_slice(&ack_nonce12);
    let tmp = cipher.encrypt(ack_nonce, Payload { msg: &ack_plain, aad: &[] })
        .map_err(|e| anyhow!("ack encrypt tmp failed: {:?}", e))?;
    let ack_len = tmp.len();
    let mut ack_aad = [0u8; 12];
    ack_aad[8..12].copy_from_slice(&(ack_len as u32).to_be_bytes());
    let ack_cipher = cipher.encrypt(ack_nonce, Payload { msg: &ack_plain, aad: &ack_aad })
        .map_err(|e| anyhow!("ack encrypt failed: {:?}", e))?;
    let mut ack_env = Vec::with_capacity(4 + 1 + 4 + ack_cipher.len());
    let payload_len = 1 + 4 + ack_cipher.len();
    ack_env.extend_from_slice(&(payload_len as u32).to_be_bytes());
    ack_env.push(F_ACK);
    ack_env.extend_from_slice(&(ack_cipher.len() as u32).to_be_bytes());
    ack_env.extend_from_slice(&ack_cipher);
    sock.write_all(&ack_env).await?;
    bytes_exchanged += (4 + payload_len) as u64;
    bytes_tx_handshake += (4 + payload_len) as u64;

    // Receiver state
    let ks_cipher = cipher;
    let ks_nonce_base = nonce_base;
    let ks_counter = Arc::new(AtomicU32::new(0));

    let hs_end_time = SystemTime::now();
    let hs_duration = hs_start_instant.elapsed();

    // handshake metrics snapshot (best-effort)
    let mut sys = System::new();
    sys.refresh_cpu();
    let cpu_avg = sys.global_cpu_info().cpu_usage();
    let mem_mb = sys.used_memory() / 1024;
    metrics.log_handshake("member", hs_duration, bytes_exchanged, true, "").await.ok();
    metrics.log_handshake_ecdh(hs_start_time, hs_end_time, "RSA-OAEP-256+AES-GCM", bytes_tx_handshake, bytes_rx_handshake, cpu_avg, mem_mb, 0.0).await.ok();

    println!("Handshake complete (display); entering receive loop.");

    // Counter for saved frames (optional)
    let mut saved_frame_idx: u64 = 0;

    loop {
        let env = match read_envelope_payload(&mut sock).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("socket read error or connection closed: {:?}", e);
                break;
            }
        };
        if env.is_empty() {
            continue;
        }

        let flag = env[0];
        eprintln!("recv envelope: flag=0x{:02x} len={}", flag, env.len());

        match flag {
            F_FRAME => {
                if env.len() < 1 + 8 {
                    eprintln!("malformed frame envelope");
                    continue;
                }
                let ts_ns = u64::from_be_bytes(env[1..9].try_into().unwrap());
                let ciphertext = &env[9..];
                let ct_len = ciphertext.len();
                eprintln!("frame: ts_ns={} ct_len={}", ts_ns, ct_len);

                // counter at receiver
                let ctr = ks_counter.fetch_add(1, Ordering::SeqCst);
                eprintln!("using receiver ctr={}", ctr);

                // nonce
                let mut nonce12 = [0u8; 12];
                nonce12[..8].copy_from_slice(&ks_nonce_base);
                nonce12[8..12].copy_from_slice(&ctr.to_be_bytes());
                eprintln!("nonce = {}", hex_prefix(&nonce12));

                // aad
                let mut aad = [0u8; 12];
                aad[..8].copy_from_slice(&ts_ns.to_be_bytes());
                aad[8..12].copy_from_slice(&ctr.to_be_bytes());
                eprintln!("aad  = {}", hex_prefix(&aad));

                // show first bytes of ciphertext (or all if small)
                eprintln!("ct[0..min32] = {}", hex_prefix(&ciphertext));

                match ks_cipher.decrypt(Nonce::from_slice(&nonce12), Payload { msg: ciphertext, aad: &aad }) {
                    Ok(plain) => {
                        eprintln!("decrypt OK: {} bytes plaintext", plain.len());

                        // Push plaintext (JPEG bytes) into GStreamer appsrc for display.
                        // Create a gst::Buffer from the JPEG data and push it.
                        let mut gst_buf = gst::Buffer::with_size(plain.len())
                            .map_err(|e| anyhow!("gst buffer alloc failed: {:?}", e))?;
                        {
                            let mut map = gst_buf.get_mut().ok_or_else(|| anyhow!("gst buffer empty"))?
                                .map_writable().map_err(|e| anyhow!("gst buffer map failed: {:?}", e))?;
                            map.copy_from_slice(&plain);
                        }
                        // NOTE: setting pts directly on gst::Buffer caused borrow errors on some gstreamer crate versions.
                        // It's optional for display; we skip setting pts here.

                        match appsrc.push_buffer(gst_buf) {
                            Ok(gst::FlowSuccess::Ok) => { /* pushed successfully */ }
                            Ok(other) => {
                                eprintln!("appsrc push returned: {:?}", other);
                            }
                            Err(err) => {
                                eprintln!("appsrc push error: {:?}", err);
                            }
                        }

                        // Optionally save a copy of the first few frames to disk for debugging
                        if saved_frame_idx < 3 {
                            let filename = format!("/tmp/recv-frame-{}.jpg", saved_frame_idx);
                            if let Err(e) = std::fs::write(&filename, &plain) {
                                eprintln!("failed to write debug frame {}: {:?}", filename, e);
                            } else {
                                eprintln!("wrote debug frame {}", filename);
                            }
                            saved_frame_idx += 1;
                        }
                    }
                    Err(e) => {
                        eprintln!("decrypt FAILED: {:?}", e);
                    }
                }
            }
            other => {
                eprintln!("unknown envelope flag 0x{:02x}", other);
            }
        }
    }

    // Shutdown pipeline
    let _ = pipeline.set_state(gst::State::Null);
    Ok(())
}

async fn read_envelope_payload(sock: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await?;
    let env_len = u32::from_be_bytes(len_buf) as usize;
    let mut env = vec![0u8; env_len];
    sock.read_exact(&mut env).await?;
    Ok(env)
}
