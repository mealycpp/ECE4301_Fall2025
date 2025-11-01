use anyhow::{anyhow, Result};
use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit, Payload}, Nonce};
use clap::Parser;
use rand::{rngs::OsRng, RngCore};
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey, PublicKey, Oaep};
use sha2::Sha256;
use std::{time::{Instant, Duration, SystemTime}, sync::{Arc, Mutex}};
use std::arch;
use tokio::{
    net::TcpListener,
    io::{AsyncWriteExt, AsyncReadExt},
};
use gstreamer as gst;
use gst::prelude::*;
use sysinfo::{System, SystemExt, CpuExt};
use std::sync::atomic::{AtomicU32, Ordering};

mod metrics;
use metrics::{MetricsLogger, log_arm_crypto_support};

/// Leader (sender) implementing RSA-OAEP (SHA-256) key-transport handshake.
/// After the handshake the leader uses AES-128-GCM for frame encryption.
/// This file focuses on the handshake and includes a test JPEG sender loop so you can
/// validate end-to-end without a physical camera.
#[derive(Parser, Debug)]
#[command(author, version, about = "Leader sender: RSA-OAEP key transport + AES-GCM MJPEG stream (with rekey & metrics)")]
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
    #[arg(long, default_value = "metrics/leader")]
    metrics_dir: String,
    #[arg(long, default_value_t = 4)]
    queue: usize,
}

const F_RSA_PUB: u8 = 0x30; // member -> leader: member public key envelope
const F_WRAP_KEY: u8 = 0x31; // leader -> member: wrapped AES key envelope
const F_ACK: u8 = 0x11;
const F_FRAME: u8 = 0x01;

struct KeyState {
    cipher: Aes128Gcm,
    nonce_base: [u8; 8],
    // counter used to derive the 4-byte suffix of the 12-byte nonce
    counter: AtomicU32,
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

    log_arm_crypto_support();

    let metrics = MetricsLogger::new(&args.metrics_dir).await?;
    let _sys_handle = metrics.spawn_periodic_sys_sampler(Duration::from_secs(5));
    metrics.log_runtime_features("leader").await.ok();

    let bind_addr = format!("{}:{}", args.host, args.port);
    println!("Binding TCP listener at {}", bind_addr);

    let listener = TcpListener::bind(&bind_addr).await?;
    println!("Waiting for member...");
    let (mut sock, peer_addr) = listener.accept().await?;
    sock.set_nodelay(true)?;
    println!("Member connected from {}", peer_addr);

    // Handshake instrumentation - RSA key transport
    let hs_start = SystemTime::now();
    let hs_start_instant = Instant::now();
    let mut bytes_exchanged: u64 = 0;
    let mut bytes_tx_handshake: u64 = 0;
    let mut bytes_rx_handshake: u64 = 0;

    // 1) Read member RSA public key envelope (PKCS#8 DER expected)
    let member_pub_env = read_envelope_payload(&mut sock).await?;
    bytes_exchanged += (4 + member_pub_env.len()) as u64;
    bytes_rx_handshake += (4 + member_pub_env.len()) as u64;
    if member_pub_env.is_empty() || member_pub_env[0] != F_RSA_PUB {
        return Err(anyhow!("expected RSA pub envelope"));
    }
    let member_pub_der = &member_pub_env[1..];
    let member_pub = RsaPublicKey::from_public_key_der(member_pub_der)
        .map_err(|e| anyhow!("invalid member RSA public key: {:?}", e))?;

    // 2) Leader generates fresh AES key + nonce_base + salt
    let mut aes_key = [0u8; 16];
    OsRng.fill_bytes(&mut aes_key);
    let mut nonce_base = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_base);
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Build plaintext blob: AES key || nonce_base || salt (salt optional, kept for parity with member)
    let mut wrapped_plain = Vec::with_capacity(16 + 8 + 16);
    wrapped_plain.extend_from_slice(&aes_key);
    wrapped_plain.extend_from_slice(&nonce_base);
    wrapped_plain.extend_from_slice(&salt);

    // 3) Wrap with RSA-OAEP(SHA-256)
    // Use Oaep helper; member.rs expects OAEP-SHA256.
    let wrapped = member_pub
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &wrapped_plain)
        .map_err(|e| anyhow!("rsa encrypt error: {:?}", e))?;

    // send wrapped blob in envelope: [u32 len][flag][wrapped bytes...]
    let mut wrap_env = Vec::with_capacity(4 + 1 + wrapped.len());
    let payload_len = 1 + wrapped.len();
    wrap_env.extend_from_slice(&(payload_len as u32).to_be_bytes());
    wrap_env.push(F_WRAP_KEY);
    wrap_env.extend_from_slice(&wrapped);
    if let Err(e) = sock.write_all(&wrap_env).await {
        eprintln!("failed to send wrapped key envelope: {:?}", e);
        return Err(anyhow!("send failed: {:?}", e));
    }
    bytes_exchanged += (4 + payload_len) as u64;
    bytes_tx_handshake += (4 + payload_len) as u64;

    // instantiate AES-GCM cipher from aes_key for ACK decryption and subsequent streaming
    let cipher = Aes128Gcm::new_from_slice(&aes_key)?;
    let ks = Arc::new(Mutex::new(KeyState {
        cipher,
        nonce_base,
        counter: AtomicU32::new(0),
    }));

    // 4) Wait for ACK encrypted with the transported AES key (counter = 0)
    wait_for_ack_and_validate_with_cipher(&mut sock, &ks).await?;

    let hs_end = SystemTime::now();
    let hs_duration = hs_start_instant.elapsed();

    // snapshot cpu/mem and log handshake metrics
    let mut sys = System::new();
    sys.refresh_cpu();
    sys.refresh_memory();
    let cpu_avg = sys.global_cpu_info().cpu_usage();
    let mem_mb = sys.used_memory() / 1024;

    metrics.log_handshake("leader", hs_duration, bytes_exchanged, true, "").await.ok();
    metrics.log_handshake_ecdh(hs_start, hs_end, "RSA-OAEP-256+AES-GCM", bytes_tx_handshake, bytes_rx_handshake, cpu_avg, mem_mb, 0.0).await.ok();

    println!("Handshake complete; entering streaming loop.");

    // ----------------------------
    // Test JPEG sender loop
    //
    // This will exercise the end-to-end path without a camera. If you want the real webcam,
    // I'll provide a GStreamer appsink-based implementation next.
    // Requires `image = "0.24"` in Cargo.toml.
    // ----------------------------
    {
        use image::{RgbImage, ImageOutputFormat};
        let mut test_frame_counter: u32 = 0;
        loop {
            // generate a small test JPEG in-memory
            let mut img = RgbImage::new(320, 240);
            test_frame_counter = test_frame_counter.wrapping_add(1);
            let r = ((test_frame_counter >> 0) & 0xff) as u8;
            let g = ((test_frame_counter >> 8) & 0xff) as u8;
            let b = ((test_frame_counter >> 16) & 0xff) as u8;
            for p in img.pixels_mut() {
                *p = image::Rgb([r, g, b]);
            }
            let mut jpeg_buf = Vec::new();
            img.write_to(&mut std::io::Cursor::new(&mut jpeg_buf), ImageOutputFormat::Jpeg(70)).unwrap();

            // Build per-frame nonce: nonce_base (8) || counter (4)
            let ctr = ks.lock().unwrap().counter.fetch_add(1, Ordering::SeqCst);
            let nonce_base_copy = {
                let guard = ks.lock().unwrap();
                guard.nonce_base
            };
            let mut nonce12 = [0u8; 12];
            nonce12[..8].copy_from_slice(&nonce_base_copy);
            nonce12[8..12].copy_from_slice(&ctr.to_be_bytes());
            let nonce = Nonce::from_slice(&nonce12);

            // AAD: 12 bytes (first 8 = sender timestamp ns, last 4 = counter)
            let ts_ns = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64;
            let mut aad = [0u8; 12];
            aad[..8].copy_from_slice(&ts_ns.to_be_bytes());
            aad[8..12].copy_from_slice(&ctr.to_be_bytes());

            // Clone cipher while holding lock, then encrypt with the clone
            let cipher_clone = {
                let guard = ks.lock().unwrap();
                guard.cipher.clone()
            };
            let ciphertext = cipher_clone.encrypt(nonce, Payload { msg: &jpeg_buf, aad: &aad })
                .map_err(|e| anyhow!("frame encrypt failed: {:?}", e))?;

            // Build frame envelope: [u32 len][flag=F_FRAME][8 bytes ts_ns][ciphertext]
            let mut env = Vec::with_capacity(4 + 1 + 8 + ciphertext.len());
            let payload_len = 1 + 8 + ciphertext.len();
            env.extend_from_slice(&(payload_len as u32).to_be_bytes());
            env.push(F_FRAME);
            env.extend_from_slice(&ts_ns.to_be_bytes());
            env.extend_from_slice(&ciphertext);

            if let Err(e) = sock.write_all(&env).await {
                eprintln!("failed to send frame envelope (peer may have closed connection): {:?}", e);
                break;
            }
            eprintln!("sent test frame #{}, jpeg={} ct={}", test_frame_counter, jpeg_buf.len(), ciphertext.len());

            // ~5 FPS for reliable testing
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    Ok(())
}

/// Read envelope payload prefixed by 4-byte big-endian length.
async fn read_envelope_payload(sock: &mut tokio::net::TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await?;
    let env_len = u32::from_be_bytes(len_buf) as usize;
    let mut env = vec![0u8; env_len];
    sock.read_exact(&mut env).await?;
    Ok(env)
}

/// Wait for ACK envelope and decrypt it using ks.cipher with counter=0
async fn wait_for_ack_and_validate_with_cipher(sock: &mut tokio::net::TcpStream, ks: &Arc<Mutex<KeyState>>) -> Result<()> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await?;
    let ack_msg_len = u32::from_be_bytes(len_buf) as usize;
    let mut ack_msg = vec![0u8; ack_msg_len];
    sock.read_exact(&mut ack_msg).await?;
    if ack_msg[0] != F_ACK { return Err(anyhow!("expected ACK")); }
    if ack_msg.len() < 1 + 4 { return Err(anyhow!("malformed ACK payload")); }
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
