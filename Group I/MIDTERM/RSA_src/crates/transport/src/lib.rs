use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use keying::{generate_rsa_keypair, export_rsa_public_key, import_rsa_public_key};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::convert::TryFrom;
use tokio::time::{Duration, Instant};
use aead::AesGcmCtx;
use tokio::sync::mpsc;
use std::sync::Arc;
use metrics::Metrics;

const SALT: &[u8] = b"salt:ECE4301-midterm-2025";
const KDF_INFO_C2S: &[u8] = b"ctx:k_c2s";
const KDF_INFO_S2C: &[u8] = b"ctx:k_s2c";
const REKEY_SEQ: u32 = u32::MAX;               // reserved sequence for control frame
const REKEY_PT_LEN: usize = 16 + 8 + 8;

#[inline] fn aad(seq: u32) -> [u8; 4] { seq.to_be_bytes() }
//cutoffstart
// Updated signatures: accept optional metrics Arc to allow logging from transport.
pub async fn run_sender_from_channel(
    host: &str,
    rekey_every: Option<Duration>,
    mut frame_rx: mpsc::Receiver<Vec<u8>>,
    metrics: Option<Arc<Metrics>>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use rand::RngCore;
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut sock = tokio::net::TcpStream::connect(host).await.context("connect")?;
    eprintln!("[send] connected to {host}");

    let handshake_start = Instant::now();
    let (mut tx, _rx_unused, shared32) = handshake_client(&mut sock).await.context("handshake_client")?;
    let handshake_duration = handshake_start.elapsed().as_secs_f64();
    eprintln!("[send] handshake OK");
    // Log handshake if metrics provided
    if let Some(m) = metrics.as_ref() {
        let _ = m.log_handshake("rsa-oaep", handshake_duration, 2048, false);
    }
    let mut next_rekey_at = rekey_every.map(|d| Instant::now() + d);
    let mut seq: u32 = 0;
    
    // Frame timing tracking for FPS calculation
    let mut last_frame_time = Instant::now();
    let mut frame_count = 0u64;
    let mut fps_window_start = Instant::now();
    let mut fps_window_frames = 0u64;

    loop {
        // handle timer first (if set), else wait for a frame
        if let Some(when) = next_rekey_at {
            tokio::select! {
                _ = tokio::time::sleep_until(when) => {
                    // send rekey control frame (salt + bases)
                    let mut salt = [0u8;16]; let mut c2s=[0u8;8]; let mut s2c=[0u8;8];
                    rand::rngs::OsRng.fill_bytes(&mut salt);
                    rand::rngs::OsRng.fill_bytes(&mut c2s);
                    rand::rngs::OsRng.fill_bytes(&mut s2c);
                    let mut pt=[0u8;REKEY_PT_LEN]; pt[0..16].copy_from_slice(&salt); pt[16..24].copy_from_slice(&c2s); pt[24..32].copy_from_slice(&s2c);
                    let ct = tx.encrypt(REKEY_SEQ, &pt, &aad(REKEY_SEQ))?;
                    let mut hdr=[0u8;12]; hdr[..8].copy_from_slice(&(REKEY_SEQ as u64).to_be_bytes()); hdr[8..12].copy_from_slice(&(u32::try_from(ct.len()).unwrap()).to_be_bytes());
                    sock.write_all(&hdr).await?; sock.write_all(&ct).await?;
                    // rotate local sender key/base
                    let (k_c2s,_)=hkdf_pair_from_shared(&shared32,&salt); tx = aead::AesGcmCtx::new(k_c2s,c2s);
                    seq=0; eprintln!("[send] rekey sent+applied");
                    // Log rekey as handshake event
                    if let Some(m) = metrics.as_ref() {
                        let _ = m.log_handshake("rekey", 0.001, REKEY_PT_LEN, false);
                    }
                    next_rekey_at = rekey_every.map(|d| Instant::now() + d);
                }
                maybe = frame_rx.recv() => {
                    let frame = match maybe { Some(f) => f, None => break };
                    let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
                    let mut pt = Vec::with_capacity(8 + frame.len());
                    pt.extend_from_slice(&now_ns.to_be_bytes()); // 8B ts
                    pt.extend_from_slice(&frame);
                    let ct = tx.encrypt(seq, &pt, &aad(seq))?;
                    let mut hdr=[0u8;12]; hdr[..8].copy_from_slice(&(seq as u64).to_be_bytes()); hdr[8..12].copy_from_slice(&(u32::try_from(ct.len()).unwrap()).to_be_bytes());
                    sock.write_all(&hdr).await?; sock.write_all(&ct).await?;
                    seq = seq.wrapping_add(1);
                    // Optionally log throughput per frame (best-effort)
                    if let Some(m) = metrics.as_ref() {
                        let now = Instant::now();
                        let interval_s = now.duration_since(last_frame_time).as_secs_f64();
                        
                        // Update FPS window tracking
                        fps_window_frames += 1;
                        let window_duration = now.duration_since(fps_window_start).as_secs_f64();
                        
                        // Calculate FPS over a 1-second rolling window
                        let fps = if window_duration >= 1.0 {
                            let calculated_fps = fps_window_frames as f64 / window_duration;
                            // Reset window
                            fps_window_start = now;
                            fps_window_frames = 0;
                            calculated_fps
                        } else {
                            // For early frames, estimate based on current rate but cap at reasonable value
                            let estimated_fps = if window_duration > 0.0 { 
                                (fps_window_frames as f64 / window_duration).min(60.0) 
                            } else { 
                                30.0 
                            };
                            estimated_fps
                        };
                        
                        let mbps = (ct.len() as f64) * 8.0 / 1_000_000.0;
                        let _ = m.log_throughput(mbps, fps, ct.len(), interval_s);
                        last_frame_time = now;
                        frame_count += 1;
                    }
                }
            }
        } else {
            // no rekey timer — just send frames
            let Some(frame) = frame_rx.recv().await else { break };
            let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
            let mut pt = Vec::with_capacity(8 + frame.len());
            pt.extend_from_slice(&now_ns.to_be_bytes());
            pt.extend_from_slice(&frame);
            let ct = tx.encrypt(seq, &pt, &aad(seq))?;
            let mut hdr=[0u8;12]; hdr[..8].copy_from_slice(&(seq as u64).to_be_bytes()); hdr[8..12].copy_from_slice(&(u32::try_from(ct.len()).unwrap()).to_be_bytes());
            sock.write_all(&hdr).await?; sock.write_all(&ct).await?;
            seq = seq.wrapping_add(1);
            if let Some(m) = metrics.as_ref() {
                let now = Instant::now();
                let interval_s = now.duration_since(last_frame_time).as_secs_f64();
                
                // Update FPS window tracking
                fps_window_frames += 1;
                let window_duration = now.duration_since(fps_window_start).as_secs_f64();
                
                // Calculate FPS over a 1-second rolling window
                let fps = if window_duration >= 1.0 {
                    let calculated_fps = fps_window_frames as f64 / window_duration;
                    // Reset window
                    fps_window_start = now;
                    fps_window_frames = 0;
                    calculated_fps
                } else {
                    // For early frames, estimate based on current rate but cap at reasonable value
                    let estimated_fps = if window_duration > 0.0 { 
                        (fps_window_frames as f64 / window_duration).min(60.0) 
                    } else { 
                        30.0 
                    };
                    estimated_fps
                };
                
                let mbps = (ct.len() as f64) * 8.0 / 1_000_000.0;
                let _ = m.log_throughput(mbps, fps, ct.len(), interval_s);
                last_frame_time = now;
                frame_count += 1;
            }
        }
    }
    eprintln!("[send] video channel closed; done");
    Ok(())
}

/// RECV: decrypt frames and forward the H.264 AU bytes to a channel.
pub async fn run_receiver_to_channel(
    bind: &str,
    frame_tx: mpsc::Sender<Vec<u8>>,
    metrics: Option<Arc<Metrics>>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let listener = tokio::net::TcpListener::bind(bind).await.context("bind")?;
    eprintln!("[recv] listening on {bind}");
    let (mut sock, peer) = listener.accept().await.context("accept")?;
    eprintln!("[recv] connection from {peer}");

    let handshake_start = Instant::now();
    let (_tx_unused, mut rx, shared32) = handshake_server(&mut sock).await.context("handshake_server")?;
    let handshake_duration = handshake_start.elapsed().as_secs_f64();
    eprintln!("[recv] handshake OK");
    // Log handshake if metrics present
    if let Some(m) = metrics.as_ref() {
        let _ = m.log_handshake("rsa-oaep", handshake_duration, 2048, false);
    }

    loop {
        let mut hdr=[0u8;12];
        if let Err(e)=sock.read_exact(&mut hdr).await { eprintln!("[recv] closed: {e}"); break; }
        let seq = u64::from_be_bytes(hdr[..8].try_into().unwrap()) as u32;
        let ct_len = u32::from_be_bytes(hdr[8..12].try_into().unwrap()) as usize;
        let mut ct = vec![0u8; ct_len];
        sock.read_exact(&mut ct).await?;
        let pt = match rx.decrypt(seq, &ct, &aad(seq)) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[recv] decrypt failed: {e}");
                if let Some(m) = metrics.as_ref() {
                    let _ = m.log_loss_errors(0, 0, 0, 1);
                }
                continue;
            }
        };

        if seq == REKEY_SEQ {
            if pt.len()!=REKEY_PT_LEN { anyhow::bail!("bad rekey payload length"); }
            let mut salt=[0u8;16]; salt.copy_from_slice(&pt[0..16]);
            let mut c2s=[0u8;8];   c2s.copy_from_slice(&pt[16..24]);
            let (k_c2s,_)=hkdf_pair_from_shared(&shared32,&salt);
            rx = aead::AesGcmCtx::new(k_c2s, c2s);
            eprintln!("[recv] rekey applied");
            // Log rekey as handshake event
            if let Some(m) = metrics.as_ref() {
                let _ = m.log_handshake("rekey", 0.001, REKEY_PT_LEN, false);
            }
            continue;
        }

        // normal data frame: strip 8B timestamp and forward H.264 AU
        // Log latency if the sender timestamp is present (first 8 bytes are ns)
        if pt.len() >= 8 {
            use std::time::{SystemTime, UNIX_EPOCH};
            let sender_ns = u64::from_be_bytes(pt[0..8].try_into().unwrap());
            let recv_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
            let sender_s = (sender_ns as f64) / 1e9;
            let recv_s = (recv_ns as f64) / 1e9;
            if let Some(m) = metrics.as_ref() {
                let _ = m.log_latency_frame(seq as u64, sender_s, recv_s);
            }
        }
        let h264 = if pt.len()>=8 { pt[8..].to_vec() } else { Vec::new() };
        if frame_tx.send(h264).await.is_err() { break; }
    }
    Ok(())
}
//cutoffend

fn hkdf_pair_from_shared(shared32: &[u8; 32], salt16: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
   let hk = Hkdf::<Sha256>::new(Some(salt16), shared32);
   let mut k_c2s = [0u8; 16];
   let mut k_s2c = [0u8; 16];
   hk.expand(b"ctx:k_c2s", &mut k_c2s).expect("HKDF expand c2s (rekey)");
   hk.expand(b"ctx:k_s2c", &mut k_s2c).expect("HKDF expand s2c (rekey)");
   (k_c2s, k_s2c)
}


fn hkdf_keys(shared: &[u8]) -> ([u8; 16], [u8; 16]) {
   let hk = Hkdf::<Sha256>::new(Some(SALT), shared);
   let mut k_c2s = [0u8; 16];
   let mut k_s2c = [0u8; 16];
   hk.expand(KDF_INFO_C2S, &mut k_c2s).expect("HKDF expand c2s");
   hk.expand(KDF_INFO_S2C, &mut k_s2c).expect("HKDF expand s2c");
   (k_c2s, k_s2c)
}


async fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
   stream.read_exact(buf).await.context("read_exact")?;
   Ok(())
}
async fn write_all(stream: &mut TcpStream, buf: &[u8]) -> Result<()> {
   stream.write_all(buf).await.context("write_all")?;
   Ok(())
}


async fn handshake_client(stream: &mut TcpStream) -> Result<(AesGcmCtx, AesGcmCtx, [u8; 32])> {
    // RSA-based handshake (client role)
    // 1) Read server RSA public key (u16 len + DER bytes)
    let mut lbuf = [0u8; 2];
    read_exact(stream, &mut lbuf).await?;
    let server_len = u16::from_be_bytes(lbuf) as usize;
    let mut server_pub_der = vec![0u8; server_len];
    read_exact(stream, &mut server_pub_der).await?;

    // import server RSA public key
    let server_pk = import_rsa_public_key(&server_pub_der);

    // Generate shared secret (32B) and encrypt it under server RSA pub
    let mut shared32 = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut shared32);
    let mut rng = rand::rngs::OsRng;
    let ct = server_pk.encrypt(&mut rng, Oaep::new::<sha2::Sha256>(), &shared32)
         .map_err(|e| anyhow!("rsa encrypt failed: {e}"))?;

    // Send enc(shared) length (u16) + ciphertext, then send client_base (8 bytes)
    let ct_len_u16 = u16::try_from(ct.len()).expect("ct fits u16");
    write_all(stream, &ct_len_u16.to_be_bytes()).await?;
    write_all(stream, &ct).await?;

    let mut client_base = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut client_base);
    write_all(stream, &client_base).await?;

    // Read server base (8 bytes)
    let mut server_base = [0u8; 8];
    read_exact(stream, &mut server_base).await?;

    // Derive initial AEAD keys from shared32
    let (k_c2s, k_s2c) = hkdf_keys(&shared32);

    let tx = AesGcmCtx::new(k_c2s, client_base); // client -> server
    let rx = AesGcmCtx::new(k_s2c, server_base); // server -> client
    Ok((tx, rx, shared32))
}


async fn handshake_server(stream: &mut TcpStream) -> Result<(AesGcmCtx, AesGcmCtx, [u8; 32])> {
   // RSA-based handshake (server role)
   // 1) Generate server RSA keypair and send public key DER (u16 len + bytes)
   let sk = generate_rsa_keypair();
   let pk = RsaPublicKey::from(&sk);
   let pk_der = export_rsa_public_key(&pk);
   let len_u16 = u16::try_from(pk_der.len()).expect("pubkey len fits u16");
   write_all(stream, &len_u16.to_be_bytes()).await?;
   write_all(stream, &pk_der).await?;

   // 2) Read client's encrypted shared (u16 len + ct) and client_base (8 bytes)
   let mut lbuf = [0u8; 2];
   read_exact(stream, &mut lbuf).await?;
   let ct_len = u16::from_be_bytes(lbuf) as usize;
   let mut ct = vec![0u8; ct_len];
   read_exact(stream, &mut ct).await?;

   let mut client_base = [0u8; 8];
   read_exact(stream, &mut client_base).await?;

   // Decrypt shared secret
   let shared_bytes = sk.decrypt(Oaep::new::<sha2::Sha256>(), &ct)
       .map_err(|e| anyhow!("rsa decrypt failed: {e}"))?;
   if shared_bytes.len() != 32 {
       return Err(anyhow!("bad shared secret length"));
   }
   let mut shared32 = [0u8; 32];
   shared32.copy_from_slice(&shared_bytes[..32]);

   let (k_c2s, k_s2c) = hkdf_keys(&shared32);

   // Generate and send server_base
   let mut server_base = [0u8; 8];
   rand::rngs::OsRng.fill_bytes(&mut server_base);
   write_all(stream, &server_base).await?;

   let tx = AesGcmCtx::new(k_s2c, server_base); // server -> client
   let rx = AesGcmCtx::new(k_c2s, client_base); // client -> server
   Ok((tx, rx, shared32))
}




/// Receiver: bind, accept 1 client, decrypt frames, print counters.
/// Receiver: bind, accept 1 client, decrypt frames, print counters, handle rekeys.
pub async fn run_receiver(bind: &str, metrics: Option<Arc<Metrics>>) -> Result<()> {
   let listener = TcpListener::bind(bind).await.context("bind")?;
   eprintln!("[recv] listening on {bind}");
   let (mut sock, peer) = listener.accept().await.context("accept")?;
   eprintln!("[recv] connection from {peer}");

   let handshake_start = Instant::now();
   let (_tx_unused, mut rx, shared32) = handshake_server(&mut sock).await.context("handshake_server")?;
   let handshake_duration = handshake_start.elapsed().as_secs_f64();
   eprintln!("[recv] handshake OK");
   // Log handshake if metrics present
   if let Some(m) = metrics.as_ref() {
       let _ = m.log_handshake("rsa-oaep", handshake_duration, 2048, false);
   }


   let mut frames = 0u64;
   loop {
       let mut hdr = [0u8; 12];
       if let Err(e) = sock.read_exact(&mut hdr).await {
           eprintln!("[recv] closed: {e}");
           break;
       }
       let seq = u64::from_be_bytes(hdr[..8].try_into().unwrap()) as u32; // low 32 used for nonce ctr
       let ct_len = u32::from_be_bytes(hdr[8..12].try_into().unwrap()) as usize;
       let mut ct = vec![0u8; ct_len];
       read_exact(&mut sock, &mut ct).await?;


       let aad = seq.to_be_bytes();
       let pt = match rx.decrypt(seq, &ct, &aad) {
           Ok(p) => p,
           Err(e) => {
               eprintln!("[recv] decrypt failed: {e}");
               if let Some(m) = metrics.as_ref() {
                   let _ = m.log_loss_errors(0, 0, 0, 1);
               }
               continue;
           }
       };


       // Rekey control frame?
       if seq == REKEY_SEQ {
           if pt.len() != REKEY_PT_LEN {
               return Err(anyhow!("bad rekey payload length"));
           }
           let mut salt = [0u8; 16];    salt.copy_from_slice(&pt[0..16]);
           let mut c2s_base = [0u8; 8]; c2s_base.copy_from_slice(&pt[16..24]);
           let mut s2c_base = [0u8; 8]; s2c_base.copy_from_slice(&pt[24..32]);


           // Server role: new RX is k_c2s with c2s_base
           let (k_c2s, _k_s2c) = hkdf_pair_from_shared(&shared32, &salt);
           rx = AesGcmCtx::new(k_c2s, c2s_base);

           eprintln!("[recv] rekey applied");
           // Log rekey as handshake event
           if let Some(m) = metrics.as_ref() {
               let _ = m.log_handshake("rekey", 0.001, REKEY_PT_LEN, false);
           }
           continue;
       }


       // Normal data frame
       frames += 1;
       // Log latency if timestamp present
       if pt.len() >= 8 {
           use std::time::{SystemTime, UNIX_EPOCH};
           let sender_ns = u64::from_be_bytes(pt[0..8].try_into().unwrap());
           let recv_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
           let sender_s = (sender_ns as f64) / 1e9;
           let recv_s = (recv_ns as f64) / 1e9;
           if let Some(m) = metrics.as_ref() {
               let _ = m.log_latency_frame(seq as u64, sender_s, recv_s);
           }
       }
       if frames % 50 == 0 {
           eprintln!("[recv] ok: {frames} frames");
       }
   }
   Ok(())
}


/// Sender: connect, handshake, send N encrypted dummy frames.
/// Sender: connect, handshake, send N encrypted dummy frames; optional timed rekey.


pub async fn run_sender(host: &str, n_frames: u32, rekey_every: Option<Duration>, metrics: Option<Arc<Metrics>>) -> anyhow::Result<()> {
   eprintln!("[send] connecting to {host} (rekey_every={rekey_every:?})");
   let mut sock = tokio::net::TcpStream::connect(host).await.context("connect")?;
   eprintln!("[send] connected to {host}");


   // Handshake must return (tx, rx, shared32). We only use tx + shared32 here.
   let handshake_start = Instant::now();
   let (mut tx, _rx_unused, shared32) = handshake_client(&mut sock).await.context("handshake_client")?;
   let handshake_duration = handshake_start.elapsed().as_secs_f64();
   eprintln!("[send] handshake OK");
   // Log handshake if metrics present
   if let Some(m) = metrics.as_ref() {
       let _ = m.log_handshake("rsa-oaep", handshake_duration, 2048, false);
   }


   // Next scheduled rekey time (if any)
   let mut next_rekey_at = rekey_every.map(|d| Instant::now() + d);


   // Per-key sequence counter (used in the 12-byte nonce: base(8) || seq_be(4))
   let mut seq: u32 = 0;


   for i in 0..n_frames {
       // --- timed REKEY (control frame using reserved seq = u32::MAX) ---
       if let Some(when) = next_rekey_at {
           if Instant::now() >= when {
               // Fresh HKDF salt + fresh per-direction nonce bases
               let mut salt = [0u8; 16];
               let mut c2s_base = [0u8; 8];
               let mut s2c_base = [0u8; 8];
               rand::rngs::OsRng.fill_bytes(&mut salt);
               rand::rngs::OsRng.fill_bytes(&mut c2s_base);
               rand::rngs::OsRng.fill_bytes(&mut s2c_base);


               // Payload: salt || c2s_base || s2c_base
               let mut pt = [0u8; REKEY_PT_LEN];
               pt[0..16].copy_from_slice(&salt);
               pt[16..24].copy_from_slice(&c2s_base);
               pt[24..32].copy_from_slice(&s2c_base);


               // Encrypt under current key with reserved seq
               let seq_ctl = REKEY_SEQ;
               let aad = seq_ctl.to_be_bytes();
               let ct = tx.encrypt(seq_ctl, &pt, &aad)?;


               // Header: [u64 seq][u32 ct_len]
               let mut hdr = [0u8; 12];
               hdr[..8].copy_from_slice(&(seq_ctl as u64).to_be_bytes());
               let ct_len_u32 = u32::try_from(ct.len()).expect("ct too large");
               hdr[8..12].copy_from_slice(&ct_len_u32.to_be_bytes());
               sock.write_all(&hdr).await?;
               sock.write_all(&ct).await?;


               // Locally rotate sender keys (client role)
               let (k_c2s, _k_s2c) = hkdf_pair_from_shared(&shared32, &salt);
               tx = aead::AesGcmCtx::new(k_c2s, c2s_base);


               // Reset per-key counter and schedule next rekey
               seq = 0;
               eprintln!("[send] rekey sent+applied");
               // Log rekey as handshake event
               if let Some(m) = metrics.as_ref() {
                   let _ = m.log_handshake("rekey", 0.001, REKEY_PT_LEN, false);
               }
               next_rekey_at = rekey_every.map(|d| Instant::now() + d);
               continue; // don't count the control frame
           }
       }


       // --- normal DATA frame (dummy 1KiB payload for now) ---
       let mut pt = vec![0u8; 1024];
       rand::rngs::OsRng.fill_bytes(&mut pt);
       let aad = seq.to_be_bytes();
       let ct = tx.encrypt(seq, &pt, &aad)?;


       let mut hdr = [0u8; 12];
       hdr[..8].copy_from_slice(&(seq as u64).to_be_bytes());
       let ct_len_u32 = u32::try_from(ct.len()).expect("ct too large");
       hdr[8..12].copy_from_slice(&ct_len_u32.to_be_bytes());
       sock.write_all(&hdr).await?;
       sock.write_all(&ct).await?;


       if i % 50 == 0 {
           eprintln!("[send] sent seq={i}");
       }
       seq = seq.wrapping_add(1);


       // Safety: you can force a rekey if seq gets big
       if seq == u32::MAX / 2 {
           eprintln!("[send] WARNING: nonce counter high; consider forcing rekey soon");
       }
   }


   eprintln!("[send] done");
   Ok(())
}




