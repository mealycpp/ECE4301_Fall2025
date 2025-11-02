/// Multi-connection receiver: for each incoming connection, spawn a handler with a new channel.
pub async fn run_multi_receiver_to_channel<Handler>(
    bind: &str,
    metrics_opt: Option<metrics::Metrics>,
    handler: Handler,
) -> anyhow::Result<()>
where
    Handler: Fn(tokio::sync::mpsc::Receiver<Vec<u8>>, String) -> tokio::task::JoinHandle<()> + Send + Sync + 'static,
{
    use anyhow::Context;
    let listener = tokio::net::TcpListener::bind(bind).await.context("bind")?;
    eprintln!("[recv] listening on {bind} (multi)");

    let handler = std::sync::Arc::new(handler);

    loop {
        let (mut sock, peer) = listener.accept().await.context("accept")?;
        let peer_str = peer.to_string();
        eprintln!("[recv] connection from {peer_str}");

        let metrics_clone = metrics_opt.clone();
        let handler = handler.clone();

        // Create a new channel for this connection
        let (frame_tx, frame_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        // Spawn the playback handler for this connection
        let _playback_handle = (handler)(frame_rx, peer_str.clone());

        tokio::spawn(async move {
            let hs_start = std::time::Instant::now();
            let (mut _tx_unused, mut rx, shared32, client_pub_len, server_pub_len) = match handshake_server(&mut sock).await.context("handshake_server") {
                Ok(v) => v,
                Err(e) => {
                    if let Some(m) = &metrics_clone {
                        let _ = m.record_handshake("ECDH", hs_start.elapsed(), 0, 0, false, Some(format!("{e}")), Some(peer_str.clone()));
                    }
                    eprintln!("[recv:{peer_str}] handshake failed: {e}");
                    return;
                }
            };
            let hs_d = hs_start.elapsed();
            eprintln!("[recv:{peer_str}] handshake OK");
            if let Some(m) = &metrics_clone {
                let bytes_sent = (2 + server_pub_len + 8) as u64;
                let bytes_received = (2 + client_pub_len + 8) as u64;
                let _ = m.record_handshake("ECDH", hs_d, bytes_sent, bytes_received, true, None, Some(peer_str.clone()));
            }

            // spawn periodic system snapshot and latency summary if requested
            if let Some(m) = metrics_clone.clone() {
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        let _ = m.record_system_snapshot();
                        let _ = m.write_latency_summary();
                    }
                });
            }

            // throughput counters
            let mut throughput_bytes: u64 = 0;
            let mut throughput_frames: u64 = 0;
            let mut throughput_last = std::time::Instant::now();

            loop {
                let mut hdr=[0u8;12];
                if let Err(e)=sock.read_exact(&mut hdr).await { eprintln!("[recv:{peer_str}] closed: {e}"); break; }
                let seq = u64::from_be_bytes(hdr[..8].try_into().unwrap()) as u32;
                let ct_len = u32::from_be_bytes(hdr[8..12].try_into().unwrap()) as usize;
                let mut ct = vec![0u8; ct_len];
                if let Err(e) = sock.read_exact(&mut ct).await { eprintln!("[recv:{peer_str}] read error: {e}"); break; }
                // measure rekey handling time for rekey control frames (decrypt + hkdf + rotate)
                let handling_start = std::time::Instant::now();
                let pt = match rx.decrypt(seq, &ct, &aad(seq)) {
                    Ok(p) => { p }
                    Err(e) => {
                        eprintln!("[recv:{peer_str}] decrypt error: {e}");
                        if let Some(m) = &metrics_clone {
                            let _ = m.record_errors(0, 1, 0);
                        }
                        continue;
                    }
                };

                if seq == REKEY_SEQ {
                    if pt.len()!=REKEY_PT_LEN { eprintln!("[recv:{peer_str}] bad rekey payload length"); continue; }
                    // extract fields
                    let mut salt=[0u8;16]; salt.copy_from_slice(&pt[0..16]);
                    let mut c2s=[0u8;8];   c2s.copy_from_slice(&pt[16..24]);
                    let mut s2c=[0u8;8];   s2c.copy_from_slice(&pt[24..32]);

                    // Server role: new RX is k_c2s with c2s_base
                    let (k_c2s, _k_s2c) = hkdf_pair_from_shared(&shared32, &salt);
                    rx = AesGcmCtx::new(k_c2s, c2s);

                    // record total handling duration for REKEY
                    if let Some(m) = &metrics_clone {
                        let bytes_received = (12 + ct.len()) as u64; // header + ciphertext
                        let handling_d = handling_start.elapsed();
                        let _ = m.record_handshake("REKEY", handling_d, 0, bytes_received, true, None, Some(peer_str.clone()));
                    }
                    eprintln!("[recv:{peer_str}] rekey applied");
                    // fallthrough to continue processing normal frames if any
                }

                // normal data frame: compute latency from 8B timestamp, strip it and forward H.264 AU
                if pt.len() >= 8 {
                    let mut tsb = [0u8;8]; tsb.copy_from_slice(&pt[0..8]);
                    let sender_ns = u64::from_be_bytes(tsb);
                    let now_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
                    if now_ns >= sender_ns {
                        let latency_ms = (now_ns - sender_ns) as f64 / 1e6;
                        if let Some(m) = &metrics_clone {
                            let _ = m.record_frame_latency_ms(latency_ms);
                        }
                    }
                    // throughput accounting
                    throughput_frames += 1;
                    throughput_bytes += (ct.len() + 12) as u64;
                    if let Some(m) = &metrics_clone {
                        let now = std::time::Instant::now();
                        let dur = now.duration_since(throughput_last).as_secs_f64();
                        if dur >= 5.0 {
                            let goodput_mbps = (throughput_bytes as f64 * 8.0) / (dur * 1e6);
                            let _ = m.record_throughput(dur, goodput_mbps, throughput_frames);
                            throughput_last = now;
                            throughput_bytes = 0;
                            throughput_frames = 0;
                        }
                    }
                }
                let h264 = if pt.len()>=8 { pt[8..].to_vec() } else { Vec::new() };
                if frame_tx.send(h264).await.is_err() { break; }
            }
            eprintln!("[recv:{peer_str}] connection handler exiting");
        });
    }
}
use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::convert::TryFrom;
use tokio::time::{Duration, Instant};
use aead::AesGcmCtx;
use tokio::sync::mpsc;

const SALT: &[u8] = b"salt:ECE4301-midterm-2025";
const KDF_INFO_C2S: &[u8] = b"ctx:k_c2s";
const KDF_INFO_S2C: &[u8] = b"ctx:k_s2c";
const REKEY_SEQ: u32 = u32::MAX;               // reserved sequence for control frame
const REKEY_PT_LEN: usize = 16 + 8 + 8;

#[inline] fn aad(seq: u32) -> [u8; 4] { seq.to_be_bytes() }
//cutoffstart
pub async fn run_sender_from_channel(
    host: &str,
    rekey_every: Option<Duration>,
    mut frame_rx: mpsc::Receiver<Vec<u8>>,
    metrics_opt: Option<metrics::Metrics>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use rand::RngCore;
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut sock = tokio::net::TcpStream::connect(host).await.context("connect")?;
    eprintln!("[send] connected to {host}");

    let hs_start = Instant::now();
    let (mut tx, _rx_unused, shared32, client_pub_len, server_pub_len) = match handshake_client(&mut sock).await.context("handshake_client") {
        Ok(v) => v,
        Err(e) => {
            // no metrics instance available, just return error
            return Err(e);
        }
    };
    let hs_d = hs_start.elapsed();
    eprintln!("[send] handshake OK");
    // record handshake if metrics provided via global app wiring
    if let Some(m) = &metrics_opt {
        let bytes_sent = (2 + client_pub_len + 8) as u64;
        let bytes_received = (2 + server_pub_len + 8) as u64;
        let _ = m.record_handshake("ECDH", hs_d, bytes_sent, bytes_received, true, None, Some(host.to_string()));
    }
    let mut next_rekey_at = rekey_every.map(|d| Instant::now() + d);
    let mut seq: u32 = 0;
    // throughput counters
    let mut throughput_bytes: u64 = 0;
    let mut throughput_frames: u64 = 0;
    let mut throughput_last = Instant::now();

    // spawn periodic system snapshot and latency summary if metrics requested
    if let Some(m) = metrics_opt.clone() {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let _ = m.record_system_snapshot();
                let _ = m.write_latency_summary();
            }
        });
    }

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
                    // measure full rekey send time (rng, encrypt, write, rotate)
                    let rekey_start = Instant::now();
                    let ct = tx.encrypt(REKEY_SEQ, &pt, &aad(REKEY_SEQ))?;
                    let mut hdr=[0u8;12]; hdr[..8].copy_from_slice(&(REKEY_SEQ as u64).to_be_bytes()); hdr[8..12].copy_from_slice(&(u32::try_from(ct.len()).unwrap()).to_be_bytes());
                    sock.write_all(&hdr).await?; sock.write_all(&ct).await?;
                    // rotate local sender key/base
                    let (k_c2s,_)=hkdf_pair_from_shared(&shared32,&salt); tx = aead::AesGcmCtx::new(k_c2s,c2s);
                    // record rekey event in metrics (if present) with measured total rekey duration
                    if let Some(m) = &metrics_opt {
                        let bytes_sent = (12 + ct.len()) as u64; // hdr + ct
                        let rekey_d = rekey_start.elapsed();
                        let _ = m.record_handshake("REKEY", rekey_d, bytes_sent, 0, true, None, Some(host.to_string()));
                    }
                    seq=0; eprintln!("[send] rekey sent+applied");
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
                    // throughput accounting
                    throughput_frames += 1;
                    throughput_bytes += (ct.len() + 12) as u64;
                    if let Some(m) = &metrics_opt {
                        let now = Instant::now();
                        let dur = now.duration_since(throughput_last).as_secs_f64();
                        if dur >= 5.0 {
                            let goodput_mbps = (throughput_bytes as f64 * 8.0) / (dur * 1e6);
                            let _ = m.record_throughput(dur, goodput_mbps, throughput_frames);
                            throughput_last = now;
                            throughput_bytes = 0;
                            throughput_frames = 0;
                        }
                    }
                    seq = seq.wrapping_add(1);
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
            throughput_frames += 1;
            throughput_bytes += (ct.len() + 12) as u64;
            if let Some(m) = &metrics_opt {
                let now = Instant::now();
                let dur = now.duration_since(throughput_last).as_secs_f64();
                if dur >= 5.0 {
                    let goodput_mbps = (throughput_bytes as f64 * 8.0) / (dur * 1e6);
                    let _ = m.record_throughput(dur, goodput_mbps, throughput_frames);
                    throughput_last = now;
                    throughput_bytes = 0;
                    throughput_frames = 0;
                }
            }
            seq = seq.wrapping_add(1);
        }
    }
    eprintln!("[send] video channel closed; done");
    Ok(())
}

/// RECV: decrypt frames and forward the H.264 AU bytes to a channel.
pub async fn run_receiver_to_channel(
    bind: &str,
    frame_tx: mpsc::Sender<Vec<u8>>,
    metrics_opt: Option<metrics::Metrics>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let listener = tokio::net::TcpListener::bind(bind).await.context("bind")?;
    eprintln!("[recv] listening on {bind}");

    loop {
        let (mut sock, peer) = listener.accept().await.context("accept")?;
        let peer_str = peer.to_string();
        eprintln!("[recv] connection from {peer_str}");

        let tx_clone = frame_tx.clone();
        let metrics_clone = metrics_opt.clone();

        // Spawn a task to handle this connection independently so we can accept more.
        tokio::spawn(async move {
            let hs_start = Instant::now();
            let (mut _tx_unused, mut rx, shared32, client_pub_len, server_pub_len) = match handshake_server(&mut sock).await.context("handshake_server") {
                Ok(v) => v,
                Err(e) => {
                    if let Some(m) = &metrics_clone {
                        let _ = m.record_handshake("ECDH", hs_start.elapsed(), 0, 0, false, Some(format!("{e}")), Some(peer_str.clone()));
                    }
                    eprintln!("[recv:{peer}] handshake failed: {e}");
                    return;
                }
            };
            let hs_d = hs_start.elapsed();
            eprintln!("[recv:{peer}] handshake OK");
            if let Some(m) = &metrics_clone {
                let bytes_sent = (2 + server_pub_len + 8) as u64;
                let bytes_received = (2 + client_pub_len + 8) as u64;
                let _ = m.record_handshake("ECDH", hs_d, bytes_sent, bytes_received, true, None, Some(peer_str.clone()));
            }

            // spawn periodic system snapshot and latency summary if requested
            if let Some(m) = metrics_clone.clone() {
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        let _ = m.record_system_snapshot();
                        let _ = m.write_latency_summary();
                    }
                });
            }

            // throughput counters
            let mut throughput_bytes: u64 = 0;
            let mut throughput_frames: u64 = 0;
            let mut throughput_last = Instant::now();

            loop {
                let mut hdr=[0u8;12];
                if let Err(e)=sock.read_exact(&mut hdr).await { eprintln!("[recv:{peer}] closed: {e}"); break; }
                let seq = u64::from_be_bytes(hdr[..8].try_into().unwrap()) as u32;
                let ct_len = u32::from_be_bytes(hdr[8..12].try_into().unwrap()) as usize;
                let mut ct = vec![0u8; ct_len];
                if let Err(e) = sock.read_exact(&mut ct).await { eprintln!("[recv:{peer}] read error: {e}"); break; }
                // measure rekey handling time for rekey control frames (decrypt + hkdf + rotate)
                let handling_start = Instant::now();
                let pt = match rx.decrypt(seq, &ct, &aad(seq)) {
                    Ok(p) => { p }
                    Err(e) => {
                        eprintln!("[recv:{peer}] decrypt error: {e}");
                        if let Some(m) = &metrics_clone {
                            let _ = m.record_errors(0, 1, 0);
                        }
                        continue;
                    }
                };

                if seq == REKEY_SEQ {
                    if pt.len()!=REKEY_PT_LEN { eprintln!("[recv:{peer}] bad rekey payload length"); continue; }
                    // extract fields
                    let mut salt=[0u8;16]; salt.copy_from_slice(&pt[0..16]);
                    let mut c2s=[0u8;8];   c2s.copy_from_slice(&pt[16..24]);
                    let mut s2c=[0u8;8];   s2c.copy_from_slice(&pt[24..32]);

                    // Server role: new RX is k_c2s with c2s_base
                    let (k_c2s, _k_s2c) = hkdf_pair_from_shared(&shared32, &salt);
                    rx = AesGcmCtx::new(k_c2s, c2s);

                    // record total handling duration for REKEY
                    if let Some(m) = &metrics_clone {
                        let bytes_received = (12 + ct.len()) as u64; // header + ciphertext
                        let handling_d = handling_start.elapsed();
                        let _ = m.record_handshake("REKEY", handling_d, 0, bytes_received, true, None, Some(peer_str.clone()));
                    }
                    eprintln!("[recv:{peer}] rekey applied");
                    // fallthrough to continue processing normal frames if any
                }

                // normal data frame: compute latency from 8B timestamp, strip it and forward H.264 AU
                if pt.len() >= 8 {
                    let mut tsb = [0u8;8]; tsb.copy_from_slice(&pt[0..8]);
                    let sender_ns = u64::from_be_bytes(tsb);
                    let now_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
                    if now_ns >= sender_ns {
                        let latency_ms = (now_ns - sender_ns) as f64 / 1e6;
                        if let Some(m) = &metrics_clone {
                            let _ = m.record_frame_latency_ms(latency_ms);
                        }
                    }
                    // throughput accounting
                    throughput_frames += 1;
                    throughput_bytes += (ct.len() + 12) as u64;
                    if let Some(m) = &metrics_clone {
                        let now = Instant::now();
                        let dur = now.duration_since(throughput_last).as_secs_f64();
                        if dur >= 5.0 {
                            let goodput_mbps = (throughput_bytes as f64 * 8.0) / (dur * 1e6);
                            let _ = m.record_throughput(dur, goodput_mbps, throughput_frames);
                            throughput_last = now;
                            throughput_bytes = 0;
                            throughput_frames = 0;
                        }
                    }
                }
                let h264 = if pt.len()>=8 { pt[8..].to_vec() } else { Vec::new() };
                if tx_clone.send(h264).await.is_err() { break; }
            }
            eprintln!("[recv:{peer}] connection handler exiting");
        });
    }
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


async fn handshake_client(stream: &mut TcpStream) -> Result<(AesGcmCtx, AesGcmCtx, [u8; 32], usize, usize)> {
   // Generate client ECDH
   let client_secret = EphemeralSecret::random(&mut rand::rngs::OsRng);
   let client_pub = PublicKey::from(&client_secret);
   let client_pub_point = EncodedPoint::from(client_pub);
   let client_pub_bytes = client_pub_point.as_bytes();


   // 1) Send client pub (u16 len + bytes)
   let len_u16 = u16::try_from(client_pub_bytes.len()).expect("pubkey len fits u16");
   write_all(stream, &len_u16.to_be_bytes()).await?;
   write_all(stream, client_pub_bytes).await?;


   // 2) Read server pub
   let mut lbuf = [0u8; 2];
   read_exact(stream, &mut lbuf).await?;
   let servidor_len = u16::from_be_bytes(lbuf) as usize;
   let mut server_pub_bytes = vec![0u8; servidor_len];
   read_exact(stream, &mut server_pub_bytes).await?;
   let server_pub = PublicKey::from_sec1_bytes(&server_pub_bytes).map_err(|_| anyhow!("bad server pub"))?;


   // ECDH -> shared
   let shared = client_secret.diffie_hellman(&server_pub);
   let shared_bytes = shared.raw_secret_bytes();
   let mut shared32 = [0u8; 32];
   shared32.copy_from_slice(shared_bytes.as_slice());


   // Initial keys via your existing hkdf_keys (uses static SALT)
   let (k_c2s, k_s2c) = hkdf_keys(shared_bytes.as_slice());


   // 3) Exchange nonce bases (client sends first)
   let mut client_base = [0u8; 8];
   rand::rngs::OsRng.fill_bytes(&mut client_base);
   write_all(stream, &client_base).await?;


   let mut server_base = [0u8; 8];
   read_exact(stream, &mut server_base).await?;


    let tx = AesGcmCtx::new(k_c2s, client_base); // client -> server
    let rx = AesGcmCtx::new(k_s2c, server_base); // server -> client
    Ok((tx, rx, shared32, client_pub_bytes.len(), server_pub_bytes.len()))
}


async fn handshake_server(stream: &mut TcpStream) -> Result<(AesGcmCtx, AesGcmCtx, [u8; 32], usize, usize)> {
   // Read client pub
   let mut lbuf = [0u8; 2];
   read_exact(stream, &mut lbuf).await?;
   let client_len = u16::from_be_bytes(lbuf) as usize;
   let mut client_pub_bytes = vec![0u8; client_len];
   read_exact(stream, &mut client_pub_bytes).await?;
   let client_pub = PublicKey::from_sec1_bytes(&client_pub_bytes).map_err(|_| anyhow!("bad client pub"))?;


   // Generate server ECDH and send pub
   let server_secret = EphemeralSecret::random(&mut rand::rngs::OsRng);
   let server_pub = PublicKey::from(&server_secret);
   let server_pub_point = EncodedPoint::from(server_pub);
   let server_pub_bytes = server_pub_point.as_bytes();
   let len_u16 = u16::try_from(server_pub_bytes.len()).expect("pubkey len fits u16");
   write_all(stream, &len_u16.to_be_bytes()).await?;
   write_all(stream, server_pub_bytes).await?;


   // ECDH -> shared
   let shared = server_secret.diffie_hellman(&client_pub);
   let shared_bytes = shared.raw_secret_bytes();
   let mut shared32 = [0u8; 32];
   shared32.copy_from_slice(shared_bytes.as_slice());


   let (k_c2s, k_s2c) = hkdf_keys(shared_bytes.as_slice());


   // Receive client's base; send server base
   let mut client_base = [0u8; 8];
   read_exact(stream, &mut client_base).await?;
   let mut server_base = [0u8; 8];
   rand::rngs::OsRng.fill_bytes(&mut server_base);
   write_all(stream, &server_base).await?;


    let tx = AesGcmCtx::new(k_s2c, server_base); // server -> client
    let rx = AesGcmCtx::new(k_c2s, client_base); // client -> server
    Ok((tx, rx, shared32, client_pub_bytes.len(), server_pub_bytes.len()))
}




/// Receiver: bind, accept 1 client, decrypt frames, print counters.
/// Receiver: bind, accept 1 client, decrypt frames, print counters, handle rekeys.
pub async fn run_receiver(bind: &str) -> Result<()> {
   let listener = TcpListener::bind(bind).await.context("bind")?;
   eprintln!("[recv] listening on {bind}");
   let (mut sock, peer) = listener.accept().await.context("accept")?;
   eprintln!("[recv] connection from {peer}");


    let (_tx_unused, mut rx, shared32, _client_pub_len, _server_pub_len) = handshake_server(&mut sock).await.context("handshake_server")?;
   eprintln!("[recv] handshake OK");


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
       let pt = rx.decrypt(seq, &ct, &aad)?;   // decrypt first to authenticate


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
           continue;
       }


       // Normal data frame
       frames += 1;
       if frames % 50 == 0 {
           eprintln!("[recv] ok: {frames} frames");
       }
   }
   Ok(())
}


/// Sender: connect, handshake, send N encrypted dummy frames.
/// Sender: connect, handshake, send N encrypted dummy frames; optional timed rekey.


pub async fn run_sender(host: &str, n_frames: u32, rekey_every: Option<Duration>) -> anyhow::Result<()> {
   eprintln!("[send] connecting to {host} (rekey_every={rekey_every:?})");
   let mut sock = tokio::net::TcpStream::connect(host).await.context("connect")?;
   eprintln!("[send] connected to {host}");


   // Handshake must return (tx, rx, shared32). We only use tx + shared32 here.
    let (mut tx, _rx_unused, shared32, _client_pub_len, _server_pub_len) = handshake_client(&mut sock).await.context("handshake_client")?;
   eprintln!("[send] handshake OK");


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
               next_rekey_at = rekey_every.map(|d| Instant::now() + d);
               continue; // don’t count the control frame
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