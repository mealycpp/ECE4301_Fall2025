use std::time::Duration;
use keying::{log_arm_crypto_support, demo_ecdh, demo_rsa};
// use transport::{run_receiver, run_sender};

fn arg_val(args: &[String], key: &str) -> Option<String> {
    // accepts: --key value  OR  --key=value
    for i in 0..args.len() {
        if args[i] == key {
            if i + 1 < args.len() { return Some(args[i + 1].clone()); }
        } else if let Some(rest) = args[i].strip_prefix(&(key.to_string() + "=")) {
            return Some(rest.to_string());
        }
    }
    None
}

fn arg_vals(args: &[String], key: &str) -> Vec<String> {
    // collect multiple --key value or --key=value occurrences
    let mut out = Vec::new();
    for i in 0..args.len() {
        if args[i] == key {
            if i + 1 < args.len() { out.push(args[i + 1].clone()); }
        } else if let Some(rest) = args[i].strip_prefix(&(key.to_string() + "=")) {
            out.push(rest.to_string());
        }
    }
    out
}

fn has_flag(args: &[String], flag: &str) -> bool {
    // accepts: --flag  OR  --flag=true  (not needed for this flow, but handy)
    args.iter().any(|a| a == flag || a.starts_with(&(flag.to_string() + "=")))
}

fn parse_rekey(s: &str) -> Option<Duration> {
    let t = s.trim();
    if t.is_empty() { return None; }

    // If last char is a supported suffix, strip it; otherwise treat as seconds.
    let (num_str, suffix) = match t.chars().last()? {
        's' | 'm' | 'h' => (&t[..t.len()-1], t.chars().last().unwrap()),
        _               => (t, 's'),
    };

    let n: u64 = num_str.parse().ok()?;
    let secs = match suffix {
        's' => n,
        'm' => n * 60,
        'h' => n * 3600,
        _   => n,
    };
    Some(Duration::from_secs(secs))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--print-config") {
        println!("rpi-secure-stream: config dump");
        log_arm_crypto_support();
        return;
    }
    if args.iter().any(|a| a == "--demo-ecdh") {
        log_arm_crypto_support();
        if let Err(e) = demo_ecdh() { eprintln!("ECDH demo failed: {e}"); std::process::exit(1); }
        return;
    }
    if args.iter().any(|a| a == "--demo-rsa") {
        log_arm_crypto_support();
        if let Err(e) = demo_rsa() { eprintln!("RSA demo failed: {e}"); std::process::exit(1); }
        return;
    }

// Mesh mode: act as full node that both sends to multiple peers and receives from many peers.
    if has_flag(&args, "--mode=mesh") {
        log_arm_crypto_support();

        let metrics_dir = arg_val(&args, "--metrics-dir");
        let metrics = metrics_dir.as_ref().and_then(|d| {
            match metrics::Metrics::new(d) {
                Ok(m) => Some(m),
                Err(e) => { eprintln!("warning: could not create metrics at {d}: {e}"); None }
            }
        });

        // peers: multiple --peer entries
        let peers = arg_vals(&args, "--peer");
        if peers.is_empty() {
            eprintln!("mesh mode requires at least one --peer=host:port");
            std::process::exit(1);
        }

        let bind = arg_val(&args, "--bind").unwrap_or_else(|| "0.0.0.0:5000".to_string());
        let payload = arg_val(&args, "--payload").unwrap_or_else(|| "video".to_string());

        eprintln!("[app] mode=mesh payload={payload} peers={:?}", peers);

        if payload == "video" {
            let fps = arg_val(&args, "--fps").and_then(|s| s.parse::<i32>().ok()).unwrap_or(30);
            // start playback pipeline (receives frames via a Sender)
            let (_playback_tx, _pipe) = match video::start_h264_playback(fps) {
                Ok(v) => v,
                Err(e) => { eprintln!("mesh error: playback init failed: {e}"); std::process::exit(1); }
            };

            // start capture source
            let dev = arg_val(&args, "--device").unwrap_or_else(|| "libcamera".to_string());
            let (mut src_rx, _cap_pipe) = if dev.eq_ignore_ascii_case("libcamera") {
                eprintln!("[app] using libcamerasrc (Pi CSI camera)");
                match video::start_h264_capture_libcamera(1280, 720, fps) {
                    Ok(v) => v,
                    Err(e) => { eprintln!("mesh error: libcamera capture failed: {e}"); std::process::exit(1); }
                }
            } else {
                eprintln!("[app] using v4l2src device={dev}");
                match video::start_h264_capture_v4l2(&dev, 1280, 720, fps) {
                    Ok(v) => v,
                    Err(e) => { eprintln!("mesh error: v4l2 capture failed: {e}"); std::process::exit(1); }
                }
            };

            // For each peer create a dedicated sender channel and task
            use tokio::sync::Mutex;
            use std::sync::Arc;
            let mut sender_txs = Vec::new();
            // Force rekey every 5 seconds
            let rekey = Some(Duration::from_secs(5));
            for peer in &peers {
                let sender = Arc::new(Mutex::new(None));
                sender_txs.push(sender.clone());
                let peer_clone = peer.clone();
                let metrics_clone = metrics.clone();
                let sender_clone = sender.clone();
                tokio::spawn(async move {
                    loop {
                        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                        // Update the sender for broadcaster
                        {
                            let mut s = sender_clone.lock().await;
                            *s = Some(tx);
                        }
                        match transport::run_sender_from_channel(&peer_clone, rekey, rx, metrics_clone.clone()).await {
                            Ok(_) => break, // exit loop if connection and run succeed
                            Err(e) => {
                                eprintln!("mesh sender to {peer_clone} failed: {e}, retrying in 2s");
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                        }
                    }
                });
            }

            // Broadcast captured frames to all sender channels
            tokio::spawn(async move {
                while let Some(frame) = src_rx.recv().await {
                    for sender in &sender_txs {
                        let tx_opt = sender.lock().await;
                        if let Some(tx) = tx_opt.as_ref() {
                            let _ = tx.send(frame.clone()).await;
                        }
                    }
                }
                eprintln!("mesh capture ended");
            });

            // Start receiver to accept many incoming connections and spawn a playback pipeline for each
            use tokio::sync::mpsc;
            let handler = move |rx: mpsc::Receiver<Vec<u8>>, peer_addr: String| {
                let fps = arg_val(&args, "--fps").and_then(|s| s.parse::<i32>().ok()).unwrap_or(30);
                tokio::spawn(async move {
                    match video::start_h264_playback(fps) {
                        Ok((tx, _pipe)) => {
                            let mut rx = rx;
                            // Forward frames from rx to playback tx
                            while let Some(frame) = rx.recv().await {
                                let _ = tx.send(frame).await;
                            }
                            eprintln!("[app] playback for {peer_addr} ended");
                        }
                        Err(e) => {
                            eprintln!("mesh error: playback init failed for {peer_addr}: {e}");
                        }
                    }
                })
            };

            if let Err(e) = transport::run_multi_receiver_to_channel(&bind, metrics.clone(), handler).await {
                eprintln!("mesh multi-receiver error: {e}");
                std::process::exit(1);
            }
        } else {
            eprintln!("mesh mode currently supports only video payload");
            std::process::exit(1);
        }
        return;
    }

// Receiver
    if has_flag(&args, "--mode=receiver") {
    log_arm_crypto_support();
        // optional metrics directory
        let metrics_dir = arg_val(&args, "--metrics-dir");
        let metrics = metrics_dir.as_ref().and_then(|d| {
            match metrics::Metrics::new(d) {
                Ok(m) => Some(m),
                Err(e) => {
                    eprintln!("warning: could not create metrics at {d}: {e}");
                    None
                }
            }
        });
    let bind    = arg_val(&args, "--bind").unwrap_or_else(|| "127.0.0.1:5000".to_string());
    let payload = arg_val(&args, "--payload").unwrap_or_else(|| "bytes".to_string());
    eprintln!("[app] mode=receiver payload={payload}");

        if payload == "video" {
        let fps = arg_val(&args, "--fps").and_then(|s| s.parse::<i32>().ok()).unwrap_or(30);
        let (tx, _pipe) = video::start_h264_playback(fps).expect("gst playback");
            if let Err(e) = transport::run_receiver_to_channel(&bind, tx, metrics.clone()).await {
            eprintln!("receiver error: {e}");
            std::process::exit(1);
        }
    } else {
        if let Err(e) = transport::run_receiver(&bind).await {
            eprintln!("receiver error: {e}");
            std::process::exit(1);
        }
    }
    return;
}

// Sender
// ----- sender branch -----
    if has_flag(&args, "--mode=sender") {
    log_arm_crypto_support();

        let metrics_dir = arg_val(&args, "--metrics-dir");
        let metrics = metrics_dir.as_ref().and_then(|d| {
            match metrics::Metrics::new(d) {
                Ok(m) => Some(m),
                Err(e) => { eprintln!("warning: could not create metrics at {d}: {e}"); None }
            }
        });

    let host   = arg_val(&args, "--host").unwrap_or_else(|| "127.0.0.1:5000".to_string());
    let _n     = arg_val(&args, "--frames").and_then(|s| s.parse::<u32>().ok()).unwrap_or(300);
    let rekey  = arg_val(&args, "--rekey").and_then(|s| parse_rekey(&s));
    let payload= arg_val(&args, "--payload").unwrap_or_else(|| "bytes".to_string());

    eprintln!("[app] mode=sender payload={payload} rekey={rekey:?}");

        if payload == "video" {
        let dev = arg_val(&args, "--device").unwrap_or_else(|| "/dev/video0".to_string());
        let w   = arg_val(&args, "--width").and_then(|s| s.parse::<i32>().ok()).unwrap_or(1280);
        let h   = arg_val(&args, "--height").and_then(|s| s.parse::<i32>().ok()).unwrap_or(720);
        let fps = arg_val(&args, "--fps").and_then(|s| s.parse::<i32>().ok()).unwrap_or(30);

        let (rx, _pipe) = if dev.eq_ignore_ascii_case("libcamera") {
            eprintln!("[app] using libcamerasrc (Pi CSI camera)");
            match video::start_h264_capture_libcamera(w, h, fps) {
                Ok(v) => v,
                Err(e) => { eprintln!("sender error: libcamera capture failed: {e}"); std::process::exit(1); }
            }
        } else {
            // dev must be a real node like /dev/video2
            eprintln!("[app] using v4l2src device={dev}");
            match video::start_h264_capture_v4l2(&dev, w, h, fps) {
                Ok(v) => v,
                Err(e) => { eprintln!("sender error: v4l2 capture failed: {e}"); std::process::exit(1); }
            }
        };

        if let Err(e) = transport::run_sender_from_channel(&host, rekey, rx, metrics.clone()).await {
            eprintln!("sender error: {e}");
            std::process::exit(1);
        }
        return;
    }

    // ... your existing non-video sender path ...
}



    eprintln!("Usage:");
    eprintln!("  rpi-secure-stream --print-config");
    eprintln!("  rpi-secure-stream --demo-ecdh | --demo-rsa");
    eprintln!("  rpi-secure-stream --mode=receiver --bind 127.0.0.1:5000");
    eprintln!("  rpi-secure-stream --mode=sender  --host 127.0.0.1:5000 [--frames 300] [--rekey 10s|5m|1h]");
}