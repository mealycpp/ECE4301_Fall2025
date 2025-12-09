use anyhow::{Result, Context, bail};
use clap::{Parser, ValueEnum};
use chrono::Utc;
use std::sync::Arc;
use std::time::{Instant, Duration, SystemTime};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use gstreamer as gst;

mod crypto_lib {
    pub use crypto::*;
}

mod metrics_lib {
    pub use metrics::*;
}

mod display;
use display::VideoDisplay;

mod group_key;

use crypto_lib::*;
use metrics_lib::*;

#[derive(Debug, Clone, ValueEnum)]
enum KeyMechanism {
    Rsa,
    Ecdh,
    Group,  // Use pre-established group key
}

#[derive(Debug, Clone, ValueEnum)]
enum Mode {
    Sender,
    Receiver,
    Relay,
    GroupLeader,   // Establish and distribute group key
    GroupMember,   // Receive group key from leader
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Secure Video Streaming for RPi5", long_about = None)]
struct Args {
    /// Operating mode: sender or receiver
    #[arg(long)]
    mode: Mode,
    
    /// Key establishment mechanism
    #[arg(long, default_value = "ecdh")]
    mechanism: KeyMechanism,
    
    /// Host to connect to (sender) or bind to (receiver)
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    
    /// Port number
    #[arg(long, default_value = "8443")]
    port: u16,
    
    /// Node identifier for metrics
    #[arg(long, default_value = "node-1")]
    node_id: String,
    
    /// Video source: "camera", "libcamera", "v4l2", or file path
    #[arg(long, default_value = "camera")]
    video_source: String,
    
    /// Video device (for v4l2)
    #[arg(long, default_value = "/dev/video0")]
    video_device: String,
    
    /// Video width
    #[arg(long, default_value = "640")]
    video_width: i32,
    
    /// Video height
    #[arg(long, default_value = "480")]
    video_height: i32,
    
    /// Video FPS
    #[arg(long, default_value = "15")]
    video_fps: i32,
    
    /// Rekey interval in seconds
    #[arg(long, default_value = "600")]
    rekey_interval: u64,
    
    /// RSA key size (2048 or 3072)
    #[arg(long, default_value = "2048")]
    rsa_bits: usize,
    
    /// Print config and exit
    #[arg(long)]
    print_config: bool,
    
    /// Use simulated video instead of camera
    #[arg(long)]
    simulate: bool,
    
    /// Enable video display (receiver only)
    #[arg(long)]
    display: bool,
    
    /// Relay destination host (relay mode only)
    #[arg(long)]
    relay_host: Option<String>,
    
    /// Relay destination port (relay mode only)
    #[arg(long)]
    relay_port: Option<u16>,
    
    /// Path to group key file (for group mechanism)
    #[arg(long, default_value = "group_key.bin")]
    group_key_file: String,
    
    /// Multicast address for group streaming
    #[arg(long)]
    multicast_addr: Option<String>,
    
    /// Group members list (for group-leader mode): node_id:host:port,node_id:host:port
    #[arg(long)]
    members: Option<String>,
}

/// Frame header: [flags:1][timestamp_us:8][counter:4][nonce_counter:4][payload_len:4]
const HEADER_SIZE: usize = 21;

#[derive(Debug, Clone)]
struct FrameHeader {
    flags: u8,
    timestamp_us: u64,
    counter: u32,
    nonce_counter: u32,
    payload_len: u32,
}

impl FrameHeader {
    fn serialize(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = self.flags;
        buf[1..9].copy_from_slice(&self.timestamp_us.to_be_bytes());
        buf[9..13].copy_from_slice(&self.counter.to_be_bytes());
        buf[13..17].copy_from_slice(&self.nonce_counter.to_be_bytes());
        buf[17..21].copy_from_slice(&self.payload_len.to_be_bytes());
        buf
    }
    
    fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            bail!("Header too short");
        }
        
        let flags = buf[0];
        let timestamp_us = u64::from_be_bytes(buf[1..9].try_into()?);
        let counter = u32::from_be_bytes(buf[9..13].try_into()?);
        let nonce_counter = u32::from_be_bytes(buf[13..17].try_into()?);
        let payload_len = u32::from_be_bytes(buf[17..21].try_into()?);
        
        Ok(Self { flags, timestamp_us, counter, nonce_counter, payload_len })
    }
}

struct SessionState {
    cipher: Arc<RwLock<AesGcmCipher>>,
    rekey_interval: Duration,
    last_rekey: Arc<RwLock<Instant>>,
}

impl SessionState {
    fn new(key_material: SessionKeyMaterial, rekey_interval: Duration) -> Self {
        let cipher = Arc::new(RwLock::new(AesGcmCipher::new(key_material, None)));
        Self {
            cipher,
            rekey_interval,
            last_rekey: Arc::new(RwLock::new(Instant::now())),
        }
    }
    
    async fn should_rekey(&self) -> bool {
        let elapsed = self.last_rekey.read().await.elapsed();
        elapsed >= self.rekey_interval || self.cipher.read().await.should_rekey()
    }
    
    async fn rekey(&self, new_key_material: SessionKeyMaterial) {
        let mut cipher = self.cipher.write().await;
        *cipher = AesGcmCipher::new(new_key_material, None);
        *self.last_rekey.write().await = Instant::now();
        info!("Session rekeyed successfully");
    }
}

/// Initialize GStreamer camera pipeline
fn init_gstreamer_camera(args: &Args) -> Result<(gst::Pipeline, AppSink)> {
    gst::init().context("Failed to initialize GStreamer")?;
    
    info!("Creating GStreamer pipeline for camera");
    
    // Build pipeline based on video source
    let pipeline_str = match args.video_source.as_str() {
        "camera" | "libcamera" => {
            // Try libcamerasrc first (Pi Camera Module 3)
            format!(
                "libcamerasrc ! video/x-raw,width={},height={},format=I420,framerate={}/1 ! appsink name=sink sync=false",
                args.video_width, args.video_height, args.video_fps
            )
        },
        "v4l2" => {
            // Use v4l2src for USB cameras
            format!(
                "v4l2src device={} ! video/x-raw,width={},height={},framerate={}/1 ! videoconvert ! video/x-raw,format=I420 ! appsink name=sink sync=false",
                args.video_device, args.video_width, args.video_height, args.video_fps
            )
        },
        path if std::path::Path::new(path).exists() => {
            // Video file playback
            format!(
                "filesrc location={} ! decodebin ! videoconvert ! videoscale ! video/x-raw,width={},height={},format=I420 ! appsink name=sink sync=false",
                path, args.video_width, args.video_height
            )
        },
        _ => {
            bail!("Invalid video source: {}. Use 'camera', 'libcamera', 'v4l2', or a file path", args.video_source);
        }
    };
    
    info!("Pipeline: {}", pipeline_str);
    
    let pipeline = gst::parse::launch(&pipeline_str)
        .context("Failed to create GStreamer pipeline")?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow::anyhow!("Failed to downcast to Pipeline"))?;
    
    // Get the appsink element
    let appsink = pipeline
        .by_name("sink")
        .context("Failed to find appsink element")?
        .downcast::<AppSink>()
        .map_err(|_| anyhow::anyhow!("Failed to downcast to AppSink"))?;
    
    // Configure appsink for low latency
    appsink.set_property("emit-signals", false);
    appsink.set_property("sync", false);
    appsink.set_property("drop", true); // Drop old frames if we can't keep up
    appsink.set_property("max-buffers", 1u32); // Only keep latest frame
    
    // Start the pipeline
    pipeline.set_state(gst::State::Playing)
        .context("Failed to start pipeline")?;
    
    info!("GStreamer pipeline started successfully");
    
    // Wait for pipeline to be ready
    let bus = pipeline.bus().context("Failed to get pipeline bus")?;
    let _msg = bus.timed_pop_filtered(
        gst::ClockTime::from_seconds(5),
        &[gst::MessageType::Error, gst::MessageType::AsyncDone]
    );
    
    Ok((pipeline, appsink))
}

/// Calculate expected frame size for I420 format (YUV 4:2:0)
fn i420_frame_size(width: i32, height: i32) -> usize {
    let y_size = (width * height) as usize;
    let uv_size = y_size / 4;
    y_size + 2 * uv_size // Y + U + V
}

async fn perform_rsa_handshake(
    stream: &mut TcpStream,
    is_initiator: bool,
    rsa_bits: usize,
) -> Result<(SessionKeyMaterial, HandshakeMetrics)> {
    let start_time = Utc::now();
    let start_instant = Instant::now();
    
    let mut bytes_tx = 0u64;
    let mut bytes_rx = 0u64;
    
    let key_material = if is_initiator {
        info!("RSA: Initiator - generating session key");
        
        // Receive responder's public key
        let pub_key_len = stream.read_u32().await? as usize;
        bytes_rx += 4;
        
        let mut pub_key_der = vec![0u8; pub_key_len];
        stream.read_exact(&mut pub_key_der).await?;
        bytes_rx += pub_key_len as u64;
        
        info!("RSA: Received public key ({} bytes)", pub_key_len);
        
        // Parse public key
        use rsa::pkcs8::DecodePublicKey;
        let peer_public = rsa::RsaPublicKey::from_public_key_der(&pub_key_der)
            .context("Failed to parse RSA public key")?;
        
        // Generate and wrap session key
        let session_key_material = SessionKeyMaterial::generate_random();
        let session_bytes = session_key_material.as_bytes();
        
        let mut rng = rand::rngs::OsRng;
        let wrapped = peer_public.encrypt(&mut rng, rsa::Oaep::new::<sha2::Sha256>(), &session_bytes)
            .context("Failed to wrap session key")?;
        
        // Send wrapped key
        stream.write_u32(wrapped.len() as u32).await?;
        stream.write_all(&wrapped).await?;
        bytes_tx += 4 + wrapped.len() as u64;
        
        info!("RSA: Sent wrapped session key ({} bytes)", wrapped.len());
        
        session_key_material
    } else {
        info!("RSA: Responder - generating keypair ({} bits)", rsa_bits);
        
        // Generate RSA keypair
        let keypair = rsa_kex::RsaKeyPair::generate(rsa_bits)?;
        let pub_key_der = keypair.public_key_der()?;
        
        // Send public key
        stream.write_u32(pub_key_der.len() as u32).await?;
        stream.write_all(&pub_key_der).await?;
        bytes_tx += 4 + pub_key_der.len() as u64;
        
        info!("RSA: Sent public key ({} bytes)", pub_key_der.len());
        
        // Receive wrapped session key
        let wrapped_len = stream.read_u32().await? as usize;
        bytes_rx += 4;
        
        let mut wrapped = vec![0u8; wrapped_len];
        stream.read_exact(&mut wrapped).await?;
        bytes_rx += wrapped_len as u64;
        
        info!("RSA: Received wrapped session key ({} bytes)", wrapped_len);
        
        // Unwrap session key
        let session_bytes = keypair.unwrap_session_key(&wrapped)?;
        SessionKeyMaterial::from_bytes(&session_bytes)?
    };
    
    let duration = start_instant.elapsed();
    
    let metrics = HandshakeMetrics {
        ts_start: start_time,
        ts_end: Utc::now(),
        mechanism: format!("RSA-{}", rsa_bits),
        bytes_tx,
        bytes_rx,
        cpu_avg: 0.0,
        mem_mb: 0.0,
        energy_j: 0.0,
        success: true,
    };
    
    info!("RSA handshake completed in {:.3}s", duration.as_secs_f64());
    
    Ok((key_material, metrics))
}

async fn perform_ecdh_handshake(
    stream: &mut TcpStream,
    _is_initiator: bool,
) -> Result<(SessionKeyMaterial, HandshakeMetrics)> {
    let start_time = Utc::now();
    let start_instant = Instant::now();
    
    let mut bytes_tx = 0u64;
    let mut bytes_rx = 0u64;
    
    info!("ECDH: Generating ephemeral keypair (P-256)");
    let my_keypair = ecdh_kex::EcdhKeyPair::generate();
    let my_public = my_keypair.public_key_bytes();
    
    // Exchange public keys
    stream.write_u32(my_public.len() as u32).await?;
    stream.write_all(&my_public).await?;
    bytes_tx += 4 + my_public.len() as u64;
    
    let peer_pub_len = stream.read_u32().await? as usize;
    bytes_rx += 4;
    
    let mut peer_public = vec![0u8; peer_pub_len];
    stream.read_exact(&mut peer_public).await?;
    bytes_rx += peer_pub_len as u64;
    
    info!("ECDH: Exchanged public keys ({} bytes each)", my_public.len());
    
    // Derive shared secret
    let context = b"ECE4301-midterm-2025";
    let key_material = my_keypair.derive_session_key(&peer_public, context)?;
    
    let duration = start_instant.elapsed();
    
    let metrics = HandshakeMetrics {
        ts_start: start_time,
        ts_end: Utc::now(),
        mechanism: "ECDH-P256".to_string(),
        bytes_tx,
        bytes_rx,
        cpu_avg: 0.0,
        mem_mb: 0.0,
        energy_j: 0.0,
        success: true,
    };
    
    info!("ECDH handshake completed in {:.3}s", duration.as_secs_f64());
    
    Ok((key_material, metrics))
}

async fn load_group_key(path: &str) -> Result<SessionKeyMaterial> {
    info!("Loading group key from: {}", path);
    let key_bytes = tokio::fs::read(path).await
        .context("Failed to read group key file")?;
    
    // SessionKeyMaterial is 24 bytes: 16-byte AES key + 8-byte nonce base
    if key_bytes.len() != 24 {
        bail!("Invalid group key file: expected 24 bytes, got {}", key_bytes.len());
    }
    
    SessionKeyMaterial::from_bytes(&key_bytes)
}

async fn save_group_key(key: &SessionKeyMaterial, path: &str) -> Result<()> {
    let key_bytes = key.as_bytes();
    tokio::fs::write(path, &key_bytes).await?;
    info!("Saved group key to: {}", path);
    Ok(())
}

async fn perform_group_handshake(
    _stream: &mut TcpStream,
    group_key_file: &str,
) -> Result<(SessionKeyMaterial, HandshakeMetrics)> {
    let start_time = Utc::now();
    let start_instant = Instant::now();
    
    // Load pre-shared group key
    let key_material = load_group_key(group_key_file).await?;
    
    let duration = start_instant.elapsed();
    
    let metrics = HandshakeMetrics {
        ts_start: start_time,
        ts_end: Utc::now(),
        mechanism: "GROUP-PSK".to_string(),
        bytes_tx: 0,
        bytes_rx: 0,
        cpu_avg: 0.0,
        mem_mb: 0.0,
        energy_j: 0.0,
        success: true,
    };
    
    info!("Group key loaded in {:.3}ms", duration.as_secs_f64() * 1000.0);
    
    Ok((key_material, metrics))
}

async fn run_sender(args: Args) -> Result<()> {
    info!("Starting sender mode");
    
    let metrics_collector = Arc::new(MetricsCollector::new(args.node_id.clone()));
    let _metrics_task = metrics_collector.clone().start_collection();
    
    // Connect to receiver
    let addr = format!("{}:{}", args.host, args.port);
    info!("Connecting to {}", addr);
    let mut stream = TcpStream::connect(&addr).await?;
    
    // Perform handshake
    metrics_collector.record_power(5.0, 2.5, "handshake".to_string()).await;
    
    let (key_material, mut handshake_metrics) = match args.mechanism {
        KeyMechanism::Rsa => perform_rsa_handshake(&mut stream, true, args.rsa_bits).await?,
        KeyMechanism::Ecdh => perform_ecdh_handshake(&mut stream, true).await?,
        KeyMechanism::Group => perform_group_handshake(&mut stream, &args.group_key_file).await?,
    };
    
    let handshake_energy = metrics_collector.calculate_energy(Some("handshake")).await;
    handshake_metrics.energy_j = handshake_energy;
    
    info!("Handshake energy: {:.3} J", handshake_energy);
    
    // Save handshake metrics
    let mech_file = match args.mechanism {
        KeyMechanism::Rsa => "handshake_rsa.csv",
        KeyMechanism::Ecdh => "handshake_ecdh.csv",
        KeyMechanism::Group => "handshake_group.csv",
    };
    MetricsCollector::write_handshake_csv(&[handshake_metrics], mech_file)?;
    
    // Initialize session
    let session = SessionState::new(
        key_material,
        Duration::from_secs(args.rekey_interval),
    );
    
    metrics_collector.record_power(5.0, 2.0, "steady".to_string()).await;
    
    info!("Starting video stream");
    
    // Initialize camera or simulation
    let (pipeline, appsink) = if !args.simulate {
        match init_gstreamer_camera(&args) {
            Ok(p) => {
                info!("Using live camera feed from: {}", args.video_source);
                (Some(p.0), Some(p.1))
            },
            Err(e) => {
                warn!("Failed to initialize camera: {}, falling back to simulation", e);
                info!("To use camera: install camera, check permissions, or use --video-source v4l2");
                (None, None)
            }
        }
    } else {
        info!("Using simulated video ({}x{} @ {} fps)", 
              args.video_width, args.video_height, args.video_fps);
        (None, None)
    };
    
    let expected_frame_size = i420_frame_size(args.video_width, args.video_height);
    info!("Expected frame size: {} bytes ({} KB)", expected_frame_size, expected_frame_size / 1024);
    
    let mut frame_count = 0u32;
    let mut total_bytes = 0u64;
    let mut dropped_frames = 0u32;
    let stream_start = Instant::now();
    
    loop {
        // Capture frame
        let frame_data = if let Some(ref sink) = appsink {
            // Get frame from camera
            match sink.try_pull_sample(gst::ClockTime::from_mseconds(100)) {
                Some(sample) => {
                    let buffer = sample.buffer().context("Failed to get buffer")?;
                    let map = buffer.map_readable().context("Failed to map buffer")?;
                    let data = map.as_slice().to_vec();
                    
                    // Verify frame size
                    if data.len() != expected_frame_size {
                        warn!("Frame size mismatch: got {} bytes, expected {} bytes", 
                              data.len(), expected_frame_size);
                    }
                    
                    data
                },
                None => {
                    // No frame available
                    dropped_frames += 1;
                    if dropped_frames % 10 == 0 {
                        warn!("Camera frame not available (dropped {} frames so far)", dropped_frames);
                    }
                    metrics_collector.record_drop().await;
                    
                    // Use dummy data to maintain stream
                    vec![0u8; expected_frame_size]
                }
            }
        } else {
            // Simulated frame
            vec![0u8; expected_frame_size]
        };
        
        // Check if we need to rekey
        if session.should_rekey().await {
            warn!("Rekey threshold reached, performing rekey");
            let new_key = SessionKeyMaterial::generate_random();
            session.rekey(new_key).await;
        }
        
        // Build frame header
        let timestamp_us = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_micros() as u64;
        
        // Get the nonce counter BEFORE encrypting
        let cipher_guard = session.cipher.read().await;
        let nonce_counter = cipher_guard.get_counter();
        
        // Build header with the nonce counter that WILL be used
        let header = FrameHeader {
            flags: 0,
            timestamp_us,
            counter: frame_count,
            nonce_counter,
            payload_len: frame_data.len() as u32,
        };
        
        // Serialize header to use as AAD
        let aad = header.serialize();
        
        // Now encrypt - the cipher will use nonce_counter and increment it
        let ciphertext = cipher_guard.encrypt(&frame_data, &aad)?;
        drop(cipher_guard);
        
        // Send header + ciphertext
        stream.write_all(&aad).await?;
        stream.write_all(&ciphertext).await?;
        
        total_bytes += (HEADER_SIZE + ciphertext.len()) as u64;
        frame_count += 1;
        
        // Update metrics every 30 frames
        if frame_count % 30 == 0 {
            let elapsed = stream_start.elapsed().as_secs_f64();
            let fps = frame_count as f32 / elapsed as f32;
            let goodput_mbps = (total_bytes as f64 * 8.0 / elapsed) / 1_000_000.0;
            
            metrics_collector.update_stream_stats(fps, goodput_mbps as f32, 0.0).await;
            
            info!("Sent {} frames, {:.2} fps, {:.2} Mbps (dropped: {})", 
                  frame_count, fps, goodput_mbps, dropped_frames);
        }
        
        // Target frame rate (dynamic based on args)
        let frame_interval_ms = 1000 / args.video_fps as u64;
        tokio::time::sleep(Duration::from_millis(frame_interval_ms)).await;
        
        // Run for 60 seconds
        if stream_start.elapsed() > Duration::from_secs(60) {
            break;
        }
    }
    
    // Stop camera pipeline
    if let Some(pipeline) = pipeline {
        info!("Stopping camera pipeline...");
        let _ = pipeline.set_state(gst::State::Null);
    }
    
    let steady_energy = metrics_collector.calculate_energy(Some("steady")).await;
    info!("Steady-state energy: {:.3} J", steady_energy);
    info!("Total frames sent: {}, dropped: {}", frame_count, dropped_frames);
    
    // Save metrics
    metrics_collector.write_stream_csv("steady_stream.csv").await?;
    metrics_collector.write_power_csv("power_samples.csv").await?;
    
    let (lat_mean, lat_p50, lat_p95) = metrics_collector.get_latency_stats().await;
    info!("Latency: mean={:.2}ms, p50={:.2}ms, p95={:.2}ms", 
          lat_mean, lat_p50, lat_p95);
    
    Ok(())
}

async fn run_receiver(args: Args) -> Result<()> {
    info!("Starting receiver mode");
    
    let metrics_collector = Arc::new(MetricsCollector::new(args.node_id.clone()));
    let _metrics_task = metrics_collector.clone().start_collection();
    
    // Listen for connections
    let addr = format!("{}:{}", args.host, args.port);
    info!("Listening on {}", addr);
    let listener = TcpListener::bind(&addr).await?;
    
    let (mut stream, peer_addr) = listener.accept().await?;
    info!("Accepted connection from {}", peer_addr);
    
    // Perform handshake
    metrics_collector.record_power(5.0, 2.5, "handshake".to_string()).await;
    
    let (key_material, _handshake_metrics) = match args.mechanism {
        KeyMechanism::Rsa => perform_rsa_handshake(&mut stream, false, args.rsa_bits).await?,
        KeyMechanism::Ecdh => perform_ecdh_handshake(&mut stream, false).await?,
        KeyMechanism::Group => perform_group_handshake(&mut stream, &args.group_key_file).await?,
    };
    
    info!("Handshake completed");
    
    // Initialize session
    let session = SessionState::new(
        key_material,
        Duration::from_secs(args.rekey_interval),
    );
    
    metrics_collector.record_power(5.0, 2.0, "steady".to_string()).await;
    
    info!("Receiving video stream");
    
    // Initialize display if requested
    let display = if args.display {
        match VideoDisplay::new(args.video_width, args.video_height, args.video_fps) {
            Ok(d) => {
                d.start()?;
                info!("Video display initialized");
                Some(d)
            },
            Err(e) => {
                warn!("Failed to initialize display: {}, continuing without display", e);
                None
            }
        }
    } else {
        None
    };
    
    let stream_start = Instant::now();
    let mut frame_count = 0u32;
    let mut tag_failures = 0u32;
    
    loop {
        // Read frame header
        let mut header_buf = [0u8; HEADER_SIZE];
        match stream.read_exact(&mut header_buf).await {
            Ok(_) => {},
            Err(e) => {
                info!("Connection closed: {}", e);
                break;
            }
        }
        
        let header = FrameHeader::deserialize(&header_buf)?;
        
        // Read ciphertext
        let mut ciphertext = vec![0u8; header.payload_len as usize + 16]; // +16 for GCM tag
        stream.read_exact(&mut ciphertext).await?;
        
        // Decrypt and verify using the nonce_counter from header
        match session.cipher.read().await.decrypt(&ciphertext, &header_buf, header.nonce_counter) {
            Ok(plaintext) => {
                // Calculate latency
                let now_us = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_micros() as u64;
                let latency_ms = (now_us.saturating_sub(header.timestamp_us)) as f32 / 1000.0;
                
                frame_count += 1;
                
                // Display frame if enabled
                if let Some(ref display) = display {
                    if let Err(e) = display.push_frame(&plaintext) {
                        warn!("Failed to display frame: {}", e);
                    }
                }
                
                if frame_count % 30 == 0 {
                    let elapsed = stream_start.elapsed().as_secs_f64();
                    let fps = frame_count as f32 / elapsed as f32;
                    
                    metrics_collector.update_stream_stats(fps, 0.0, latency_ms).await;
                    
                    info!("Received {} frames, {:.2} fps, latency {:.2}ms (tag failures: {})", 
                          frame_count, fps, latency_ms, tag_failures);
                }
            },
            Err(e) => {
                error!("Decryption failed for frame {}: {}", frame_count, e);
                tag_failures += 1;
                metrics_collector.record_tag_failure().await;
            }
        }
        
        if stream_start.elapsed() > Duration::from_secs(60) {
            break;
        }
    }
    
    // Stop display
    if let Some(display) = display {
        display.stop()?;
    }
    
    info!("Stream completed. Frames: {}, Tag failures: {}", frame_count, tag_failures);
    
    // Save metrics
    metrics_collector.write_stream_csv("steady_stream.csv").await?;
    metrics_collector.write_power_csv("power_samples.csv").await?;
    
    Ok(())
}

async fn run_relay(args: Args) -> Result<()> {
    info!("Starting relay mode");
    
    let relay_host = args.relay_host.context("--relay-host required for relay mode")?;
    let relay_port = args.relay_port.context("--relay-port required for relay mode")?;
    
    let metrics_collector = Arc::new(MetricsCollector::new(args.node_id.clone()));
    let _metrics_task = metrics_collector.clone().start_collection();
    
    // Listen for incoming connection (from sender)
    let listen_addr = format!("{}:{}", args.host, args.port);
    info!("Relay listening on {}", listen_addr);
    let listener = TcpListener::bind(&listen_addr).await?;
    
    let (mut incoming_stream, sender_addr) = listener.accept().await?;
    info!("Accepted connection from sender: {}", sender_addr);
    
    // Connect to next hop (receiver)
    let relay_addr = format!("{}:{}", relay_host, relay_port);
    info!("Connecting to next hop: {}", relay_addr);
    let mut outgoing_stream = TcpStream::connect(&relay_addr).await?;
    info!("Connected to receiver");
    
    // Perform handshake with sender (as receiver)
    metrics_collector.record_power(5.0, 2.5, "handshake_in".to_string()).await;
    
    let (key_material_in, _) = match args.mechanism {
        KeyMechanism::Rsa => perform_rsa_handshake(&mut incoming_stream, false, args.rsa_bits).await?,
        KeyMechanism::Ecdh => perform_ecdh_handshake(&mut incoming_stream, false).await?,
        KeyMechanism::Group => perform_group_handshake(&mut incoming_stream, &args.group_key_file).await?,
    };
    
    info!("Incoming handshake completed");
    
    // Perform handshake with receiver (as sender)
    metrics_collector.record_power(5.0, 2.5, "handshake_out".to_string()).await;
    
    let (key_material_out, _) = match args.mechanism {
        KeyMechanism::Rsa => perform_rsa_handshake(&mut outgoing_stream, true, args.rsa_bits).await?,
        KeyMechanism::Ecdh => perform_ecdh_handshake(&mut outgoing_stream, true).await?,
        KeyMechanism::Group => perform_group_handshake(&mut outgoing_stream, &args.group_key_file).await?,
    };
    
    info!("Outgoing handshake completed");
    
    // Initialize sessions
    let session_in = SessionState::new(
        key_material_in,
        Duration::from_secs(args.rekey_interval),
    );
    
    let session_out = SessionState::new(
        key_material_out,
        Duration::from_secs(args.rekey_interval),
    );
    
    metrics_collector.record_power(5.0, 2.0, "steady".to_string()).await;
    
    info!("Relaying video stream");
    
    let stream_start = Instant::now();
    let mut frame_count = 0u32;
    let mut decrypt_failures = 0u32;
    
    loop {
        // Read frame header from sender
        let mut header_buf = [0u8; HEADER_SIZE];
        match incoming_stream.read_exact(&mut header_buf).await {
            Ok(_) => {},
            Err(e) => {
                info!("Connection closed: {}", e);
                break;
            }
        }
        
        let header = FrameHeader::deserialize(&header_buf)?;
        
        // Read ciphertext from sender
        let mut ciphertext_in = vec![0u8; header.payload_len as usize + 16];
        incoming_stream.read_exact(&mut ciphertext_in).await?;
        
        // Decrypt from sender
        match session_in.cipher.read().await.decrypt(&ciphertext_in, &header_buf, header.nonce_counter) {
            Ok(plaintext) => {
                frame_count += 1;
                
                // Get the nonce counter for outgoing encryption
                let cipher_guard = session_out.cipher.read().await;
                let nonce_counter_out = cipher_guard.get_counter();
                
                // Build new header with updated nonce counter
                let new_header = FrameHeader {
                    flags: header.flags,
                    timestamp_us: header.timestamp_us,
                    counter: header.counter,
                    nonce_counter: nonce_counter_out,
                    payload_len: plaintext.len() as u32,
                };
                
                let aad_out = new_header.serialize();
                
                // Re-encrypt for receiver
                let ciphertext_out = cipher_guard.encrypt(&plaintext, &aad_out)?;
                drop(cipher_guard);
                
                // Send to receiver
                outgoing_stream.write_all(&aad_out).await?;
                outgoing_stream.write_all(&ciphertext_out).await?;
                
                if frame_count % 30 == 0 {
                    let elapsed = stream_start.elapsed().as_secs_f64();
                    let fps = frame_count as f32 / elapsed as f32;
                    
                    info!("Relayed {} frames, {:.2} fps (decrypt failures: {})", 
                          frame_count, fps, decrypt_failures);
                }
            },
            Err(e) => {
                error!("Decryption failed for frame {}: {}", frame_count, e);
                decrypt_failures += 1;
                metrics_collector.record_tag_failure().await;
            }
        }
        
        if stream_start.elapsed() > Duration::from_secs(60) {
            break;
        }
    }
    
    let steady_energy = metrics_collector.calculate_energy(Some("steady")).await;
    info!("Relay completed. Frames: {}, Failures: {}, Energy: {:.3}J", 
          frame_count, decrypt_failures, steady_energy);
    
    metrics_collector.write_stream_csv("relay_stream.csv").await?;
    metrics_collector.write_power_csv("relay_power.csv").await?;
    
    Ok(())
}

async fn run_group_leader(args: Args) -> Result<()> {
    info!("Starting group leader mode");
    
    let members_str = args.members.context("--members required for group-leader mode")?;
    
    // Parse members list
    let members: Result<Vec<group_key::GroupMember>> = members_str
        .split(',')
        .map(|m| group_key::GroupMember::parse(m.trim()))
        .collect();
    let members = members?;
    
    info!("Group leader will distribute keys to {} members:", members.len());
    for member in &members {
        info!("  - {} @ {}", member.node_id, member.address);
    }
    
    let leader = group_key::LeaderNode::new(args.node_id.clone(), members);
    
    info!("Establishing group key...");
    let group_ctx = leader.establish_group_key().await?;
    
    info!("Group key established successfully!");
    info!("Key hash: {:02x?}", &group_ctx.key_hash[..8]);
    
    // Save group key to file
    save_group_key(&group_ctx.group_key, &args.group_key_file).await?;
    
    info!("Group key saved to: {}", args.group_key_file);
    info!("All members should now have the same group key.");
    
    Ok(())
}

async fn run_group_member(args: Args) -> Result<()> {
    info!("Starting group member mode");
    
    let listen_addr = format!("{}:{}", args.host, args.port);
    let member = group_key::MemberNode::new(args.node_id.clone(), listen_addr);
    
    info!("Waiting for leader to distribute group key...");
    let group_ctx = member.receive_group_key().await?;
    
    info!("Group key received successfully!");
    info!("Key hash: {:02x?}", &group_ctx.key_hash[..8]);
    
    // Save group key to file
    save_group_key(&group_ctx.group_key, &args.group_key_file).await?;
    
    info!("Group key saved to: {}", args.group_key_file);
    info!("Ready to use group key for encrypted streaming.");
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    // Print configuration if requested
    if args.print_config {
        println!("=== Configuration ===");
        println!("Mode: {:?}", args.mode);
        println!("Mechanism: {:?}", args.mechanism);
        println!("Host: {}", args.host);
        println!("Port: {}", args.port);
        println!("Node ID: {}", args.node_id);
        println!("Video Source: {}", args.video_source);
        println!("Video Device: {}", args.video_device);
        println!("Resolution: {}x{} @ {} fps", args.video_width, args.video_height, args.video_fps);
        println!("Rekey interval: {}s", args.rekey_interval);
        println!("Simulate: {}", args.simulate);
        println!("Display: {}", args.display);
        println!();
        
        log_arm_crypto_support();
        return Ok(());
    }
    
    // Log hardware crypto support
    log_arm_crypto_support();
    
    // Run appropriate mode
    match args.mode {
        Mode::Sender => run_sender(args).await,
        Mode::Receiver => run_receiver(args).await,
        Mode::Relay => run_relay(args).await,
        Mode::GroupLeader => run_group_leader(args).await,
        Mode::GroupMember => run_group_member(args).await,
    }
}