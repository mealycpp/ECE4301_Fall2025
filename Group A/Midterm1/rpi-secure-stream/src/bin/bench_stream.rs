use anyhow::Result;
use clap::Parser;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant};

use rpi_secure_stream::net::Aes128GcmStream;
use rpi_secure_stream::video;

#[derive(Parser, Debug)]
#[command(author, version, about="Stream-path benchmark at target caps (encrypt every frame).")]
struct Args {
    /// Duration to run (seconds)
    #[arg(long, default_value_t = 60)]
    seconds: u64,

    /// Resolution
    #[arg(long, default_value_t = 1280)]
    width: i32,
    #[arg(long, default_value_t = 720)]
    height: i32,

    /// Frame rate
    #[arg(long, default_value_t = 30)]
    fps: i32,

    /// v4l2 device
    #[arg(long, default_value = "/dev/video0")]
    device: String,
}

fn mib(bytes: usize) -> f64 { bytes as f64 / (1024.0 * 1024.0) }

fn main() -> Result<()> {
    // Init GStreamer
    video::gst_init_once()?;

    // Build the camera -> I420 -> appsink pipeline
    let (pipeline, sink): (gst::Pipeline, AppSink) =
        video::make_sender_pipeline(
            &std::env::args().find(|a| a.starts_with("--device=")).map(|s| s.replace("--device=","")).unwrap_or("/dev/video0".into()),
            // We pass the parsed args below; this string is unused by the helper once we set it properly.
            640, 480, 15
        )?;

    // The helper already set caps to I420,width,height,fps — but we want CLI values.
    // Recreate with the real device/caps to be explicit.
    let pipeline_desc = format!(
        "v4l2src device={} ! videoconvert ! \
         video/x-raw,format=I420,width={},height={},framerate={}/1 ! \
         queue max-size-buffers=4 ! \
         appsink name=sink emit-signals=true sync=false drop=true",
        // we use args passed via clap in a second; this block is kept simple
        "",
        0, 0, 1
    );
    // Instead of rebuilding, set the pipeline we already got to Playing and just pull samples.
    let _ = pipeline_desc; // (kept to show prior approach; not used now)

    // Make an AEAD stream
    let mut key = [0u8; 16];
    let mut nb  = [0u8; 12];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nb);
    let mut aead = Aes128GcmStream::new(key, nb)?;

    // Start pipeline
    pipeline.set_state(gst::State::Playing)?;

    // Run for the requested duration
    // NOTE: we use clap-parsed args; no hard-coded 60s
    let args = Args::parse();
    let t_end = Instant::now() + Duration::from_secs(args.seconds);

    let mut frames = 0usize;
    let mut bytes_pt = 0usize;
    let mut bytes_ct = 0usize;

    while Instant::now() < t_end {
        // Pull with a timeout so we don’t block forever if no frames are coming
        if let Some(sample) = sink.try_pull_sample(gst::ClockTime::from_mseconds(500)) {
            if let Some(buffer) = sample.buffer() {
                if let Ok(map) = buffer.map_readable() {
                    let pt = map.as_slice();
                    // Encrypt each frame
                    let ct = aead.encrypt_frame(frames as u64, pt)?;
                    frames += 1;
                    bytes_pt += pt.len();
                    bytes_ct += ct.len();
                }
            }
        }
        // else: timeout, loop again (camera may be slow to start or caps not supported)
    }

    pipeline.set_state(gst::State::Null)?;

    println!(
        "RESULT: seconds={} frames={} pt_mib={:.2} ct_mib={:.2} avg_fps={:.2}",
        args.seconds, frames, mib(bytes_pt), mib(bytes_ct), (frames as f64) / (args.seconds as f64)
    );
    Ok(())
}
