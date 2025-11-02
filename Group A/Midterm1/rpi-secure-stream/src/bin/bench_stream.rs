use anyhow::Result;
use clap::Parser;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::time::Instant;
use rpi_secure_stream::net::Aes128GcmStream;
use rpi_secure_stream::video; // only once
use std::time::Duration;
//use gstreamer::query::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about="Stream-path benchmark at the target requirement (720p@30).")]
struct Args {
    /// Duration to run (seconds)
    #[arg(long, default_value_t = 60)]
    seconds: u64,

    /// Resolution (default 1280x720)
    #[arg(long, default_value_t = 1280)]
    width: i32,
    #[arg(long, default_value_t = 720)]
    height: i32,

    /// Frame rate (default 30)
    #[arg(long, default_value_t = 30)]
    fps: i32,

    /// v4l2 device
    #[arg(long, default_value = "/dev/video0")]
    device: String,
}

fn mib(bytes: usize) -> f64 { bytes as f64 / (1024.0*1024.0) }

fn main() -> Result<()> {
    video::gst_init_once()?;

    // Build sender-side appsink only; we measure capture + encrypt throughput (no network/GStreamer sink).
    let (pipeline, sink): (gst::Pipeline, AppSink) = video::make_sender_pipeline(
        &format!("v4l2:{}", &""), // not used here; we provide full desc below if needed
        // but use the function signature as-is; we pass device string directly below
        // NOTE: to force a specific device, we override pipeline below:
        1280, 720, 30
    )?;

    // Override with desired caps by rebuilding using given device (simplify: rebuild descriptor directly)
    let pipeline_desc = format!(
        "v4l2src device={} ! videoconvert ! video/x-raw,format=I420,width={},height={},framerate={}/1 ! queue max-size-buffers=4 ! appsink name=sink emit-signals=true sync=false drop=true",
        &std::env::args().find(|a| a.starts_with("--device=")).map(|s| s.replace("--device=","")).unwrap_or("/dev/video0".into()),
        1280, 720, 30
    );
    let pipeline = gst::parse::launch(&pipeline_desc)?.downcast::<gst::Pipeline>().unwrap();
    let sink = pipeline.by_name("sink").unwrap().downcast::<AppSink>().unwrap();

    // Make an AEAD stream
    let mut key = [0u8; 16]; let mut nb = [0u8; 12];
    OsRng.fill_bytes(&mut key); OsRng.fill_bytes(&mut nb);
    let mut aead = Aes128GcmStream::new(key, nb)?;

    pipeline.set_state(gst::State::Playing)?;
    let t_end = Instant::now() + Duration::from_secs(60);

    let mut frames = 0usize;
    let mut bytes_pt = 0usize;
    let mut bytes_ct = 0usize;

    while Instant::now() < t_end {
        if let Some(sample) = sink.try_pull_sample(gst::ClockTime::from_seconds(2)) {
            let buffer = sample.buffer().ok_or_else(|| anyhow::anyhow!("no buffer"))?;
            let map = buffer.map_readable().map_err(|_| anyhow::anyhow!("map failed"))?;
            let pt = map.as_slice();
            let ct = aead.encrypt_frame(frames as u64, pt)?;
            frames += 1;
            bytes_pt += pt.len();
            bytes_ct += ct.len();
        }
    }

    pipeline.set_state(gst::State::Null)?;

    println!(
        "RESULT: seconds=60 frames={} pt_mib={:.2} ct_mib={:.2} avg_fps={:.2}",
        frames, mib(bytes_pt), mib(bytes_ct), frames as f64 / 60.0
    );
    Ok(())
}
