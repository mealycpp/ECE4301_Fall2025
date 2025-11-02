use anyhow::Result;
use clap::Parser;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSinkCallbacks};

use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

/// Camera -> H264 -> TCP (length-prefixed AU frames)
#[derive(Parser, Debug)]
#[command(name = "sender_plain")]
#[command(about = "Camera -> H264 -> TCP (length-prefixed AU frames)", long_about=None)]
struct Args {
    /// Receiver IP:PORT (e.g., 192.168.1.10:6000)
    #[arg(long, value_name = "IP:PORT")]
    dest: String,

    /// Width (default 640)
    #[arg(long, default_value_t = 640)]
    width: u32,

    /// Height (default 480)
    #[arg(long, default_value_t = 480)]
    height: u32,

    /// FPS (default 15)
    #[arg(long, default_value_t = 15)]
    fps: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();
    gst::init()?;

    // Open TCP connection to receiver
    let stream = TcpStream::connect(&args.dest)?;
    stream.set_nodelay(true)?;
    let stream = Arc::new(Mutex::new(stream));

    // Pipeline: camera -> H.264 encoder -> appsink
    let launch = format!(
        "libcamerasrc ! video/x-raw,format=NV12,width={w},height={h},framerate={f}/1 \
         ! videoconvert \
         ! x264enc tune=zerolatency speed-preset=ultrafast key-int-max={gop} bitrate=1200 \
         ! video/x-h264,stream-format=byte-stream,alignment=au \
         ! appsink name=appsink emit-signals=false sync=false max-buffers=1 drop=true",
        w = args.width,
        h = args.height,
        f = args.fps,
        gop = args.fps * 2
    );

    // ✅ Updated for GStreamer 0.22:
    let pipeline = gst::parse::launch(&launch)?
        .downcast::<gst::Pipeline>()
        .expect("not a pipeline");

    let appsink: AppSink = pipeline
        .by_name("appsink")
        .expect("appsink not found")
        .dynamic_cast::<AppSink>()
        .expect("appsink has wrong type");

    let stream_for_cb = Arc::clone(&stream);

    appsink.set_callbacks(
        AppSinkCallbacks::builder()
            .new_sample(move |sink| -> Result<gst::FlowSuccess, gst::FlowError> {
                // Pull encoded H.264 AU
                let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;
                let map = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;
                let data = map.as_slice();

                // Send over TCP with 4-byte length prefix
                let mut guard = stream_for_cb.lock().unwrap();
                let len: u32 = data.len().try_into().unwrap_or(u32::MAX);
                guard.write_all(&len.to_be_bytes()).map_err(|_| gst::FlowError::Error)?;
                guard.write_all(data).map_err(|_| gst::FlowError::Error)?;

                Ok(gst::FlowSuccess::Ok)
            })
            .build(),
    );

    // Start streaming
    pipeline.set_state(gst::State::Playing)?;

    let bus = pipeline.bus().expect("pipeline without bus");
    for msg in bus.iter_timed(gst::ClockTime::NONE) {
        use gst::MessageView;
        match msg.view() {
            MessageView::Error(err) => {
                eprintln!(
                    "GStreamer error from {:?}: {}",
                    err.src().map(|s| s.path_string()),
                    err.error()
                );
                eprintln!("Debug: {:?}", err.debug());
                break;
            }
            MessageView::Eos(..) => {
                eprintln!("EOS received");
                break;
            }
            _ => {}
        }
    }

    pipeline.set_state(gst::State::Null)?;
    Ok(())
}
