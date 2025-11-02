use anyhow::Result;
use clap::Parser;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use std::io::Read;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

/// TCP (length-prefixed H.264 AUs) → appsrc → decode → display
#[derive(Parser, Debug)]
#[command(name = "receiver_plain")]
#[command(about = "Receive length-prefixed H.264 AUs over TCP and display", long_about=None)]
struct Args {
    /// Listen address (e.g. 0.0.0.0:6000)
    #[arg(long, default_value = "0.0.0.0:6000")]
    listen: String,
}

static RX_CT: AtomicU64 = AtomicU64::new(0);

fn main() -> Result<()> {
    let args = Args::parse();
    gst::init()?;

    // Choose display sink via env var (fakesink/autovideosink/kmssink)
    let sink = std::env::var("SINK").unwrap_or_else(|_| "autovideosink".to_string());

    let launch = format!(
        "appsrc name=src is-live=true do-timestamp=true format=time \
         ! queue max-size-buffers=4 leaky=downstream \
         ! h264parse config-interval=1 \
         ! avdec_h264 \
         ! videoconvert \
         ! {} sync=false",
        sink
    );

    let pipeline = gst::parse::launch(&launch)?
        .downcast::<gst::Pipeline>()
        .expect("pipeline");

    let appsrc: AppSrc = pipeline
        .by_name("src")
        .expect("appsrc not found")
        .dynamic_cast::<AppSrc>()
        .expect("appsrc type");

    // Caps: match sender (byte-stream + AU alignment)
    let caps = gst::Caps::builder("video/x-h264")
        .field("stream-format", "byte-stream")
        .field("alignment", "au")
        .build();
    appsrc.set_caps(Some(&caps));

    // Explicitly set live/timestamp behavior (typed setters return ())
    appsrc.set_is_live(true);
    appsrc.set_format(gst::Format::Time);
    appsrc.set_do_timestamp(true);

    pipeline.set_state(gst::State::Playing)?;

    // TCP listener (single client)
    let listener = TcpListener::bind(&args.listen)?;
    println!("Listening on {}", args.listen);
    let (mut stream, addr) = listener.accept()?;
    println!("Client connected from {addr}");

    // Reader thread: TCP -> length-prefixed frames -> appsrc
    let appsrc_clone = appsrc.clone();
    thread::spawn(move || -> Result<()> {
        let mut len_buf = [0u8; 4];
        loop {
            if stream.read_exact(&mut len_buf).is_err() {
                println!("Connection closed");
                let _ = appsrc_clone.end_of_stream();
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;

            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload)?;

            let gst_buf = gst::Buffer::from_mut_slice(payload);
            match appsrc_clone.push_buffer(gst_buf) {
                Ok(_) => {
                    let n = RX_CT.fetch_add(1, Ordering::Relaxed) + 1;
                    if n % 30 == 0 {
                        eprintln!("receiver: fed {} frames (last push OK)", n);
                    }
                }
                Err(e) => {
                    eprintln!("receiver: push_buffer error: {e:?}");
                    let _ = appsrc_clone.end_of_stream();
                    break;
                }
            }
        }
        Ok(())
    });

    // Bus loop
    let bus = pipeline.bus().expect("no bus");
    for msg in bus.iter_timed(gst::ClockTime::NONE) {
        use gst::MessageView;
        match msg.view() {
            MessageView::Eos(..) => {
                println!("EOS");
                break;
            }
            MessageView::Error(err) => {
                eprintln!(
                    "GStreamer error from {:?}: {}",
                    err.src().map(|s| s.path_string()),
                    err.error()
                );
                eprintln!("Debug: {:?}", err.debug());
                break;
            }
            _ => {}
        }
    }

    pipeline.set_state(gst::State::Null)?;
    Ok(())
}
