use anyhow::Result;
use clap::Parser;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::{AppSrc, AppSrcCallbacks};
use std::io::Read;
use std::net::TcpListener;
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

fn main() -> Result<()> {
    let args = Args::parse();
    gst::init()?;

    // Build playback pipeline
    let pipeline = gst::parse::launch(
        "appsrc name=src is-live=true format=3 do-timestamp=true \
         ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false",
    )?
    .downcast::<gst::Pipeline>()
    .expect("pipeline");

    let appsrc: AppSrc = pipeline
        .by_name("src")
        .expect("appsrc not found")
        .dynamic_cast::<AppSrc>()
        .expect("appsrc type");

    appsrc.set_caps(Some(
        &gst::Caps::builder("video/x-h264")
            .field("stream-format", "byte-stream")
            .field("alignment", "au")
            .build(),
    ));

    pipeline.set_state(gst::State::Playing)?;

    let listener = TcpListener::bind(&args.listen)?;
    println!("Listening on {}", args.listen);
    let (mut stream, addr) = listener.accept()?;
    println!("Client connected from {addr}");

    // spawn background thread reading TCP -> appsrc
    let appsrc_clone = appsrc.clone();
    thread::spawn(move || -> Result<()> {
        let mut len_buf = [0u8; 4];
        loop {
            if stream.read_exact(&mut len_buf).is_err() {
                println!("Connection closed");
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf)?;
            let gst_buf = gst::Buffer::from_mut_slice(buf);
            appsrc_clone.push_buffer(gst_buf)?;
        }
        Ok(())
    });

    // keep main thread alive until EOS or error
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
                break;
            }
            _ => {}
        }
    }

    pipeline.set_state(gst::State::Null)?;
    Ok(())
}
