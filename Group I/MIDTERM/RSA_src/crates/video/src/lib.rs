use anyhow::{anyhow, Context, Result};
use std::{sync::Once, time::Duration};

use gstreamer as gst;
use gstreamer_app as gst_app;
use gst::prelude::*;
use gstreamer_app::prelude::*;
use tokio::sync::mpsc;

static GST_INIT: Once = Once::new();
fn ensure_gst() {
    GST_INIT.call_once(|| gst::init().expect("gstreamer init"));
}

/// Simple path escaper for filesrc location=""
fn escape_path(path: &str) -> String {
    path.replace('\\', "\\\\").replace('"', "\\\"")
}

fn attach_bus_log(p: &gst::Pipeline, tag: &'static str) {
    if let Some(bus) = p.bus() {
        let bus = bus.clone();
        std::thread::spawn(move || {
            use gst::message::MessageView;
            while let Some(msg) = bus.timed_pop(gst::ClockTime::from_seconds(1)) {
                match msg.view() {
                    MessageView::Error(e) => eprintln!("[{tag}] GST ERROR: {} ({:?})", e.error(), e.debug()),
                    MessageView::Warning(w) => eprintln!("[{tag}] GST WARN: {} ({:?})", w.error(), w.debug()),
                    _ => {}
                }
            }
        });
    }
}

/// Build a pipeline, set PLAYING, and wire its appsink("sink") to a Tokio mpsc channel.
fn setup_appsink_pipeline(desc: &str, tag: &'static str) -> Result<(mpsc::Receiver<Vec<u8>>, gst::Pipeline)> {
    ensure_gst();

    let pipeline = gst::parse::launch(desc)
        .with_context(|| format!("parse_launch {tag} pipeline"))?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow!("not a pipeline"))?;

    attach_bus_log(&pipeline, tag);

    let sink = pipeline
        .by_name("sink")
        .ok_or_else(|| anyhow!("appsink not found"))?
        .downcast::<gst_app::AppSink>()
        .map_err(|_| anyhow!("appsink cast failed"))?;

    pipeline
        .set_state(gst::State::Playing)
        .map_err(|e| anyhow!("Element failed to change state: {e}"))?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        while let Ok(sample) = sink.pull_sample() {
            if let Some(buf) = sample.buffer() {
                if let Ok(map) = buf.map_readable() {
                    let _ = tx.blocking_send(map.as_slice().to_vec());
                }
            }
        }
        // EOS/error → channel closes
    });

    Ok((rx, pipeline))
}

/// Pi CSI camera via libcamerasrc. NV12 from ISP.
/// Try HW encoder first; if starting fails, fall back to x264 (software).
pub fn start_h264_capture_libcamera(
    width: i32,
    height: i32,
    fps: i32,
) -> Result<(mpsc::Receiver<Vec<u8>>, gst::Pipeline)> {
    // HW first: libcamerasrc(NV12) → v4l2h264enc → h264parse → caps(byte-stream, AU) → appsink
    let hw = format!(
        "libcamerasrc ! \
         video/x-raw,format=NV12,width={width},height={height},framerate={fps}/1 ! \
         v4l2h264enc extra-controls=\"controls,repeat_sequence_header=1\" ! \
         h264parse config-interval=1 ! \
         video/x-h264,stream-format=byte-stream,alignment=au ! \
         appsink name=sink emit-signals=true sync=false max-buffers=10 drop=true"
    );

    match setup_appsink_pipeline(&hw, "libcamera-hw") {
        Ok(ok) => Ok(ok),
        Err(e_hw) => {
            eprintln!("[video] HW encoder path failed, falling back to x264: {e_hw}");
            // SW fallback: libcamerasrc(NV12) → videoconvert → x264enc → h264parse → caps(byte-stream, AU) → appsink
            let sw = format!(
                "libcamerasrc ! \
                 video/x-raw,format=NV12,width={width},height={height},framerate={fps}/1 ! \
                 videoconvert ! \
                 x264enc tune=zerolatency speed-preset=ultrafast bitrate=1500 key-int-max=30 ! \
                 h264parse config-interval=1 ! \
                 video/x-h264,stream-format=byte-stream,alignment=au ! \
                 appsink name=sink emit-signals=true sync=false max-buffers=10 drop=true"
            );
            setup_appsink_pipeline(&sw, "libcamera-sw")
        }
    }
}

/// UVC webcam via v4l2src + x264enc.
pub fn start_h264_capture_v4l2(
    device: &str,
    width: i32,
    height: i32,
    fps: i32,
) -> Result<(mpsc::Receiver<Vec<u8>>, gst::Pipeline)> {
    let desc = format!(
        "v4l2src device={device} ! \
         video/x-raw,width={width},height={height},framerate={fps}/1 ! \
         videoconvert ! \
         x264enc tune=zerolatency speed-preset=ultrafast bitrate=1500 key-int-max=30 ! \
         h264parse config-interval=1 ! \
         video/x-h264,stream-format=byte-stream,alignment=au ! \
         appsink name=sink emit-signals=true sync=false max-buffers=10 drop=true"
    );
    setup_appsink_pipeline(&desc, "v4l2cap")
}

/// Playback: appsrc (H.264 byte-stream, AU-aligned) → parse → decode → autovideosink.
/// Returns a Sender<Vec<u8>> you feed with decrypted H.264 access units.
pub fn start_h264_playback(fps: i32) -> Result<(mpsc::Sender<Vec<u8>>, gst::Pipeline)> {
    ensure_gst();

    let desc =
        "appsrc name=src is-live=true format=time \
         caps=video/x-h264,stream-format=byte-stream,alignment=au \
         ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false";

    let pipeline = gst::parse::launch(desc)?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow!("not a pipeline"))?;

    attach_bus_log(&pipeline, "playback");

    let appsrc = pipeline
        .by_name("src")
        .ok_or_else(|| anyhow!("appsrc not found"))?
        .downcast::<gst_app::AppSrc>()
        .map_err(|_| anyhow!("appsrc cast failed"))?;

    pipeline.set_state(gst::State::Playing).context("playback set Playing")?;

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        // Timestamp frames if fps > 0
        let frame_ns = if fps > 0 {
            Some(Duration::from_nanos(1_000_000_000u64 / fps as u64))
        } else {
            None
        };
        let mut pts = 0u64;

        while let Some(bytes) = rx.recv().await {
            let mut buf = gst::Buffer::from_slice(bytes);
            if let Some(fd) = frame_ns {
                if let Some(b) = buf.get_mut() {
                    b.set_pts(gst::ClockTime::from_nseconds(pts));
                    b.set_dts(gst::ClockTime::from_nseconds(pts));
                }
                pts = pts.saturating_add(fd.as_nanos() as u64);
            }
            let _ = appsrc.push_buffer(buf);
        }
        let _ = appsrc.end_of_stream();
    });

    Ok((tx, pipeline))
}

/// Optional: use a local video file as the source (great for testing without a camera).
pub fn start_h264_from_file(path: &str) -> Result<(mpsc::Receiver<Vec<u8>>, gst::Pipeline)> {
    ensure_gst();
    let desc = format!(
        "filesrc location=\"{}\" ! decodebin ! videoconvert ! \
         x264enc tune=zerolatency speed-preset=ultrafast bitrate=1500 key-int-max=30 ! \
         h264parse config-interval=1 ! \
         video/x-h264,stream-format=byte-stream,alignment=au ! \
         appsink name=sink emit-signals=true sync=false max-buffers=10 drop=true",
        escape_path(path)
    );
    setup_appsink_pipeline(&desc, "filecap")
}