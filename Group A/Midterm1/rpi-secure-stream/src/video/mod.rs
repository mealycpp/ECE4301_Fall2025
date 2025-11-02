// src/video/mod.rs
use anyhow::{anyhow, Result};
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSrc};

pub mod sender;
pub mod receiver;

pub use sender::Sender;
pub use receiver::Receiver;

pub fn gst_init_once() -> Result<()> {
    // Safe to call repeatedly; returns Ok if already initialized.
    gst::init()?;
    Ok(())
}

pub fn make_sender_pipeline(device: &str, width: i32, height: i32, fps: i32)
    -> Result<(gst::Pipeline, AppSink)>
{
    gst_init_once()?;
    let pipeline_desc = format!(
        "v4l2src device={device} ! videoconvert ! \
         video/x-raw,format=I420,width={width},height={height},framerate={fps}/1 \
         ! queue max-size-buffers=4 \
         ! appsink name=sink emit-signals=true sync=false drop=true"
    );
    let pipeline = gst::parse::launch(&pipeline_desc)?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow!("not a pipeline"))?;
    let sink = pipeline
        .by_name("sink")
        .ok_or_else(|| anyhow!("appsink not found"))?
        .downcast::<AppSink>()
        .map_err(|_| anyhow!("appsink downcast failed"))?;
    Ok((pipeline, sink))
}

pub fn make_receiver_pipeline(width: i32, height: i32, fps: i32)
    -> Result<(gst::Pipeline, AppSrc)>
{
    gst_init_once()?;
    let pipeline_desc = format!(
        "appsrc name=src is-live=true format=time \
         caps=video/x-raw,format=I420,width={width},height={height},framerate={fps}/1 \
         ! videoconvert ! autovideosink"
    );
    let pipeline = gst::parse::launch(&pipeline_desc)?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow!("not a pipeline"))?;
    let src = pipeline
        .by_name("src")
        .ok_or_else(|| anyhow!("appsrc not found"))?
        .downcast::<AppSrc>()
        .map_err(|_| anyhow!("appsrc downcast failed"))?;
    Ok((pipeline, src))
}

pub fn make_receiver_pipeline_headless(width: i32, height: i32, fps: i32)
    -> Result<(gst::Pipeline, AppSrc)>
{
    gst_init_once()?;

    // identical to normal, but ends with fakesink so no display is needed
    let pipeline_desc = format!(
        "appsrc name=src is-live=true format=time \
         caps=video/x-raw,format=I420,width={width},height={height},framerate={fps}/1 \
         ! videoconvert ! fakesink sync=false",
    );

    let pipeline = gst::parse::launch(&pipeline_desc)?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow!("not a pipeline"))?;
    let src = pipeline
        .by_name("src")
        .ok_or_else(|| anyhow!("appsrc not found"))?
        .downcast::<AppSrc>()
        .map_err(|_| anyhow!("appsrc downcast failed"))?;

    Ok((pipeline, src))
}

// src/video/mod.rs (receiver/display)
pub fn make_receiver_pipeline(width: i32, height: i32, fps: i32)
    -> anyhow::Result<(gst::Pipeline, gstreamer_app::AppSrc)>
{
    gst_init_once()?;

    let desc = format!(
        "appsrc name=src is-live=true format=time do-timestamp=true block=false
         caps=video/x-raw,format=I420,width={width},height={height},framerate={fps}/1 !
         queue max-size-buffers=10 leaky=downstream !
         videoconvert !
         autovideosink sync=false"
    );

    let pipeline = gst::parse::launch(&desc)?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow::anyhow!("not a pipeline"))?;

    let src = pipeline
        .by_name("src").ok_or_else(|| anyhow::anyhow!("appsrc not found"))?
        .downcast::<gstreamer_app::AppSrc>()
        .map_err(|_| anyhow::anyhow!("appsrc downcast failed"))?;

    Ok((pipeline, src))
}

// src/video/mod.rs (sender side)
pub fn make_sender_pipeline(device: &str, width: i32, height: i32, fps: i32)
    -> anyhow::Result<(gst::Pipeline, gstreamer_app::AppSink)>
{
    gst_init_once()?;

    let desc = format!(
        "v4l2src device={device} do-timestamp=true !
         queue max-size-buffers=5 leaky=downstream !
         videoconvert !
         video/x-raw,format=I420,width={width},height={height},framerate={fps}/1 !
         queue max-size-buffers=5 leaky=downstream !
         appsink name=sink sync=false max-buffers=2 drop=true emit-signals=false"
    );

    let pipeline = gst::parse::launch(&desc)?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow::anyhow!("not a pipeline"))?;

    let sink = pipeline
        .by_name("sink").ok_or_else(|| anyhow::anyhow!("appsink not found"))?
        .downcast::<gstreamer_app::AppSink>()
        .map_err(|_| anyhow::anyhow!("appsink downcast failed"))?;

    Ok((pipeline, sink))
}
