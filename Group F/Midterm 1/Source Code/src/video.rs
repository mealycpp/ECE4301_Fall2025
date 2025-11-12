use anyhow::Result;
use gstreamer as gst;
use gstreamer_app as gst_app;
use gstreamer::prelude::*; // for ElementExt, set_state, etc.

pub fn init() -> Result<()> { gst::init()?; Ok(()) }

pub fn build_sender_640x480() -> Result<(gst::Pipeline, gst_app::AppSink)> {
    let e = gst::parse::launch(
        "v4l2src ! video/x-raw,format=I420,width=640,height=480,framerate=15/1 ! \
         videoconvert ! x264enc tune=zerolatency bitrate=1200 speed-preset=superfast ! \
         h264parse config-interval=1 ! appsink name=mysink emit-signals=true sync=false"
    )?;
    let pipeline = e.downcast::<gst::Pipeline>()
        .map_err(|el| anyhow::anyhow!("not a pipeline: {:?}", el))?;
    let appsink = pipeline
        .by_name("mysink").ok_or_else(|| anyhow::anyhow!("appsink not found"))?
        .downcast::<gst_app::AppSink>().map_err(|el| anyhow::anyhow!("downcast AppSink: {:?}", el))?;
    Ok((pipeline, appsink))
}

pub fn build_receiver() -> Result<(gst::Pipeline, gst_app::AppSrc)> {
    let e = gst::parse::launch(
        "appsrc name=mysrc is-live=true format=time do-timestamp=true ! \
         h264parse ! avdec_h264 ! videoconvert ! fakesink sync=true"
    )?;
    let pipeline = e.downcast::<gst::Pipeline>()
        .map_err(|el| anyhow::anyhow!("not a pipeline: {:?}", el))?;
    let appsrc = pipeline
        .by_name("mysrc").ok_or_else(|| anyhow::anyhow!("appsrc not found"))?
        .downcast::<gst_app::AppSrc>().map_err(|el| anyhow::anyhow!("downcast AppSrc: {:?}", el))?;
    Ok((pipeline, appsrc))
}
