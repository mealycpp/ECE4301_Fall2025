// src/video/mod.rs  (showing only the two fns to keep)

use anyhow::Result;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSrc};

// src/video/mod.rs

pub mod sender;
pub mod receiver;

// Re-export so code can do `video::Sender` and `video::Receiver`
pub use sender::Sender;
pub use receiver::Receiver;

// ... keep your existing gst_init_once(), make_sender_pipeline(), make_receiver_pipeline() ...


pub fn gst_init_once() -> Result<()> {
    gst::init()?;
    Ok(())
}

pub fn make_sender_pipeline(device: &str, width: i32, height: i32, fps: i32)
    -> Result<(gst::Pipeline, AppSink)>
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
        .downcast::<AppSink>()
        .map_err(|_| anyhow::anyhow!("appsink downcast failed"))?;

    Ok((pipeline, sink))
}

pub fn make_receiver_pipeline(width: i32, height: i32, fps: i32)
    -> Result<(gst::Pipeline, AppSrc)>
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
        .downcast::<AppSrc>()
        .map_err(|_| anyhow::anyhow!("appsrc downcast failed"))?;

    Ok((pipeline, src))
}
