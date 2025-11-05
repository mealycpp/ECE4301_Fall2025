use anyhow::Result;
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;

pub struct Capture {
    pub pipeline: gst::Pipeline,
    pub sink: gst_app::AppSink,
}
pub struct Player {
    pub pipeline: gst::Pipeline,
    pub src: gst_app::AppSrc,
}

pub fn init_gst() -> Result<()> { gst::init()?; Ok(()) }

pub fn make_sender_pipeline(width: i32, height: i32, fps: i32) -> Result<Capture> {
    let pipeline = gst::Pipeline::default();
    let src = gst::ElementFactory::make("libcamerasrc").build().unwrap_or_else(|_| {
        gst::ElementFactory::make("v4l2src").build().expect("need a camera")
    });
    let capsfilter = gst::ElementFactory::make("capsfilter").build()?;
    let caps = gst::Caps::builder("video/x-raw")
        .field("width", width)
        .field("height", height)
        .field("framerate", gst::Fraction::new(fps,1))
        .build();
    // In your version this returns (), not Result
    capsfilter.set_property("caps", &caps);

    let conv = gst::ElementFactory::make("videoconvert").build()?;
    // x264 software encoder; low-latency settings
    let enc = gst::ElementFactory::make("x264enc")
        .property_from_str("tune", "zerolatency")
        .property_from_str("speed-preset", "ultrafast")
        .property("bitrate", 1500u32)           // <-- unsigned integer!
        .property("key-int-max", 30u32)         // <-- make this unsigned too
        .build()?;

    let h264caps = gst::ElementFactory::make("capsfilter").build()?;
    let hcaps = gst::Caps::builder("video/x-h264")
        .field("stream-format", "byte-stream")
        .field("alignment", "au")
        .build();
    h264caps.set_property("caps", &hcaps);

    let sink = gst::ElementFactory::make("appsink")
        .property("emit-signals", true)
        .property("sync", false)
        .build()?;
    let sink = sink.dynamic_cast::<gst_app::AppSink>().unwrap();

    pipeline.add_many(&[&src, &capsfilter, &conv, &enc, &h264caps, sink.upcast_ref()])?;
    gst::Element::link_many(&[&src, &capsfilter, &conv, &enc, &h264caps, sink.upcast_ref()])?;
    pipeline.set_state(gst::State::Playing)?;
    Ok(Capture{ pipeline, sink })
}

pub fn pull_h264_sample(cap: &Capture) -> Result<Vec<u8>> {
    let sample = cap.sink.pull_sample()?;                          // already Result
    let buf = sample.buffer().ok_or_else(|| anyhow::anyhow!("no buffer"))?;
    let map = buf.map_readable()?;                                 // <-- use ? here
    Ok(map.as_slice().to_vec())
}

pub fn make_receiver_pipeline() -> Result<Player> {
    let pipeline = gst::Pipeline::default();
    let src = gst::ElementFactory::make("appsrc")
        .property("is-live", true)
        .property("format", gst::Format::Time)
        .build()?;
    let src = src.dynamic_cast::<gst_app::AppSrc>().unwrap();

    let caps = gst::Caps::builder("video/x-h264")
        .field("stream-format", "byte-stream")
        .field("alignment", "au")
        .build();
    src.set_caps(Some(&caps));

    let parse = gst::ElementFactory::make("h264parse").build()?;
    let dec = gst::ElementFactory::make("avdec_h264").build()?;
    let conv = gst::ElementFactory::make("videoconvert").build()?;
    let sink = gst::ElementFactory::make("autovideosink")
        .property("sync", false)
        .build()?;

    pipeline.add_many(&[src.upcast_ref(), &parse, &dec, &conv, &sink])?;
    gst::Element::link_many(&[src.upcast_ref(), &parse, &dec, &conv, &sink])?;
    pipeline.set_state(gst::State::Playing)?;
    Ok(Player{ pipeline, src })
}

pub fn push_h264_frame(player: &Player, data: &[u8]) -> anyhow::Result<()> {
    let mut buf = gst::Buffer::with_size(data.len())
        .map_err(|e| anyhow::anyhow!("alloc buffer: {e:?}"))?;

    {
        // Get a mutable BufferRef, then map it writable
        let buf_ref = buf
            .get_mut()
            .ok_or_else(|| anyhow::anyhow!("failed to get mutable buffer ref"))?;
        let mut map = buf_ref
            .map_writable()
            .map_err(|e| anyhow::anyhow!("map writable failed: {e:?}"))?;
        map.as_mut_slice().copy_from_slice(data);
    }

    player.src.push_buffer(buf)?;
    Ok(())
}


