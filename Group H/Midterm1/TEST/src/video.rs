use gstreamer as gst;
use gstreamer_app as gst_app;
use gst::prelude::*;
use gstreamer::ClockTime;
use std::sync::mpsc::{channel, Receiver};

pub fn start_sender_pipeline(
    dev: &str,
    width: i32,
    height: i32,
    fps: i32,
) -> anyhow::Result<Receiver<Vec<u8>>> {
    gst::init()?;

    // C922: MJPEG -> decode -> H.264 (low-latency) -> appsink (H.264 byte-stream AUs)
    let pipeline = gst::parse::launch(&format!(r#"
        v4l2src device={dev} !
        image/jpeg,width={w},height={h},framerate={f}/1 !
        jpegdec ! videoconvert !
        x264enc tune=zerolatency speed-preset=ultrafast bitrate=1500 key-int-max=30 bframes=0 !
        h264parse config-interval=-1 !
        video/x-h264,stream-format=byte-stream,alignment=au !
        appsink name=sink emit-signals=true sync=false max-buffers=8 drop=true
    "#, dev=dev, w=width, h=height, f=fps))?
    .downcast::<gst::Pipeline>()
    .unwrap();

    let appsink = pipeline
        .by_name("sink").unwrap()
        .downcast::<gst_app::AppSink>().unwrap();

    let (tx, rx) = channel::<Vec<u8>>();
    appsink.set_callbacks(
        gst_app::AppSinkCallbacks::builder()
            .new_sample(move |sink| {
                let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;
                let map = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;
                if tx.send(map.as_slice().to_vec()).is_err() { return Err(gst::FlowError::Eos); }
                Ok(gst::FlowSuccess::Ok)
            })
            .build(),
    );

    pipeline.set_state(gst::State::Playing)?;
    Ok(rx)
}

pub struct ReceiverVideo {
    appsrc: gst_app::AppSrc,
    _pipeline: gst::Pipeline,
}

impl ReceiverVideo {
    pub fn new() -> anyhow::Result<Self> {
        gst::init()?;

        // Robust on Wayland/WayVNC
	let pipeline = gst::parse::launch(
	    "appsrc name=src is-live=true block=true format=time do-timestamp=true ! \
	     h264parse config-interval=-1 ! \
	     avdec_h264 ! \
	     videoconvert ! queue ! \
	     autovideosink sync=false"
	)?
	.downcast::<gst::Pipeline>()
	.unwrap();

        let appsrc = pipeline.by_name("src").unwrap().downcast::<gst_app::AppSrc>().unwrap();

	let caps = gst::Caps::builder("video/x-h264")
	    .field("stream-format", "byte-stream")
	    .field("alignment", "au")
	    .build();
	appsrc.set_caps(Some(&caps));

        appsrc.set_max_bytes(1_000_000);
        appsrc.set_latency(ClockTime::from_mseconds(0), ClockTime::from_mseconds(250));

        pipeline.set_state(gst::State::Playing)?;
        Ok(Self { appsrc, _pipeline: pipeline })
    }

    pub fn push_au(&self, bytes: &[u8]) {
        let mut buf = gst::Buffer::with_size(bytes.len()).unwrap();
        {
            let buf_mut = buf.get_mut().unwrap();
            let mut map = buf_mut.map_writable().unwrap();
            map.as_mut_slice().copy_from_slice(bytes);
        }
        let _ = self.appsrc.push_buffer(buf);
    }
}