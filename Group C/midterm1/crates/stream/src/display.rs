use anyhow::{Result, Context};
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use gstreamer as gst;
use tracing::info;

pub struct VideoDisplay {
    pipeline: gst::Pipeline,
    appsrc: AppSrc,
    width: i32,
    height: i32,
    fps: i32,
}

impl VideoDisplay {
    pub fn new(width: i32, height: i32, fps: i32) -> Result<Self> {
        gst::init().context("Failed to initialize GStreamer")?;
        
        info!("Creating display pipeline: {}x{} @ {} fps", width, height, fps);
        
        // Create pipeline: appsrc -> videoconvert -> autovideosink
        let pipeline_str = format!(
            "appsrc name=src format=time is-live=true do-timestamp=true \
             caps=video/x-raw,format=I420,width={},height={},framerate={}/1 ! \
             queue max-size-buffers=2 leaky=downstream ! \
             videoconvert ! \
             autovideosink sync=false",
            width, height, fps
        );
        
        info!("Display pipeline: {}", pipeline_str);
        
        let pipeline = gst::parse::launch(&pipeline_str)
            .context("Failed to create display pipeline")?
            .downcast::<gst::Pipeline>()
            .map_err(|_| anyhow::anyhow!("Failed to downcast to Pipeline"))?;
        
        let appsrc = pipeline
            .by_name("src")
            .context("Failed to find appsrc element")?
            .downcast::<AppSrc>()
            .map_err(|_| anyhow::anyhow!("Failed to downcast to AppSrc"))?;
        
        // Configure appsrc for streaming
        appsrc.set_property("format", gst::Format::Time);
        appsrc.set_property("is-live", true);
        appsrc.set_property("do-timestamp", true);
        appsrc.set_property("block", false);
        
        Ok(Self {
            pipeline,
            appsrc,
            width,
            height,
            fps,
        })
    }
    
    pub fn start(&self) -> Result<()> {
        self.pipeline
            .set_state(gst::State::Playing)
            .context("Failed to start display pipeline")?;
        
        info!("Video display started");
        
        // Wait for pipeline to be ready
        let bus = self.pipeline.bus().context("Failed to get bus")?;
        if let Some(msg) = bus.timed_pop_filtered(
            gst::ClockTime::from_seconds(2),
            &[gst::MessageType::Error, gst::MessageType::AsyncDone]
        ) {
            match msg.view() {
                gst::MessageView::Error(err) => {
                    return Err(anyhow::anyhow!(
                        "Display pipeline error: {} (debug: {:?})",
                        err.error(),
                        err.debug()
                    ));
                },
                _ => {}
            }
        }
        
        Ok(())
    }
    
    pub fn push_frame(&self, data: &[u8]) -> Result<()> {
        // Create buffer from frame data
        let mut buffer = gst::Buffer::from_slice(data.to_vec());
        
        // Make buffer writable and set PTS
        let buffer_ref = buffer.get_mut().unwrap();
        buffer_ref.set_pts(gst::ClockTime::NONE);
        
        // Push buffer to appsrc
        self.appsrc
            .push_buffer(buffer)
            .map_err(|_| anyhow::anyhow!("Failed to push buffer to display"))?;
        
        Ok(())
    }
    
    pub fn stop(&self) -> Result<()> {
        // Send EOS
        let _ = self.appsrc.end_of_stream();
        
        // Stop pipeline
        self.pipeline
            .set_state(gst::State::Null)
            .context("Failed to stop display pipeline")?;
        
        info!("Video display stopped");
        Ok(())
    }
}

impl Drop for VideoDisplay {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}