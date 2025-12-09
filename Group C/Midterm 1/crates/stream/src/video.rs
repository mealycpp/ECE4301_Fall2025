use anyhow::{Result, Context, bail};
use gstreamer as gst;
use gstreamer_app as gst_app;
use gstreamer::prelude::*;
use std::sync::{Arc, Mutex};

pub struct VideoCapture {
    pipeline: gst::Pipeline,
    appsink: gst_app::AppSink,
}

impl VideoCapture {
    pub fn new(device: &str, width: i32, height: i32, fps: i32) -> Result<Self> {
        // Initialize GStreamer
        gst::init().context("Failed to initialize GStreamer")?;
        
        // Build pipeline string
        let pipeline_str = format!(
            "v4l2src device={} ! video/x-raw,width={},height={},framerate={}/1 ! \
             videoconvert ! video/x-raw,format=I420 ! appsink name=sink",
            device, width, height, fps
        );
        
        eprintln!("Creating pipeline: {}", pipeline_str);
        
        // Create pipeline
        let pipeline = gst::parse_launch(&pipeline_str)
            .context("Failed to create pipeline")?
            .dynamic_cast::<gst::Pipeline>()
            .map_err(|_| anyhow::anyhow!("Pipeline is not a Pipeline"))?;
        
        // Get appsink
        let appsink = pipeline
            .by_name("sink")
            .context("Failed to get appsink")?
            .dynamic_cast::<gst_app::AppSink>()
            .map_err(|_| anyhow::anyhow!("Sink is not an AppSink"))?;
        
        // Configure appsink
        appsink.set_property("emit-signals", true);
        appsink.set_property("sync", false); // Don't sync to clock for low latency
        
        Ok(Self { pipeline, appsink })
    }
    
    pub fn start(&self) -> Result<()> {
        self.pipeline
            .set_state(gst::State::Playing)
            .context("Failed to set pipeline to Playing")?;
        
        eprintln!("Video capture started");
        Ok(())
    }
    
    pub fn capture_frame(&self) -> Result<Vec<u8>> {
        // Pull sample from appsink
        let sample = self.appsink
            .pull_sample()
            .map_err(|_| anyhow::anyhow!("Failed to pull sample"))?;
        
        // Get buffer from sample
        let buffer = sample.buffer()
            .context("Failed to get buffer from sample")?;
        
        // Map buffer for reading
        let map = buffer.map_readable()
            .context("Failed to map buffer")?;
        
        // Copy data
        let data = map.as_slice().to_vec();
        
        Ok(data)
    }
    
    pub fn stop(&self) -> Result<()> {
        self.pipeline
            .set_state(gst::State::Null)
            .context("Failed to stop pipeline")?;
        
        eprintln!("Video capture stopped");
        Ok(())
    }
}

impl Drop for VideoCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// Helper to calculate frame size for I420 format (YUV 4:2:0)
pub fn i420_frame_size(width: i32, height: i32) -> usize {
    let y_size = (width * height) as usize;
    let uv_size = y_size / 4;
    y_size + 2 * uv_size // Y + U + V
}

pub struct VideoDisplay {
    pipeline: gst::Pipeline,
    appsrc: gst_app::AppSrc,
}

impl VideoDisplay {
    pub fn new(width: i32, height: i32, fps: i32) -> Result<Self> {
        gst::init().context("Failed to initialize GStreamer")?;
        
        let pipeline_str = format!(
            "appsrc name=src ! video/x-raw,format=I420,width={},height={},framerate={}/1 ! \
             videoconvert ! autovideosink",
            width, height, fps
        );
        
        let pipeline = gst::parse_launch(&pipeline_str)?
            .dynamic_cast::<gst::Pipeline>()
            .map_err(|_| anyhow::anyhow!("Not a pipeline"))?;
        
        let appsrc = pipeline
            .by_name("src")
            .context("Failed to get appsrc")?
            .dynamic_cast::<gst_app::AppSrc>()
            .map_err(|_| anyhow::anyhow!("Not an AppSrc"))?;
        
        Ok(Self { pipeline, appsrc })
    }
    
    pub fn start(&self) -> Result<()> {
        self.pipeline.set_state(gst::State::Playing)?;
        Ok(())
    }
    
    pub fn display_frame(&self, data: &[u8]) -> Result<()> {
        let buffer = gst::Buffer::from_slice(data.to_vec());
        self.appsrc.push_buffer(buffer)
            .map_err(|_| anyhow::anyhow!("Failed to push buffer"))?;
        Ok(())
    }
    
    pub fn stop(&self) -> Result<()> {
        self.pipeline.set_state(gst::State::Null)?;
        Ok(())
    }
}