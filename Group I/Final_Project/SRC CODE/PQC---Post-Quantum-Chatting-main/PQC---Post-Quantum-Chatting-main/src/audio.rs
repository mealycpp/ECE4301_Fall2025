//! Real-time Audio Capture and Playback
//!
//! Handles audio input from USB microphone and output to headset/speakers
//! Uses CPAL for cross-platform audio I/O

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{Device, Host, Stream, StreamConfig};
use ringbuf::{HeapRb, HeapProducer, HeapConsumer};
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Audio-related errors
#[derive(Error, Debug)]
pub enum AudioError {
    #[error("No audio devices found")]
    NoDevicesFound,
    #[error("Failed to get default config: {0}")]
    ConfigError(String),
    #[error("Failed to build stream: {0}")]
    StreamError(String),
    #[error("Audio device error: {0}")]
    DeviceError(#[from] cpal::DevicesError),
    #[error("Other error: {0}")]
    Other(String),
}

const SAMPLE_RATE: u32 = 48000;  // 48kHz standard audio
const CHANNELS: u16 = 1;  // Mono audio
const BUFFER_SIZE: usize = 960;  // 20ms at 48kHz - good balance
// Playback buffer in milliseconds. Lower values reduce latency but increase
// risk of underruns. Default to 80ms as a reasonable balance for Raspberry Pi 5.
const PLAYBACK_BUFFER_MS: usize = 80;  // 80ms buffer - lower latency

/// Audio Manager - handles both capture and playback
pub struct AudioManager {
    host: Host,
    input_device: Option<Device>,
    output_device: Option<Device>,
    input_stream: Option<Stream>,
    output_stream: Option<Stream>,
    audio_tx: Arc<Mutex<Option<HeapProducer<f32>>>>,
    audio_rx: Arc<Mutex<Option<HeapConsumer<f32>>>>,
}

impl AudioManager {
    /// Create a new AudioManager
    pub fn new() -> Result<Self, AudioError> {
        let host = cpal::default_host();
        
        Ok(Self {
            host,
            input_device: None,
            output_device: None,
            input_stream: None,
            output_stream: None,
            audio_tx: Arc::new(Mutex::new(None)),
            audio_rx: Arc::new(Mutex::new(None)),
        })
    }

    /// List available input devices
    pub fn list_input_devices(&self) -> Result<Vec<String>, AudioError> {
        let devices = self.host.input_devices()?;
        let mut device_names = Vec::new();
        
        for device in devices {
            if let Ok(name) = device.name() {
                device_names.push(name);
            }
        }
        
        Ok(device_names)
    }

    /// List available output devices
    pub fn list_output_devices(&self) -> Result<Vec<String>, AudioError> {
        let devices = self.host.output_devices()?;
        let mut device_names = Vec::new();
        
        for device in devices {
            if let Ok(name) = device.name() {
                device_names.push(name);
            }
        }
        
        Ok(device_names)
    }

    /// Initialize audio capture from microphone
    pub fn start_capture<F>(&mut self, mut callback: F) -> Result<(), AudioError>
    where
        F: FnMut(Vec<f32>) + Send + 'static,
    {
        // Get default input device
        let device = self.host
            .default_input_device()
            .ok_or(AudioError::NoDevicesFound)?;
        
        log::info!("Using input device: {}", device.name().unwrap_or_else(|_| "Unknown".to_string()));
        
        // Try to use our desired config
        let config = StreamConfig {
            channels: CHANNELS,
            sample_rate: cpal::SampleRate(SAMPLE_RATE),
            buffer_size: cpal::BufferSize::Fixed(BUFFER_SIZE as u32),
        };
        
        // Build input stream - send immediately for lowest latency
        let mut audio_buffer = Vec::with_capacity(BUFFER_SIZE);
        
        let stream = device.build_input_stream(
            &config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                // For ultra-low latency: send data as soon as we get any
                // Don't wait to accumulate a full buffer
                for sample in data {
                    audio_buffer.push(*sample);
                    
                    // Send when we have minimum viable packet size
                    if audio_buffer.len() >= BUFFER_SIZE {
                        let chunk: Vec<f32> = audio_buffer.drain(..BUFFER_SIZE).collect();
                        callback(chunk);
                    }
                }
            },
            |err| {
                log::error!("Audio input error: {}", err);
            },
            None,
        ).map_err(|e| AudioError::StreamError(e.to_string()))?;
        
        stream.play().map_err(|e| AudioError::StreamError(e.to_string()))?;
        
        self.input_device = Some(device);
        self.input_stream = Some(stream);
        
        log::info!("Audio capture started: {}Hz, {} channels", SAMPLE_RATE, CHANNELS);
        Ok(())
    }

    /// Initialize audio playback to speakers/headset
    pub fn start_playback(&mut self) -> Result<Arc<Mutex<HeapProducer<f32>>>, AudioError> {
        // Get default output device
        let device = self.host
            .default_output_device()
            .ok_or(AudioError::NoDevicesFound)?;
        
        log::info!("Using output device: {}", device.name().unwrap_or_else(|_| "Unknown".to_string()));
        
        // Try to use our desired config
        let config = StreamConfig {
            channels: CHANNELS,
            sample_rate: cpal::SampleRate(SAMPLE_RATE),
            buffer_size: cpal::BufferSize::Fixed(BUFFER_SIZE as u32),
        };
        
        // Create ring buffer for audio data - smaller buffer for lower latency
        // 60ms buffer - very tight for lowest latency
        let buffer_samples = (SAMPLE_RATE as usize * PLAYBACK_BUFFER_MS) / 1000;
        let ring_buffer = HeapRb::<f32>::new(buffer_samples); 
        let (mut producer, mut consumer) = ring_buffer.split();
        
        // NO prefill - start immediately to minimize latency
        // First packet may glitch but subsequent audio will be real-time
        
        let stream = device.build_output_stream(
            &config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                for sample in data.iter_mut() {
                    *sample = consumer.pop().unwrap_or(0.0);
                }
            },
            |err| {
                log::error!("Audio output error: {}", err);
            },
            None,
        ).map_err(|e| AudioError::StreamError(e.to_string()))?;
        
        stream.play().map_err(|e| AudioError::StreamError(e.to_string()))?;
        
        self.output_device = Some(device);
        self.output_stream = Some(stream);
        
        let producer_arc = Arc::new(Mutex::new(producer));
        
        log::info!("Audio playback started: {}Hz, {} channels", SAMPLE_RATE, CHANNELS);
        Ok(producer_arc)
    }

    /// Stop audio capture
    pub fn stop_capture(&mut self) {
        if let Some(stream) = self.input_stream.take() {
            drop(stream);
            log::info!("Audio capture stopped");
        }
        self.input_device = None;
    }

    /// Stop audio playback
    pub fn stop_playback(&mut self) {
        if let Some(stream) = self.output_stream.take() {
            drop(stream);
            log::info!("Audio playback stopped");
        }
        self.output_device = None;
    }

    /// Stop all audio
    pub fn stop_all(&mut self) {
        self.stop_capture();
        self.stop_playback();
    }

    /// Check if capture is active
    pub fn is_capturing(&self) -> bool {
        self.input_stream.is_some()
    }

    /// Check if playback is active
    pub fn is_playing(&self) -> bool {
        self.output_stream.is_some()
    }
}

impl Drop for AudioManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}

/// Helper function to convert f32 samples to bytes for transmission
pub fn samples_to_bytes(samples: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(samples.len() * 4);
    for sample in samples {
        bytes.extend_from_slice(&sample.to_le_bytes());
    }
    bytes
}

/// Helper function to convert bytes to f32 samples for playback
pub fn bytes_to_samples(bytes: &[u8]) -> Vec<f32> {
    let mut samples = Vec::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks_exact(4) {
        if let Ok(array) = chunk.try_into() {
            samples.push(f32::from_le_bytes(array));
        }
    }
    samples
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_conversion() {
        let original = vec![0.0, 0.5, -0.5, 1.0, -1.0];
        let bytes = samples_to_bytes(&original);
        let converted = bytes_to_samples(&bytes);
        
        assert_eq!(original.len(), converted.len());
        for (o, c) in original.iter().zip(converted.iter()) {
            assert!((o - c).abs() < 0.0001);
        }
    }

    #[test]
    fn test_audio_manager_creation() {
        let manager = AudioManager::new();
        assert!(manager.is_ok());
        
        if let Ok(manager) = manager {
            assert!(!manager.is_capturing());
            assert!(!manager.is_playing());
        }
    }
}
