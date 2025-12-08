//! Audio codec support (Opus compression)
//!
//! Provides Opus encoding/decoding for low-bandwidth, high-quality audio transmission.
//! Reduces audio payload from ~3.8 KB per 20ms to ~100-200 bytes.

use opus::{Encoder, Decoder, Application, Channels};
use thiserror::Error;

/// Codec errors
#[derive(Error, Debug)]
pub enum CodecError {
    #[error("Opus error: {0}")]
    OpusError(String),
    #[error("Invalid audio format")]
    InvalidFormat,
    #[error("Buffer too small")]
    BufferTooSmall,
}

/// Opus audio encoder (48kHz, mono, 20ms frames)
pub struct OpusEncoder {
    encoder: Encoder,
}

impl OpusEncoder {
    /// Create a new Opus encoder (48kHz, mono, optimized for voice)
    pub fn new() -> Result<Self, CodecError> {
        let encoder = Encoder::new(48000, Channels::Mono, Application::Voip)
            .map_err(|e| CodecError::OpusError(format!("Failed to create encoder: {:?}", e)))?;
        Ok(Self { encoder })
    }

    /// Encode f32 audio samples to Opus bytes
    /// Input: 960 samples @ 48kHz = 20ms frame
    pub fn encode(&mut self, samples: &[f32]) -> Result<Vec<u8>, CodecError> {
        if samples.len() != 960 {
            return Err(CodecError::InvalidFormat);
        }

        // Opus internally expects i16 samples, but we can use f32
        // Create a buffer for encoded output (Opus max frame is typically 4000 bytes)
        let mut encoded = vec![0u8; 4000];
        
        let encoded_len = self.encoder.encode_float(samples, &mut encoded)
            .map_err(|e| CodecError::OpusError(format!("Encode failed: {:?}", e)))?;
        
        encoded.truncate(encoded_len);
        Ok(encoded)
    }
}

/// Opus audio decoder (48kHz, mono, 20ms frames)
pub struct OpusDecoder {
    decoder: Decoder,
}

impl OpusDecoder {
    /// Create a new Opus decoder (48kHz, mono)
    pub fn new() -> Result<Self, CodecError> {
        let decoder = Decoder::new(48000, Channels::Mono)
            .map_err(|e| CodecError::OpusError(format!("Failed to create decoder: {:?}", e)))?;
        Ok(Self { decoder })
    }

    /// Decode Opus bytes to f32 audio samples
    /// Output: 960 samples @ 48kHz = 20ms frame
    pub fn decode(&mut self, encoded: &[u8]) -> Result<Vec<f32>, CodecError> {
        // Opus produces 960 samples for 20ms @ 48kHz
        let mut samples = vec![0f32; 960];
        
        let decoded_len = self.decoder.decode_float(encoded, &mut samples, false)
            .map_err(|e| CodecError::OpusError(format!("Decode failed: {:?}", e)))?;
        
        if decoded_len != 960 {
            eprintln!("WARNING: Decoded {} samples, expected 960", decoded_len);
        }
        
        samples.truncate(decoded_len);
        Ok(samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opus_encode_decode() {
        let mut encoder = OpusEncoder::new().expect("Failed to create encoder");
        let mut decoder = OpusDecoder::new().expect("Failed to create decoder");

        // Generate test audio (silence)
        let input = vec![0.0f32; 960];

        // Encode
        let encoded = encoder.encode(&input).expect("Encode failed");
        println!("Encoded {} samples to {} bytes", 960, encoded.len());

        // Decode
        let decoded = decoder.decode(&encoded).expect("Decode failed");
        println!("Decoded {} bytes back to {} samples", encoded.len(), decoded.len());

        assert_eq!(decoded.len(), 960);
        // Silence should stay silent (with small numerical error)
        for sample in decoded {
            assert!(sample.abs() < 0.01);
        }
    }
}
