//! Configuration
//!
//! Configuration structures for server and client.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub signaling_host: String,
    pub signaling_port: u16,
    pub media_host: String,
    pub audio_port: u16,
    pub video_port: u16,
    pub certfile: PathBuf,
    pub keyfile: PathBuf,
    #[serde(default)]
    pub ca_certfile: Option<PathBuf>,
    #[serde(default = "default_max_participants")]
    pub default_max_participants: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_max_participants() -> u32 {
    10
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            signaling_host: "0.0.0.0".to_string(),
            signaling_port: 8443,
            media_host: "0.0.0.0".to_string(),
            audio_port: 10000,
            video_port: 10001,
            certfile: PathBuf::from("server.crt"),
            keyfile: PathBuf::from("server.key"),
            ca_certfile: None,
            default_max_participants: 10,
            log_level: "info".to_string(),
        }
    }
}

impl ServerConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(e.to_string()))?;
        toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))
    }
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_host: String,
    pub signaling_port: u16,
    pub audio_port: u16,
    pub video_port: u16,
    #[serde(default)]
    pub ca_certfile: Option<PathBuf>,
    #[serde(default)]
    pub certfile: Option<PathBuf>,
    #[serde(default)]
    pub keyfile: Option<PathBuf>,
    #[serde(default = "default_username")]
    pub default_username: String,
    pub video: VideoConfig,
    pub audio: AudioConfig,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_username() -> String {
    "User".to_string()
}

/// Video capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoConfig {
    #[serde(default = "default_video_width")]
    pub width: u32,
    #[serde(default = "default_video_height")]
    pub height: u32,
    #[serde(default = "default_video_fps")]
    pub fps: u32,
    #[serde(default)]
    pub device_index: u32,
}

fn default_video_width() -> u32 {
    640
}

fn default_video_height() -> u32 {
    480
}

fn default_video_fps() -> u32 {
    30
}

impl Default for VideoConfig {
    fn default() -> Self {
        Self {
            width: 640,
            height: 480,
            fps: 30,
            device_index: 0,
        }
    }
}

/// Audio capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioConfig {
    #[serde(default = "default_sample_rate")]
    pub sample_rate: u32,
    #[serde(default = "default_channels")]
    pub channels: u8,
    #[serde(default)]
    pub device_index: Option<u32>,
}

fn default_sample_rate() -> u32 {
    48000
}

fn default_channels() -> u8 {
    1
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            sample_rate: 48000,
            channels: 1,
            device_index: None,
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_host: "127.0.0.1".to_string(),
            signaling_port: 8443,
            audio_port: 10000,
            video_port: 10001,
            ca_certfile: None,
            certfile: None,
            keyfile: None,
            default_username: "User".to_string(),
            video: VideoConfig::default(),
            audio: AudioConfig::default(),
            log_level: "info".to_string(),
        }
    }
}

impl ClientConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(e.to_string()))?;
        toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))
    }
}

/// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_server_config() {
        let config = ServerConfig::default();
        assert_eq!(config.signaling_port, 8443);
        assert_eq!(config.audio_port, 10000);
        assert_eq!(config.video_port, 10001);
    }

    #[test]
    fn test_default_client_config() {
        let config = ClientConfig::default();
        assert_eq!(config.server_host, "127.0.0.1");
        assert_eq!(config.video.width, 640);
        assert_eq!(config.audio.sample_rate, 48000);
    }
}
