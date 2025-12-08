//! PQC Chat - Post-Quantum Secure Chat Library
//!
//! This library provides core functionality for the LAN-based,
//! post-quantum secure audio/video chat system.

pub mod crypto;
pub mod protocol;
pub mod room;
pub mod media;
pub mod config;
pub mod audio;
pub mod audio_codec;

pub use crypto::kyber::KyberKeyExchange;
pub use protocol::SignalingMessage;
pub use room::{Room, RoomManager, Participant};
pub use config::{ServerConfig, ClientConfig};
