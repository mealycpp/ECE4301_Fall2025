// src/net/mod.rs

pub mod transport;
pub mod aead_stream;

// Optional: re-export commonly used items for convenience
pub use transport::{tcp_bind, tcp_connect, WireMsg, FLAG_FRAME, FLAG_REKEY};
pub use aead_stream::Aes128GcmStream;
