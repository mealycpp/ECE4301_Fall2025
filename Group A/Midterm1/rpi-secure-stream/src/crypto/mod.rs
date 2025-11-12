// src/crypto/mod.rs

pub mod rsa_kem;
pub mod ecdh;

// Optional: re-exports so callers can do `use crypto::rsa_wrap;` directly
pub use rsa_kem::{generate_rsa_keypair, rsa_unwrap, rsa_wrap, SESSION_KEY_LEN};
pub use ecdh::{generate_ephemeral, ecdh_derive, DerivedSecrets, AES128_KEY_LEN, GCM_NONCE_LEN};
