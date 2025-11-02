use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use aes_gcm::aead::consts::U12;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use rand::{RngCore, rngs::OsRng};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::sync::atomic::{AtomicU32, Ordering};
use anyhow::{Result, Context, bail};

/// Log ARM crypto support at runtime
pub fn log_arm_crypto_support() {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        // Try reading from /proc/cpuinfo as fallback
        let cpu_features = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let aes = cpu_features.contains("aes");
        let pmull = cpu_features.contains("pmull");
        let sha1 = cpu_features.contains("sha1");
        let sha2 = cpu_features.contains("sha2");
        
        eprintln!("=== ARMv8 Crypto Extensions Detection ===");
        eprintln!("AES:   {}", if aes { "ACTIVE ✓" } else { "NOT DETECTED ✗" });
        eprintln!("PMULL: {}", if pmull { "ACTIVE ✓" } else { "NOT DETECTED ✗" });
        eprintln!("SHA1:  {}", if sha1 { "ACTIVE ✓" } else { "NOT DETECTED ✗" });
        eprintln!("SHA2:  {}", if sha2 { "ACTIVE ✓" } else { "NOT DETECTED ✗" });
        eprintln!("=========================================");
        
        if !aes || !pmull {
            eprintln!("WARNING: Hardware crypto acceleration not fully active!");
        }
    }
    
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    #[cfg(target_arch = "aarch64")]
    {
        eprintln!("=== ARMv8 Crypto Extensions Detection ===");
        eprintln!("Runtime detection not available on this platform");
        eprintln!("=========================================");
    }
    
    #[cfg(not(target_arch = "aarch64"))]
    {
        eprintln!("=== ARMv8 Crypto Extensions Detection ===");
        eprintln!("Not running on aarch64 - hardware acceleration unavailable");
        eprintln!("=========================================");
    }
}

/// RSA key establishment with OAEP-SHA256
pub mod rsa_kex {
    use super::*;
    
    pub struct RsaKeyPair {
        private_key: RsaPrivateKey,
        public_key: RsaPublicKey,
    }
    
    impl RsaKeyPair {
        pub fn generate(bits: usize) -> Result<Self> {
            let mut rng = OsRng;
            let private_key = RsaPrivateKey::new(&mut rng, bits)
                .context("Failed to generate RSA private key")?;
            let public_key = RsaPublicKey::from(&private_key);
            Ok(Self { private_key, public_key })
        }
        
        pub fn public_key_der(&self) -> Result<Vec<u8>> {
            use rsa::pkcs8::EncodePublicKey;
            self.public_key.to_public_key_der()
                .map(|d| d.to_vec())
                .context("Failed to encode public key")
        }
        
        pub fn wrap_session_key(&self, session_key: &[u8]) -> Result<Vec<u8>> {
            let mut rng = OsRng;
            self.public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), session_key)
                .context("Failed to wrap session key")
        }
        
        pub fn unwrap_session_key(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
            self.private_key.decrypt(Oaep::new::<Sha256>(), wrapped)
                .context("Failed to unwrap session key")
        }
    }
    
    impl Drop for RsaKeyPair {
        fn drop(&mut self) {
            // Zero out private key memory (best effort)
            // Note: rsa crate uses zeroize internally
        }
    }
}

/// ECDH key establishment with P-256 + HKDF
pub mod ecdh_kex {
    use super::*;
    
    pub struct EcdhKeyPair {
        secret: EphemeralSecret,
        public: PublicKey,
    }
    
    impl EcdhKeyPair {
        pub fn generate() -> Self {
            let secret = EphemeralSecret::random(&mut OsRng);
            let public = PublicKey::from(&secret);
            Self { secret, public }
        }
        
        pub fn public_key_bytes(&self) -> Vec<u8> {
            EncodedPoint::from(self.public).as_bytes().to_vec()
        }
        
        pub fn derive_session_key(
            self,
            peer_public_bytes: &[u8],
            context: &[u8],
        ) -> Result<SessionKeyMaterial> {
            let peer_public = PublicKey::from_sec1_bytes(peer_public_bytes)
                .context("Invalid peer public key")?;
            
            let shared_secret = self.secret.diffie_hellman(&peer_public);
            
            // HKDF-SHA256: shared_secret -> AES key + nonce base
            let hk = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
            
            let mut aes_key = [0u8; 16];
            hk.expand(context, &mut aes_key)
                .map_err(|_| anyhow::anyhow!("HKDF expand failed for AES key"))?;
            
            // Derive nonce_base from HKDF too, not random!
            let mut nonce_base = [0u8; 8];
            let mut combined = [0u8; 24];
            hk.expand(b"nonce-base", &mut combined)
                .map_err(|_| anyhow::anyhow!("HKDF expand failed for nonce base"))?;
            nonce_base.copy_from_slice(&combined[16..24]); // Use bytes after AES key
            
            Ok(SessionKeyMaterial { aes_key, nonce_base })
        }
    }
}

/// Session key material derived from key establishment
#[derive(Debug, Clone)]
pub struct SessionKeyMaterial {
    aes_key: [u8; 16],
    nonce_base: [u8; 8],
}

impl SessionKeyMaterial {
    pub fn generate_random() -> Self {
        let mut aes_key = [0u8; 16];
        let mut nonce_base = [0u8; 8];
        OsRng.fill_bytes(&mut aes_key);
        OsRng.fill_bytes(&mut nonce_base);
        Self { aes_key, nonce_base }
    }
    
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&self.aes_key);
        bytes.extend_from_slice(&self.nonce_base);
        bytes
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 24 {
            bail!("Invalid session key material length");
        }
        let mut aes_key = [0u8; 16];
        let mut nonce_base = [0u8; 8];
        aes_key.copy_from_slice(&bytes[0..16]);
        nonce_base.copy_from_slice(&bytes[16..24]);
        Ok(Self { aes_key, nonce_base })
    }
}

impl Drop for SessionKeyMaterial {
    fn drop(&mut self) {
        // Zero out sensitive material
        self.aes_key.iter_mut().for_each(|b| *b = 0);
        self.nonce_base.iter_mut().for_each(|b| *b = 0);
    }
}

/// AES-128-GCM cipher with nonce management
pub struct AesGcmCipher {
    cipher: Aes128Gcm,
    nonce_base: [u8; 8],
    counter: AtomicU32,
    rekey_threshold: u32,
}

impl AesGcmCipher {
    const MAX_COUNTER: u32 = 1 << 20; // 2^20 frames max per key
    
    pub fn new(key_material: SessionKeyMaterial, rekey_threshold: Option<u32>) -> Self {
        let cipher = Aes128Gcm::new_from_slice(&key_material.aes_key)
            .expect("Invalid key length");
        
        Self {
            cipher,
            nonce_base: key_material.nonce_base,
            counter: AtomicU32::new(0),
            rekey_threshold: rekey_threshold.unwrap_or(Self::MAX_COUNTER),
        }
    }
    
    pub fn should_rekey(&self) -> bool {
        self.counter.load(Ordering::Relaxed) >= self.rekey_threshold
    }
    
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let ctr = self.counter.fetch_add(1, Ordering::SeqCst);
        
        if ctr >= Self::MAX_COUNTER {
            bail!("Nonce counter exhausted - MUST rekey");
        }
        
        let nonce = self.build_nonce(ctr);
        
        self.cipher
            .encrypt(&nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))
    }
    
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8], nonce_ctr: u32) -> Result<Vec<u8>> {
        let nonce = self.build_nonce(nonce_ctr);
        
        self.cipher
            .decrypt(&nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
            .map_err(|e| anyhow::anyhow!("Decryption/Authentication failed: {}", e))
    }
    
    fn build_nonce(&self, counter: u32) -> Nonce<U12> {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce_base);
        nonce[8..].copy_from_slice(&counter.to_be_bytes());
        Nonce::from(nonce)
    }
    
    pub fn get_counter(&self) -> u32 {
        self.counter.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rsa_wrap_unwrap() {
        let keypair = rsa_kex::RsaKeyPair::generate(2048).unwrap();
        let session_key = b"0123456789abcdef";
        
        let wrapped = keypair.wrap_session_key(session_key).unwrap();
        let unwrapped = keypair.unwrap_session_key(&wrapped).unwrap();
        
        assert_eq!(session_key, unwrapped.as_slice());
    }
    
    #[test]
    fn test_ecdh_derive() {
        let alice = ecdh_kex::EcdhKeyPair::generate();
        let bob = ecdh_kex::EcdhKeyPair::generate();
        
        let alice_pub = alice.public_key_bytes();
        let bob_pub = bob.public_key_bytes();
        
        let alice_key = alice.derive_session_key(&bob_pub, b"test-context").unwrap();
        let bob_key = bob.derive_session_key(&alice_pub, b"test-context").unwrap();
        
        assert_eq!(alice_key.aes_key, bob_key.aes_key);
        assert_eq!(alice_key.nonce_base, bob_key.nonce_base);
    }
    
    #[test]
    fn test_aes_gcm_roundtrip() {
        let key_material = SessionKeyMaterial::generate_random();
        let cipher = AesGcmCipher::new(key_material, None);
        
        let plaintext = b"Hello, secure world!";
        let aad = b"frame-42";
        
        let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
        let counter = cipher.get_counter() - 1;
        let decrypted = cipher.decrypt(&ciphertext, aad, counter).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_nonce_uniqueness() {
        let key_material = SessionKeyMaterial::generate_random();
        let cipher = AesGcmCipher::new(key_material, None);
        
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..1000 {
            let ciphertext = cipher.encrypt(b"test", b"").unwrap();
            let counter = cipher.get_counter() - 1;
            assert!(nonces.insert(counter), "Nonce reuse detected!");
        }
    }
}