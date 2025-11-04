pub mod keying {
    use hkdf::Hkdf;
    use p256::ecdh::EphemeralSecret;
    use p256::{EncodedPoint, PublicKey};
    use p256::elliptic_curve::rand_core::{OsRng, RngCore}; // ? use p256?s rand_core
    use sha2::Sha256;

    const SUITE: &[u8] = b"ECE4301-midterm-2025";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SessionParams {
        pub enc_key: [u8; 16],   // AES-128 key
        pub nonce_base: [u8; 8], // 64-bit base; append a 32-bit counter for 96-bit GCM nonce
    }

    pub struct EcdhOffer {
        pub pubkey_sec1: Vec<u8>,
        pub salt: [u8; 32],
    }

    pub fn start_offer() -> (EcdhOffer, EphemeralSecret) {
        // Use the OsRng that matches p256?s rand_core
        let mut osrng = OsRng;
        let secret = EphemeralSecret::random(&mut osrng);
        let public = PublicKey::from(&secret);
        let pub_bytes = EncodedPoint::from(public).as_bytes().to_vec();

        let mut salt = [0u8; 32];
        osrng.fill_bytes(&mut salt);

        (EcdhOffer { pubkey_sec1: pub_bytes, salt }, secret)
    }

    pub fn derive_params(
        my_secret: &EphemeralSecret,
        peer_pub_sec1: &[u8],
        salt: &[u8; 32],
    ) -> SessionParams {
        let peer_pub = PublicKey::from_sec1_bytes(peer_pub_sec1)
            .expect("valid P-256 SEC1 pubkey");
        let shared = my_secret.diffie_hellman(&peer_pub);

        // Use raw_secret_bytes() on SharedSecret (API change)
        let hk = Hkdf::<Sha256>::new(Some(salt), shared.raw_secret_bytes());

        let mut enc_key = [0u8; 16];
        hk.expand(&[SUITE, b"-aes"].concat(), &mut enc_key).expect("HKDF aes");

        let mut nonce_base = [0u8; 8];
        hk.expand(&[SUITE, b"-nonce"].concat(), &mut nonce_base).expect("HKDF nonce");

        SessionParams { enc_key, nonce_base }
    }
}

pub mod aead {
    use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit, Payload}};

    pub struct NonceCtr { base: [u8;8], ctr: u32 }
    impl NonceCtr {
        pub fn new(base: [u8;8]) -> Self { Self { base, ctr: 0 } }
        pub fn next(&mut self) -> [u8;12] {
            let mut n=[0u8;12];
            n[..8].copy_from_slice(&self.base);
            n[8..].copy_from_slice(&self.ctr.to_be_bytes());
            self.ctr = self.ctr.wrapping_add(1);
            n
        }
    }

    pub struct AeadCtx(Aes128Gcm);
    impl AeadCtx {
        pub fn new(key: [u8;16]) -> Self { Self(Aes128Gcm::new_from_slice(&key).unwrap()) }
        pub fn seal(&self, nonce: [u8;12], seq: u64, pt: &[u8]) -> Vec<u8> {
            self.0.encrypt((&nonce).into(), Payload{ msg: pt, aad: &seq.to_be_bytes() }).unwrap()
        }
        pub fn open(&self, nonce: [u8;12], seq: u64, ct: &[u8]) -> Vec<u8> {
            self.0.decrypt((&nonce).into(), Payload{ msg: ct, aad: &seq.to_be_bytes() }).unwrap()
        }
    }
}

// src/lib.rs (new helper; keep your existing keying::derive_params for single-dir if you want)
pub mod session {
    use hkdf::Hkdf;
    use sha2::Sha256;

    #[derive(Clone, Copy)]
    pub struct DirParams {
        pub enc_key: [u8; 16],
        pub nonce_base: [u8; 8],
    }
    pub struct Session {
        pub tx: DirParams, // what I use to SEND
        pub rx: DirParams, // what I expect to RECEIVE
    }

    /// Derive per-direction keys from a shared secret and a salt.
    /// `secret`: ECDH raw bytes (32B) OR your RSA prekey (32B)
    /// `role_me`: b"SENDER" or b"RECEIVER" (labels avoid reuse)
    pub fn derive_bidirectional(secret: &[u8], salt: &[u8; 32], role_me: &[u8], role_peer: &[u8]) -> Session {
        let hk = Hkdf::<Sha256>::new(Some(salt), secret);

        let mut k_tx = [0u8; 16];
        let mut n_tx = [0u8; 8];
        let mut k_rx = [0u8; 16];
        let mut n_rx = [0u8; 8];

        hk.expand(&[b"ECE4301-2025-aes-", role_me, b"->", role_peer].concat(), &mut k_tx).unwrap();
        hk.expand(&[b"ECE4301-2025-non-", role_me, b"->", role_peer].concat(), &mut n_tx).unwrap();
        hk.expand(&[b"ECE4301-2025-aes-", role_peer, b"->", role_me].concat(), &mut k_rx).unwrap();
        hk.expand(&[b"ECE4301-2025-non-", role_peer, b"->", role_me].concat(), &mut n_rx).unwrap();

        Session {
            tx: DirParams { enc_key: k_tx, nonce_base: n_tx },
            rx: DirParams { enc_key: k_rx, nonce_base: n_rx },
        }
    }
}


