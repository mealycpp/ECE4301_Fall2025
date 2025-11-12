use p256::{ecdh::EphemeralSecret, PublicKey, EncodedPoint};
use rand::RngCore;

pub struct OfferState { pub pubkey_sec1: Vec<u8>, pub salt: [u8;32] }

pub fn start_offer() -> (OfferState, EphemeralSecret) {
    let sec = EphemeralSecret::random(&mut rand::rngs::OsRng);
    let pubk = PublicKey::from(&sec);
    let ep = EncodedPoint::from(pubk);
    let mut salt=[0u8;32]; rand::rngs::OsRng.fill_bytes(&mut salt);
    (OfferState{ pubkey_sec1: ep.as_bytes().to_vec(), salt }, sec)
}