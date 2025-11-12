use hkdf::Hkdf;
use sha2::Sha256;

pub struct DirKeys { pub enc_key: [u8;16], pub nonce_base: [u8;8] }
pub struct BiSession { pub tx: DirKeys, pub rx: DirKeys }

fn expand(secret: &[u8], salt: &[u8], info: &[u8]) -> ([u8;16],[u8;8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut out = [0u8;24]; // 16 key + 8 nonce_base
    hk.expand(info, &mut out).expect("HKDF expand");
    let mut k=[0u8;16]; k.copy_from_slice(&out[..16]);
    let mut n=[0u8; 8]; n.copy_from_slice(&out[16..24]);
    (k,n)
}

/// Derive per-direction keys using symmetric labels:
///   info_ab = "ECE4301-midterm-2025|SENDER->RECEIVER"
///   info_ba = "ECE4301-midterm-2025|RECEIVER->SENDER"
/// Caller passes (my_label, peer_label). We map:
///   TX uses  my->peer
///   RX uses  peer->my
pub fn derive_bidirectional(secret: &[u8], salt: &[u8], my_label: &[u8], peer_label: &[u8]) -> BiSession {
    let info_ab = [b"ECE4301-midterm-2025|", my_label, b"->", peer_label].concat();
    let info_ba = [b"ECE4301-midterm-2025|", peer_label, b"->", my_label].concat();
    let (ktx,ntx) = expand(secret, salt, &info_ab);
    let (krx,nrx) = expand(secret, salt, &info_ba);
    BiSession {
        tx: DirKeys{ enc_key: ktx, nonce_base: ntx },
        rx: DirKeys{ enc_key: krx, nonce_base: nrx },
    }
}
