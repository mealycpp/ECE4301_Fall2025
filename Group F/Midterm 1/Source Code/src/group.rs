use crate::crypto::*;
use crate::frame::{Frame, FLAG_HANDSHAKE};
use crate::transport;
use anyhow::Result;
use bytes::BytesMut;
use std::time::{SystemTime, UNIX_EPOCH};
use rsa::{RsaPublicKey, RsaPrivateKey};

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Leader: generate group key, wrap it per-member, send
pub async fn leader_distribute(
    members: Vec<String>,
    member_pubs: Vec<RsaPublicKey>,
) -> Result<(Vec<u8>, Vec<[u8; 32]>)> {
    let mut group_key = [0u8; 16];
    os_rand_maybe_mix(&mut group_key);

    let mut salts = Vec::new();
    for (addr, pk) in members.iter().zip(member_pubs.iter()) {
        println!("Leader: connecting to {}", addr);
        let mut salt = [0u8; 32];
        os_rand_maybe_mix(&mut salt);
        salts.push(salt);

        // wrap group key with member pubkey (RSA-OAEP-SHA256)
        let enc = rsa_wrap(pk, &group_key)?;
        let mut payload = bytes::BytesMut::new();
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&enc);

        let f = Frame { flags: FLAG_HANDSHAKE, ts_ns: now_ns(), seq: 0, payload: payload.to_vec() };

        // connect & send (bubble up errors so you see them)
        let mut conn = transport::connect(addr).await
            .map_err(|e| anyhow::anyhow!("connect {} failed: {e}", addr))?;
        transport::send(&mut conn, &f.encode()).await
            .map_err(|e| anyhow::anyhow!("send to {} failed: {e}", addr))?;

        println!("Leader: sent group key to {}", addr);
    }

    Ok((group_key.to_vec(), salts))
}

/// Member: receive WRAP, unwrap, confirm
pub fn member_receive_wrap(
    privk: &RsaPrivateKey,
    wrap_payload: &[u8],
) -> Result<Vec<u8>> {
    let (salt, enc) = wrap_payload.split_at(32);
    let group_key = rsa_unwrap(privk, enc)?;
    let confirm = hmac_sha256(&group_key, b"confirm|ECE4301-midterm-2025");
    println!("member: group key confirmed, salt={:?}", &salt[..4]);
    Ok(confirm)
}
