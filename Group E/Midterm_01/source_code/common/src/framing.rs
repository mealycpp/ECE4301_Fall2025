use bytes::{BufMut, BytesMut};

#[repr(u8)]
pub enum MsgKind { Handshake=1, HandshakeResp=2, Rekey=3, Data=4 }

pub fn pack(kind: MsgKind, flags: u8, ts_ns: u64, payload: &[u8]) -> Vec<u8> {
    let mut b = BytesMut::with_capacity(4+1+1+8+payload.len());
    b.put_u32((1+1+8+payload.len()) as u32);
    b.put_u8(kind as u8);
    b.put_u8(flags);
    b.put_u64(ts_ns);
    b.extend_from_slice(payload);
    b.freeze().to_vec()
}

pub async fn read_one<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<(u8,u8,u64,Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let mut lenb=[0u8;4];
    r.read_exact(&mut lenb).await?;
    let len = u32::from_be_bytes(lenb) as usize;
    let mut head = vec![0u8; len];
    r.read_exact(&mut head).await?;
    let kind = head[0];
    let flags = head[1];
    let ts = u64::from_be_bytes(head[2..10].try_into()?);
    Ok((kind, flags, ts, head[10..].to_vec()))
}
