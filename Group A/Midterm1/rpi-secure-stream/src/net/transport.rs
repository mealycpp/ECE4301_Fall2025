use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const FLAG_FRAME: u8 = 0x01;
pub const FLAG_REKEY: u8 = 0x02;

#[derive(Clone, Debug)]
pub struct WireMsg {
    pub flags: u8,
    pub ts_ns: u64,
    pub seq: u64,
    pub pt_len: u32,
    pub payload: Bytes,
}

impl WireMsg {
    /// [u32 len][u8 flags][u64 ts][u64 seq][u32 pt_len][payload...]
    pub fn encode(&self) -> Bytes {
        let body_len = 1 + 8 + 8 + 4 + self.payload.len();
        let mut b = BytesMut::with_capacity(4 + body_len);
        b.put_u32(body_len as u32);
        b.put_u8(self.flags);
        b.put_u64(self.ts_ns);
        b.put_u64(self.seq);
        b.put_u32(self.pt_len);
        b.extend_from_slice(&self.payload);
        b.freeze()
    }

    pub async fn write_to(&self, s: &mut TcpStream) -> Result<()> {
        let buf = self.encode();
        s.write_all(&buf).await?;
        Ok(())
    }

    pub async fn read_from(s: &mut TcpStream) -> Result<WireMsg> {
        let mut len4 = [0u8; 4];
        s.read_exact(&mut len4).await?;
        let len = u32::from_be_bytes(len4) as usize;
        if len < (1 + 8 + 8 + 4) {
            return Err(anyhow!("short frame: {}", len));
        }
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await?;

        let mut rd = &body[..];
        let flags = rd.get_u8();
        let ts_ns = rd.get_u64();
        let seq = rd.get_u64();
        let pt_len = rd.get_u32();
        let payload = Bytes::copy_from_slice(rd);

        Ok(WireMsg { flags, ts_ns, seq, pt_len, payload })
    }
}

pub async fn tcp_bind(addr: &str) -> Result<TcpListener> {
    Ok(TcpListener::bind(addr).await?)
}
pub async fn tcp_connect(addr: &str) -> Result<TcpStream> {
    Ok(TcpStream::connect(addr).await?)
}
