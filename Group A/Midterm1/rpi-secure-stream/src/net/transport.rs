// src/transport.rs
use anyhow::{anyhow, Result};
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const FLAG_FRAME: u8 = 0x01;
pub const FLAG_REKEY: u8 = 0x02;

#[derive(Clone, Debug)]
pub struct WireMsg {
    pub flags: u8,
    /// monotonic timestamp in **nanoseconds** (sender-side)
    pub ts_ns: u64,
    /// payload bytes (e.g., ciphertext+tag)
    pub payload: Bytes,
}

impl WireMsg {
    /// Serialize as: [u32 len][u8 flags][u64 ts_ns][payload...]
    /// len = 1 + 8 + payload.len()
    pub fn encode(&self) -> Bytes {
        let len: u32 = 1 + 8 + (self.payload.len() as u32);
        let mut buf = BytesMut::with_capacity(4 + len as usize);
        buf.put_u32(len);
        buf.put_u8(self.flags);
        buf.put_u64(self.ts_ns);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    pub async fn write_to(&self, stream: &mut TcpStream) -> Result<()> {
        let b = self.encode();
        stream.write_all(&b).await?;
        Ok(())
    }

    pub async fn read_from(stream: &mut TcpStream) -> Result<WireMsg> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);

        if len < 9 {
            return Err(anyhow!("length too small: {}", len));
        }
        let mut body = vec![0u8; len as usize];
        stream.read_exact(&mut body).await?;

        let flags = body[0];
        let ts_ns = u64::from_be_bytes(body[1..9].try_into()?);
        let payload = Bytes::copy_from_slice(&body[9..]);
        Ok(WireMsg { flags, ts_ns, payload })
    }
}

pub async fn tcp_bind(addr: &str) -> Result<TcpListener> {
    Ok(TcpListener::bind(addr).await?)
}
pub async fn tcp_connect(addr: &str) -> Result<TcpStream> {
    Ok(TcpStream::connect(addr).await?)
}
