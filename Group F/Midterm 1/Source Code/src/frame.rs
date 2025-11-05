use bytes::{Buf, BufMut, BytesMut};

pub const FLAG_HANDSHAKE: u8 = 1<<0;
pub const FLAG_VIDEO:     u8 = 1<<1;
pub const FLAG_REKEY:     u8 = 1<<2;

#[derive(Debug, Clone)]
pub struct Frame {
    pub flags: u8,
    pub ts_ns: u64,
    pub seq: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn encode(&self) -> BytesMut {
        let mut b = BytesMut::with_capacity(4 + 1 + 8 + 8 + self.payload.len());
        let len = (1 + 8 + 8 + self.payload.len()) as u32;
        b.put_u32(len);
        b.put_u8(self.flags);
        b.put_u64(self.ts_ns);
        b.put_u64(self.seq);
        b.extend_from_slice(&self.payload);
        b
    }
    pub fn decode(mut buf: &[u8]) -> Self {
        let flags = buf.get_u8();
        let ts_ns = buf.get_u64();
        let seq = buf.get_u64();
        let payload = buf.to_vec();
        Self { flags, ts_ns, seq, payload }
    }
    pub fn aad(&self) -> [u8;16] {
        let mut aad=[0u8;16];
        aad[..8].copy_from_slice(&self.seq.to_be_bytes());
        aad[8..].copy_from_slice(&(self.payload.len() as u64).to_be_bytes());
        aad
    }
}
