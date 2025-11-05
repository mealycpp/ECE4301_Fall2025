use anyhow::Result;
use tokio::{net::{TcpListener,TcpStream}, io::{AsyncReadExt,AsyncWriteExt}};
use std::sync::{Arc, Mutex};

pub async fn listen(
    addr:&str,
    handler: Arc<Mutex<Box<dyn FnMut(Vec<u8>) -> Result<()> + Send>>>
) -> Result<()> {
    println!("transport: binding on {}", addr);
    let listener = TcpListener::bind(addr).await?;
    println!("transport: waiting for incoming connections...");
    loop {
        let (mut s,_) = listener.accept().await?;
        println!("transport: accepted new connection");
        let h = Arc::clone(&handler);
        tokio::spawn(async move {
            let _ = read_loop(&mut s, h).await;
        });
    }
}

async fn read_loop(
    s:&mut TcpStream,
    handler: Arc<Mutex<Box<dyn FnMut(Vec<u8>) -> Result<()> + Send>>>
) -> Result<()> {
    loop {
        let mut lenb=[0u8;4]; s.read_exact(&mut lenb).await?;
        let len = u32::from_be_bytes(lenb) as usize;
        let mut buf=vec![0u8;len]; s.read_exact(&mut buf).await?;
        println!("transport: received {} bytes", len);
	(handler.lock().unwrap())(buf)?;
    }
}

pub async fn connect(addr:&str) -> Result<TcpStream> { Ok(TcpStream::connect(addr).await?) }

pub async fn send(s:&mut TcpStream, data:&[u8]) -> Result<()> {
    s.write_all(&(data.len() as u32).to_be_bytes()).await?;
    s.write_all(data).await?;
    Ok(())
}
