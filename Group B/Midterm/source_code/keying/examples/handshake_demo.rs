#![allow(deprecated)]
use keying::*;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};      // AES-128-GCM (matches 16-byte key)
use aes_gcm::aead::Aead;
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn handle_client(mut stream: TcpStream) {
    // --- ECDH side B (receiver) ---
    let mut buf = vec![0u8; 100];
    let n = stream.read(&mut buf).unwrap();
    buf.truncate(n);
    let (shared_key, pub_bytes_b) = ecdh_derive_from_peer(&buf);
    stream.write_all(&pub_bytes_b).unwrap();

    println!("ECDH done (receiver). AES-128 key: {:02x?}", &shared_key[..8]);

    // --- Receive encrypted message (length-prefixed) ---
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).unwrap();
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf).unwrap();

    // Split into nonce (12 bytes) + ciphertext
    if msg_buf.len() < 12 {
        eprintln!("Received too-short packet");
        return;
    }
    let (nonce_bytes, ciphertext) = msg_buf.split_at(12);

    let cipher = Aes128Gcm::new_from_slice(&shared_key).unwrap();
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).expect("decrypt failed");
    println!("Decrypted message: {}", String::from_utf8_lossy(&plaintext));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: handshake_demo [server|client] [ip:port]");
        return;
    }

    match args[1].as_str() {
        // --- SERVER MODE ---
        "server" => {
            let default_addr = "0.0.0.0:5000".to_string();
            let addr = args.get(2).unwrap_or(&default_addr);
            let listener = TcpListener::bind(addr).unwrap();
            println!("Listening on {addr}");
            for stream in listener.incoming() {
                let stream = stream.unwrap();
                println!("Client connected from {:?}", stream.peer_addr());
                handle_client(stream);
            }
        }

        // --- CLIENT MODE ---
        "client" => {
            let default_addr = "127.0.0.1:5000".to_string();
            let addr = args.get(2).unwrap_or(&default_addr);
            let mut stream = TcpStream::connect(addr).unwrap();
            println!("Connected to server at {addr}");

            // Perform ECDH (initiator)
            let (pub_bytes_a, secret_a) = gen_ecdh_keypair();
            stream.write_all(&pub_bytes_a).unwrap();

            let mut buf = vec![0u8; 100];
            let n = stream.read(&mut buf).unwrap();
            buf.truncate(n);

            let shared = finish_ecdh(&secret_a, &buf);
            println!("ECDH done (initiator). AES-128 key: {:02x?}", &shared[..8]);

            // --- Encrypt message with AES-128-GCM ---
            let cipher = Aes128Gcm::new_from_slice(&shared).unwrap();

            // Fresh 96-bit nonce
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let message = b"Hello from the Pi Client!";
            let ciphertext = cipher.encrypt(nonce, message.as_ref()).unwrap();

            // Send length-prefixed: [u16 len][nonce(12)][ciphertext]
            let mut packet = Vec::with_capacity(12 + ciphertext.len());
            packet.extend_from_slice(&nonce_bytes);
            packet.extend_from_slice(&ciphertext);

            let len = (packet.len() as u16).to_be_bytes();
            stream.write_all(&len).unwrap();
            stream.write_all(&packet).unwrap();

            println!("Encrypted and sent message ({} bytes)", packet.len());
        }

        _ => eprintln!("Invalid mode."),
    }
}
