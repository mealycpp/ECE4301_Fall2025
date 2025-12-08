use clap::{Parser, Subcommand, ValueEnum};
use log::{debug, info};
use pqc_kyber::*;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand::rngs::OsRng;

#[derive(Clone, Debug, ValueEnum, Serialize, Deserialize)]
enum Mode {
    BufferExchange,
    DiffieHellman,
    Kyber,
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    buffer_size: usize,
    mode: Mode,
}

#[derive(Parser)]
#[command(name = "ECE4301-Final")]
#[command(about = "TCP echo client/server with configurable buffer size")]
struct Args {
    /// Enable debug output
    #[arg(short = 'd', long = "debug", global = true)]
    debug: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run in client mode
    Client {
        #[command(subcommand)]
        mode: ClientMode,
    },
    /// Run in server mode
    Server {
        /// Host address to bind to
        host: String,
        /// Port to listen on
        port: u16,
    },
}

#[derive(Subcommand)]
enum ClientMode {
    /// Buffer exchange mode
    BufferExchange {
        /// Server host address
        host: String,
        /// Server port
        port: u16,
        /// Buffer size in bytes
        #[arg(short = 'b', long = "buffer-size")]
        buffer_size: usize,
    },
    /// Diffie-Hellman key exchange mode
    DiffieHellman {
        /// Server host address
        host: String,
        /// Server port
        port: u16,
    },
    /// Kyber key exchange mode
    Kyber {
        /// Server host address
        host: String,
        /// Server port
        port: u16,
    },
}

fn main() {
    let args = Args::parse();

    // Initialize logger based on debug flag
    if args.debug {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    match args.command {
        Commands::Client { mode } => match mode {
            ClientMode::BufferExchange { host, port, buffer_size } => {
                let config = Config { buffer_size, mode: Mode::BufferExchange };
                debug!("Running in {:?} mode", config.mode);
                client(&format!("{}:{}", host, port), config);
            }
            ClientMode::DiffieHellman { host, port } => {
                let config = Config { buffer_size: 0, mode: Mode::DiffieHellman };
                debug!("Running in {:?} mode", config.mode);
                client(&format!("{}:{}", host, port), config);
            }
            ClientMode::Kyber { host, port } => {
                let config = Config { buffer_size: 0, mode: Mode::Kyber };
                debug!("Running in {:?} mode", config.mode);
                client(&format!("{}:{}", host, port), config);
            }
        },
        Commands::Server { host, port } => server(&format!("{}:{}", host, port)),
    }
}

fn client(addr: &str, config: Config) {
    let mut stream = TcpStream::connect(addr).unwrap();
    ciborium::into_writer(&config, &mut stream).unwrap();
    stream.flush().unwrap();

    match config.mode {
        Mode::BufferExchange => {
            let mut recv_buf = vec![0u8; config.buffer_size];
            let start = Instant::now();
            stream.write_all(&vec![0u8; config.buffer_size]).unwrap();
            stream.flush().unwrap();
            stream.read_exact(&mut recv_buf).unwrap();
            println!("RTT for {} bytes: {:.3} ms", config.buffer_size, start.elapsed().as_secs_f64() * 1000.0);

            // Graceful shutdown: wait for server acknowledgment before exiting
            let mut ack = [0u8; 1];
            stream.read_exact(&mut ack).unwrap();
            debug!("Received graceful shutdown ACK from server");
        }
        Mode::DiffieHellman => {
            let start = Instant::now();

            // Generate client's ephemeral key pair
            let client_secret = EphemeralSecret::random_from_rng(OsRng);
            let client_public = PublicKey::from(&client_secret);

            debug!("Client public key: {:?}", client_public.as_bytes());

            // Send client public key
            stream.write_all(client_public.as_bytes()).unwrap();
            stream.flush().unwrap();

            // Receive server public key
            let mut server_public_bytes = [0u8; 32];
            stream.read_exact(&mut server_public_bytes).unwrap();
            let server_public = PublicKey::from(server_public_bytes);

            debug!("Client received server public key: {:?}", server_public.as_bytes());

            // Compute shared secret
            let shared_secret = client_secret.diffie_hellman(&server_public);
            debug!("Client shared secret: {:?}", shared_secret.as_bytes());

            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            println!("Diffie-Hellman exchange time: {:.3} ms", elapsed);

            // Graceful shutdown: wait for server acknowledgment before exiting
            let mut ack = [0u8; 1];
            stream.read_exact(&mut ack).unwrap();
            debug!("Received graceful shutdown ACK from server");
        }
        Mode::Kyber => {
            let start = Instant::now();

            // Receive server's public key
            let mut public_key_bytes = [0u8; KYBER_PUBLICKEYBYTES];
            stream.read_exact(&mut public_key_bytes).unwrap();
            debug!("Client received server public key ({} bytes)", public_key_bytes.len());

            // Generate ciphertext and shared secret
            let mut rng = OsRng;
            let (ciphertext, client_shared_secret) = encapsulate(&public_key_bytes, &mut rng).unwrap();

            debug!("Client shared secret: {:?}", client_shared_secret);

            // Send ciphertext to server
            stream.write_all(&ciphertext).unwrap();
            stream.flush().unwrap();

            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            println!("Kyber exchange time: {:.3} ms", elapsed);

            // Graceful shutdown: wait for server acknowledgment before exiting
            let mut ack = [0u8; 1];
            stream.read_exact(&mut ack).unwrap();
            debug!("Received graceful shutdown ACK from server");
        }
    }
}

fn server(addr: &str) {
    let listener = TcpListener::bind(addr).unwrap();
    info!("Server listening on {}", addr);

    loop {
        let (mut stream, peer_addr) = listener.accept().unwrap();
        debug!("Connection from {}", peer_addr);

        let config: Config = ciborium::from_reader(&mut stream).unwrap();
        debug!("Received config: mode = {:?}, buffer_size = {}", config.mode, config.buffer_size);

        match config.mode {
            Mode::BufferExchange => {
                let mut buf = vec![0u8; config.buffer_size];
                stream.read_exact(&mut buf).unwrap();
                stream.write_all(&buf).unwrap();
                stream.flush().unwrap();
                debug!("Echoed {} bytes to {}", config.buffer_size, peer_addr);

                // Graceful shutdown: send acknowledgment to client
                stream.write_all(&[0u8]).unwrap();
                stream.flush().unwrap();
                debug!("Sent graceful shutdown ACK to {}", peer_addr);
            }
            Mode::DiffieHellman => {
                debug!("Diffie-Hellman mode from {}", peer_addr);

                // Generate server's ephemeral key pair
                let server_secret = EphemeralSecret::random_from_rng(OsRng);
                let server_public = PublicKey::from(&server_secret);

                debug!("Server public key: {:?}", server_public.as_bytes());

                // Receive client public key
                let mut client_public_bytes = [0u8; 32];
                stream.read_exact(&mut client_public_bytes).unwrap();
                let client_public = PublicKey::from(client_public_bytes);

                debug!("Server received client public key: {:?}", client_public.as_bytes());

                // Send server public key
                stream.write_all(server_public.as_bytes()).unwrap();
                stream.flush().unwrap();

                // Compute shared secret
                let shared_secret = server_secret.diffie_hellman(&client_public);
                debug!("Server shared secret: {:?}", shared_secret.as_bytes());

                // Graceful shutdown: send acknowledgment to client
                stream.write_all(&[0u8]).unwrap();
                stream.flush().unwrap();
                debug!("Sent graceful shutdown ACK to {}", peer_addr);
            }
            Mode::Kyber => {
                debug!("Kyber mode from {}", peer_addr);

                // Generate server's keypair
                let mut rng = OsRng;
                let keys = keypair(&mut rng).unwrap();

                debug!("Server public key ({} bytes generated)", keys.public.len());
                debug!("Server secret key ({} bytes generated)", keys.secret.len());

                // Send public key to client
                stream.write_all(&keys.public).unwrap();
                stream.flush().unwrap();
                debug!("Server sent public key ({} bytes)", keys.public.len());

                // Receive ciphertext from client
                let mut ciphertext = [0u8; KYBER_CIPHERTEXTBYTES];
                stream.read_exact(&mut ciphertext).unwrap();
                debug!("Server received ciphertext ({} bytes)", ciphertext.len());

                // Decapsulate to get shared secret
                let server_shared_secret = decapsulate(&ciphertext, &keys.secret).unwrap();
                debug!("Server shared secret: {:?}", server_shared_secret);

                // Graceful shutdown: send acknowledgment to client
                stream.write_all(&[0u8]).unwrap();
                stream.flush().unwrap();
                debug!("Sent graceful shutdown ACK to {}", peer_addr);
            }
        }
    }
}