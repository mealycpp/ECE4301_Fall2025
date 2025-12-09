//! Interactive PQC Chat Client
//! 
//! Enhanced client with real-time updates and interactive commands

use anyhow::Result;
use clap::Parser;
use log::{error, info};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::{self, pki_types::ServerName};
use tokio_rustls::TlsConnector;

use pqc_chat::crypto::kyber::KyberKeyExchange;
use pqc_chat::protocol::SignalingMessage;
use pqc_chat::ClientConfig;

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(name = "pqc-interactive")]
#[command(about = "PQC Chat Interactive Client")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config/client.toml")]
    config: PathBuf,

    /// Server host
    #[arg(long)]
    host: Option<String>,

    /// Server port
    #[arg(short, long)]
    port: Option<u16>,

    /// Username
    #[arg(short, long)]
    username: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    // Load configuration
    let config = if args.config.exists() {
        ClientConfig::from_file(args.config.to_str().unwrap())?
    } else {
        info!("Config file not found, using defaults");
        ClientConfig::default()
    };

    let host = args.host.unwrap_or(config.server_host.clone());
    let port = args.port.unwrap_or(config.signaling_port);
    let username = args.username.unwrap_or(config.default_username.clone());

    println!("🚀 PQC Chat Interactive Client");
    println!("================================");
    println!("Username: {}", username);
    println!("Server: {}:{}", host, port);
    println!();

    // Configure TLS (accept self-signed certificates for development)
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));

    // Connect to server
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    println!("🔌 Connecting to server...");

    let stream = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from(host.clone())?;
    let mut tls_stream = connector.connect(server_name, stream).await?;

    println!("✅ Connected to server");

    // Perform key exchange and login
    let kyber = KyberKeyExchange::new();
    
    // Key exchange
    let key_init = SignalingMessage::KeyExchangeInit {
        public_key: kyber.public_key_bytes(),
    };
    send_message(&mut tls_stream, &key_init).await?;

    let response = receive_message(&mut tls_stream).await?;
    if let SignalingMessage::KeyExchangeResponse { ciphertext } = response {
        kyber.decapsulate(&ciphertext)?;
        println!("🔐 Post-quantum key exchange completed");
    } else {
        return Err(anyhow::anyhow!("Key exchange failed"));
    }

    // Login
    let login = SignalingMessage::Login {
        username: username.clone(),
    };
    send_message(&mut tls_stream, &login).await?;

    let response = receive_message(&mut tls_stream).await?;
    if let SignalingMessage::LoginResponse { success, .. } = response {
        if success {
            println!("👤 Logged in as {}", username);
        } else {
            return Err(anyhow::anyhow!("Login failed"));
        }
    }

    // Create channels for communication between tasks
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<String>();
    
    // Split the stream for reading and writing
    let (read_half, write_half) = tokio::io::split(tls_stream);
    let write_half = Arc::new(tokio::sync::Mutex::new(write_half));

    // Spawn task to handle server messages
    let write_half_clone = write_half.clone();
    let mut server_task = tokio::spawn(async move {
        handle_server_messages(read_half, write_half_clone).await
    });

    // Spawn task to handle user input
    let cmd_tx_clone = cmd_tx.clone();
    let input_task = tokio::spawn(async move {
        handle_user_input(cmd_tx_clone).await
    });

    // Main loop to process commands
    let mut _current_room: Option<String> = None;
    
    // Initial room list
    {
        let mut stream = write_half.lock().await;
        send_message(&mut *stream, &SignalingMessage::ListRooms).await?;
    }

    println!();
    println!("💬 Interactive Commands:");
    println!("  rooms          - List available rooms");
    println!("  join <room_id> - Join a room by ID");
    println!("  create <name>  - Create a new room");
    println!("  leave          - Leave current room");
    println!("  quit           - Exit client");
    println!();

    loop {
        tokio::select! {
            Some(command) = cmd_rx.recv() => {
                let parts: Vec<&str> = command.trim().split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                match parts[0].to_lowercase().as_str() {
                    "rooms" => {
                        let mut stream = write_half.lock().await;
                        send_message(&mut *stream, &SignalingMessage::ListRooms).await?;
                    },
                    "join" => {
                        if parts.len() < 2 {
                            println!("Usage: join <room_id>");
                            continue;
                        }
                        let room_id = parts[1].to_string();
                        let msg = SignalingMessage::JoinRoom {
                            room_id: room_id.clone(),
                            username: username.clone(),
                        };
                        let mut stream = write_half.lock().await;
                        send_message(&mut *stream, &msg).await?;
                        _current_room = Some(room_id);
                    },
                    "create" => {
                        if parts.len() < 2 {
                            println!("Usage: create <room_name>");
                            continue;
                        }
                        let room_name = parts[1..].join(" ");
                        let msg = SignalingMessage::CreateRoom {
                            name: room_name,
                            max_participants: Some(10),
                        };
                        let mut stream = write_half.lock().await;
                        send_message(&mut *stream, &msg).await?;
                    },
                    "leave" => {
                        let mut stream = write_half.lock().await;
                        send_message(&mut *stream, &SignalingMessage::LeaveRoom).await?;
                        _current_room = None;
                    },
                    "quit" | "exit" => {
                        println!("👋 Goodbye!");
                        break;
                    },
                    _ => {
                        println!("Unknown command: {}. Type 'help' for available commands.", parts[0]);
                    }
                }
            }
            _ = &mut server_task => {
                println!("Server connection lost");
                break;
            }
        }
    }

    input_task.abort();
    Ok(())
}

async fn handle_server_messages<R, W>(
    mut reader: R,
    _writer: Arc<tokio::sync::Mutex<W>>,
) -> Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    loop {
        match receive_message(&mut reader).await {
            Ok(message) => {
                match message {
                    SignalingMessage::RoomList { rooms } => {
                        println!();
                        println!("📋 Available Rooms:");
                        if rooms.is_empty() {
                            println!("  No rooms available");
                        } else {
                            for room in rooms {
                                println!(
                                    "  🏠 {} - {} ({}/{} participants)",
                                    room.id, room.name, room.participants, room.max_participants
                                );
                            }
                        }
                        print!("> ");
                        io::stdout().flush().unwrap();
                    },
                    SignalingMessage::RoomCreated { success, room_id, room_name, error } => {
                        if success {
                            println!("✅ Created room: {} ({})", 
                                room_name.unwrap_or_default(), 
                                room_id.unwrap_or_default()
                            );
                        } else {
                            println!("❌ Failed to create room: {}", error.unwrap_or_default());
                        }
                        print!("> ");
                        io::stdout().flush().unwrap();
                    },
                    SignalingMessage::RoomJoined { success, room_name, participants, error, .. } => {
                        if success {
                            println!("🎉 Joined room: {}", room_name.unwrap_or_default());
                            if let Some(participants) = participants {
                                println!("👥 Participants in room:");
                                for p in participants {
                                    let status = if p.audio_enabled && p.video_enabled {
                                        "🎤📹"
                                    } else if p.audio_enabled {
                                        "🎤"
                                    } else if p.video_enabled {
                                        "📹"
                                    } else {
                                        "🔇"
                                    };
                                    println!("  {} {} ({})", status, p.username, p.id);
                                }
                            }
                        } else {
                            println!("❌ Failed to join room: {}", error.unwrap_or_default());
                        }
                        print!("> ");
                        io::stdout().flush().unwrap();
                    },
                    SignalingMessage::RoomLeft { success, error } => {
                        if success {
                            println!("👋 Left room");
                        } else {
                            println!("❌ Failed to leave room: {}", error.unwrap_or_default());
                        }
                        print!("> ");
                        io::stdout().flush().unwrap();
                    },
                    SignalingMessage::ParticipantJoined { username, participant_id } => {
                        println!("🟢 {} joined the room ({})", username, participant_id);
                        print!("> ");
                        io::stdout().flush().unwrap();
                    },
                    SignalingMessage::ParticipantLeft { participant_id } => {
                        println!("🔴 {} left the room", participant_id);
                        print!("> ");
                        io::stdout().flush().unwrap();
                    },
                    SignalingMessage::AudioToggled { participant_id, enabled } => {
                        let status = if enabled { "🎤 enabled" } else { "🔇 disabled" };
                        println!("🔊 {} audio {}", participant_id, status);
                        print!("> ");
                        io::stdout().flush().unwrap();
                    },
                    SignalingMessage::VideoToggled { participant_id, enabled } => {
                        let status = if enabled { "📹 enabled" } else { "📺 disabled" };
                        println!("📽️ {} video {}", participant_id, status);
                        print!("> ");
                        io::stdout().flush().unwrap();
                    },
                    SignalingMessage::Error { message } => {
                        println!("❌ Server error: {}", message);
                        print!("> ");
                        io::stdout().flush().unwrap();
                    },
                    _ => {
                        println!("📨 Received: {:?}", message);
                        print!("> ");
                        io::stdout().flush().unwrap();
                    }
                }
            },
            Err(e) => {
                error!("Error receiving message: {}", e);
                break;
            }
        }
    }
    Ok(())
}

async fn handle_user_input(cmd_tx: mpsc::UnboundedSender<String>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    print!("> ");
    io::stdout().flush().unwrap();

    while let Some(line) = lines.next_line().await? {
        if cmd_tx.send(line).is_err() {
            break;
        }
    }
    Ok(())
}

async fn send_message<S>(stream: &mut S, message: &SignalingMessage) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let data = message.to_framed()?;
    stream.write_all(&data).await?;
    Ok(())
}

async fn receive_message<S>(stream: &mut S) -> Result<SignalingMessage>
where
    S: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf).await?;

    Ok(SignalingMessage::from_bytes(&msg_buf)?)
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}