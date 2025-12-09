//! PQC Chat Client - Main Entry Point
//!
//! Signaling client with post-quantum key exchange.

use anyhow::Result;
use clap::Parser;
use log::{error, info};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, pki_types::ServerName};
use tokio_rustls::TlsConnector;

use pqc_chat::crypto::kyber::{KyberKeyExchange, KyberSession};
use pqc_chat::protocol::SignalingMessage;
use pqc_chat::ClientConfig;

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(name = "pqc-client")]
#[command(about = "PQC Chat Client - Post-Quantum Secure Chat")]
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

/// Client engine state
pub struct ClientEngine {
    config: ClientConfig,
    kyber: KyberKeyExchange,
    session: Option<KyberSession>,
    participant_id: Option<String>,
    username: String,
    current_room: Option<String>,
}

impl ClientEngine {
    pub fn new(config: ClientConfig, username: String) -> Self {
        Self {
            config,
            kyber: KyberKeyExchange::new(),
            session: None,
            participant_id: None,
            username,
            current_room: None,
        }
    }

    /// Get the Kyber public key for key exchange
    pub fn get_public_key(&self) -> Vec<u8> {
        self.kyber.public_key_bytes()
    }

    /// Complete key exchange with server's ciphertext
    pub fn complete_key_exchange(&mut self, ciphertext: &[u8]) -> Result<()> {
        let shared_secret = self.kyber.decapsulate(ciphertext)?;
        self.session = Some(KyberSession::new(shared_secret));
        info!("Post-quantum key exchange completed");
        Ok(())
    }

    /// Check if key exchange is complete
    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }
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

    // Create client engine
    let mut engine = ClientEngine::new(config, username.clone());

    // Configure TLS
    // WARNING: NoVerifier is used for development with self-signed certificates.
    // For production, use proper certificate verification with CA certificates.
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));

    // Connect to server
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    info!("Connecting to server at {}...", addr);

    let stream = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from(host.clone())?;
    let mut tls_stream = connector.connect(server_name, stream).await?;

    info!("Connected to server");

    // Perform Kyber key exchange
    let key_init = SignalingMessage::KeyExchangeInit {
        public_key: engine.get_public_key(),
    };
    send_message(&mut tls_stream, &key_init).await?;

    let response = receive_message(&mut tls_stream).await?;
    if let SignalingMessage::KeyExchangeResponse { ciphertext } = response {
        engine.complete_key_exchange(&ciphertext)?;
    } else {
        error!("Unexpected response to key exchange");
        return Err(anyhow::anyhow!("Key exchange failed"));
    }

    // Login
    let login = SignalingMessage::Login {
        username: username.clone(),
    };
    send_message(&mut tls_stream, &login).await?;

    let response = receive_message(&mut tls_stream).await?;
    if let SignalingMessage::LoginResponse {
        success,
        participant_id,
        error,
    } = response
    {
        if success {
            engine.participant_id = participant_id;
            info!("Logged in as {}", username);
        } else {
            error!("Login failed: {:?}", error);
            return Err(anyhow::anyhow!("Login failed"));
        }
    }

    // Interactive mode - list rooms
    let list_rooms = SignalingMessage::ListRooms;
    send_message(&mut tls_stream, &list_rooms).await?;

    let response = receive_message(&mut tls_stream).await?;
    if let SignalingMessage::RoomList { rooms } = response {
        info!("Available rooms:");
        for room in &rooms {
            info!(
                "  {} - {} ({}/{} participants)",
                room.id, room.name, room.participants, room.max_participants
            );
        }
        
        if rooms.is_empty() {
            info!("No rooms available. Creating a test room...");
            let create_room = SignalingMessage::CreateRoom {
                name: "Test Room".to_string(),
                max_participants: Some(10),
            };
            send_message(&mut tls_stream, &create_room).await?;
            
            let response = receive_message(&mut tls_stream).await?;
            if let SignalingMessage::RoomCreated { success, room_id, room_name, .. } = response {
                if success {
                    info!("Created room: {} ({})", room_name.unwrap_or_default(), room_id.clone().unwrap_or_default());
                    
                    // Join the room
                    if let Some(rid) = room_id {
                        let join_room = SignalingMessage::JoinRoom {
                            room_id: rid,
                            username: username.clone(),
                        };
                        send_message(&mut tls_stream, &join_room).await?;
                        
                        let response = receive_message(&mut tls_stream).await?;
                        if let SignalingMessage::RoomJoined { success, room_name, .. } = response {
                            if success {
                                info!("Joined room: {}", room_name.unwrap_or_default());
                            }
                        }
                    }
                }
            }
        }
    }

    info!("Client session complete. Press Ctrl+C to exit.");
    
    // Keep connection alive
    tokio::signal::ctrl_c().await?;
    
    info!("Disconnecting...");
    Ok(())
}

/// Send a signaling message
async fn send_message<S>(stream: &mut S, message: &SignalingMessage) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let data = message.to_framed()?;
    stream.write_all(&data).await?;
    Ok(())
}

/// Receive a signaling message
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

/// Certificate verifier that accepts any certificate.
/// 
/// WARNING: This is for DEVELOPMENT ONLY with self-signed certificates.
/// In production, use proper certificate verification with CA certificates.
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
