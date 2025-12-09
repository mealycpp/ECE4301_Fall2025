//! PQC Chat Server - Main Entry Point
//!
//! TCP TLS listener for signaling with post-quantum key exchange.

use anyhow::Result;
use clap::Parser;
use log::{error, info};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::rustls::{self, pki_types::PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use pqc_chat::crypto::kyber::KyberKeyExchange;
use pqc_chat::media::MediaForwarder;
use pqc_chat::protocol::{ParticipantInfo, RoomInfo, ServerUserInfo, SignalingMessage};
use pqc_chat::room::{Participant, RoomManager};
use pqc_chat::ServerConfig;

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(name = "pqc-server")]
#[command(about = "PQC Chat Server - Post-Quantum Secure Chat")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config/server.toml")]
    config: PathBuf,

    /// Override host to bind to
    #[arg(long)]
    host: Option<String>,

    /// Override signaling port
    #[arg(short, long)]
    port: Option<u16>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Client connection state
struct ClientState {
    participant_id: String,
    username: Option<String>,
    shared_secret: Option<Vec<u8>>,
    message_tx: mpsc::UnboundedSender<SignalingMessage>,
}

impl ClientState {
    fn new(message_tx: mpsc::UnboundedSender<SignalingMessage>) -> Self {
        Self {
            participant_id: Uuid::new_v4().to_string(),
            username: None,
            shared_secret: None,
            message_tx,
        }
    }
}

/// Server state
struct ServerState {
    room_manager: RoomManager,
    media_forwarder: RwLock<MediaForwarder>,
    clients: RwLock<HashMap<String, Arc<RwLock<ClientState>>>>,
}

impl ServerState {
    fn new(audio_port: u16, video_port: u16) -> Self {
        Self {
            room_manager: RoomManager::new(),
            media_forwarder: RwLock::new(MediaForwarder::new(audio_port, video_port)),
            clients: RwLock::new(HashMap::new()),
        }
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
        ServerConfig::from_file(args.config.to_str().unwrap())?
    } else {
        info!("Config file not found, using defaults");
        ServerConfig::default()
    };

    let host = args.host.unwrap_or(config.signaling_host.clone());
    let port = args.port.unwrap_or(config.signaling_port);

    // Load TLS certificates
    let certs = load_certs(&config.certfile)?;
    let key = load_key(&config.keyfile)?;

    // Configure TLS
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Create server state
    let state = Arc::new(ServerState::new(config.audio_port, config.video_port));

    // Start media forwarder
    state.media_forwarder.write().start()?;

    // Bind TCP listener
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("PQC Chat Server listening on {}", addr);

    // Accept connections
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    info!("New TLS connection from {}", peer_addr);
                    if let Err(e) = handle_client(tls_stream, peer_addr, state).await {
                        error!("Client {} error: {}", peer_addr, e);
                    }
                }
                Err(e) => {
                    error!("TLS handshake failed for {}: {}", peer_addr, e);
                }
            }
        });
    }
}

/// Handle a connected client
async fn handle_client<S>(
    stream: tokio_rustls::server::TlsStream<S>,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Create message channel for broadcasting to this client
    let (message_tx, mut message_rx) = mpsc::unbounded_channel();
    
    let client_state = Arc::new(RwLock::new(ClientState::new(message_tx)));
    let participant_id = client_state.read().participant_id.clone();

    // Register client
    state
        .clients
        .write()
        .insert(participant_id.clone(), client_state.clone());

    // Split stream for concurrent reading and writing
    let (read_half, mut write_half) = tokio::io::split(stream);
    
    // Spawn task to handle outgoing messages (broadcasts from server)
    let broadcast_task = tokio::spawn(async move {
        while let Some(message) = message_rx.recv().await {
            if let Ok(data) = message.to_framed() {
                if write_half.write_all(&data).await.is_err() {
                    break;
                }
            }
        }
    });

    // Handle incoming messages
    let mut read_stream = read_half;

    let result = async {
        loop {
            // Read message length (4 bytes)
            let mut len_buf = [0u8; 4];
            if read_stream.read_exact(&mut len_buf).await.is_err() {
                break;
            }

            let msg_len = u32::from_be_bytes(len_buf) as usize;
            // Limit signaling messages to 64KB (reasonable for JSON)
            if msg_len > 64 * 1024 {
                error!("Message too large from {} ({} bytes)", peer_addr, msg_len);
                break;
            }

            // Read message
            let mut msg_buf = vec![0u8; msg_len];
            if read_stream.read_exact(&mut msg_buf).await.is_err() {
                break;
            }

            // Parse and handle message
            match SignalingMessage::from_bytes(&msg_buf) {
                Ok(message) => {
                    let response =
                        handle_message(message, &participant_id, &client_state, &state).await;
                    
                    // Send response through the client's message channel
                    if let Some(client) = state.clients.read().get(&participant_id) {
                        let _ = client.read().message_tx.send(response);
                    }
                }
                Err(e) => {
                    error!("Invalid message from {}: {}", peer_addr, e);
                    let error_msg = SignalingMessage::Error {
                        message: "Invalid message format".to_string(),
                    };
                    if let Some(client) = state.clients.read().get(&participant_id) {
                        let _ = client.read().message_tx.send(error_msg);
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Cleanup
    state.clients.write().remove(&participant_id);
    
    // Notify other room participants that this user left
    if let Some(room) = state.room_manager.get_participant_room(&participant_id) {
        let _username = client_state.read().username.clone().unwrap_or_default();
        broadcast_to_room(&state, &room.id, &participant_id, SignalingMessage::ParticipantLeft {
            participant_id: participant_id.clone(),
        }).await;
    }
    
    let _ = state.room_manager.leave_room(&participant_id);
    broadcast_task.abort();
    info!("Client {} disconnected", peer_addr);

    result
}

/// Handle a signaling message
async fn handle_message(
    message: SignalingMessage,
    participant_id: &str,
    client_state: &Arc<RwLock<ClientState>>,
    state: &Arc<ServerState>,
) -> SignalingMessage {
    match message {
        SignalingMessage::Login { username } => {
            client_state.write().username = Some(username.clone());
            info!("User {} logged in as {}", participant_id, username);
            SignalingMessage::LoginResponse {
                success: true,
                participant_id: Some(participant_id.to_string()),
                error: None,
            }
        }

        SignalingMessage::KeyExchangeInit { public_key } => {
            // Receive client's public key and encapsulate
            match KyberKeyExchange::public_key_from_bytes(&public_key) {
                Ok(client_pk) => {
                    let (ciphertext, shared_secret) = KyberKeyExchange::encapsulate(&client_pk);
                    client_state.write().shared_secret = Some(shared_secret);
                    info!("Kyber key exchange completed for {}", participant_id);
                    SignalingMessage::KeyExchangeResponse { ciphertext }
                }
                Err(e) => SignalingMessage::Error {
                    message: format!("Key exchange failed: {}", e),
                },
            }
        }

        SignalingMessage::ListRooms => {
            let rooms: Vec<RoomInfo> = state
                .room_manager
                .list_rooms()
                .iter()
                .map(|r| RoomInfo {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    participants: r.participant_count() as u32,
                    max_participants: r.max_participants,
                    is_locked: r.is_locked,
                })
                .collect();
            SignalingMessage::RoomList { rooms }
        }

        SignalingMessage::ListServerUsers => {
            let clients = state.clients.read();
            let mut users = Vec::new();
            
            for (client_id, client_state) in clients.iter() {
                let client = client_state.read();
                if let Some(username) = &client.username {
                    // Get current room for this user
                    let current_room = state.room_manager.get_participant_room(client_id)
                        .map(|room| room.name.clone());
                    
                    // Get audio/video status from room if they're in one
                    let (audio_enabled, video_enabled) = if let Some(room) = state.room_manager.get_participant_room(client_id) {
                        if let Some(participant) = room.get_participant(client_id) {
                            (participant.audio_enabled, participant.video_enabled)
                        } else {
                            (true, false) // Default values
                        }
                    } else {
                        (true, false) // Default values for lobby users
                    };
                    
                    users.push(ServerUserInfo {
                        id: client_id.clone(),
                        username: username.clone(),
                        connected_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        current_room,
                        audio_enabled,
                        video_enabled,
                    });
                }
            }
            
            info!("Returning {} connected users", users.len());
            SignalingMessage::ServerUserList { users }
        }

        SignalingMessage::CreateRoom {
            name,
            max_participants,
        } => {
            let room = state
                .room_manager
                .create_room(name.clone(), max_participants.unwrap_or(10));
            SignalingMessage::RoomCreated {
                success: true,
                room_id: Some(room.id.clone()),
                room_name: Some(room.name.clone()),
                error: None,
            }
        }

        SignalingMessage::JoinRoom { room_id, username } => {
            let participant = Participant::new(participant_id.to_string(), username.clone());

            match state.room_manager.join_room(&room_id, participant) {
                Ok(room) => {
                    // Broadcast to other participants that someone joined
                    broadcast_to_room(&state, &room_id, participant_id, SignalingMessage::ParticipantJoined {
                        participant_id: participant_id.to_string(),
                        username: username.clone(),
                    }).await;

                    let participants: Vec<ParticipantInfo> = room
                        .get_participants()
                        .iter()
                        .map(|p| ParticipantInfo {
                            id: p.id.clone(),
                            username: p.username.clone(),
                            audio_enabled: p.audio_enabled,
                            video_enabled: p.video_enabled,
                        })
                        .collect();

                    SignalingMessage::RoomJoined {
                        success: true,
                        room_id: Some(room.id.clone()),
                        room_name: Some(room.name.clone()),
                        participants: Some(participants),
                        error: None,
                    }
                }
                Err(e) => SignalingMessage::RoomJoined {
                    success: false,
                    room_id: None,
                    room_name: None,
                    participants: None,
                    error: Some(e.to_string()),
                },
            }
        }

        SignalingMessage::LeaveRoom => {
            // Get room info before leaving
            let room_info = state.room_manager.get_participant_room(participant_id);
            
            match state.room_manager.leave_room(participant_id) {
                Ok(()) => {
                    // Broadcast to other participants that someone left
                    if let Some(room) = room_info {
                        broadcast_to_room(&state, &room.id, participant_id, SignalingMessage::ParticipantLeft {
                            participant_id: participant_id.to_string(),
                        }).await;
                    }
                    
                    SignalingMessage::RoomLeft {
                        success: true,
                        error: None,
                    }
                },
                Err(e) => SignalingMessage::RoomLeft {
                    success: false,
                    error: Some(e.to_string()),
                },
            }
        },

        SignalingMessage::ToggleAudio { enabled } => {
            if let Some(room) = state.room_manager.get_participant_room(participant_id) {
                room.set_participant_audio(participant_id, enabled);
            }
            SignalingMessage::AudioToggled {
                participant_id: participant_id.to_string(),
                enabled,
            }
        }

        SignalingMessage::ToggleVideo { enabled } => {
            if let Some(room) = state.room_manager.get_participant_room(participant_id) {
                room.set_participant_video(participant_id, enabled);
            }
            SignalingMessage::VideoToggled {
                participant_id: participant_id.to_string(),
                enabled,
            }
        }

        SignalingMessage::SendMessage { content } => {
            // Get sender username
            let sender_username = client_state.read().username.clone().unwrap_or_else(|| "Unknown".to_string());
            
            // Find which room the sender is in
            if let Some(room) = state.room_manager.get_participant_room(participant_id) {
                let room_id = room.id.clone();
                
                // Create chat message
                let chat_message = SignalingMessage::MessageReceived {
                    sender_id: participant_id.to_string(),
                    sender_username: sender_username.clone(),
                    content: content.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
                
                // Broadcast to all participants in the room (including sender)
                broadcast_to_room_all(&state, &room_id, chat_message).await;
                
                info!("Chat message from {} in room {}: {}", sender_username, room.name, content);
            }
            
            // Return success response
            SignalingMessage::Error { message: "Message sent".to_string() }
        }

        SignalingMessage::AudioData { data } => {
            // Find which room the sender is in and forward audio to all participants
            if let Some(room) = state.room_manager.get_participant_room(participant_id) {
                let room_id = room.id.clone();
                
                // Create audio message
                let audio_message = SignalingMessage::AudioDataReceived {
                    sender_id: participant_id.to_string(),
                    data,
                };
                
                // Broadcast to all other participants in the room (excluding sender)
                broadcast_to_room(&state, &room_id, participant_id, audio_message).await;
            }
            
            // No response needed for audio data
            SignalingMessage::Error { message: "Audio forwarded".to_string() }
        }

        _ => SignalingMessage::Error {
            message: "Unsupported message type".to_string(),
        },
    }
}

/// Load TLS certificates
fn load_certs(path: &PathBuf) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// Load TLS private key
fn load_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let keys = rustls_pemfile::private_key(&mut reader)?;
    keys.ok_or_else(|| anyhow::anyhow!("No private key found"))
}

/// Broadcast a message to all participants in a room except the sender
async fn broadcast_to_room(
    state: &Arc<ServerState>, 
    room_id: &str, 
    sender_id: &str, 
    message: SignalingMessage
) {
    if let Some(room) = state.room_manager.get_room(room_id) {
        let participant_ids = room.get_participant_ids();
        let clients = state.clients.read();
        
        info!("Broadcasting {:?} to room {} (except sender {})", message, room_id, sender_id);
        info!("Participants in room: {:?}", participant_ids);
        
        for participant_id in participant_ids {
            // Don't send to the sender
            if participant_id != sender_id {
                if let Some(client_state) = clients.get(&participant_id) {
                    info!("Sending broadcast to participant {}", participant_id);
                    if let Err(e) = client_state.read().message_tx.send(message.clone()) {
                        error!("Failed to send broadcast to {}: {}", participant_id, e);
                    }
                } else {
                    info!("Client {} not found in clients map", participant_id);
                }
            }
        }
    } else {
        info!("Room {} not found for broadcast", room_id);
    }
}

/// Broadcast a message to all participants in a room including the sender
async fn broadcast_to_room_all(
    state: &Arc<ServerState>, 
    room_id: &str, 
    message: SignalingMessage
) {
    if let Some(room) = state.room_manager.get_room(room_id) {
        let participant_ids = room.get_participant_ids();
        let clients = state.clients.read();
        
        info!("Broadcasting {:?} to all in room {}", message, room_id);
        info!("Participants in room: {:?}", participant_ids);
        
        for participant_id in participant_ids {
            if let Some(client_state) = clients.get(&participant_id) {
                info!("Sending broadcast to participant {}", participant_id);
                if let Err(e) = client_state.read().message_tx.send(message.clone()) {
                    error!("Failed to send broadcast to {}: {}", participant_id, e);
                }
            } else {
                info!("Client {} not found in clients map", participant_id);
            }
        }
    } else {
        info!("Room {} not found for broadcast", room_id);
    }
}
