//! Signaling Protocol
//!
//! Defines the message format for client-server signaling.

use serde::{Deserialize, Serialize};

/// Signaling messages exchanged between client and server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalingMessage {
    // Client -> Server
    Login {
        username: String,
    },
    ListRooms,
    ListServerUsers,
    CreateRoom {
        name: String,
        max_participants: Option<u32>,
    },
    JoinRoom {
        room_id: String,
        username: String,
    },
    LeaveRoom,
    ToggleAudio {
        enabled: bool,
    },
    ToggleVideo {
        enabled: bool,
    },
    MediaOffer {
        target_id: String,
        sdp: String,
    },
    MediaAnswer {
        target_id: String,
        sdp: String,
    },
    IceCandidate {
        target_id: String,
        candidate: String,
    },
    
    // Chat messages
    SendMessage {
        content: String,
    },
    
    // Audio streaming
    AudioData {
        data: Vec<u8>,
    },
    
    // Key exchange messages
    KeyExchangeInit {
        public_key: Vec<u8>,
    },
    KeyExchangeResponse {
        ciphertext: Vec<u8>,
    },

    // Server -> Client
    LoginResponse {
        success: bool,
        participant_id: Option<String>,
        error: Option<String>,
    },
    RoomList {
        rooms: Vec<RoomInfo>,
    },
    ServerUserList {
        users: Vec<ServerUserInfo>,
    },
    RoomCreated {
        success: bool,
        room_id: Option<String>,
        room_name: Option<String>,
        error: Option<String>,
    },
    RoomJoined {
        success: bool,
        room_id: Option<String>,
        room_name: Option<String>,
        participants: Option<Vec<ParticipantInfo>>,
        error: Option<String>,
    },
    RoomLeft {
        success: bool,
        error: Option<String>,
    },
    ParticipantJoined {
        participant_id: String,
        username: String,
    },
    ParticipantLeft {
        participant_id: String,
    },
    AudioToggled {
        participant_id: String,
        enabled: bool,
    },
    VideoToggled {
        participant_id: String,
        enabled: bool,
    },
    
    // Chat messages
    MessageReceived {
        sender_id: String,
        sender_username: String,
        content: String,
        timestamp: u64,
    },
    
    // Audio streaming
    AudioDataReceived {
        sender_id: String,
        data: Vec<u8>,
    },
    
    Error {
        message: String,
    },
}

/// Information about a room
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomInfo {
    pub id: String,
    pub name: String,
    pub participants: u32,
    pub max_participants: u32,
    pub is_locked: bool,
}

/// Information about a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantInfo {
    pub id: String,
    pub username: String,
    pub audio_enabled: bool,
    pub video_enabled: bool,
}

/// Information about a server-wide user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerUserInfo {
    pub id: String,
    pub username: String,
    pub connected_at: u64, // Unix timestamp
    pub current_room: Option<String>,
    pub audio_enabled: bool,
    pub video_enabled: bool,
}

impl SignalingMessage {
    /// Serialize the message to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize a message from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Create a framed message with length prefix (4 bytes, big-endian)
    pub fn to_framed(&self) -> Result<Vec<u8>, serde_json::Error> {
        let data = self.to_bytes()?;
        let len = (data.len() as u32).to_be_bytes();
        let mut framed = Vec::with_capacity(4 + data.len());
        framed.extend_from_slice(&len);
        framed.extend_from_slice(&data);
        Ok(framed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_login() {
        let msg = SignalingMessage::Login {
            username: "test_user".to_string(),
        };
        let bytes = msg.to_bytes().unwrap();
        let parsed: SignalingMessage = SignalingMessage::from_bytes(&bytes).unwrap();
        
        if let SignalingMessage::Login { username } = parsed {
            assert_eq!(username, "test_user");
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn test_framed_message() {
        let msg = SignalingMessage::ListRooms;
        let framed = msg.to_framed().unwrap();
        
        // Check length prefix
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]);
        assert_eq!(len as usize, framed.len() - 4);
    }
}
