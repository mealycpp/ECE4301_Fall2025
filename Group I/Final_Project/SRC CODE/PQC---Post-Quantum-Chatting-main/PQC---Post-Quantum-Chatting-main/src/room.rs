//! Room Management
//!
//! Handles chat room creation, joining, and participant management.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use uuid::Uuid;

/// Represents a participant in a room
#[derive(Debug, Clone)]
pub struct Participant {
    pub id: String,
    pub username: String,
    pub joined_at: SystemTime,
    pub audio_enabled: bool,
    pub video_enabled: bool,
}

impl Participant {
    pub fn new(id: String, username: String) -> Self {
        Self {
            id,
            username,
            joined_at: SystemTime::now(),
            audio_enabled: true,
            video_enabled: true,
        }
    }
}

/// Represents a chat room
#[derive(Debug)]
pub struct Room {
    pub id: String,
    pub name: String,
    pub created_at: SystemTime,
    pub max_participants: u32,
    pub is_locked: bool,
    participants: RwLock<HashMap<String, Participant>>,
}

impl Room {
    pub fn new(name: String, max_participants: u32) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            created_at: SystemTime::now(),
            max_participants,
            is_locked: false,
            participants: RwLock::new(HashMap::new()),
        }
    }

    /// Add a participant to the room
    pub fn add_participant(&self, participant: Participant) -> Result<(), RoomError> {
        if self.is_locked {
            return Err(RoomError::RoomLocked);
        }

        let mut participants = self.participants.write();
        if participants.len() >= self.max_participants as usize {
            return Err(RoomError::RoomFull);
        }

        participants.insert(participant.id.clone(), participant);
        Ok(())
    }

    /// Remove a participant from the room
    pub fn remove_participant(&self, participant_id: &str) -> Option<Participant> {
        self.participants.write().remove(participant_id)
    }

    /// Get a participant by ID
    pub fn get_participant(&self, participant_id: &str) -> Option<Participant> {
        self.participants.read().get(participant_id).cloned()
    }

    /// Get all participant IDs
    pub fn get_participant_ids(&self) -> Vec<String> {
        self.participants.read().keys().cloned().collect()
    }

    /// Get participant count
    pub fn participant_count(&self) -> usize {
        self.participants.read().len()
    }

    /// Get all participants
    pub fn get_participants(&self) -> Vec<Participant> {
        self.participants.read().values().cloned().collect()
    }

    /// Update participant audio state
    pub fn set_participant_audio(&self, participant_id: &str, enabled: bool) -> bool {
        if let Some(p) = self.participants.write().get_mut(participant_id) {
            p.audio_enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Update participant video state
    pub fn set_participant_video(&self, participant_id: &str, enabled: bool) -> bool {
        if let Some(p) = self.participants.write().get_mut(participant_id) {
            p.video_enabled = enabled;
            true
        } else {
            false
        }
    }
}

/// Room-related errors
#[derive(Debug, thiserror::Error)]
pub enum RoomError {
    #[error("Room is full")]
    RoomFull,
    #[error("Room is locked")]
    RoomLocked,
    #[error("Room not found")]
    RoomNotFound,
    #[error("Participant not found")]
    ParticipantNotFound,
    #[error("Already in a room")]
    AlreadyInRoom,
}

/// Manages all chat rooms
pub struct RoomManager {
    rooms: RwLock<HashMap<String, Arc<Room>>>,
    /// Maps participant ID to room ID
    participant_rooms: RwLock<HashMap<String, String>>,
}

impl RoomManager {
    pub fn new() -> Self {
        Self {
            rooms: RwLock::new(HashMap::new()),
            participant_rooms: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new room
    pub fn create_room(&self, name: String, max_participants: u32) -> Arc<Room> {
        let room = Arc::new(Room::new(name, max_participants));
        self.rooms.write().insert(room.id.clone(), room.clone());
        log::info!("Created room: {} ({})", room.name, room.id);
        room
    }

    /// Get a room by ID
    pub fn get_room(&self, room_id: &str) -> Option<Arc<Room>> {
        self.rooms.read().get(room_id).cloned()
    }

    /// Get a room by name
    pub fn get_room_by_name(&self, name: &str) -> Option<Arc<Room>> {
        self.rooms.read().values().find(|r| r.name == name).cloned()
    }

    /// List all rooms
    pub fn list_rooms(&self) -> Vec<Arc<Room>> {
        self.rooms.read().values().cloned().collect()
    }

    /// Join a room
    pub fn join_room(
        &self,
        room_id: &str,
        participant: Participant,
    ) -> Result<Arc<Room>, RoomError> {
        // Check if already in a room
        if self.participant_rooms.read().contains_key(&participant.id) {
            self.leave_room(&participant.id)?;
        }

        let room = self.get_room(room_id).ok_or(RoomError::RoomNotFound)?;
        room.add_participant(participant.clone())?;
        self.participant_rooms
            .write()
            .insert(participant.id.clone(), room_id.to_string());
        
        log::info!("Participant {} joined room {}", participant.username, room.name);
        Ok(room)
    }

    /// Leave current room
    pub fn leave_room(&self, participant_id: &str) -> Result<(), RoomError> {
        let room_id = self
            .participant_rooms
            .write()
            .remove(participant_id)
            .ok_or(RoomError::ParticipantNotFound)?;

        if let Some(room) = self.get_room(&room_id) {
            room.remove_participant(participant_id);
            log::info!("Participant {} left room {}", participant_id, room.name);
        }

        Ok(())
    }

    /// Get the room a participant is in
    pub fn get_participant_room(&self, participant_id: &str) -> Option<Arc<Room>> {
        let room_id = self.participant_rooms.read().get(participant_id).cloned()?;
        self.get_room(&room_id)
    }

    /// Delete a room
    pub fn delete_room(&self, room_id: &str) -> bool {
        if let Some(room) = self.rooms.write().remove(room_id) {
            // Remove all participants from mapping
            let participant_ids = room.get_participant_ids();
            let mut pr = self.participant_rooms.write();
            for pid in participant_ids {
                pr.remove(&pid);
            }
            log::info!("Deleted room: {} ({})", room.name, room.id);
            true
        } else {
            false
        }
    }
}

impl Default for RoomManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_room() {
        let room = Room::new("Test Room".to_string(), 10);
        assert_eq!(room.name, "Test Room");
        assert_eq!(room.max_participants, 10);
        assert!(!room.is_locked);
    }

    #[test]
    fn test_add_participant() {
        let room = Room::new("Test Room".to_string(), 10);
        let participant = Participant::new("p1".to_string(), "User1".to_string());
        
        room.add_participant(participant).unwrap();
        assert_eq!(room.participant_count(), 1);
    }

    #[test]
    fn test_room_capacity() {
        let room = Room::new("Test Room".to_string(), 2);
        
        let p1 = Participant::new("p1".to_string(), "User1".to_string());
        let p2 = Participant::new("p2".to_string(), "User2".to_string());
        let p3 = Participant::new("p3".to_string(), "User3".to_string());
        
        room.add_participant(p1).unwrap();
        room.add_participant(p2).unwrap();
        
        let result = room.add_participant(p3);
        assert!(matches!(result, Err(RoomError::RoomFull)));
    }

    #[test]
    fn test_room_manager() {
        let manager = RoomManager::new();
        
        let room = manager.create_room("Test Room".to_string(), 10);
        let room_id = room.id.clone();
        
        let participant = Participant::new("p1".to_string(), "User1".to_string());
        manager.join_room(&room_id, participant).unwrap();
        
        let participant_room = manager.get_participant_room("p1");
        assert!(participant_room.is_some());
        assert_eq!(participant_room.unwrap().id, room_id);
        
        manager.leave_room("p1").unwrap();
        assert!(manager.get_participant_room("p1").is_none());
    }
}
