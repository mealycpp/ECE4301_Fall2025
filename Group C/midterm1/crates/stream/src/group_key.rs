// Group Key Establishment Module
// crates/stream/src/group_key.rs

use anyhow::{Result, bail};
use crypto::{SessionKeyMaterial, ecdh_kex};
use sha2::{Sha256, Digest};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct GroupMember {
    pub node_id: String,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct GroupKeyContext {
    pub group_key: SessionKeyMaterial,
    pub members: Vec<GroupMember>,
    pub key_hash: [u8; 32],
}

impl GroupMember {
    pub fn parse(member_str: &str) -> Result<Self> {
        let parts: Vec<&str> = member_str.split(':').collect();
        if parts.len() != 3 {
            bail!("Invalid member format. Expected: node_id:host:port");
        }
        
        Ok(Self {
            node_id: parts[0].to_string(),
            address: format!("{}:{}", parts[1], parts[2]),
        })
    }
}

/// Leader-distributed group key establishment
pub struct LeaderNode {
    node_id: String,
    members: Vec<GroupMember>,
}

impl LeaderNode {
    pub fn new(node_id: String, members: Vec<GroupMember>) -> Self {
        Self { node_id, members }
    }
    
    /// Generate group key and distribute to all members
    pub async fn establish_group_key(&self) -> Result<GroupKeyContext> {
        info!("Leader: Generating group key for {} members", self.members.len());
        
        // Generate fresh group key
        let group_key = SessionKeyMaterial::generate_random();
        let group_key_bytes = group_key.as_bytes();
        
        // Compute key hash for verification
        let mut hasher = Sha256::new();
        hasher.update(&group_key_bytes);
        let key_hash: [u8; 32] = hasher.finalize().into();
        
        info!("Leader: Group key hash: {}", hex::encode(&key_hash));
        
        // Establish pairwise channels and distribute key
        for member in &self.members {
            info!("Leader: Connecting to member {}", member.node_id);
            
            let mut stream = match TcpStream::connect(&member.address).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Leader: Failed to connect to {}: {}", member.node_id, e);
                    continue;
                }
            };
            
            // Perform ECDH with member
            let my_keypair = ecdh_kex::EcdhKeyPair::generate();
            let my_public = my_keypair.public_key_bytes();
            
            // Exchange public keys
            stream.write_u32(my_public.len() as u32).await?;
            stream.write_all(&my_public).await?;
            
            let peer_pub_len = stream.read_u32().await? as usize;
            let mut peer_public = vec![0u8; peer_pub_len];
            stream.read_exact(&mut peer_public).await?;
            
            // Derive pairwise key
            let pairwise_key = my_keypair.derive_session_key(
                &peer_public,
                format!("leader-{}", member.node_id).as_bytes()
            )?;
            
            // Encrypt group key with pairwise key
            use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit}};
            let cipher = Aes128Gcm::new_from_slice(&pairwise_key.as_bytes()[..16])?;
            let nonce = [0u8; 12]; // Single-use key, can use zero nonce
            
            let encrypted_group_key = cipher.encrypt(&nonce.into(), group_key_bytes.as_ref())
                .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
            
            // Send encrypted group key + hash
            stream.write_u32(encrypted_group_key.len() as u32).await?;
            stream.write_all(&encrypted_group_key).await?;
            stream.write_all(&key_hash).await?;
            
            // Wait for confirmation
            let mut confirm = [0u8; 32];
            stream.read_exact(&mut confirm).await?;
            
            if confirm != key_hash {
                bail!("Member {} failed to confirm group key", member.node_id);
            }
            
            info!("Leader: Member {} confirmed group key", member.node_id);
        }
        
        Ok(GroupKeyContext {
            group_key,
            members: self.members.clone(),
            key_hash,
        })
    }
}

pub struct MemberNode {
    node_id: String,
    listen_addr: String,
}

impl MemberNode {
    pub fn new(node_id: String, listen_addr: String) -> Self {
        Self { node_id, listen_addr }
    }
    
    /// Wait for leader to distribute group key
    pub async fn receive_group_key(&self) -> Result<GroupKeyContext> {
        info!("Member {}: Waiting for leader connection on {}", self.node_id, self.listen_addr);
        
        let listener = tokio::net::TcpListener::bind(&self.listen_addr).await?;
        let (mut stream, peer) = listener.accept().await?;
        
        info!("Member {}: Accepted leader connection from {}", self.node_id, peer);
        
        // Perform ECDH with leader
        let my_keypair = ecdh_kex::EcdhKeyPair::generate();
        let my_public = my_keypair.public_key_bytes();
        
        // Exchange public keys
        let leader_pub_len = stream.read_u32().await? as usize;
        let mut leader_public = vec![0u8; leader_pub_len];
        stream.read_exact(&mut leader_public).await?;
        
        stream.write_u32(my_public.len() as u32).await?;
        stream.write_all(&my_public).await?;
        
        // Derive pairwise key
        let pairwise_key = my_keypair.derive_session_key(
            &leader_public,
            format!("leader-{}", self.node_id).as_bytes()
        )?;
        
        // Receive encrypted group key + hash
        let enc_key_len = stream.read_u32().await? as usize;
        let mut encrypted_group_key = vec![0u8; enc_key_len];
        stream.read_exact(&mut encrypted_group_key).await?;
        
        let mut expected_hash = [0u8; 32];
        stream.read_exact(&mut expected_hash).await?;
        
        // Decrypt group key
        use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit}};
        let cipher = Aes128Gcm::new_from_slice(&pairwise_key.as_bytes()[..16])?;
        let nonce = [0u8; 12];
        
        let group_key_bytes = cipher.decrypt(&nonce.into(), encrypted_group_key.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        let group_key = SessionKeyMaterial::from_bytes(&group_key_bytes)?;
        
        // Verify hash
        let mut hasher = Sha256::new();
        hasher.update(&group_key_bytes);
        let computed_hash: [u8; 32] = hasher.finalize().into();
        
        if computed_hash != expected_hash {
            bail!("Group key hash mismatch!");
        }
        
        info!("Member {}: Group key verified: {}", self.node_id, hex::encode(&computed_hash));
        
        // Send confirmation
        stream.write_all(&computed_hash).await?;
        
        Ok(GroupKeyContext {
            group_key,
            members: vec![],
            key_hash: computed_hash,
        })
    }
}

/// Save group key to file
pub async fn save_group_key(key: &SessionKeyMaterial, path: &str) -> Result<()> {
    let key_bytes = key.as_bytes();
    tokio::fs::write(path, &key_bytes).await?;
    info!("Saved group key ({} bytes) to: {}", key_bytes.len(), path);
    Ok(())
}

/// Load group key from file
pub async fn load_group_key(path: &str) -> Result<SessionKeyMaterial> {
    info!("Loading group key from: {}", path);
    let key_bytes = tokio::fs::read(path).await?;
    
    // SessionKeyMaterial is 24 bytes: 16-byte AES key + 8-byte nonce base
    if key_bytes.len() != 24 {
        bail!("Invalid group key file: expected 24 bytes, got {}", key_bytes.len());
    }
    
    SessionKeyMaterial::from_bytes(&key_bytes)
}