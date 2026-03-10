//! Node identity generation and key management.
//!
//! A ZTLP NodeID is a stable 128-bit random identifier assigned at enrollment.
//! Keys are X25519 (for Noise handshake) and optionally Ed25519 (for signing).
//! For this prototype, identities are stored as simple JSON files.

#![deny(unsafe_code)]

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

use crate::error::IdentityError;

/// 128-bit Node ID — the permanent identity of a ZTLP node.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 16]);

impl NodeId {
    /// Generate a new random NodeID.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a NodeID from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Zero NodeID (used in initial HELLO before identity is established).
    pub fn zero() -> Self {
        Self([0u8; 16])
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", hex::encode(self.0))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Persisted node identity, stored as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Stable 128-bit node identifier.
    pub node_id: NodeId,

    /// X25519 static private key (32 bytes) for Noise_XX handshake.
    /// In a real deployment this would be hardware-bound; here it's in the file.
    #[serde(with = "hex_bytes")]
    pub static_private_key: Vec<u8>,

    /// X25519 static public key (32 bytes), derived from the private key.
    #[serde(with = "hex_bytes")]
    pub static_public_key: Vec<u8>,
}

impl NodeIdentity {
    /// Generate a fresh identity with a new NodeID and X25519 keypair.
    pub fn generate() -> Result<Self, IdentityError> {
        let node_id = NodeId::generate();

        // Use snow's key generation for X25519 to ensure compatibility
        let builder = snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()
            .map_err(|e: snow::Error| IdentityError::InvalidKey(e.to_string()))?);
        let keypair = builder.generate_keypair()
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;

        Ok(Self {
            node_id,
            static_private_key: keypair.private.to_vec(),
            static_public_key: keypair.public.to_vec(),
        })
    }

    /// Load an identity from a JSON file.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let data = std::fs::read_to_string(path)?;
        let identity: Self = serde_json::from_str(&data)?;
        Ok(identity)
    }

    /// Save this identity to a JSON file.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Serde helper for Vec<u8> as hex strings.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_generation() {
        let id1 = NodeId::generate();
        let id2 = NodeId::generate();
        assert_ne!(id1, id2, "two random NodeIDs should differ");
    }

    #[test]
    fn test_identity_generation() {
        let ident = NodeIdentity::generate().expect("identity generation should succeed");
        assert_eq!(ident.static_private_key.len(), 32);
        assert_eq!(ident.static_public_key.len(), 32);
    }

    #[test]
    fn test_identity_roundtrip_json() {
        let ident = NodeIdentity::generate().expect("identity generation should succeed");
        let json = serde_json::to_string(&ident).expect("serialize");
        let restored: NodeIdentity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ident.node_id, restored.node_id);
        assert_eq!(ident.static_private_key, restored.static_private_key);
        assert_eq!(ident.static_public_key, restored.static_public_key);
    }
}
