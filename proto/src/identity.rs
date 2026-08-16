//! Node identity generation and key management.
//!
//! A ZTLP NodeID is a stable 128-bit random identifier assigned at enrollment.
//! Keys are X25519 (for Noise handshake) and optionally Ed25519 (for signing).
//! For this prototype, identities are stored as simple JSON files.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

use crate::error::IdentityError;

/// 128-bit Node ID — the permanent identity of a ZTLP node.
/// Serializes to/from hex strings in JSON (e.g., "76f200a5...").
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 16]);

impl serde::Serialize for NodeId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for NodeId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom(format!(
                "expected 16 bytes for NodeId, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(NodeId(arr))
    }
}

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

    /// Optional OS-user binding (D3.T1).
    ///
    /// When set (typically by `ztlp setup --bind-user`), the daemon will refuse
    /// to start if the current process's user identity does not match this
    /// value. The format is platform-specific:
    /// - Windows: a SID string like `S-1-5-21-...`.
    /// - Unix: `uid:<numeric uid>` (e.g. `uid:1000`).
    ///
    /// `#[serde(default)]` keeps existing identity.json files (written before
    /// this field existed) loading cleanly with `bound_user_sid = None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_user_sid: Option<String>,

    /// Ed25519 signing key seed (32 bytes), used to authenticate
    /// PEER_ENDPOINTS/PUNCH_REPORT claims to the NS (irt-rwzo fix:
    /// without this, any UDP sender could claim to be any node_id
    /// and poison the NS's endpoint store for that node — a MITM/DoS
    /// vector). `#[serde(default)]` + the migrating `load()` below
    /// keep pre-existing identity.json files (written before this
    /// field existed) loading cleanly, lazily generating and
    /// persisting a signing key on first load.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_bytes")]
    pub signing_key_seed: Option<Vec<u8>>,
}

impl NodeIdentity {
    /// Generate a fresh identity with a new NodeID, X25519 keypair, and
    /// Ed25519 signing keypair.
    pub fn generate() -> Result<Self, IdentityError> {
        let node_id = NodeId::generate();

        // Use snow's key generation for X25519 to ensure compatibility
        let builder = snow::Builder::new(
            "Noise_XX_25519_ChaChaPoly_BLAKE2s"
                .parse()
                .map_err(|e: snow::Error| IdentityError::InvalidKey(e.to_string()))?,
        );
        let keypair = builder
            .generate_keypair()
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;

        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        Ok(Self {
            node_id,
            static_private_key: keypair.private.to_vec(),
            static_public_key: keypair.public.to_vec(),
            bound_user_sid: None,
            signing_key_seed: Some(seed.to_vec()),
        })
    }

    /// Load an identity from a JSON file.
    ///
    /// Identities persisted before the irt-rwzo fix have no
    /// `signing_key_seed`. Rather than silently leaving such nodes
    /// unable to authenticate PEER_ENDPOINTS/PUNCH_REPORT claims
    /// forever, lazily generate and persist a signing key the first
    /// time an old identity file is loaded.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let data = std::fs::read_to_string(path)?;
        let mut identity: Self = serde_json::from_str(&data)?;

        if identity.signing_key_seed.is_none() {
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            identity.signing_key_seed = Some(seed.to_vec());
            identity.save(path)?;
        }

        Ok(identity)
    }

    /// Save this identity to a JSON file.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Return the Ed25519 signing key, generating an ephemeral one if
    /// this identity somehow has none (defensive — `load()`/`generate()`
    /// always populate it, but callers holding a hand-built `NodeIdentity`
    /// in tests should not panic).
    pub fn signing_key(&self) -> SigningKey {
        match &self.signing_key_seed {
            Some(seed) if seed.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(seed);
                SigningKey::from_bytes(&arr)
            }
            _ => {
                let mut seed = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut seed);
                SigningKey::from_bytes(&seed)
            }
        }
    }

    /// Hex-encoded Ed25519 verifying (public) key, for inclusion in
    /// registration/enrollment records so the NS can build its
    /// node_id → pubkey index.
    pub fn signing_public_key_hex(&self) -> String {
        hex::encode(self.signing_key().verifying_key().to_bytes())
    }

    /// Sign an arbitrary message with this identity's Ed25519 key.
    /// Used to authenticate PEER_ENDPOINTS/PUNCH_REPORT claims to NS.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key().sign(message).to_bytes()
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

/// Serde helper for Option<Vec<u8>> as hex strings.
mod opt_hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_str(&hex::encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => hex::decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
