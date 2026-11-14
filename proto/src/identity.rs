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
///
/// Deserialization goes through [`NodeIdentityFile`] so that both on-disk
/// spellings of the Ed25519 seed are accepted (see that type).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "NodeIdentityFile")]
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
    ///
    /// On load the seed is also accepted under the name `ed25519_seed`,
    /// which is what `ztlp keygen` writes (see [`NodeIdentityFile`]). It is
    /// always written back as `signing_key_seed`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_hex_bytes"
    )]
    pub signing_key_seed: Option<Vec<u8>>,
}

/// Length of an Ed25519 seed in bytes.
const ED25519_SEED_LEN: usize = 32;

/// On-disk shape of an identity file, as read.
///
/// Two tools write this file and they name the Ed25519 seed differently:
///
/// - the daemon ([`NodeIdentity::save`]) writes `signing_key_seed`;
/// - `ztlp keygen` writes `ed25519_seed` (plus `ed25519_public_key`, which
///   is derivable from the seed and ignored here like any unknown field).
///
/// Before this type existed only `signing_key_seed` was read, so a
/// keygen-format file looked like a pre-signing-key legacy file:
/// [`NodeIdentity::load`] generated a RANDOM signing key and rewrote the
/// file, silently replacing the provisioned key (the name server then
/// rejected the node's registrations as `unauthorized`).
///
/// Both names are accepted. If both are present they must hold the same
/// seed; a file with two different seeds is refused rather than guessing
/// which key the operator meant.
#[derive(Deserialize)]
struct NodeIdentityFile {
    node_id: NodeId,
    #[serde(with = "hex_bytes")]
    static_private_key: Vec<u8>,
    #[serde(with = "hex_bytes")]
    static_public_key: Vec<u8>,
    #[serde(default)]
    bound_user_sid: Option<String>,
    #[serde(default, with = "opt_hex_bytes")]
    signing_key_seed: Option<Vec<u8>>,
    /// `ztlp keygen` spelling of `signing_key_seed`.
    #[serde(default, with = "opt_hex_bytes")]
    ed25519_seed: Option<Vec<u8>>,
}

impl TryFrom<NodeIdentityFile> for NodeIdentity {
    type Error = String;

    fn try_from(file: NodeIdentityFile) -> Result<Self, Self::Error> {
        let signing_key_seed = match (file.signing_key_seed, file.ed25519_seed) {
            (Some(a), Some(b)) if a != b => {
                return Err(
                    "identity file has both `signing_key_seed` and `ed25519_seed` and they \
                     differ; remove the one that is not this node's provisioned Ed25519 seed"
                        .to_string(),
                );
            }
            (Some(seed), _) | (None, Some(seed)) => Some(seed),
            (None, None) => None,
        };

        // A seed of the wrong length cannot be used: `signing_key()` would
        // fall back to a fresh random key on every call. Refuse it here so
        // a truncated or mistyped file is reported instead of re-keying.
        if let Some(seed) = &signing_key_seed {
            if seed.len() != ED25519_SEED_LEN {
                return Err(format!(
                    "Ed25519 seed must be {} bytes ({} hex characters), got {} bytes",
                    ED25519_SEED_LEN,
                    ED25519_SEED_LEN * 2,
                    seed.len()
                ));
            }
        }

        Ok(Self {
            node_id: file.node_id,
            static_private_key: file.static_private_key,
            static_public_key: file.static_public_key,
            bound_user_sid: file.bound_user_sid,
            signing_key_seed,
        })
    }
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
    ///
    /// A file written by `ztlp keygen` carries its seed as `ed25519_seed`;
    /// that is a provisioned key, not a legacy file, so it is loaded as-is
    /// and the file is left untouched (see [`NodeIdentityFile`]).
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
    ///
    /// [CWE-522 ubf-gfyh] This file contains `static_private_key`, the
    /// long-term Noise authentication key -- sufficient on its own to
    /// clone this node's identity. `std::fs::write` alone creates the
    /// file with default permissions subject to the process umask
    /// (commonly 022, i.e. world-readable), so any other local user on
    /// a multi-user host could read it. On Unix, explicitly set 0o600
    /// (owner read/write only) immediately after writing, matching this
    /// project's existing Go implementation's behavior for the same
    /// file. This is set AFTER the write (rather than relying on a
    /// pre-set umask, which is process-global state we shouldn't
    /// mutate) so it applies deterministically regardless of the
    /// caller's umask.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
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
            Some(s) => hex::decode(&s).map(Some).map_err(serde::de::Error::custom),
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

    // [CWE-522 ubf-gfyh] Regression tests: save() must always leave the
    // identity file at mode 0600 (owner read/write only) regardless of
    // the process umask, since the file contains the long-term Noise
    // private key.
    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn test_save_sets_mode_0600_even_under_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("ztlp_identity_save_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("identity.json");

        // Simulate a permissive umask (022, the common default) by
        // setting it for this process before the save -- if save()
        // relied on umask alone rather than an explicit chmod, this
        // would leave the file group/world readable.
        unsafe {
            libc::umask(0o022);
        }

        let ident = NodeIdentity::generate().expect("identity generation should succeed");
        ident.save(&path).expect("save should succeed");

        let mode = std::fs::metadata(&path)
            .expect("stat saved file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "identity file must be mode 0600 regardless of process umask, got {:o}",
            mode
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_save_overwrites_existing_permissive_file_to_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("ztlp_identity_save_test2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("identity.json");

        // Pre-create the file with permissive (world-readable) perms,
        // simulating an identity file created by an older binary
        // before this fix -- re-saving must correct it, not just leave
        // it as-is because the file already existed.
        std::fs::write(&path, "{}").expect("pre-create file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("set permissive perms");

        let ident = NodeIdentity::generate().expect("identity generation should succeed");
        ident.save(&path).expect("save should succeed");

        let mode = std::fs::metadata(&path)
            .expect("stat saved file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "re-saving over a pre-existing permissive file must still end at 0600, got {:o}",
            mode
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── identity.json field names: `ztlp keygen` vs the daemon ──────────
    //
    // `ztlp keygen` writes the Ed25519 seed as `ed25519_seed`; the daemon
    // writes `signing_key_seed`. Loading a keygen file used to re-key the
    // node with a random signing key.

    /// Fixed test vector: X25519 keys are arbitrary 32-byte values, the
    /// Ed25519 public key is derived from `seed` by the test itself.
    const TEST_NODE_ID: &str = "00112233445566778899aabbccddeeff";
    const TEST_X25519_PRIV: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const TEST_X25519_PUB: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";

    fn seed_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn public_key_hex_for(seed_hex: &str) -> String {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hex::decode(seed_hex).unwrap());
        hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    }

    /// The exact field set `ztlp keygen --format json` emits.
    fn keygen_json(seed_hex: &str) -> String {
        serde_json::json!({
            "node_id": TEST_NODE_ID,
            "static_private_key": TEST_X25519_PRIV,
            "static_public_key": TEST_X25519_PUB,
            "ed25519_seed": seed_hex,
            "ed25519_public_key": public_key_hex_for(seed_hex),
        })
        .to_string()
    }

    fn write_temp_identity(tag: &str, json: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "ztlp_identity_{}_{}_{}",
            tag,
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("identity.json");
        std::fs::write(&path, json).expect("write identity");
        (dir, path)
    }

    #[test]
    fn keygen_format_loads_with_the_provisioned_signing_key() {
        let seed = seed_hex(0x42);
        let json = keygen_json(&seed);
        let (dir, path) = write_temp_identity("keygen", &json);

        let ident = NodeIdentity::load(&path).expect("keygen-format identity must load");

        assert_eq!(
            ident.signing_public_key_hex(),
            public_key_hex_for(&seed),
            "the loaded signing key must be the one in the file's ed25519_public_key"
        );
        assert_eq!(ident.signing_key_seed, Some(vec![0x42; 32]));
        assert_eq!(ident.node_id.to_string(), TEST_NODE_ID);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keygen_format_is_not_rekeyed_or_rewritten_on_load() {
        let seed = seed_hex(0x42);
        let json = keygen_json(&seed);
        let (dir, path) = write_temp_identity("keygen_stable", &json);

        let first = NodeIdentity::load(&path).expect("first load");
        let second = NodeIdentity::load(&path).expect("second load");

        assert_eq!(first.signing_key_seed, second.signing_key_seed);
        assert_eq!(first.signing_key_seed, Some(vec![0x42; 32]));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            json,
            "a file that already has a seed must not be rewritten by load()"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn daemon_format_signing_key_seed_still_loads() {
        let seed = seed_hex(0x07);
        let json = serde_json::json!({
            "node_id": TEST_NODE_ID,
            "static_private_key": TEST_X25519_PRIV,
            "static_public_key": TEST_X25519_PUB,
            "signing_key_seed": seed,
        })
        .to_string();
        let (dir, path) = write_temp_identity("daemon", &json);

        let ident = NodeIdentity::load(&path).expect("daemon-format identity must load");

        assert_eq!(ident.signing_key_seed, Some(vec![0x07; 32]));
        assert_eq!(ident.signing_public_key_hex(), public_key_hex_for(&seed));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), json);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_file_without_any_seed_gets_a_generated_key_persisted() {
        let json = serde_json::json!({
            "node_id": TEST_NODE_ID,
            "static_private_key": TEST_X25519_PRIV,
            "static_public_key": TEST_X25519_PUB,
        })
        .to_string();
        let (dir, path) = write_temp_identity("legacy", &json);

        let first = NodeIdentity::load(&path).expect("legacy identity must load");
        let seed = first.signing_key_seed.clone().expect("a key is generated");
        assert_eq!(seed.len(), 32);

        // The generated key is persisted (as `signing_key_seed`), so the
        // next load returns the same key instead of generating another.
        let second = NodeIdentity::load(&path).expect("reload");
        assert_eq!(second.signing_key_seed, Some(seed));
        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(on_disk.get("signing_key_seed").is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn both_seed_fields_with_the_same_value_load() {
        let seed = seed_hex(0x42);
        let json = serde_json::json!({
            "node_id": TEST_NODE_ID,
            "static_private_key": TEST_X25519_PRIV,
            "static_public_key": TEST_X25519_PUB,
            "signing_key_seed": seed,
            "ed25519_seed": seed,
        })
        .to_string();

        let ident: NodeIdentity = serde_json::from_str(&json).expect("equal seeds must load");
        assert_eq!(ident.signing_key_seed, Some(vec![0x42; 32]));
    }

    #[test]
    fn both_seed_fields_with_different_values_are_rejected() {
        let json = serde_json::json!({
            "node_id": TEST_NODE_ID,
            "static_private_key": TEST_X25519_PRIV,
            "static_public_key": TEST_X25519_PUB,
            "signing_key_seed": seed_hex(0x01),
            "ed25519_seed": seed_hex(0x02),
        })
        .to_string();
        let (dir, path) = write_temp_identity("conflict", &json);

        let Err(err) = NodeIdentity::load(&path) else {
            panic!("conflicting seeds must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("signing_key_seed") && msg.contains("ed25519_seed"),
            "error must name both fields, got: {msg}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            json,
            "a rejected file must be left untouched"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn seed_of_the_wrong_length_is_rejected() {
        let json = serde_json::json!({
            "node_id": TEST_NODE_ID,
            "static_private_key": TEST_X25519_PRIV,
            "static_public_key": TEST_X25519_PUB,
            "ed25519_seed": "abcd",
        })
        .to_string();

        let Err(err) = serde_json::from_str::<NodeIdentity>(&json) else {
            panic!("a 2-byte seed must be rejected");
        };
        assert!(err.to_string().contains("32 bytes"), "got: {err}");
    }

    #[test]
    fn saved_identity_roundtrips_through_load() {
        let ident = NodeIdentity::generate().expect("generate");
        let (dir, path) = write_temp_identity("roundtrip", "{}");
        ident.save(&path).expect("save");

        let loaded = NodeIdentity::load(&path).expect("load");
        assert_eq!(loaded.node_id, ident.node_id);
        assert_eq!(loaded.signing_key_seed, ident.signing_key_seed);
        assert_eq!(loaded.static_private_key, ident.static_private_key);
        std::fs::remove_dir_all(&dir).ok();
    }
}
