//! Mobile-specific types for ZTLP on iOS and Android.
//!
//! Provides platform identity abstractions (Secure Enclave, Android Keystore),
//! mobile client configuration, connection state management, and event types.
//!
//! # Architecture
//!
//! On mobile platforms, the actual cryptographic operations may happen in
//! hardware-backed secure enclaves. The [`PlatformIdentity`] trait abstracts
//! over software (file-based) and hardware identity providers, allowing the
//! FFI layer to work uniformly regardless of the underlying platform.
//!
//! ```text
//!  ┌─────────────────┐      ┌──────────────────────┐
//!  │  iOS Swift App   │      │  Android Kotlin App   │
//!  └────────┬────────┘      └──────────┬───────────┘
//!           │                          │
//!           ▼                          ▼
//!  ┌────────────────────────────────────────────────┐
//!  │         C FFI Layer (ffi.rs)                    │
//!  │  ztlp_identity_from_hardware(provider)         │
//!  └────────────────────┬───────────────────────────┘
//!                       │
//!           ┌───────────┴───────────┐
//!           │  PlatformIdentity     │
//!           │  trait dispatch        │
//!           ├───────────┬───────────┤
//!           ▼           ▼           ▼
//!     Software     SecureEnclave  AndroidKeystore
//!     (file-based) (iOS SE)      (TEE/StrongBox)
//! ```

use crate::identity::{NodeId, NodeIdentity};

// ── Identity Provider Enum ──────────────────────────────────────────────

/// Platform-specific identity provider type.
///
/// Determines where the cryptographic keys are stored and where
/// crypto operations are performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum IdentityProvider {
    /// Software-only (file-based, default).
    /// Keys are stored as plaintext JSON on disk.
    Software = 0,

    /// iOS Secure Enclave.
    /// The P-256 key is stored in the Secure Enclave; X25519 is derived.
    SecureEnclave = 1,

    /// Android Keystore.
    /// Key material is stored in the TEE or StrongBox if available.
    AndroidKeystore = 2,

    /// Hardware token (YubiKey, etc.) — reserved for future use.
    HardwareToken = 3,
}

impl IdentityProvider {
    /// Convert from raw i32 (for FFI boundary).
    /// Returns `None` for unknown values.
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(IdentityProvider::Software),
            1 => Some(IdentityProvider::SecureEnclave),
            2 => Some(IdentityProvider::AndroidKeystore),
            3 => Some(IdentityProvider::HardwareToken),
            _ => None,
        }
    }
}

// ── Platform Identity Trait ─────────────────────────────────────────────

/// Trait for platform identity providers.
///
/// On mobile, the actual implementation calls into platform APIs via FFI
/// callbacks. The software provider wraps [`NodeIdentity`] directly.
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` — the identity may be accessed
/// from the tokio runtime thread and the FFI calling thread concurrently.
pub trait PlatformIdentity: Send + Sync {
    /// Get the NodeID (stable, generated once).
    fn node_id(&self) -> &NodeId;

    /// Get the X25519 public key (32 bytes).
    fn public_key(&self) -> &[u8; 32];

    /// Sign data with the identity key (used for name-service registration).
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String>;

    /// Perform X25519 Diffie-Hellman key exchange.
    /// On hardware providers, the private key never leaves the secure element.
    fn dh(&self, their_public: &[u8; 32]) -> Result<[u8; 32], String>;

    /// Get the provider type.
    fn provider(&self) -> IdentityProvider;

    /// Get the underlying [`NodeIdentity`] if this is a software provider.
    /// Hardware providers return `None`.
    fn as_node_identity(&self) -> Option<&NodeIdentity>;
}

// ── Software Identity Provider ──────────────────────────────────────────

/// Software identity provider — wraps a [`NodeIdentity`].
///
/// Keys are stored in memory (loaded from / saved to JSON files).
/// This is the default provider for development and non-mobile platforms.
pub struct SoftwareIdentityProvider {
    identity: NodeIdentity,
    /// Cached public key as a fixed-size array.
    public_key_array: [u8; 32],
}

impl SoftwareIdentityProvider {
    /// Create a new software identity provider from an existing identity.
    pub fn new(identity: NodeIdentity) -> Self {
        let mut public_key_array = [0u8; 32];
        public_key_array.copy_from_slice(&identity.static_public_key);
        Self {
            identity,
            public_key_array,
        }
    }

    /// Generate a fresh software identity.
    pub fn generate() -> Result<Self, String> {
        let identity = NodeIdentity::generate().map_err(|e| e.to_string())?;
        Ok(Self::new(identity))
    }

    /// Get a reference to the underlying [`NodeIdentity`].
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }
}

impl PlatformIdentity for SoftwareIdentityProvider {
    fn node_id(&self) -> &NodeId {
        &self.identity.node_id
    }

    fn public_key(&self) -> &[u8; 32] {
        &self.public_key_array
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        // Use BLAKE2s-based HMAC as a simple signing mechanism.
        // In production, this would use Ed25519 with the identity's signing key.
        use blake2::digest::Mac;
        type HmacBlake2s = blake2::Blake2sMac<blake2::digest::consts::U32>;

        let mut mac = <HmacBlake2s as Mac>::new_from_slice(&self.identity.static_private_key)
            .map_err(|e| format!("HMAC init failed: {e}"))?;
        mac.update(data);
        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    fn dh(&self, their_public: &[u8; 32]) -> Result<[u8; 32], String> {
        // Perform X25519 DH using curve25519-dalek.
        use curve25519_dalek::montgomery::MontgomeryPoint;
        use curve25519_dalek::scalar::Scalar;

        let mut private_bytes = [0u8; 32];
        private_bytes.copy_from_slice(&self.identity.static_private_key);

        // Clamp the scalar per X25519 spec
        private_bytes[0] &= 248;
        private_bytes[31] &= 127;
        private_bytes[31] |= 64;

        let scalar = Scalar::from_bytes_mod_order(private_bytes);
        let their_point = MontgomeryPoint(*their_public);
        let shared_secret = scalar * their_point;

        Ok(shared_secret.to_bytes())
    }

    fn provider(&self) -> IdentityProvider {
        IdentityProvider::Software
    }

    fn as_node_identity(&self) -> Option<&NodeIdentity> {
        Some(&self.identity)
    }
}

// ── Hardware Identity Provider ──────────────────────────────────────────

/// Hardware identity provider stub.
///
/// On iOS/Android, the actual crypto happens in native platform code.
/// This struct holds callbacks set by the platform glue layer.
///
/// # iOS (Secure Enclave)
///
/// The iOS integration layer creates a `HardwareIdentityProvider` and sets
/// `sign_fn` and `dh_fn` to closures that call into the Secure Enclave
/// via Security.framework.
///
/// # Android (Keystore)
///
/// The Android integration layer sets callbacks that invoke
/// `java.security.KeyStore` operations via JNI.
///
/// # Example
///
/// ```rust,ignore
/// let mut provider = HardwareIdentityProvider::new(
///     IdentityProvider::SecureEnclave,
///     node_id,
///     public_key,
/// );
/// provider.set_sign_fn(|data| {
///     // Call into iOS Secure Enclave via Security.framework
///     secure_enclave_sign(data)
/// });
/// provider.set_dh_fn(|their_pub| {
///     // Call into iOS Secure Enclave for ECDH
///     secure_enclave_ecdh(their_pub)
/// });
/// ```
/// Platform sign callback type — set by iOS/Android glue code.
type SignCallback = Box<dyn Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

/// Platform DH callback type — set by iOS/Android glue code.
type DhCallback = Box<dyn Fn(&[u8; 32]) -> Result<[u8; 32], String> + Send + Sync>;

pub struct HardwareIdentityProvider {
    provider_type: IdentityProvider,
    node_id: NodeId,
    public_key: [u8; 32],
    /// Platform sign callback — set by iOS/Android glue code.
    sign_fn: Option<SignCallback>,
    /// Platform DH callback — set by iOS/Android glue code.
    dh_fn: Option<DhCallback>,
}

impl HardwareIdentityProvider {
    /// Create a new hardware identity provider with the given node ID and public key.
    ///
    /// The sign and DH callbacks must be set before the provider is used for
    /// any cryptographic operations.
    pub fn new(provider_type: IdentityProvider, node_id: NodeId, public_key: [u8; 32]) -> Self {
        Self {
            provider_type,
            node_id,
            public_key,
            sign_fn: None,
            dh_fn: None,
        }
    }

    /// Set the platform sign callback.
    pub fn set_sign_fn<F>(&mut self, f: F)
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync + 'static,
    {
        self.sign_fn = Some(Box::new(f));
    }

    /// Set the platform DH callback.
    pub fn set_dh_fn<F>(&mut self, f: F)
    where
        F: Fn(&[u8; 32]) -> Result<[u8; 32], String> + Send + Sync + 'static,
    {
        self.dh_fn = Some(Box::new(f));
    }

    /// Check whether the required callbacks have been set.
    pub fn is_ready(&self) -> bool {
        self.sign_fn.is_some() && self.dh_fn.is_some()
    }
}

impl PlatformIdentity for HardwareIdentityProvider {
    fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match &self.sign_fn {
            Some(f) => f(data),
            None => Err("hardware sign callback not set".into()),
        }
    }

    fn dh(&self, their_public: &[u8; 32]) -> Result<[u8; 32], String> {
        match &self.dh_fn {
            Some(f) => f(their_public),
            None => Err("hardware DH callback not set".into()),
        }
    }

    fn provider(&self) -> IdentityProvider {
        self.provider_type
    }

    fn as_node_identity(&self) -> Option<&NodeIdentity> {
        None // Hardware providers don't expose the raw NodeIdentity
    }
}

// Allow Debug for HardwareIdentityProvider (callbacks can't be Debug)
impl std::fmt::Debug for HardwareIdentityProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareIdentityProvider")
            .field("provider_type", &self.provider_type)
            .field("node_id", &self.node_id)
            .field("public_key", &hex::encode(self.public_key))
            .field("sign_fn", &self.sign_fn.is_some())
            .field("dh_fn", &self.dh_fn.is_some())
            .finish()
    }
}

// ── Mobile Configuration ────────────────────────────────────────────────

/// Mobile client configuration.
///
/// Provides sensible defaults for mobile environments, including
/// auto-reconnect, NAT assist, and keepalive intervals.
#[derive(Debug, Clone)]
pub struct MobileConfig {
    /// Which identity provider to use.
    pub identity_provider: IdentityProvider,
    /// Optional relay address (e.g., "relay.ztlp.net:4433").
    pub relay_address: Option<String>,
    /// STUN servers for NAT discovery.
    pub stun_servers: Vec<String>,
    /// Enable NAT traversal assistance (STUN + hole punching).
    pub nat_assist: bool,
    /// Automatically reconnect on disconnect.
    pub auto_reconnect: bool,
    /// Delay between reconnect attempts (milliseconds).
    pub reconnect_delay_ms: u64,
    /// Maximum number of reconnect attempts before giving up.
    pub max_reconnect_attempts: u32,
    /// Keepalive ping interval (milliseconds).
    pub keepalive_interval_ms: u64,
}

impl Default for MobileConfig {
    fn default() -> Self {
        Self {
            identity_provider: IdentityProvider::Software,
            relay_address: None,
            stun_servers: vec![
                "stun.l.google.com:19302".into(),
                "stun1.l.google.com:19302".into(),
            ],
            nat_assist: true,
            auto_reconnect: true,
            reconnect_delay_ms: 1000,
            max_reconnect_attempts: 10,
            keepalive_interval_ms: 30000,
        }
    }
}

// ── Connection State ────────────────────────────────────────────────────

/// Connection state machine for mobile clients.
///
/// ```text
///  Disconnected ──► Discovering ──► Handshaking ──► Connected
///       ▲                                               │
///       │                                               ▼
///       └──────────── Reconnecting ◄────────── (disconnect)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ConnectionState {
    /// Not connected to any peer.
    Disconnected = 0,
    /// STUN/NAT discovery in progress.
    Discovering = 1,
    /// Noise_XX handshake in progress.
    Handshaking = 2,
    /// Active session — data can be sent and received.
    Connected = 3,
    /// Auto-reconnect in progress after a disconnect.
    Reconnecting = 4,
}

impl ConnectionState {
    /// Check if this state allows sending data.
    pub fn can_send(&self) -> bool {
        matches!(self, ConnectionState::Connected)
    }

    /// Check if this state represents an active or transitioning connection.
    pub fn is_active(&self) -> bool {
        !matches!(self, ConnectionState::Disconnected)
    }
}

// ── Mobile Events ───────────────────────────────────────────────────────

/// Event types emitted by the mobile client.
///
/// These map to callback invocations in the FFI layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MobileEvent {
    /// Successfully connected to a peer.
    Connected = 1,
    /// Disconnected from a peer.
    Disconnected = 2,
    /// Data received from a peer.
    DataReceived = 3,
    /// Connection state changed.
    StateChanged = 4,
    /// An error occurred.
    Error = 5,
    /// NAT type discovered (STUN result available).
    NatDiscovered = 6,
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SoftwareIdentityProvider tests ──

    #[test]
    fn test_software_provider_generate() {
        let provider = SoftwareIdentityProvider::generate().expect("should generate identity");
        assert_eq!(provider.provider(), IdentityProvider::Software);
        assert!(provider.as_node_identity().is_some());
    }

    #[test]
    fn test_software_provider_node_id() {
        let provider = SoftwareIdentityProvider::generate().unwrap();
        let node_id = provider.node_id();
        // NodeID should be 16 bytes and non-zero
        assert_ne!(node_id.as_bytes(), &[0u8; 16]);
    }

    #[test]
    fn test_software_provider_public_key() {
        let provider = SoftwareIdentityProvider::generate().unwrap();
        let pubkey = provider.public_key();
        // Public key should be 32 bytes and non-zero
        assert_ne!(pubkey, &[0u8; 32]);
    }

    #[test]
    fn test_software_provider_sign() {
        let provider = SoftwareIdentityProvider::generate().unwrap();
        let data = b"test data to sign";
        let sig1 = provider.sign(data).expect("sign should succeed");
        let sig2 = provider.sign(data).expect("sign should succeed");
        // Same data should produce the same signature (deterministic HMAC)
        assert_eq!(sig1, sig2);
        // Signature should be 32 bytes (BLAKE2s output)
        assert_eq!(sig1.len(), 32);
    }

    #[test]
    fn test_software_provider_sign_different_data() {
        let provider = SoftwareIdentityProvider::generate().unwrap();
        let sig1 = provider.sign(b"hello").unwrap();
        let sig2 = provider.sign(b"world").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_software_provider_dh() {
        let alice = SoftwareIdentityProvider::generate().unwrap();
        let bob = SoftwareIdentityProvider::generate().unwrap();

        let alice_shared = alice.dh(bob.public_key()).expect("alice DH should succeed");
        let bob_shared = bob.dh(alice.public_key()).expect("bob DH should succeed");

        // Shared secrets should match (X25519 is commutative)
        assert_eq!(alice_shared, bob_shared);
        // Shared secret should be non-zero
        assert_ne!(alice_shared, [0u8; 32]);
    }

    #[test]
    fn test_software_provider_from_identity() {
        let identity = NodeIdentity::generate().unwrap();
        let expected_node_id = identity.node_id;
        let provider = SoftwareIdentityProvider::new(identity);
        assert_eq!(*provider.node_id(), expected_node_id);
    }

    // ── HardwareIdentityProvider tests ──

    #[test]
    fn test_hardware_provider_construction() {
        let node_id = NodeId::generate();
        let public_key = [42u8; 32];
        let provider =
            HardwareIdentityProvider::new(IdentityProvider::SecureEnclave, node_id, public_key);
        assert_eq!(provider.provider(), IdentityProvider::SecureEnclave);
        assert_eq!(*provider.node_id(), node_id);
        assert_eq!(*provider.public_key(), public_key);
        assert!(!provider.is_ready());
        assert!(provider.as_node_identity().is_none());
    }

    #[test]
    fn test_hardware_provider_without_callbacks() {
        let provider = HardwareIdentityProvider::new(
            IdentityProvider::AndroidKeystore,
            NodeId::generate(),
            [0u8; 32],
        );
        // Sign and DH should fail without callbacks
        assert!(provider.sign(b"test").is_err());
        assert!(provider.dh(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_hardware_provider_with_callbacks() {
        let node_id = NodeId::generate();
        let mut provider =
            HardwareIdentityProvider::new(IdentityProvider::SecureEnclave, node_id, [1u8; 32]);

        provider.set_sign_fn(|data| {
            // Mock: return first 32 bytes of data padded with zeros
            let mut sig = vec![0u8; 32];
            let copy_len = data.len().min(32);
            sig[..copy_len].copy_from_slice(&data[..copy_len]);
            Ok(sig)
        });

        provider.set_dh_fn(|their_pub| {
            // Mock: XOR their public key with 0xFF
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = their_pub[i] ^ 0xFF;
            }
            Ok(result)
        });

        assert!(provider.is_ready());

        let sig = provider.sign(b"test").expect("should sign with callback");
        assert_eq!(sig.len(), 32);

        let dh_result = provider.dh(&[0xAA; 32]).expect("should DH with callback");
        assert_eq!(dh_result, [0x55; 32]); // 0xAA ^ 0xFF = 0x55
    }

    #[test]
    fn test_hardware_provider_debug() {
        let provider = HardwareIdentityProvider::new(
            IdentityProvider::SecureEnclave,
            NodeId::generate(),
            [0u8; 32],
        );
        let debug_str = format!("{:?}", provider);
        assert!(debug_str.contains("HardwareIdentityProvider"));
        assert!(debug_str.contains("SecureEnclave"));
    }

    // ── IdentityProvider tests ──

    #[test]
    fn test_identity_provider_from_i32() {
        assert_eq!(
            IdentityProvider::from_i32(0),
            Some(IdentityProvider::Software)
        );
        assert_eq!(
            IdentityProvider::from_i32(1),
            Some(IdentityProvider::SecureEnclave)
        );
        assert_eq!(
            IdentityProvider::from_i32(2),
            Some(IdentityProvider::AndroidKeystore)
        );
        assert_eq!(
            IdentityProvider::from_i32(3),
            Some(IdentityProvider::HardwareToken)
        );
        assert_eq!(IdentityProvider::from_i32(4), None);
        assert_eq!(IdentityProvider::from_i32(-1), None);
    }

    // ── MobileConfig tests ──

    #[test]
    fn test_mobile_config_defaults() {
        let config = MobileConfig::default();
        assert_eq!(config.identity_provider, IdentityProvider::Software);
        assert!(config.relay_address.is_none());
        assert!(!config.stun_servers.is_empty());
        assert!(config.nat_assist);
        assert!(config.auto_reconnect);
        assert_eq!(config.reconnect_delay_ms, 1000);
        assert_eq!(config.max_reconnect_attempts, 10);
        assert_eq!(config.keepalive_interval_ms, 30000);
    }

    #[test]
    fn test_mobile_config_custom() {
        let config = MobileConfig {
            identity_provider: IdentityProvider::SecureEnclave,
            relay_address: Some("relay.example.com:4433".into()),
            stun_servers: vec!["stun.example.com:3478".into()],
            nat_assist: false,
            auto_reconnect: false,
            reconnect_delay_ms: 5000,
            max_reconnect_attempts: 3,
            keepalive_interval_ms: 60000,
        };
        assert_eq!(config.identity_provider, IdentityProvider::SecureEnclave);
        assert_eq!(
            config.relay_address.as_deref(),
            Some("relay.example.com:4433")
        );
        assert_eq!(config.stun_servers.len(), 1);
        assert!(!config.nat_assist);
        assert!(!config.auto_reconnect);
    }

    // ── ConnectionState tests ──

    #[test]
    fn test_connection_state_can_send() {
        assert!(!ConnectionState::Disconnected.can_send());
        assert!(!ConnectionState::Discovering.can_send());
        assert!(!ConnectionState::Handshaking.can_send());
        assert!(ConnectionState::Connected.can_send());
        assert!(!ConnectionState::Reconnecting.can_send());
    }

    #[test]
    fn test_connection_state_is_active() {
        assert!(!ConnectionState::Disconnected.is_active());
        assert!(ConnectionState::Discovering.is_active());
        assert!(ConnectionState::Handshaking.is_active());
        assert!(ConnectionState::Connected.is_active());
        assert!(ConnectionState::Reconnecting.is_active());
    }

    #[test]
    fn test_connection_state_repr_values() {
        // Verify repr(i32) values are distinct
        let states = [
            ConnectionState::Disconnected as i32,
            ConnectionState::Discovering as i32,
            ConnectionState::Handshaking as i32,
            ConnectionState::Connected as i32,
            ConnectionState::Reconnecting as i32,
        ];
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(
                    states[i], states[j],
                    "states at index {} and {} have same value",
                    i, j
                );
            }
        }
    }

    // ── MobileEvent tests ──

    #[test]
    fn test_mobile_event_repr_values() {
        let events = [
            MobileEvent::Connected as i32,
            MobileEvent::Disconnected as i32,
            MobileEvent::DataReceived as i32,
            MobileEvent::StateChanged as i32,
            MobileEvent::Error as i32,
            MobileEvent::NatDiscovered as i32,
        ];
        // All values should be positive and distinct
        for &val in &events {
            assert!(val > 0, "event value should be positive");
        }
        for i in 0..events.len() {
            for j in (i + 1)..events.len() {
                assert_ne!(
                    events[i], events[j],
                    "events at index {} and {} have same value",
                    i, j
                );
            }
        }
    }
}
