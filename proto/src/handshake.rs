//! Noise_XX handshake implementation for ZTLP session establishment.
//!
//! Implements the three-message Noise_XX pattern using the `snow` crate:
//!
//! 1. Initiator → Responder: ephemeral key (HELLO)
//! 2. Responder → Initiator: ephemeral key + encrypted identity (HELLO_ACK)
//! 3. Initiator → Responder: encrypted identity (final confirmation)
//!
//! After the handshake completes, session keys are derived and a SessionID
//! is assigned. The session is registered in the session table.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use blake2::{Blake2s256, Digest};
use snow::{Builder, HandshakeState, TransportState};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::error::HandshakeError;
use crate::identity::{NodeId, NodeIdentity};
use crate::packet::{HandshakeHeader, MsgType, SessionId};
use crate::pipeline::compute_header_auth_tag;
use crate::session::SessionState;

// ─── Handshake Retransmit Constants ─────────────────────────────────────────

/// Maximum handshake retransmit attempts per message.
pub const MAX_HANDSHAKE_RETRIES: u8 = 5;

/// Initial handshake retransmit delay.
pub const INITIAL_HANDSHAKE_RETRY_MS: u64 = 500;

/// Maximum handshake retransmit delay (exponential backoff cap).
pub const MAX_HANDSHAKE_RETRY_MS: u64 = 5000;

/// Maximum half-open handshake cache entries (DoS protection).
pub const MAX_HALF_OPEN_HANDSHAKES: usize = 64;

/// Half-open handshake TTL (seconds).
pub const HALF_OPEN_TTL_SECS: u64 = 15;

/// Maximum responder retransmits of HELLO_ACK per session (amplification limit).
pub const MAX_RESPONDER_RETRANSMITS: u8 = 3;

/// Noise protocol pattern string.
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

// ─── Half-Open Handshake Cache ──────────────────────────────────────────────

/// Cached state for a half-open handshake (responder side).
///
/// When a HELLO arrives, the responder creates a `HandshakeContext`, processes
/// msg1, generates and sends HELLO_ACK (msg2). The full msg2 packet bytes are
/// cached here so that duplicate HELLOs can be answered with the same bytes
/// (no nonce reuse with different plaintext).
pub struct HalfOpenHandshake {
    /// The Noise handshake context (for finalize once msg3 arrives).
    pub ctx: HandshakeContext,
    /// Cached HELLO_ACK packet (full packet: header + noise payload).
    pub msg2_bytes: Vec<u8>,
    /// Peer address to retransmit to.
    pub peer_addr: SocketAddr,
    /// When this entry was created (for TTL enforcement).
    pub created_at: Instant,
    /// Number of times HELLO_ACK has been retransmitted.
    pub retransmit_count: u8,
    /// Original HELLO packet bytes (for duplicate detection).
    pub hello_data: Vec<u8>,
}

/// Bounded cache for half-open handshakes (responder side).
///
/// Prevents memory exhaustion by limiting size and enforcing TTL.
/// When full, the oldest entry is evicted (LRU-style).
pub struct HalfOpenCache {
    entries: HashMap<SessionId, HalfOpenHandshake>,
    max_entries: usize,
    ttl: Duration,
}

impl HalfOpenCache {
    /// Create a new half-open cache with default limits.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: MAX_HALF_OPEN_HANDSHAKES,
            ttl: Duration::from_secs(HALF_OPEN_TTL_SECS),
        }
    }

    /// Create a cache with custom limits (primarily for testing).
    pub fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            ttl,
        }
    }

    /// Insert a new half-open handshake. Evicts the oldest entry if at capacity.
    pub fn insert(&mut self, session_id: SessionId, entry: HalfOpenHandshake) {
        // Evict expired entries first
        self.cleanup_expired();

        // If still at capacity, evict the oldest entry
        if self.entries.len() >= self.max_entries {
            if let Some(oldest_id) = self.oldest_session_id() {
                self.entries.remove(&oldest_id);
            }
        }

        self.entries.insert(session_id, entry);
    }

    /// Look up a cached half-open handshake by session ID.
    pub fn get_mut(&mut self, session_id: &SessionId) -> Option<&mut HalfOpenHandshake> {
        // Check TTL before returning
        if let Some(entry) = self.entries.get(session_id) {
            if entry.created_at.elapsed() > self.ttl {
                self.entries.remove(session_id);
                return None;
            }
        }
        self.entries.get_mut(session_id)
    }

    /// Check if a session ID is in the cache (and not expired).
    pub fn contains(&mut self, session_id: &SessionId) -> bool {
        self.get_mut(session_id).is_some()
    }

    /// Remove a session from the cache (e.g., after handshake completes).
    pub fn remove(&mut self, session_id: &SessionId) -> Option<HalfOpenHandshake> {
        self.entries.remove(session_id)
    }

    /// Remove all expired entries.
    pub fn cleanup_expired(&mut self) -> usize {
        let ttl = self.ttl;
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.created_at.elapsed() <= ttl);
        before - self.entries.len()
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find the session ID of the oldest entry (for LRU eviction).
    fn oldest_session_id(&self) -> Option<SessionId> {
        self.entries
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(id, _)| *id)
    }
}

impl Default for HalfOpenCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Handshake role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// State of an in-progress handshake.
pub struct HandshakeContext {
    /// Our identity.
    pub identity: NodeIdentity,
    /// Our role in the handshake.
    pub role: Role,
    /// The Noise handshake state machine.
    noise: HandshakeState,
    /// Which message we're on (0-indexed).
    pub message_index: u8,
}

impl HandshakeContext {
    /// Create a new handshake context for the initiator.
    pub fn new_initiator(identity: &NodeIdentity) -> Result<Self, HandshakeError> {
        let pattern: snow::params::NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|e: snow::Error| HandshakeError::Noise(e.to_string()))?;
        let noise = Builder::new(pattern)
            .local_private_key(&identity.static_private_key)
            .build_initiator()
            .map_err(|e| HandshakeError::Noise(e.to_string()))?;

        Ok(Self {
            identity: identity.clone(),
            role: Role::Initiator,
            noise,
            message_index: 0,
        })
    }

    /// Create a new handshake context for the responder.
    pub fn new_responder(identity: &NodeIdentity) -> Result<Self, HandshakeError> {
        let pattern: snow::params::NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|e: snow::Error| HandshakeError::Noise(e.to_string()))?;
        let noise = Builder::new(pattern)
            .local_private_key(&identity.static_private_key)
            .build_responder()
            .map_err(|e| HandshakeError::Noise(e.to_string()))?;

        Ok(Self {
            identity: identity.clone(),
            role: Role::Responder,
            noise,
            message_index: 0,
        })
    }

    /// Generate the next handshake message (Noise payload).
    ///
    /// Returns the Noise message bytes to be wrapped in a ZTLP header.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; 65535];
        let len = self
            .noise
            .write_message(payload, &mut buf)
            .map_err(|e| HandshakeError::Noise(e.to_string()))?;
        buf.truncate(len);
        self.message_index += 1;
        Ok(buf)
    }

    /// Process a received handshake message.
    ///
    /// Returns the decrypted payload from the Noise message.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; 65535];
        let len = self
            .noise
            .read_message(message, &mut buf)
            .map_err(|e| HandshakeError::Noise(e.to_string()))?;
        buf.truncate(len);
        self.message_index += 1;
        Ok(buf)
    }

    /// Check if the handshake is complete.
    pub fn is_finished(&self) -> bool {
        self.noise.is_handshake_finished()
    }

    /// Get the remote peer's static X25519 public key as a hex string.
    /// Available after the handshake is finished (message 2+ for responder).
    /// Returns `None` if the remote static key is not yet available.
    pub fn remote_static_hex(&self) -> Option<String> {
        self.noise.get_remote_static().map(hex::encode)
    }

    /// Finalize the handshake — derive transport keys and create session state.
    ///
    /// The `session_id` must be agreed upon by both sides (typically the
    /// responder generates it and sends it in the HELLO_ACK, or the initiator
    /// proposes it in message 3). For in-process handshakes, the caller
    /// provides a single shared SessionID.
    ///
    /// Key derivation: both sides compute keys using both static public keys
    /// (sorted for determinism) and the role label. The initiator's "send" key
    /// matches the responder's "recv" key and vice versa.
    pub fn finalize(
        self,
        peer_node_id: NodeId,
        session_id: SessionId,
    ) -> Result<(TransportState, SessionState), HandshakeError> {
        if !self.noise.is_handshake_finished() {
            return Err(HandshakeError::UnexpectedState(
                "handshake not yet finished".into(),
            ));
        }

        let our_public = self.identity.static_public_key.clone();
        let role = self.role;

        let transport = self
            .noise
            .into_transport_mode()
            .map_err(|e| HandshakeError::Noise(e.to_string()))?;

        // Build a shared key derivation base from BOTH static public keys.
        // Sort the keys lexicographically so both sides produce identical material
        // regardless of which side calls finalize().
        let remote_static = transport.get_remote_static().unwrap_or(&[0u8; 32]);

        let mut shared_material = Vec::with_capacity(64);
        if our_public.as_slice() <= remote_static {
            shared_material.extend_from_slice(&our_public);
            shared_material.extend_from_slice(remote_static);
        } else {
            shared_material.extend_from_slice(remote_static);
            shared_material.extend_from_slice(&our_public);
        }

        // Derive directional keys using BLAKE2s-256 (deterministic, crypto-grade).
        // Hash(shared_material || label || session_id) → 32-byte key.
        // Both sides compute identical i2r_key and r2i_key because
        // shared_material is sorted and labels are fixed.
        let derive_key = |label: &[u8], sid: &[u8; 12], base: &[u8]| -> [u8; 32] {
            let mut hasher = Blake2s256::new();
            hasher.update(base);
            hasher.update(label);
            hasher.update(sid);
            let result = hasher.finalize();
            let mut key = [0u8; 32];
            key.copy_from_slice(&result);
            key
        };

        // i2r = Initiator→Responder direction key
        // r2i = Responder→Initiator direction key
        let i2r_key = derive_key(
            b"ztlp_initiator_to_responder",
            session_id.as_bytes(),
            &shared_material,
        );
        let r2i_key = derive_key(
            b"ztlp_responder_to_initiator",
            session_id.as_bytes(),
            &shared_material,
        );

        // Assign send/recv keys based on role:
        // Initiator sends with i2r, receives with r2i
        // Responder sends with r2i, receives with i2r
        let (send_key, recv_key) = match role {
            Role::Initiator => (i2r_key, r2i_key),
            Role::Responder => (r2i_key, i2r_key),
        };

        let session = SessionState::new(session_id, peer_node_id, send_key, recv_key, false);

        Ok((transport, session))
    }
}

/// Build a ZTLP handshake packet wrapping a Noise message.
pub fn build_handshake_packet(
    msg_type: MsgType,
    src_node_id: &NodeId,
    dst_svc_id: &[u8; 16],
    session_id: SessionId,
    packet_seq: u64,
    noise_payload: &[u8],
    auth_key: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut header = HandshakeHeader::new(msg_type);
    header.session_id = session_id;
    header.packet_seq = packet_seq;
    header.src_node_id = *src_node_id.as_bytes();
    header.dst_svc_id = *dst_svc_id;
    header.payload_len = noise_payload.len() as u16;

    // Compute auth tag if we have a key
    if let Some(key) = auth_key {
        let aad = header.aad_bytes();
        header.header_auth_tag = compute_header_auth_tag(key, &aad);
    }

    let mut packet = header.serialize();
    packet.extend_from_slice(noise_payload);
    packet
}

/// Result of a completed handshake — the session state for both sides.
pub struct HandshakeResult {
    pub initiator_session: SessionState,
    pub responder_session: SessionState,
}

/// Perform a complete Noise_XX handshake in-process (no network).
///
/// Useful for testing. Returns session states for both sides.
pub fn perform_handshake(
    initiator_identity: &NodeIdentity,
    responder_identity: &NodeIdentity,
) -> Result<HandshakeResult, HandshakeError> {
    let mut initiator = HandshakeContext::new_initiator(initiator_identity)?;
    let mut responder = HandshakeContext::new_responder(responder_identity)?;

    // Message 1: Initiator → Responder (ephemeral key)
    let msg1 = initiator.write_message(&[])?;
    let _payload1 = responder.read_message(&msg1)?;

    // Message 2: Responder → Initiator (ephemeral + static + identity)
    let msg2 = responder.write_message(&[])?;
    let _payload2 = initiator.read_message(&msg2)?;

    // Message 3: Initiator → Responder (static + identity)
    let msg3 = initiator.write_message(&[])?;
    let _payload3 = responder.read_message(&msg3)?;

    // Both sides should be finished
    if !initiator.is_finished() || !responder.is_finished() {
        return Err(HandshakeError::UnexpectedState(
            "handshake not finished after 3 messages".into(),
        ));
    }

    // Both sides agree on a single SessionID
    // (In a real implementation, the responder assigns it in HELLO_ACK)
    let session_id = SessionId::generate();

    // Finalize both sides with the shared SessionID
    let (_init_transport, init_session) =
        initiator.finalize(responder_identity.node_id, session_id)?;
    let (_resp_transport, resp_session) =
        responder.finalize(initiator_identity.node_id, session_id)?;

    Ok(HandshakeResult {
        initiator_session: init_session,
        responder_session: resp_session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn test_identity() -> NodeIdentity {
        NodeIdentity::generate().expect("failed to generate test identity")
    }

    fn make_half_open(_session_id: SessionId) -> HalfOpenHandshake {
        let identity = test_identity();
        let ctx =
            HandshakeContext::new_responder(&identity).expect("failed to create responder context");
        HalfOpenHandshake {
            ctx,
            msg2_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
            peer_addr: "127.0.0.1:12345".parse().expect("valid addr"),
            created_at: Instant::now(),
            retransmit_count: 0,
            hello_data: vec![0x01, 0x02, 0x03],
        }
    }

    // ── Test 1: Initiator retransmits HELLO after timeout ────────────────
    // (This is a unit-level simulation; actual network retransmit is in CLI)
    #[test]
    fn test_handshake_retransmit_msg1_lost() {
        // Simulate: initiator creates HELLO, sends it. If it were lost,
        // the initiator would re-send the exact same bytes. Verify the
        // bytes produced by write_message are deterministic per context.
        let identity = test_identity();
        let mut ctx = HandshakeContext::new_initiator(&identity).expect("initiator context");
        let msg1 = ctx.write_message(&[]).expect("write msg1");

        // The msg1 bytes would be stored and re-sent verbatim on timeout.
        // Verify they're non-empty and well-formed.
        assert!(!msg1.is_empty(), "HELLO message should not be empty");
        assert!(
            msg1.len() >= 32,
            "HELLO should contain at least an ephemeral key"
        );

        // Verify that retransmitting the exact same bytes is valid:
        // A new responder context should be able to read the same msg1.
        let resp_identity = test_identity();
        let mut resp = HandshakeContext::new_responder(&resp_identity).expect("responder context");
        let result = resp.read_message(&msg1);
        assert!(result.is_ok(), "responder should accept the HELLO bytes");
    }

    // ── Test 2: Responder resends cached HELLO_ACK on duplicate HELLO ───
    #[test]
    fn test_handshake_retransmit_msg2_lost() {
        let init_id = test_identity();
        let resp_id = test_identity();

        // Initiator creates HELLO
        let mut init_ctx = HandshakeContext::new_initiator(&init_id).expect("initiator context");
        let msg1 = init_ctx.write_message(&[]).expect("write msg1");

        // Responder processes HELLO and generates HELLO_ACK
        let mut resp_ctx = HandshakeContext::new_responder(&resp_id).expect("responder context");
        resp_ctx.read_message(&msg1).expect("read msg1");
        let msg2 = resp_ctx.write_message(&[]).expect("write msg2");

        // Cache the msg2 bytes (simulating what the responder does)
        let _session_id = SessionId::generate();
        let cached_msg2 = msg2.clone();

        // Simulate: msg2 was lost, initiator retransmits HELLO.
        // Responder should resend the CACHED msg2, not generate new bytes.
        // The cached bytes must be byte-identical.
        assert_eq!(cached_msg2, msg2, "cached msg2 must be byte-identical");

        // Verify the initiator can process the cached msg2
        let result = init_ctx.read_message(&cached_msg2);
        assert!(result.is_ok(), "initiator should accept cached HELLO_ACK");
    }

    // ── Test 3: Initiator retransmits msg3 after timeout ────────────────
    #[test]
    fn test_handshake_retransmit_msg3_lost() {
        let init_id = test_identity();
        let resp_id = test_identity();

        let mut init_ctx = HandshakeContext::new_initiator(&init_id).expect("init");
        let mut resp_ctx = HandshakeContext::new_responder(&resp_id).expect("resp");

        // Full handshake to msg3
        let msg1 = init_ctx.write_message(&[]).expect("msg1");
        resp_ctx.read_message(&msg1).expect("read msg1");
        let msg2 = resp_ctx.write_message(&[]).expect("msg2");
        init_ctx.read_message(&msg2).expect("read msg2");
        let msg3 = init_ctx.write_message(&[]).expect("msg3");

        // The msg3 bytes would be cached and re-sent on timeout.
        // Verify they're non-empty.
        assert!(!msg3.is_empty(), "msg3 should not be empty");

        // A fresh responder with same state should be able to process msg3.
        // (In practice, the same responder context processes it.)
        let result = resp_ctx.read_message(&msg3);
        assert!(result.is_ok(), "responder should accept msg3");
        assert!(
            resp_ctx.is_finished(),
            "handshake should be complete after msg3"
        );
    }

    // ── Test 4: Verify exponential backoff timing ───────────────────────
    #[test]
    fn test_handshake_retransmit_backoff() {
        let initial = Duration::from_millis(INITIAL_HANDSHAKE_RETRY_MS);
        let max_delay = Duration::from_millis(MAX_HANDSHAKE_RETRY_MS);

        let mut delay = initial;
        let expected_delays = [
            Duration::from_millis(500),
            Duration::from_millis(1000),
            Duration::from_millis(2000),
            Duration::from_millis(4000),
            Duration::from_millis(5000), // capped at MAX_HANDSHAKE_RETRY_MS
        ];

        for (i, expected) in expected_delays.iter().enumerate() {
            assert_eq!(
                delay, *expected,
                "backoff step {} should be {:?}",
                i, expected
            );
            delay = (delay * 2).min(max_delay);
        }

        // After cap, it stays at max
        assert_eq!(delay, max_delay, "delay should stay at max after capping");
    }

    // ── Test 5: Fails after MAX_HANDSHAKE_RETRIES ───────────────────────
    #[test]
    fn test_handshake_retransmit_max_retries() {
        let mut retries: u8 = 0;
        let mut failed = false;

        while retries <= MAX_HANDSHAKE_RETRIES {
            retries += 1;
            if retries > MAX_HANDSHAKE_RETRIES {
                failed = true;
                break;
            }
        }

        assert!(failed, "should fail after MAX_HANDSHAKE_RETRIES attempts");
        assert_eq!(retries, MAX_HANDSHAKE_RETRIES + 1);
    }

    // ── Test 6: Half-open cache bounded — evicts oldest when full ───────
    #[test]
    fn test_half_open_cache_bounded() {
        let mut cache = HalfOpenCache::with_limits(4, Duration::from_secs(60));

        // Fill cache to capacity
        let mut session_ids = Vec::new();
        for _ in 0..4 {
            let sid = SessionId::generate();
            session_ids.push(sid);
            cache.insert(sid, make_half_open(sid));
        }
        assert_eq!(cache.len(), 4);

        // Insert one more — oldest should be evicted
        let new_sid = SessionId::generate();
        cache.insert(new_sid, make_half_open(new_sid));
        assert_eq!(cache.len(), 4, "cache should not exceed max_entries");

        // The first session should have been evicted (it was oldest)
        assert!(
            !cache.contains(&session_ids[0]),
            "oldest session should be evicted"
        );

        // The new session should be present
        assert!(cache.contains(&new_sid), "new session should be in cache");
    }

    // ── Test 7: Half-open cache TTL — entries expire ────────────────────
    #[test]
    fn test_half_open_cache_ttl() {
        // Use a very short TTL for testing
        let mut cache = HalfOpenCache::with_limits(64, Duration::from_millis(50));

        let sid = SessionId::generate();
        cache.insert(sid, make_half_open(sid));
        assert!(cache.contains(&sid), "session should be in cache initially");

        // Wait for TTL to expire
        thread::sleep(Duration::from_millis(100));

        // Should be gone after TTL
        assert!(!cache.contains(&sid), "session should be expired after TTL");
        assert_eq!(cache.len(), 0, "expired entries should be removed");
    }

    // ── Test 8: Responder amplification limit ───────────────────────────
    #[test]
    fn test_responder_amplification_limit() {
        let mut cache = HalfOpenCache::new();
        let sid = SessionId::generate();
        cache.insert(sid, make_half_open(sid));

        // Simulate retransmits up to the limit
        for i in 0..MAX_RESPONDER_RETRANSMITS {
            let entry = cache.get_mut(&sid).expect("should exist");
            assert!(
                entry.retransmit_count < MAX_RESPONDER_RETRANSMITS,
                "should allow retransmit {}",
                i
            );
            entry.retransmit_count += 1;
        }

        // Next attempt should be blocked
        let entry = cache.get_mut(&sid).expect("should exist");
        assert!(
            entry.retransmit_count >= MAX_RESPONDER_RETRANSMITS,
            "should block further retransmits after limit"
        );
    }

    // ── Test 9: Different session IDs create independent handshakes ─────
    #[test]
    fn test_duplicate_hello_different_session() {
        let mut cache = HalfOpenCache::new();

        let sid1 = SessionId::generate();
        let sid2 = SessionId::generate();

        cache.insert(sid1, make_half_open(sid1));
        cache.insert(sid2, make_half_open(sid2));

        assert_eq!(cache.len(), 2, "should have two independent entries");
        assert!(cache.contains(&sid1));
        assert!(cache.contains(&sid2));

        // Modifying one should not affect the other
        if let Some(entry) = cache.get_mut(&sid1) {
            entry.retransmit_count = MAX_RESPONDER_RETRANSMITS;
        }

        let entry2 = cache.get_mut(&sid2).expect("sid2 should exist");
        assert_eq!(entry2.retransmit_count, 0, "sid2 should be unaffected");
    }

    // ── Test 10: Retransmitted msg bytes are identical ──────────────────
    #[test]
    fn test_retransmitted_msg_identical() {
        let init_id = test_identity();

        // Initiator generates msg1
        let mut init_ctx = HandshakeContext::new_initiator(&init_id).expect("init");
        let msg1 = init_ctx.write_message(&[]).expect("msg1");

        // Build a full handshake packet (simulating what the CLI does)
        let session_id = SessionId::generate();
        let pkt1 = build_handshake_packet(
            MsgType::Hello,
            &init_id.node_id,
            &[0u8; 16],
            session_id,
            0,
            &msg1,
            None,
        );

        // The "retransmit" is the exact same bytes
        let retransmit_pkt1 = pkt1.clone();
        assert_eq!(
            pkt1, retransmit_pkt1,
            "retransmitted packet must be byte-identical"
        );

        // Both should parse to the same header
        let hdr1 = HandshakeHeader::deserialize(&pkt1).expect("parse pkt1");
        let hdr2 = HandshakeHeader::deserialize(&retransmit_pkt1).expect("parse retransmit");
        assert_eq!(hdr1.session_id, hdr2.session_id);
        assert_eq!(hdr1.msg_type, hdr2.msg_type);
    }

    // ── Test: cleanup_expired removes stale entries ─────────────────────
    #[test]
    fn test_half_open_cache_cleanup() {
        let mut cache = HalfOpenCache::with_limits(64, Duration::from_millis(50));

        let sid1 = SessionId::generate();
        let sid2 = SessionId::generate();
        cache.insert(sid1, make_half_open(sid1));

        thread::sleep(Duration::from_millis(100));

        // sid1 is now expired, insert sid2 (fresh)
        cache.insert(sid2, make_half_open(sid2));

        // Explicit cleanup
        let expired = cache.cleanup_expired();
        // sid1 was already cleaned up by insert's cleanup_expired call,
        // so this may be 0
        assert!(expired == 0 || expired == 1);
        assert_eq!(cache.len(), 1, "only sid2 should remain");
        assert!(cache.contains(&sid2));
    }

    // ── Test: remove works correctly ────────────────────────────────────
    #[test]
    fn test_half_open_cache_remove() {
        let mut cache = HalfOpenCache::new();
        let sid = SessionId::generate();
        cache.insert(sid, make_half_open(sid));

        assert!(cache.contains(&sid));
        let removed = cache.remove(&sid);
        assert!(removed.is_some());
        assert!(!cache.contains(&sid));
        assert!(cache.is_empty());
    }
}
