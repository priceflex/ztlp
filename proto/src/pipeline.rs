//! Three-layer admission pipeline.
//!
//! The ZTLP admission pipeline processes inbound packets through three layers,
//! ordered by computational cost:
//!
//! - **Layer 1 — Magic check** (nanoseconds, no crypto): reject non-ZTLP traffic.
//! - **Layer 2 — SessionID lookup** (microseconds, no crypto): reject unknown sessions.
//! - **Layer 3 — HeaderAuthTag verification** (real crypto cost): reject forged packets.
//!
//! Each layer returns a clear `AdmissionResult`. Drop counters are tracked per layer.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::packet::{self, MsgType, SessionId, MAGIC};
use crate::security::{log_security_event, SecurityEvent};
use crate::session::SessionState;

/// Result of a pipeline admission check at any layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionResult {
    /// Packet passed this layer.
    Pass,
    /// Packet should be silently dropped.
    Drop,
    /// Packet should be rate-limited (for HELLO floods).
    RateLimit,
}

/// Per-layer drop counters for monitoring / diagnostics.
#[derive(Debug)]
pub struct PipelineCounters {
    /// Packets dropped at Layer 1 (bad magic).
    pub layer1_drops: AtomicU64,
    /// Packets dropped at Layer 2 (unknown SessionID).
    pub layer2_drops: AtomicU64,
    /// Packets dropped at Layer 3 (invalid auth tag).
    pub layer3_drops: AtomicU64,
    /// Packets that passed all three layers.
    pub passed: AtomicU64,
}

impl PipelineCounters {
    /// Create zeroed counters.
    pub fn new() -> Self {
        Self {
            layer1_drops: AtomicU64::new(0),
            layer2_drops: AtomicU64::new(0),
            layer3_drops: AtomicU64::new(0),
            passed: AtomicU64::new(0),
        }
    }

    /// Snapshot the current counter values.
    pub fn snapshot(&self) -> PipelineSnapshot {
        PipelineSnapshot {
            layer1_drops: self.layer1_drops.load(Ordering::Relaxed),
            layer2_drops: self.layer2_drops.load(Ordering::Relaxed),
            layer3_drops: self.layer3_drops.load(Ordering::Relaxed),
            passed: self.passed.load(Ordering::Relaxed),
        }
    }
}

impl Default for PipelineCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable snapshot of pipeline counters.
#[derive(Debug, Clone)]
pub struct PipelineSnapshot {
    pub layer1_drops: u64,
    pub layer2_drops: u64,
    pub layer3_drops: u64,
    pub passed: u64,
}

impl std::fmt::Display for PipelineSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Pipeline: L1(magic) drops={}, L2(session) drops={}, L3(auth) drops={}, passed={}",
            self.layer1_drops, self.layer2_drops, self.layer3_drops, self.passed
        )
    }
}

/// The three-layer admission pipeline.
pub struct Pipeline {
    /// Active session table: SessionID → SessionState.
    sessions: HashMap<SessionId, SessionState>,
    /// Drop / pass counters.
    pub counters: PipelineCounters,
}

impl Pipeline {
    /// Create a new empty pipeline.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            counters: PipelineCounters::new(),
        }
    }

    /// Register a session in the pipeline's session table.
    pub fn register_session(&mut self, session: SessionState) {
        self.sessions.insert(session.session_id, session);
    }

    /// Remove a session from the pipeline.
    pub fn remove_session(&mut self, session_id: &SessionId) {
        self.sessions.remove(session_id);
    }

    /// Get a reference to a session by ID.
    pub fn get_session(&self, session_id: &SessionId) -> Option<&SessionState> {
        self.sessions.get(session_id)
    }

    /// Get a mutable reference to a session by ID.
    pub fn get_session_mut(&mut self, session_id: &SessionId) -> Option<&mut SessionState> {
        self.sessions.get_mut(session_id)
    }

    /// **Layer 1: Magic byte check.**
    ///
    /// Cost: single 16-bit comparison, nanoseconds, no crypto.
    /// Rejects all non-ZTLP UDP noise.
    pub fn layer1_magic_check(&self, data: &[u8]) -> AdmissionResult {
        if data.len() < 2 {
            return AdmissionResult::Drop;
        }
        let magic = u16::from_be_bytes([data[0], data[1]]);
        if magic != MAGIC {
            AdmissionResult::Drop
        } else {
            AdmissionResult::Pass
        }
    }

    /// **Layer 2: SessionID lookup.**
    ///
    /// Cost: O(1) HashMap lookup, microseconds, no crypto.
    /// Rejects packets with unknown SessionIDs.
    /// Allows HELLO messages through (they have zero SessionID).
    ///
    /// Packet type discrimination uses the HdrLen field (12 bits at offset 2–3):
    /// - Handshake header = 24 words (95 bytes → rounded to 24 × 4-byte words)
    /// - Data header = 11 words (42 bytes → rounded to 11 × 4-byte words)
    ///
    /// This is reliable because each header type sets HdrLen to a fixed value.
    pub fn layer2_session_check(&self, data: &[u8]) -> AdmissionResult {
        // Need at least 4 bytes to read Magic + VerHdrLen
        if data.len() < 4 {
            return AdmissionResult::Drop;
        }

        // Extract HdrLen (lower 12 bits of the second u16)
        let ver_hdrlen = u16::from_be_bytes([data[2], data[3]]);
        let hdr_len = ver_hdrlen & 0x0FFF;

        // HdrLen 24 = handshake/control header (95 bytes)
        // HdrLen 11 = compact data header (42 bytes)
        let is_handshake = hdr_len == 24;

        if is_handshake {
            // Handshake header: MsgType at byte 6, SessionID at byte 11
            if data.len() < packet::HANDSHAKE_HEADER_SIZE {
                return AdmissionResult::Drop;
            }

            let msg_type_byte = data[6];
            if msg_type_byte == MsgType::Hello as u8 || msg_type_byte == MsgType::HelloAck as u8 {
                // HELLO/HELLO_ACK get through Layer 2 (they establish sessions)
                return AdmissionResult::Pass;
            }

            let mut sid = [0u8; 12];
            sid.copy_from_slice(&data[11..23]);
            let session_id = SessionId(sid);

            if self.sessions.contains_key(&session_id) {
                AdmissionResult::Pass
            } else {
                AdmissionResult::Drop
            }
        } else {
            // Data header: SessionID at byte 6
            if data.len() < packet::DATA_HEADER_SIZE {
                return AdmissionResult::Drop;
            }

            let mut sid = [0u8; 12];
            sid.copy_from_slice(&data[6..18]);
            let session_id = SessionId(sid);

            if self.sessions.contains_key(&session_id) {
                AdmissionResult::Pass
            } else {
                AdmissionResult::Drop
            }
        }
    }

    /// **Layer 3: HeaderAuthTag verification.**
    ///
    /// Cost: real cryptographic work (ChaCha20-Poly1305 AEAD).
    /// Only reached by packets that passed Layers 1 and 2.
    ///
    /// Uses HdrLen to discriminate handshake vs data headers (same as Layer 2).
    pub fn layer3_auth_check(&self, data: &[u8]) -> AdmissionResult {
        if data.len() < 4 {
            return AdmissionResult::Drop;
        }

        let ver_hdrlen = u16::from_be_bytes([data[2], data[3]]);
        let hdr_len = ver_hdrlen & 0x0FFF;
        let is_handshake = hdr_len == 24;

        if is_handshake {
            if data.len() < packet::HANDSHAKE_HEADER_SIZE {
                return AdmissionResult::Drop;
            }

            let msg_type_byte = data[6];
            if msg_type_byte == MsgType::Hello as u8 {
                // Initial HELLO has no session keys yet — skip auth check
                return AdmissionResult::Pass;
            }

            let mut sid = [0u8; 12];
            sid.copy_from_slice(&data[11..23]);
            let session_id = SessionId(sid);

            if let Some(session) = self.sessions.get(&session_id) {
                let aad = &data[..packet::HANDSHAKE_HEADER_SIZE - 16];
                let auth_tag =
                    &data[packet::HANDSHAKE_HEADER_SIZE - 16..packet::HANDSHAKE_HEADER_SIZE];

                if verify_header_auth_tag(&session.recv_key, aad, auth_tag) {
                    AdmissionResult::Pass
                } else {
                    AdmissionResult::Drop
                }
            } else {
                AdmissionResult::Drop
            }
        } else {
            // Data packet
            if data.len() < packet::DATA_HEADER_SIZE {
                return AdmissionResult::Drop;
            }

            let mut sid = [0u8; 12];
            sid.copy_from_slice(&data[6..18]);
            let session_id = SessionId(sid);

            if let Some(session) = self.sessions.get(&session_id) {
                // Data header AAD is non-contiguous: bytes before AuthTag + bytes after AuthTag
                // Layout: [0..26] pre-tag | [26..42] AuthTag | [42..46] ExtLen+PayloadLen
                let mut aad = Vec::with_capacity(30);
                aad.extend_from_slice(&data[..26]);
                aad.extend_from_slice(&data[42..46]);
                let auth_tag = &data[26..42];

                if verify_header_auth_tag(&session.recv_key, &aad, auth_tag) {
                    AdmissionResult::Pass
                } else {
                    AdmissionResult::Drop
                }
            } else {
                AdmissionResult::Drop
            }
        }
    }

    /// Run all three layers on a raw packet. Returns the final admission result.
    ///
    /// Emits [`SecurityEvent`] warnings for each rejection layer so that
    /// drops are auditable.
    pub fn process(&self, data: &[u8]) -> AdmissionResult {
        self.process_from(data, None)
    }

    /// Same as [`process`](Self::process) but accepts an optional peer address
    /// for richer audit logging.
    pub fn process_from(&self, data: &[u8], peer_addr: Option<&str>) -> AdmissionResult {
        // Layer 1: Magic check
        let r1 = self.layer1_magic_check(data);
        if r1 != AdmissionResult::Pass {
            self.counters.layer1_drops.fetch_add(1, Ordering::Relaxed);
            log_security_event(&SecurityEvent::MalformedPacket {
                reason: "bad magic (layer 1)".into(),
                peer_addr: peer_addr.map(|s| s.to_string()),
                bytes_received: Some(data.len()),
            });
            return r1;
        }

        // Layer 2: SessionID lookup
        let r2 = self.layer2_session_check(data);
        if r2 != AdmissionResult::Pass {
            self.counters.layer2_drops.fetch_add(1, Ordering::Relaxed);
            // Extract session_id hex for logging (best-effort)
            let sid_hex = extract_session_id_hex(data);
            log_security_event(&SecurityEvent::MalformedPacket {
                reason: format!("unknown session (layer 2), session_id={}", sid_hex),
                peer_addr: peer_addr.map(|s| s.to_string()),
                bytes_received: Some(data.len()),
            });
            return r2;
        }

        // Layer 3: HeaderAuthTag verification
        let r3 = self.layer3_auth_check(data);
        if r3 != AdmissionResult::Pass {
            self.counters.layer3_drops.fetch_add(1, Ordering::Relaxed);
            let sid_hex = extract_session_id_hex(data);
            log_security_event(&SecurityEvent::AuthTagInvalid {
                peer_addr: peer_addr.map(|s| s.to_string()),
                session_id: Some(sid_hex),
                direction: "rx".into(),
            });
            return r3;
        }

        self.counters.passed.fetch_add(1, Ordering::Relaxed);
        AdmissionResult::Pass
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Best-effort extraction of session ID hex from a raw packet for logging.
fn extract_session_id_hex(data: &[u8]) -> String {
    if data.len() < 4 {
        return "-".into();
    }
    let ver_hdrlen = u16::from_be_bytes([data[2], data[3]]);
    let hdr_len = ver_hdrlen & 0x0FFF;
    let is_handshake = hdr_len == 24;

    if is_handshake && data.len() >= 23 {
        hex::encode(&data[11..23])
    } else if !is_handshake && data.len() >= 18 {
        hex::encode(&data[6..18])
    } else {
        "-".into()
    }
}

/// Compute a HeaderAuthTag (AEAD tag) over header AAD bytes.
///
/// Uses ChaCha20-Poly1305 with a zero nonce for header authentication.
/// The "ciphertext" is empty — we only use the tag as a MAC over the AAD.
pub fn compute_header_auth_tag(key: &[u8; 32], aad: &[u8]) -> [u8; 16] {
    // We use the AEAD in a MAC-only mode: encrypt empty plaintext with the AAD.
    // The resulting ciphertext is just the 16-byte Poly1305 tag.
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::default(); // 96-bit zero nonce — each packet uses unique AAD via seq/timestamp

    // Encrypt empty payload with the header as AAD — produces a 16-byte tag
    // SAFETY: ChaCha20Poly1305 encryption with a valid 32-byte key and empty
    // plaintext is infallible — the only failure mode is invalid key length,
    // which cannot happen since we take &[u8; 32].
    let ciphertext = match cipher.encrypt(&nonce, chacha20poly1305::aead::Payload { msg: &[], aad })
    {
        Ok(ct) => ct,
        Err(_) => {
            // Defensive: return zero tag if encryption somehow fails
            return [0u8; 16];
        }
    };

    // The ciphertext IS the tag (empty plaintext → ciphertext is just tag)
    let mut tag = [0u8; 16];
    if ciphertext.len() >= 16 {
        tag.copy_from_slice(&ciphertext[..16]);
    }
    tag
}

/// Verify a HeaderAuthTag against the header AAD bytes.
///
/// SECURITY: This uses AEAD decryption (ChaCha20-Poly1305) for verification,
/// which is inherently constant-time because the Poly1305 MAC comparison
/// inside the AEAD implementation uses constant-time primitives. This avoids
/// timing side-channels that could leak information about the expected tag.
fn verify_header_auth_tag(key: &[u8; 32], aad: &[u8], tag: &[u8]) -> bool {
    if tag.len() != 16 {
        return false;
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::default();

    cipher
        .decrypt(&nonce, chacha20poly1305::aead::Payload { msg: tag, aad })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeId;
    use crate::session::SessionState;

    /// Helper: build a minimal valid ZTLP packet with magic bytes.
    fn make_magic_packet(magic: u16, remaining: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&magic.to_be_bytes());
        pkt.extend_from_slice(remaining);
        pkt
    }

    /// Helper: create a test session state.
    fn make_test_session(session_id: SessionId, recv_key: [u8; 32]) -> SessionState {
        SessionState::new(
            session_id,
            NodeId::from_bytes([0u8; 16]),
            [0u8; 32],   // send_key
            recv_key,
            false,        // multipath
        )
    }

    // ── Layer 1: Magic byte tests ───────────────────────────────────────

    #[test]
    fn test_layer1_accepts_valid_magic() {
        let pipeline = Pipeline::new();
        let pkt = make_magic_packet(MAGIC, &[0u8; 10]);
        assert_eq!(pipeline.layer1_magic_check(&pkt), AdmissionResult::Pass);
    }

    #[test]
    fn test_layer1_rejects_invalid_magic() {
        let pipeline = Pipeline::new();
        let pkt = make_magic_packet(0xDEAD, &[0u8; 10]);
        assert_eq!(pipeline.layer1_magic_check(&pkt), AdmissionResult::Drop);
    }

    #[test]
    fn test_layer1_rejects_empty_packet() {
        let pipeline = Pipeline::new();
        assert_eq!(pipeline.layer1_magic_check(&[]), AdmissionResult::Drop);
    }

    #[test]
    fn test_layer1_rejects_single_byte() {
        let pipeline = Pipeline::new();
        assert_eq!(pipeline.layer1_magic_check(&[0x5A]), AdmissionResult::Drop);
    }

    // ── Layer 2: Session check tests ────────────────────────────────────

    #[test]
    fn test_layer2_rejects_too_short() {
        let pipeline = Pipeline::new();
        let pkt = [0u8; 3]; // Less than 4 bytes
        assert_eq!(pipeline.layer2_session_check(&pkt), AdmissionResult::Drop);
    }

    #[test]
    fn test_layer2_rejects_unknown_session() {
        let pipeline = Pipeline::new();
        // Build a data header (HdrLen = 11) with unknown session ID
        let mut pkt = vec![0u8; packet::DATA_HEADER_SIZE];
        pkt[0] = (MAGIC >> 8) as u8;
        pkt[1] = (MAGIC & 0xFF) as u8;
        // VerHdrLen: version 0, hdrlen 11
        pkt[2] = 0x00;
        pkt[3] = 0x0B; // HdrLen = 11
        // Unknown session ID at bytes 6..18
        for i in 6..18 {
            pkt[i] = 0xFF;
        }
        assert_eq!(pipeline.layer2_session_check(&pkt), AdmissionResult::Drop);
    }

    // ── Layer 3: Auth tag tests ─────────────────────────────────────────

    #[test]
    fn test_layer3_rejects_too_short() {
        let pipeline = Pipeline::new();
        assert_eq!(pipeline.layer3_auth_check(&[0u8; 3]), AdmissionResult::Drop);
    }

    // ── Header auth tag tests ───────────────────────────────────────────

    #[test]
    fn test_compute_and_verify_auth_tag() {
        let key = [0x42u8; 32];
        let aad = b"test header data";

        let tag = compute_header_auth_tag(&key, aad);
        assert_eq!(tag.len(), 16);
        assert!(verify_header_auth_tag(&key, aad, &tag));
    }

    #[test]
    fn test_auth_tag_rejects_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x99u8; 32];
        let aad = b"test header data";

        let tag = compute_header_auth_tag(&key, aad);
        assert!(!verify_header_auth_tag(&wrong_key, aad, &tag));
    }

    #[test]
    fn test_auth_tag_rejects_wrong_aad() {
        let key = [0x42u8; 32];
        let aad = b"test header data";
        let wrong_aad = b"wrong header data";

        let tag = compute_header_auth_tag(&key, aad);
        assert!(!verify_header_auth_tag(&key, wrong_aad, &tag));
    }

    /// SECURITY: Verify that tags of wrong length are rejected.
    #[test]
    fn test_auth_tag_rejects_wrong_length() {
        let key = [0x42u8; 32];
        let aad = b"test";

        // Too short
        assert!(!verify_header_auth_tag(&key, aad, &[0u8; 15]));
        // Too long
        assert!(!verify_header_auth_tag(&key, aad, &[0u8; 17]));
        // Empty
        assert!(!verify_header_auth_tag(&key, aad, &[]));
    }

    /// SECURITY: Verify that a tampered tag is rejected (single-bit flip).
    #[test]
    fn test_auth_tag_rejects_single_bit_flip() {
        let key = [0x42u8; 32];
        let aad = b"test header data for tamper check";

        let tag = compute_header_auth_tag(&key, aad);

        // Flip each bit in each byte of the tag
        for byte_idx in 0..16 {
            let mut tampered_tag = tag;
            tampered_tag[byte_idx] ^= 0x01;
            assert!(
                !verify_header_auth_tag(&key, aad, &tampered_tag),
                "flipping bit in tag byte {} should fail",
                byte_idx
            );
        }
    }

    // ── Pipeline integration tests ──────────────────────────────────────

    #[test]
    fn test_pipeline_counters_new() {
        let counters = PipelineCounters::new();
        let snap = counters.snapshot();
        assert_eq!(snap.layer1_drops, 0);
        assert_eq!(snap.layer2_drops, 0);
        assert_eq!(snap.layer3_drops, 0);
        assert_eq!(snap.passed, 0);
    }

    #[test]
    fn test_pipeline_snapshot_display() {
        let counters = PipelineCounters::new();
        counters.layer1_drops.fetch_add(5, Ordering::Relaxed);
        let snap = counters.snapshot();
        let display = format!("{}", snap);
        assert!(display.contains("L1(magic) drops=5"));
    }

    #[test]
    fn test_pipeline_process_bad_magic() {
        let pipeline = Pipeline::new();
        let pkt = make_magic_packet(0xDEAD, &[0u8; 50]);
        assert_eq!(pipeline.process(&pkt), AdmissionResult::Drop);
        let snap = pipeline.counters.snapshot();
        assert_eq!(snap.layer1_drops, 1);
    }

    #[test]
    fn test_pipeline_register_remove_session() {
        let mut pipeline = Pipeline::new();
        let sid = SessionId::generate();
        let session = make_test_session(sid, [0x42; 32]);
        pipeline.register_session(session);
        assert!(pipeline.get_session(&sid).is_some());

        pipeline.remove_session(&sid);
        assert!(pipeline.get_session(&sid).is_none());
    }
}
