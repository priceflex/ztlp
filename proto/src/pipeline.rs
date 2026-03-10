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

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::packet::{self, MsgType, SessionId, MAGIC};
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
                let auth_tag = &data[packet::HANDSHAKE_HEADER_SIZE - 16..packet::HANDSHAKE_HEADER_SIZE];

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
                let aad = &data[..packet::DATA_HEADER_SIZE - 16];
                let auth_tag = &data[packet::DATA_HEADER_SIZE - 16..packet::DATA_HEADER_SIZE];

                if verify_header_auth_tag(&session.recv_key, aad, auth_tag) {
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
    pub fn process(&self, data: &[u8]) -> AdmissionResult {
        // Layer 1: Magic check
        let r1 = self.layer1_magic_check(data);
        if r1 != AdmissionResult::Pass {
            self.counters.layer1_drops.fetch_add(1, Ordering::Relaxed);
            return r1;
        }

        // Layer 2: SessionID lookup
        let r2 = self.layer2_session_check(data);
        if r2 != AdmissionResult::Pass {
            self.counters.layer2_drops.fetch_add(1, Ordering::Relaxed);
            return r2;
        }

        // Layer 3: HeaderAuthTag verification
        let r3 = self.layer3_auth_check(data);
        if r3 != AdmissionResult::Pass {
            self.counters.layer3_drops.fetch_add(1, Ordering::Relaxed);
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
    let ciphertext = cipher
        .encrypt(&nonce, chacha20poly1305::aead::Payload { msg: &[], aad })
        .expect("AEAD encryption should not fail with valid key");

    // The ciphertext IS the tag (empty plaintext → ciphertext is just tag)
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext);
    tag
}

/// Verify a HeaderAuthTag against the header AAD bytes.
fn verify_header_auth_tag(key: &[u8; 32], aad: &[u8], tag: &[u8]) -> bool {
    if tag.len() != 16 {
        return false;
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::default();

    cipher
        .decrypt(
            &nonce,
            chacha20poly1305::aead::Payload { msg: tag, aad },
        )
        .is_ok()
}
