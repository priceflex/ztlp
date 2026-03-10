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

use blake2::{Blake2s256, Digest};
use snow::{Builder, HandshakeState, TransportState};

use crate::error::HandshakeError;
use crate::identity::{NodeId, NodeIdentity};
use crate::packet::{HandshakeHeader, MsgType, SessionId};
use crate::pipeline::compute_header_auth_tag;
use crate::session::SessionState;

/// Noise protocol pattern string.
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

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
        let remote_static = transport.get_remote_static()
            .unwrap_or(&[0u8; 32]);

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
        let i2r_key = derive_key(b"ztlp_initiator_to_responder", session_id.as_bytes(), &shared_material);
        let r2i_key = derive_key(b"ztlp_responder_to_initiator", session_id.as_bytes(), &shared_material);

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
