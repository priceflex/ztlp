//! Error types for the ZTLP protocol stack.

#![deny(unsafe_code)]

use thiserror::Error;

/// Top-level error type for all ZTLP operations.
#[derive(Debug, Error)]
pub enum ZtlpError {
    /// Packet serialization or deserialization failed.
    #[error("packet error: {0}")]
    Packet(#[from] PacketError),

    /// Pipeline admission check failed.
    #[error("pipeline error: {0}")]
    Pipeline(#[from] PipelineError),

    /// Session management error.
    #[error("session error: {0}")]
    Session(#[from] SessionError),

    /// Handshake protocol error.
    #[error("handshake error: {0}")]
    Handshake(#[from] HandshakeError),

    /// Transport / IO error.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// Identity management error.
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

/// Errors during packet marshal / unmarshal.
#[derive(Debug, Error)]
pub enum PacketError {
    #[error("buffer too short: need {need} bytes, have {have}")]
    BufferTooShort { need: usize, have: usize },

    #[error("invalid magic: expected 0x5A37, got 0x{0:04X}")]
    InvalidMagic(u16),

    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("invalid message type: {0}")]
    InvalidMsgType(u8),

    #[error("header length mismatch: declared {declared} bytes, but header is {actual} bytes")]
    HeaderLengthMismatch { declared: usize, actual: usize },
}

/// Errors from the three-layer admission pipeline.
#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("dropped at layer 1: bad magic")]
    BadMagic,

    #[error("dropped at layer 2: unknown session ID")]
    UnknownSession,

    #[error("dropped at layer 3: invalid header auth tag")]
    InvalidAuthTag,
}

/// Session state errors.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session not found: {0}")]
    NotFound(String),

    #[error("replay detected: packet seq {0} already seen")]
    ReplayDetected(u64),

    #[error("session expired")]
    Expired,

    #[error("crypto error: {0}")]
    Crypto(String),
}

/// Handshake errors.
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("noise protocol error: {0}")]
    Noise(String),

    #[error("unexpected handshake state: {0}")]
    UnexpectedState(String),

    #[error("handshake timeout")]
    Timeout,
}

/// Transport / IO errors.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("gateway pin mismatch: expected [{expected_hex}], got {got_hex}", expected_hex = display_pin_list(.expected), got_hex = hex::encode(.got))]
    PinMismatch {
        expected: Vec<[u8; 32]>,
        got: Vec<u8>,
    },
}

/// Format a list of pinned keys as comma-separated hex strings.
fn display_pin_list(keys: &[[u8; 32]]) -> String {
    keys.iter().map(hex::encode).collect::<Vec<_>>().join(", ")
}

/// Identity management errors.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid key material: {0}")]
    InvalidKey(String),
}
