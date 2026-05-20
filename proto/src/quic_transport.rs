//! Experimental QUIC transport scaffold (Phase 0).
//!
//! This module is **intentionally empty of working logic**. It exists so
//! the new transport layer has a stable home in the crate while the
//! existing hand-rolled UDP stack (`mux.rs`, `send_controller.rs`,
//! `congestion.rs`, ...) keeps the tree running.
//!
//! See `docs/architecture/quic-noise-handshake.md` for the full design.
//!
//! # Why feature-gated
//!
//! `quinn`, `quinn-proto`, and `rustls` together pull in ~200k LOC of
//! transitive dependencies. We do not want default builds — especially
//! the iOS Network Extension build — paying that cost until the
//! implementation is real. Build with:
//!
//!   cargo build --features quic-transport
//!
//! to opt in. The iOS NE build will use `--features
//! ios-sync,quic-transport` once Phase 4 lands; until then `ios-sync`
//! continues to compile without this module.
//!
//! # Two backends, one feature flag
//!
//! - `quinn::Endpoint` (tokio-backed) — used on Gateway/Relay/macOS.
//!   Only compiled when both `quic-transport` AND `tokio-runtime` are on.
//! - `quinn-proto` sans-io state machine — used by iOS NE.
//!   Compiled whenever `quic-transport` is on.
//!
//! # ALPN
//!
//! Reserved: `ztlp/1`. Stored as a const so all call sites agree.

#![cfg(feature = "quic-transport")]

/// ALPN identifier advertised in QUIC `Initial` packets.
///
/// Distinct ALPN values let us run multiple QUIC-based protocols on
/// the same UDP port without collision and give middleboxes a clean
/// signal that this is ZTLP traffic, not generic HTTP/3.
pub const ZTLP_ALPN: &[u8] = b"ztlp/1";

/// Magic byte prefix on stream-0 control frames.
///
/// `0xZ1` (= `0x5A`, ASCII 'Z') marks a handshake-version-1 frame.
/// Range `0xZ2..=0xZF` is reserved for future stream-0 control
/// messages (rekey, keepalive, graceful close, etc.). Keeping this
/// const centralises the wire-format authority — never hard-code
/// the byte elsewhere.
pub const STREAM0_MAGIC_V1: u8 = b'Z';

/// Errors produced by the QUIC transport scaffold.
///
/// Every variant is a *placeholder* in Phase 0. Real error taxonomy
/// will be defined in Phase 1 once the endpoint is wired.
#[derive(Debug, thiserror::Error)]
pub enum QuicTransportError {
    /// The caller invoked a code path that has not been implemented yet.
    ///
    /// This is distinct from a runtime failure: it means the *feature*
    /// is not built. Returning a real error (rather than `unimplemented!()`)
    /// lets tests assert on it without panicking.
    #[error("QUIC transport phase {phase} not yet implemented: {what}")]
    NotImplemented {
        /// Which migration phase owns this code path (see design doc §8).
        phase: u8,
        /// Short human-readable description of the missing capability.
        what: &'static str,
    },
}

/// Sans-io QUIC endpoint configuration shared by both backends.
///
/// Phase 0: the struct exists so callers can be wired up against a
/// stable type. Fields will grow in Phase 1 (peer auth keys, ALPN
/// list, transport params) and Phase 4 (iOS-specific tuning).
#[derive(Debug, Clone)]
pub struct QuicEndpointConfig {
    /// Bind address for the underlying UDP socket.
    ///
    /// `None` means "let the OS choose" (used by client-mode
    /// connections that don't accept inbound). Servers must set this.
    pub bind: Option<std::net::SocketAddr>,
    /// ALPN values to advertise. Defaults to `[ZTLP_ALPN]`.
    pub alpn: Vec<Vec<u8>>,
}

impl Default for QuicEndpointConfig {
    fn default() -> Self {
        Self {
            bind: None,
            alpn: vec![ZTLP_ALPN.to_vec()],
        }
    }
}

// ─── Tokio-backed endpoint (server/desktop) ───────────────────────────────
//
// Only compiled when both `quic-transport` and `tokio-runtime` are on.
// iOS NE builds (`ios-sync`) skip this entire block.

#[cfg(feature = "tokio-runtime")]
pub mod tokio_endpoint {
    //! `quinn::Endpoint`-backed server/client. Not implemented yet —
    //! Phase 1 deliverable.

    use super::{QuicEndpointConfig, QuicTransportError};

    /// Tokio-backed QUIC endpoint wrapping `quinn::Endpoint`.
    ///
    /// Empty in Phase 0. Phase 1 will hold the `quinn::Endpoint`,
    /// a `tokio::task::JoinHandle` for the accept loop, and a
    /// channel surface for incoming connections.
    #[derive(Debug)]
    pub struct QuicEndpoint {
        _cfg: QuicEndpointConfig,
    }

    impl QuicEndpoint {
        /// Bind the underlying UDP socket and start accepting QUIC
        /// connections.
        ///
        /// # Phase 0 behavior
        ///
        /// Returns `NotImplemented`. The signature is locked in so
        /// callers (Gateway / Relay forwarder) can be written against
        /// it now.
        pub async fn bind(cfg: QuicEndpointConfig) -> Result<Self, QuicTransportError> {
            Err(QuicTransportError::NotImplemented {
                phase: 1,
                what: "QuicEndpoint::bind — quinn endpoint setup",
            })
        }

        /// Accept the next incoming QUIC connection.
        ///
        /// Phase 0: always errors. Phase 1 returns a typed handle
        /// that exposes a stream-0 bidi stream pre-opened for Noise
        /// handshake bytes.
        pub async fn accept(&self) -> Result<(), QuicTransportError> {
            Err(QuicTransportError::NotImplemented {
                phase: 1,
                what: "QuicEndpoint::accept — quinn incoming connection",
            })
        }
    }
}

// ─── Sans-io path (iOS NE — Phase 4) ──────────────────────────────────────
//
// quinn-proto has no IO: the caller drives `Connection` by feeding raw
// UDP datagrams in (`handle_dgram`) and pulling them out (`poll_transmit`).
// Suitable for the NE which owns its own socket and has no tokio runtime.

/// Sans-io QUIC connection state. Phase 0 placeholder.
///
/// Phase 4 will wrap `quinn_proto::Connection`. The current empty
/// struct lets us start writing the iOS-side wiring code (FFI shim
/// in `ffi.rs`) against a stable Rust type without committing to the
/// final field layout.
#[derive(Debug)]
pub struct SansIoConnection {
    _placeholder: (),
}

impl SansIoConnection {
    /// Construct a new sans-io connection.
    ///
    /// Phase 0: returns `NotImplemented`. The point of having the
    /// constructor at all is so test #3 (`sans_io_path_compiles_without_tokio`)
    /// can exercise the type signature on the `ios-sync` build and
    /// catch any accidental `tokio` leak via compile error.
    pub fn new(_cfg: QuicEndpointConfig) -> Result<Self, QuicTransportError> {
        Err(QuicTransportError::NotImplemented {
            phase: 4,
            what: "SansIoConnection::new — quinn-proto state machine init",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_stable() {
        // Locking the ALPN string in a test catches accidental edits.
        // Wire-format constants change == handshake breakage in the
        // field, so we treat this like a wire-compat assertion.
        assert_eq!(ZTLP_ALPN, b"ztlp/1");
    }

    #[test]
    fn stream0_magic_is_ascii_z() {
        // 'Z' = 0x5A. The handshake design picks this so a packet
        // capture is human-readable when debugging.
        assert_eq!(STREAM0_MAGIC_V1, 0x5A);
    }

    #[test]
    fn default_config_advertises_ztlp_alpn() {
        let cfg = QuicEndpointConfig::default();
        assert_eq!(cfg.alpn, vec![ZTLP_ALPN.to_vec()]);
        assert!(cfg.bind.is_none());
    }

    #[test]
    fn sans_io_constructor_returns_not_implemented() {
        // Documents the Phase 0 contract: callers get a structured
        // error, not a panic. When Phase 4 lands, this test flips to
        // asserting `is_ok()` and a new test takes over the
        // not-implemented role.
        let err = SansIoConnection::new(QuicEndpointConfig::default()).unwrap_err();
        match err {
            QuicTransportError::NotImplemented { phase, .. } => assert_eq!(phase, 4),
        }
    }
}
