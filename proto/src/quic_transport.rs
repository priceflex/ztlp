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
    #[error("QUIC transport phase {phase} not yet implemented: {what}")]
    NotImplemented { phase: u8, what: &'static str },

    #[error("endpoint error: {0}")]
    Endpoint(#[from] std::io::Error),

    #[error("connect error: {0}")]
    Connect(String),

    #[error("connection error: {0}")]
    Connection(String),

    #[error("read error: {0}")]
    Read(String),

    #[error("read exact error: {0}")]
    ReadExact(String),

    #[error("write error: {0}")]
    Write(String),

    #[error("bad magic: expected {expected:#04x}, got {got:#04x}")]
    BadMagic { expected: u8, got: u8 },

    #[error("frame too large: {sz}")]
    FrameTooLarge { sz: usize },

    #[error("handshake error: {0}")]
    Handshake(String),
}

impl From<quinn::ConnectError> for QuicTransportError {
    fn from(e: quinn::ConnectError) -> Self {
        QuicTransportError::Connect(e.to_string())
    }
}
impl From<quinn::ConnectionError> for QuicTransportError {
    fn from(e: quinn::ConnectionError) -> Self {
        QuicTransportError::Connection(e.to_string())
    }
}
impl From<quinn::ReadError> for QuicTransportError {
    fn from(e: quinn::ReadError) -> Self {
        QuicTransportError::Read(e.to_string())
    }
}
impl From<quinn::ReadExactError> for QuicTransportError {
    fn from(e: quinn::ReadExactError) -> Self {
        QuicTransportError::ReadExact(e.to_string())
    }
}
impl From<quinn::WriteError> for QuicTransportError {
    fn from(e: quinn::WriteError) -> Self {
        QuicTransportError::Write(e.to_string())
    }
}
impl From<crate::error::HandshakeError> for QuicTransportError {
    fn from(e: crate::error::HandshakeError) -> Self {
        QuicTransportError::Handshake(e.to_string())
    }
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
    /// Optional override for Quinn's `max_idle_timeout`. v0.29.3 sets a
    /// 60s default on both client and server so a brief packet-loss window
    /// or a relay-side ETS GC tick doesn't immediately tear down a tunnel.
    /// Quinn's own default is 30s; the ZTLP relay's α-path adds an extra
    /// RTT + UDP loss surface, so we want headroom.
    pub max_idle_timeout_ms: Option<u32>,
    /// Optional override for Quinn's `keep_alive_interval`. v0.29.3 sets a
    /// 15s default so an idle tunnel still emits keepalive packets through
    /// the relay (which both refreshes the relay's `{:client_map, ...}`
    /// inserted_at and prevents the gateway from dropping the connection
    /// on idle).
    pub keep_alive_interval_ms: Option<u32>,
}

impl Default for QuicEndpointConfig {
    fn default() -> Self {
        Self {
            bind: None,
            alpn: vec![ZTLP_ALPN.to_vec()],
            // 60s idle timeout — long enough to survive a relay sweeper tick
            // (60s) plus jitter, short enough that a truly-dead client doesn't
            // hold a gateway slot forever.
            max_idle_timeout_ms: Some(60_000),
            // 15s keepalive — well under the 60s idle timeout. Picks up after
            // any natural traffic gap (e.g. user-initiated curl through the
            // local-forward) without flooding the relay.
            keep_alive_interval_ms: Some(15_000),
        }
    }
}

// ─── Tokio-backed endpoint (server/desktop) ───────────────────────────────
//
// Only compiled when both `quic-transport` and `tokio-runtime` are on.
// iOS NE builds (`ios-sync`) skip this entire block.

// ---------------------------------------------------------------------------
// Relay-routable client connection IDs (2026-10-20)
// ---------------------------------------------------------------------------
//
// A relay that fronts a NAT'd gateway receives every gateway->client packet
// from the same gateway address, so it must route replies by the QUIC
// Destination Connection ID. quinn servers switch to a fresh client-issued
// CID as soon as the client's first NEW_CONNECTION_ID frame arrives; that
// frame is encrypted, so the relay cannot learn the new CID. Giving every CID
// issued by one client endpoint the same random prefix lets the relay learn
// `prefix -> client address` from the client's Initial (cleartext SCID) and
// keep routing after the switch. One endpoint == one UDP socket == one relay
// client address, so the endpoint is exactly the right granularity.
//
// Trade-off: CIDs of one endpoint are linkable by an on-path observer through
// the prefix. They already share the endpoint's UDP 4-tuple, and ZTLP clients
// do not migrate, so this costs no unlinkability we actually had.

/// Length of the per-endpoint routing prefix at the start of every client CID.
pub const RELAY_CID_PREFIX_LEN: usize = 4;
/// Total client CID length (prefix + random). quinn's default is also 8.
pub const RELAY_CID_LEN: usize = 8;

/// [`quinn_proto::ConnectionIdGenerator`] that stamps a fixed random prefix
/// on every CID it issues. See the module comment above.
#[derive(Debug, Clone, Copy)]
pub struct RelayRoutableCidGenerator {
    prefix: [u8; RELAY_CID_PREFIX_LEN],
}

impl RelayRoutableCidGenerator {
    /// New generator with a fresh random prefix.
    pub fn new() -> Self {
        Self {
            prefix: rand::random(),
        }
    }

    /// The routing prefix shared by every CID this generator issues.
    pub fn prefix(&self) -> [u8; RELAY_CID_PREFIX_LEN] {
        self.prefix
    }
}

impl Default for RelayRoutableCidGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl quinn_proto::ConnectionIdGenerator for RelayRoutableCidGenerator {
    fn generate_cid(&mut self) -> quinn_proto::ConnectionId {
        let mut bytes = [0u8; RELAY_CID_LEN];
        bytes[..RELAY_CID_PREFIX_LEN].copy_from_slice(&self.prefix);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes[RELAY_CID_PREFIX_LEN..]);
        quinn_proto::ConnectionId::new(&bytes)
    }

    fn cid_len(&self) -> usize {
        RELAY_CID_LEN
    }

    fn cid_lifetime(&self) -> Option<std::time::Duration> {
        None
    }
}

/// `quinn::EndpointConfig` for every ZTLP **client** endpoint: default config
/// plus [`RelayRoutableCidGenerator`]. quinn calls the factory once per
/// endpoint, so each endpoint gets its own prefix.
pub fn client_endpoint_config() -> quinn::EndpointConfig {
    let mut cfg = quinn::EndpointConfig::default();
    cfg.cid_generator(|| -> Box<dyn quinn_proto::ConnectionIdGenerator> {
        Box::new(RelayRoutableCidGenerator::new())
    });
    cfg
}

#[cfg(feature = "tokio-runtime")]
/// What the name server said about the gateway being dialed
/// (NS-anchored gateway trust, plan section 3.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RecordState {
    /// No NS record consulted (static target, legacy caller).
    #[default]
    None,
    /// The NS answered, but the answer did not verify (legacy device only;
    /// a strict device never gets this far with an unverified answer).
    Unverified,
    /// The SVC/KEY record verified against a trusted NS key and is
    /// unexpired. `fp` is its `quic_cert_sha256` (lowercase hex), absent
    /// for gateways that predate publishing it.
    Verified { fp: Option<String> },
}

/// Everything the QUIC client needs to judge the gateway's certificate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertExpectation {
    pub record: RecordState,
    /// The device trusts a name-server key for this name's zone. Derived
    /// from `ns_trust.toml`, never configured: a strict device has no
    /// fallback to TOFU pins for an unverified answer.
    pub strict: bool,
}

/// Outcome of [`decide_cert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertDecision {
    /// Accept the certificate. `write_pin`: store it as the TOFU pin
    /// (legacy paths only; NS-backed accepts never touch pin files).
    Accept {
        write_pin: bool,
        ns_backed: bool,
    },
    Reject(CertReject),
}

/// Why a certificate was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertReject {
    /// NS-signed fingerprint differs from the presented cert. The caller
    /// re-resolves once (the gateway may have restarted with a new cert and
    /// re-registered) before failing.
    NsMismatch { expected: String },
    /// Strict device, NS answer missing or not verified.
    UnverifiedAnswer,
    /// Legacy TOFU pin mismatch.
    LegacyPinMismatch { pinned: String },
}

/// Marker embedded in rejection messages so callers can recognise an
/// NS fingerprint mismatch through quinn's error chain.
pub const NS_MISMATCH_MARKER: &str = "[ztlp-ns-cert-mismatch]";
/// Marker for a strict device refusing an unverified answer.
pub const UNVERIFIED_MARKER: &str = "[ztlp-ns-unverified]";

/// Plan table 3.3, as a pure function. `presented` and the expected
/// fingerprints are hex SHA-256 (compared case-insensitively).
pub fn decide_cert(
    expect: &CertExpectation,
    presented: &str,
    cached_pin: Option<&str>,
) -> CertDecision {
    let legacy = |cached_pin: Option<&str>| match cached_pin {
        None => CertDecision::Accept {
            write_pin: true,
            ns_backed: false,
        },
        Some(p) if p.trim().eq_ignore_ascii_case(presented) => CertDecision::Accept {
            write_pin: false,
            ns_backed: false,
        },
        Some(p) => CertDecision::Reject(CertReject::LegacyPinMismatch {
            pinned: p.trim().to_string(),
        }),
    };
    match &expect.record {
        RecordState::Verified { fp: Some(fp) } => {
            if fp.trim().eq_ignore_ascii_case(presented) {
                CertDecision::Accept {
                    write_pin: false,
                    ns_backed: true,
                }
            } else {
                CertDecision::Reject(CertReject::NsMismatch {
                    expected: fp.trim().to_ascii_lowercase(),
                })
            }
        }
        // Verified record from a gateway that does not publish a
        // fingerprint yet (plan 3.5 interim): the TLS signature check still
        // proves key possession; the legacy pin acts as a cache.
        RecordState::Verified { fp: None } => legacy(cached_pin),
        RecordState::Unverified | RecordState::None if expect.strict => {
            CertDecision::Reject(CertReject::UnverifiedAnswer)
        }
        RecordState::Unverified | RecordState::None => legacy(cached_pin),
    }
}

#[cfg(test)]
mod decide_cert_tests {
    use super::*;

    const FP: &str = "abababababababababababababababababababababababababababababababab";
    const OTHER: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    fn e(record: RecordState, strict: bool) -> CertExpectation {
        CertExpectation { record, strict }
    }

    fn verified(fp: &str) -> RecordState {
        RecordState::Verified {
            fp: Some(fp.to_string()),
        }
    }

    #[test]
    fn verified_matching_fp_accepts_without_pins_strict_or_not() {
        for strict in [true, false] {
            assert_eq!(
                decide_cert(&e(verified(FP), strict), FP, Some(OTHER)),
                CertDecision::Accept {
                    write_pin: false,
                    ns_backed: true
                },
                "a stale pin must not matter"
            );
        }
    }

    #[test]
    fn verified_fp_comparison_is_case_insensitive() {
        assert!(matches!(
            decide_cert(&e(verified(&FP.to_uppercase()), true), FP, None),
            CertDecision::Accept {
                ns_backed: true,
                ..
            }
        ));
    }

    #[test]
    fn verified_mismatch_is_ns_mismatch_even_with_a_matching_pin() {
        assert_eq!(
            decide_cert(&e(verified(FP), false), OTHER, Some(OTHER)),
            CertDecision::Reject(CertReject::NsMismatch {
                expected: FP.to_string()
            })
        );
    }

    #[test]
    fn strict_unverified_or_missing_record_is_rejected_even_with_a_matching_pin() {
        for rec in [RecordState::Unverified, RecordState::None] {
            assert_eq!(
                decide_cert(&e(rec, true), FP, Some(FP)),
                CertDecision::Reject(CertReject::UnverifiedAnswer)
            );
        }
    }

    #[test]
    fn non_strict_unverified_keeps_legacy_tofu() {
        for rec in [RecordState::Unverified, RecordState::None] {
            assert_eq!(
                decide_cert(&e(rec.clone(), false), FP, None),
                CertDecision::Accept {
                    write_pin: true,
                    ns_backed: false
                }
            );
            assert_eq!(
                decide_cert(&e(rec.clone(), false), FP, Some(FP)),
                CertDecision::Accept {
                    write_pin: false,
                    ns_backed: false
                }
            );
            assert_eq!(
                decide_cert(&e(rec, false), FP, Some(OTHER)),
                CertDecision::Reject(CertReject::LegacyPinMismatch {
                    pinned: OTHER.to_string()
                })
            );
        }
    }

    #[test]
    fn verified_without_fp_uses_the_pin_as_a_cache_for_strict_devices_too() {
        let rec = RecordState::Verified { fp: None };
        assert!(matches!(
            decide_cert(&e(rec.clone(), true), FP, None),
            CertDecision::Accept {
                write_pin: true,
                ns_backed: false
            }
        ));
        assert!(matches!(
            decide_cert(&e(rec, true), FP, Some(OTHER)),
            CertDecision::Reject(CertReject::LegacyPinMismatch { .. })
        ));
    }

    #[test]
    fn default_expectation_is_legacy() {
        assert_eq!(CertExpectation::default(), e(RecordState::None, false));
    }
}

pub mod tokio_endpoint {
    //! `quinn::Endpoint`-backed server/client. Phase 1 deliverable.

    use super::{QuicEndpointConfig, QuicTransportError};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn ensure_crypto() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Apply ZTLP transport tuning to a `quinn::TransportConfig`.
    ///
    /// Throughput fix (v0.35.x, quic-pump-throughput): the default quinn
    /// stream receive window (~64 KiB) caused large transfers (>~256 KiB
    /// through a relay) to stall — the sender filled the window and waited
    /// for the peer's `MAX_STREAM_DATA` / `FLOW_CONTROL` updates, which
    /// arrived too slowly over the relay hop, so the transfer truncated and
    /// aborted (reproduced on the AWS box: 32–256 KiB pass byte-exact,
    /// 512 KiB+ truncate at a variable point).
    ///
    /// Fix: raise the per-stream and connection-level receive windows so a
    /// multi-MB transfer stays in flight, and allow many concurrent
    /// bidirectional streams (each ZTLP tunnel stream is a bidi stream).
    /// We keep quinn's built-in congestion control (cubic) — we do NOT
    /// hand-roll a custom CC; quinn's `congestion` trait is the supported
    /// swap point if we later want BBR.
    ///
    /// `max_idle_timeout_ms` / `keep_alive_interval_ms` are carried over from
    /// the existing v0.29.3 tuning (idle timeout / keepalive so gateway-side
    /// tunnels survive the 60 s relay-sweeper tick).
    fn apply_ztlp_transport_tuning(
        mut tc: quinn::TransportConfig,
        max_idle_timeout_ms: Option<u32>,
        keep_alive_interval_ms: Option<u32>,
    ) -> quinn::TransportConfig {
        // Throughput: generous flow-control windows.
        // Per-stream receive window: 4 MiB (lets a single large file transfer
        // stay in flight without stalling on a 64 KiB default).
        tc.stream_receive_window(quinn::VarInt::from_u32(4 * 1024 * 1024));
        // Connection-level receive window: 16 MiB (aggregate across the
        // parallel streams a browser / multi-tool load opens).
        tc.receive_window(quinn::VarInt::from_u32(16 * 1024 * 1024));
        // Allow up to 256 concurrent bidi/uni streams (initiated), so 8+
        // parallel tunnel streams never hit the stream-count cap.
        tc.max_concurrent_bidi_streams(quinn::VarInt::from_u32(256));
        tc.max_concurrent_uni_streams(quinn::VarInt::from_u32(256));

        // Windows: quinn coalesces datagrams with UDP_SEND_MSG_SIZE (USO). On
        // the test PC every coalesced send failed with WSAEMSGSIZE (10040),
        // quinn-udp logged "sendmsg error", the QUIC handshake/first flight
        // never left the box, and the browser hung until "connection error:
        // timed out". One datagram per send works everywhere.
        #[cfg(windows)]
        tc.enable_segmentation_offload(false);

        // Preserve the existing idle/keepalive tuning (v0.29.3 idiom).
        if let Some(idle_ms) = max_idle_timeout_ms {
            tc.max_idle_timeout(Some(quinn::VarInt::from_u32(idle_ms).into()));
        }
        if let Some(ka_ms) = keep_alive_interval_ms {
            tc.keep_alive_interval(Some(std::time::Duration::from_millis(ka_ms as u64)));
        }
        tc
    }

    /// [SAST fix: lqq-wjuo] TOFU (Trust On First Use) certificate
    /// verifier for the QUIC transport layer. Replaces the previous
    /// NoCertVerifier, which unconditionally accepted ANY certificate
    /// (removed entirely, not just retired dead code, to avoid it
    /// being accidentally re-wired in later).
    ///
    /// Background: the QUIC server always generates a fresh, ephemeral
    /// self-signed cert on every bind (see `generate_self_signed`
    /// below) — there is no real PKI backing these certs, which is why
    /// `NoCertVerifier` existed (there's genuinely nothing to validate
    /// against a trust anchor). Per the crate's own documented design
    /// (Cargo.toml comment: "we still pin identity via the Noise XX
    /// prologue tunneled over stream 0 ... so the X.509 layer is
    /// effectively ignored"), real ZTLP peer authentication happens via
    /// the Noise_XX handshake running INSIDE the QUIC stream, not via
    /// this TLS layer. That means `NoCertVerifier` does NOT allow a
    /// MITM to forge or decrypt the actual ZTLP session — but it DOES
    /// let a MITM transparently intercept/tamper with the outer QUIC
    /// transport (traffic analysis, connection-level DoS, metadata
    /// exposure), and ships a certificate verifier that unconditionally
    /// accepts ANY certificate, which is dangerous in isolation and
    /// exactly what CWE-295 flags.
    ///
    /// This TOFU verifier closes that gap as defense-in-depth: it
    /// computes the SHA-256 fingerprint of the leaf certificate and
    /// pins it (in `~/.ztlp/quic_pins/<sni>_<ip>_<port>.pin` after
    /// sanitization, see
    /// `pin_key_for`) on first connection to a given gateway endpoint. Every subsequent connection
    /// must present a certificate matching the pinned fingerprint or
    /// verification fails outright — same trust model as SSH host-key
    /// pinning and the rhf-phvo/sjy-yrjl iOS fixes: doesn't protect the
    /// very first connection against an active MITM, but converts a
    /// silent, repeatable MITM into a hard connection failure.
    #[derive(Debug)]
    struct TofuCertVerifier {
        server_name: String,
        /// Directory pins are stored in. Defaults to
        /// `~/.ztlp/quic_pins` via `new()`; overridable via
        /// `with_pin_dir` for tests (avoids needing to mutate $HOME,
        /// which requires `unsafe` in modern Rust and risks races in
        /// a shared test binary).
        pin_dir: std::path::PathBuf,
        /// NS-anchored trust: what the name server said about this gateway.
        /// Default = legacy TOFU behavior.
        expect: super::CertExpectation,
    }

    /// TOFU pin identity for a dial: the REMOTE ENDPOINT plus the SNI.
    ///
    /// Every ZTLP dial uses the fixed SNI "localhost" (gateways serve a
    /// self-signed "localhost" cert), so pinning on the SNI alone yielded a
    /// single global pin: the first gateway ever contacted was pinned and
    /// every other gateway was rejected as a fingerprint mismatch (found
    /// live 2026-10-05 with direct-first dialing to a second gateway).
    /// Keying on `ip:port` + SNI gives each gateway its own pin while the
    /// on-wire SNI is unchanged. `TofuCertVerifier::pin_path` sanitizes the
    /// result into one flat filename.
    pub(crate) fn pin_key_for(remote: SocketAddr, server_name: &str) -> String {
        format!("{}@{}", server_name, remote)
    }

    /// TOFU pin identity for a dial, scoped to the SERVICE when the dial goes
    /// through a relay (ZT-04).
    ///
    /// Every service behind a relay is dialed at the same `relay_ip:port`
    /// with the same SNI, but each gateway serves its own self-signed cert.
    /// Keying on the endpoint alone therefore gave every relayed service ONE
    /// shared pin: the first service a device used worked and every other
    /// one failed with "QUIC certificate fingerprint ... does not match".
    ///
    /// `relayed_service` is `Some(service)` for a relayed dial: the pin key
    /// gains a `#<service>` suffix (lowercased). It is `None` for a direct
    /// dial, which already has a unique address, so that key is byte-for-byte
    /// what `pin_key_for` returns and existing pins survive an upgrade.
    /// The result still goes through `TofuCertVerifier::pin_path`, which
    /// sanitizes it into one flat filename, so the service name cannot
    /// traverse out of the pin directory.
    pub(crate) fn pin_key_for_service(
        remote: SocketAddr,
        server_name: &str,
        relayed_service: Option<&str>,
    ) -> String {
        match relayed_service {
            Some(svc) => format!(
                "{}#{}",
                pin_key_for(remote, server_name),
                svc.trim().to_ascii_lowercase()
            ),
            None => pin_key_for(remote, server_name),
        }
    }

    /// Remove the pin file the pre-2026-10-05 per-SNI scheme wrote for
    /// `sni` (`<sanitized sni>.pin`), if present. Only that exact file:
    /// per-endpoint pins (`<sni>_<ip>_<port>.pin`), operator backups and
    /// unrelated files are untouched. Never creates the directory. Returns
    /// the number of files removed (0 or 1).
    pub(crate) fn remove_legacy_sni_pins(pin_dir: &std::path::Path, sni: &str) -> usize {
        if !pin_dir.is_dir() {
            return 0;
        }
        let legacy = TofuCertVerifier::with_pin_dir_pub(sni, pin_dir.to_path_buf()).pin_path();
        match std::fs::remove_file(&legacy) {
            Ok(()) => 1,
            Err(_) => 0,
        }
    }

    /// Remove the legacy pin for `sni` unless this process already did so,
    /// tracked per SNI in `done`. Returns the number of files removed.
    /// Split out from `cleanup_legacy_pins_once` so the bookkeeping is
    /// testable without touching the real pin directory.
    pub(crate) fn cleanup_legacy_pin_for(
        pin_dir: &std::path::Path,
        sni: &str,
        done: &std::sync::Mutex<std::collections::HashSet<String>>,
    ) -> usize {
        let first_time = match done.lock() {
            Ok(mut g) => g.insert(sni.to_string()),
            // a poisoned lock must not block dialing; skip the cleanup
            Err(_) => false,
        };
        if !first_time {
            return 0;
        }
        remove_legacy_sni_pins(pin_dir, sni)
    }

    /// Run the legacy-pin cleanup for the default pin dir once PER SNI per
    /// process (first dial with that SNI). Cheap, idempotent, logs only when
    /// it actually removed something.
    fn cleanup_legacy_pins_once(sni: &str) {
        static DONE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
            std::sync::OnceLock::new();
        let done = DONE.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
        let dir = TofuCertVerifier::default_pin_dir();
        if cleanup_legacy_pin_for(&dir, sni, done) > 0 {
            tracing::info!(
                "removed legacy per-SNI QUIC pin for '{}' from {} (pins are per gateway endpoint now)",
                sni,
                dir.display()
            );
        }
    }

    impl TofuCertVerifier {
        fn new(server_name: &str) -> Self {
            Self {
                server_name: server_name.to_string(),
                pin_dir: Self::default_pin_dir(),
                expect: super::CertExpectation::default(),
            }
        }

        fn with_expectation(server_name: &str, expect: super::CertExpectation) -> Self {
            Self {
                expect,
                ..Self::new(server_name)
            }
        }

        fn with_pin_dir_pub(server_name: &str, pin_dir: std::path::PathBuf) -> Self {
            Self {
                server_name: server_name.to_string(),
                pin_dir,
                expect: super::CertExpectation::default(),
            }
        }

        #[cfg(test)]
        fn with_pin_dir(server_name: &str, pin_dir: std::path::PathBuf) -> Self {
            Self {
                server_name: server_name.to_string(),
                pin_dir,
                expect: super::CertExpectation::default(),
            }
        }

        #[cfg(test)]
        fn with_pin_dir_and_expectation(
            server_name: &str,
            pin_dir: std::path::PathBuf,
            expect: super::CertExpectation,
        ) -> Self {
            Self {
                server_name: server_name.to_string(),
                pin_dir,
                expect,
            }
        }

        fn default_pin_dir() -> std::path::PathBuf {
            dirs::home_dir()
                .map(|h| h.join(".ztlp").join("quic_pins"))
                .unwrap_or_else(|| std::path::PathBuf::from(".ztlp/quic_pins"))
        }

        fn pin_path(&self) -> std::path::PathBuf {
            // server_name is attacker-influenced input (it's the
            // caller-supplied connect target) — sanitize before using
            // it as a filename component to avoid path traversal via a
            // crafted server_name like "../../etc/passwd".
            //
            // [caught by test_server_name_sanitized_against_path_traversal]
            // A first attempt allowed '.' through unchanged (to permit
            // normal hostnames like "gw1.example.com"), which meant
            // "../../etc/passwd" sanitized to ".._.._etc_passwd" —
            // slashes were replaced but the ".." sequences survived
            // intact, still a working traversal payload. Fixed by
            // replacing '.' with '_' too, then collapsing repeated
            // underscores — hostnames remain distinguishable
            // (sanitization only needs to prevent traversal +
            // collisions, not preserve exact readability).
            let mut safe_name = String::with_capacity(self.server_name.len());
            for c in self.server_name.chars() {
                if c.is_ascii_alphanumeric() || c == '-' {
                    safe_name.push(c);
                } else {
                    safe_name.push('_');
                }
            }
            // Collapse repeated underscores so ".." (-> "__") and similar
            // patterns can't be used to construct recognizable/colliding
            // paths, and to keep filenames readable.
            let mut collapsed = String::with_capacity(safe_name.len());
            let mut last_was_underscore = false;
            for c in safe_name.chars() {
                if c == '_' {
                    if !last_was_underscore {
                        collapsed.push(c);
                    }
                    last_was_underscore = true;
                } else {
                    collapsed.push(c);
                    last_was_underscore = false;
                }
            }
            self.pin_dir.join(format!("{}.pin", collapsed))
        }

        fn fingerprint(cert: &CertificateDer<'_>) -> String {
            cert_sha256_hex(cert.as_ref())
        }

        /// Returns Ok(()) if this is the first-ever pin for this server
        /// (now pinned) or the fingerprint matches the existing pin.
        /// Returns Err with a descriptive message if it does NOT match
        /// (the connection must be rejected).
        fn verify_or_pin(&self, cert: &CertificateDer<'_>) -> Result<(), String> {
            use super::{decide_cert, CertDecision, CertReject};
            let fingerprint = Self::fingerprint(cert);
            let path = self.pin_path();
            let pinned = std::fs::read_to_string(&path).ok();

            match decide_cert(&self.expect, &fingerprint, pinned.as_deref()) {
                CertDecision::Accept {
                    write_pin,
                    ns_backed,
                } => {
                    if ns_backed && pinned.is_some() {
                        // Task 5.5: the NS-signed fingerprint now covers this
                        // gateway; retire its TOFU pin.
                        let _ = std::fs::remove_file(&path);
                    }
                    if write_pin {
                        if let Some(parent) = path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        let _ = std::fs::write(&path, &fingerprint);
                    }
                    Ok(())
                }
                CertDecision::Reject(CertReject::NsMismatch { expected }) => Err(format!(
                    "{} gateway '{}' presented QUIC certificate {} but its name-server-signed \
                     record says {}",
                    super::NS_MISMATCH_MARKER,
                    self.server_name,
                    fingerprint,
                    expected
                )),
                CertDecision::Reject(CertReject::UnverifiedAnswer) => Err(format!(
                    "{} no verified name-server record for gateway '{}'; refusing its certificate",
                    super::UNVERIFIED_MARKER,
                    self.server_name
                )),
                CertDecision::Reject(CertReject::LegacyPinMismatch { pinned }) => Err(format!(
                    "QUIC certificate fingerprint for '{}' does not match the pinned value \
                     (expected {}, got {}). This may indicate a MITM attack, or the server's \
                     certificate was legitimately rotated (delete {} to reset the pin).",
                    self.server_name,
                    pinned,
                    fingerprint,
                    path.display()
                )),
            }
        }
    }

    impl rustls::client::danger::ServerCertVerifier for TofuCertVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            match self.verify_or_pin(end_entity) {
                Ok(()) => Ok(rustls::client::danger::ServerCertVerified::assertion()),
                Err(msg) => Err(rustls::Error::General(msg)),
            }
        }
        // CertificateVerify MUST be checked against the presented leaf. The
        // leaf cert is public (every client sees it), so the fingerprint
        // check above proves nothing by itself: without this an on-path
        // attacker presents the pinned cert, signs the handshake with its
        // own key and passes. The TLS 1.3 CertificateVerify signature is the
        // only proof the server holds the cert's private key. Noise does not
        // cover this gap on desktop clients (it is not bound to the TLS
        // channel and the gateway's static key is not checked there), so
        // this check is the gateway authentication. Chain validation is
        // still skipped on purpose: there is no PKI, trust comes from the
        // fingerprint (pin today, NS-signed record later).
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &signature_algorithms())
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &signature_algorithms())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            signature_algorithms().supported_schemes()
        }
    }

    /// Signature algorithms of the process crypto provider (ring, installed
    /// by [`ensure_crypto`]). Used to verify the server's CertificateVerify.
    fn signature_algorithms() -> rustls::crypto::WebPkiSupportedAlgorithms {
        ensure_crypto();
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms)
            .unwrap_or_else(|| {
                rustls::crypto::ring::default_provider().signature_verification_algorithms
            })
    }

    fn generate_self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        // ZT-06: reuse the cert persisted in `ZTLP_QUIC_CERT_DIR` when the
        // operator mounted one (containers: a volume), else a fresh ephemeral
        // cert exactly as before.
        let dir = quic_cert_dir_from_env();
        let (certs, key) = match &dir {
            Some(dir) => load_or_generate_self_signed_in(dir),
            None => generate_ephemeral_self_signed(),
        };
        publish_server_cert(&certs, dir.as_deref());
        (certs, key)
    }

    /// Lowercase hex SHA-256 of a DER certificate: the value clients pin and
    /// the value a gateway publishes as `quic_cert_sha256` in its SVC record.
    pub fn cert_sha256_hex(der: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(der))
    }

    static PUBLISHED_CERT_SHA256: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

    /// Fingerprint of the cert the QUIC server of this process last bound
    /// (NS-anchored trust, task 3.4). `ztlp listen` publishes it in its SVC
    /// record so clients can check the gateway cert against an NS-signed
    /// value. `None` until a server endpoint is bound.
    pub fn published_server_cert_sha256() -> Option<String> {
        PUBLISHED_CERT_SHA256.read().ok().and_then(|g| g.clone())
    }

    fn publish_server_cert(certs: &[CertificateDer<'static>], dir: Option<&std::path::Path>) {
        let Some(leaf) = certs.first() else { return };
        let fp = cert_sha256_hex(leaf.as_ref());
        match dir {
            Some(d) => tracing::info!("QUIC cert sha256={} persisted={}", fp, d.display()),
            None => tracing::warn!(
                "QUIC cert sha256={} persisted=ephemeral (set ZTLP_QUIC_CERT_DIR so the cert survives restarts)",
                fp
            ),
        }
        if let Ok(mut g) = PUBLISHED_CERT_SHA256.write() {
            *g = Some(fp);
        }
    }

    fn generate_ephemeral_self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (
            vec![cert.cert.into()],
            PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
        )
    }

    /// Directory holding the gateway's persisted QUIC identity (ZT-06), from
    /// `ZTLP_QUIC_CERT_DIR`. Unset/blank means "no persistence": a fresh cert
    /// per bind, the historical behaviour.
    ///
    /// Why: clients pin the gateway's self-signed cert on first use (TOFU).
    /// A fresh cert on every process start meant every container recreate or
    /// restart invalidated every client's pin, and each affected device had to
    /// clear its pin by hand before the site would load again.
    fn quic_cert_dir_from_env() -> Option<std::path::PathBuf> {
        parse_cert_dir(std::env::var("ZTLP_QUIC_CERT_DIR").ok().as_deref())
    }

    fn parse_cert_dir(v: Option<&str>) -> Option<std::path::PathBuf> {
        let v = v?.trim();
        if v.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(v))
        }
    }

    const QUIC_CERT_FILE: &str = "quic-cert.der";
    const QUIC_KEY_FILE: &str = "quic-key.der";

    /// Load the persisted self-signed cert + key from `dir`, creating and
    /// saving them on first use. Never fatal: if the directory is unusable the
    /// caller still gets a working (ephemeral) cert, and a corrupt or
    /// half-written pair is regenerated rather than crashing the gateway.
    fn load_or_generate_self_signed_in(
        dir: &std::path::Path,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        // ServerConfig::builder() below needs a process crypto provider.
        ensure_crypto();
        let cert_path = dir.join(QUIC_CERT_FILE);
        let key_path = dir.join(QUIC_KEY_FILE);

        if let (Ok(cert_der), Ok(key_der)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) {
            if !cert_der.is_empty() && !key_der.is_empty() {
                let key = PrivateKeyDer::Pkcs8(key_der.into());
                let cert = CertificateDer::from(cert_der);
                // Refuse a pair rustls cannot actually serve (corrupt file).
                if rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert.clone()], key.clone_key())
                    .is_ok()
                {
                    return (vec![cert], key);
                }
                tracing::warn!(
                    "persisted QUIC cert in {} is unusable; generating a new one",
                    dir.display()
                );
            }
        }

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der: CertificateDer<'static> = cert.cert.into();
        let key_der = cert.key_pair.serialize_der();

        if let Err(e) = persist_quic_identity(dir, cert_der.as_ref(), &key_der) {
            tracing::warn!(
                "could not persist the QUIC cert to {} ({e}); clients will have to re-pin after a restart",
                dir.display()
            );
        } else {
            tracing::info!(
                "generated and saved a persistent QUIC cert in {}",
                dir.display()
            );
        }
        (vec![cert_der], PrivateKeyDer::Pkcs8(key_der.into()))
    }

    fn persist_quic_identity(
        dir: &std::path::Path,
        cert_der: &[u8],
        key_der: &[u8],
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        // Write to a temp name then rename, so a crash mid-write can never
        // leave a cert without its key (or vice versa).
        for (name, bytes) in [(QUIC_KEY_FILE, key_der), (QUIC_CERT_FILE, cert_der)] {
            let tmp = dir.join(format!("{name}.tmp"));
            std::fs::write(&tmp, bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if name == QUIC_KEY_FILE {
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
                }
            }
            std::fs::rename(&tmp, dir.join(name))?;
        }
        Ok(())
    }

    #[derive(Debug, Clone)]
    pub struct QuicConnection {
        pub inner: quinn::Connection,
    }

    impl QuicConnection {
        pub async fn open_bi(
            &self,
        ) -> Result<(quinn::SendStream, quinn::RecvStream), QuicTransportError> {
            Ok(self.inner.open_bi().await?)
        }

        pub async fn accept_bi(
            &self,
        ) -> Result<(quinn::SendStream, quinn::RecvStream), QuicTransportError> {
            Ok(self.inner.accept_bi().await?)
        }

        pub fn close(&self) {
            self.inner.close(0u32.into(), b"closed");
        }
    }

    /// `quinn::Endpoint::client(addr)` equivalent that installs
    /// [`super::client_endpoint_config`] (relay-routable CIDs).
    fn client_endpoint_bind(bind_addr: SocketAddr) -> Result<quinn::Endpoint, QuicTransportError> {
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        Ok(quinn::Endpoint::new(
            super::client_endpoint_config(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?)
    }

    #[derive(Debug)]
    pub struct QuicEndpoint {
        pub _cfg: QuicEndpointConfig,
        pub inner: quinn::Endpoint,
    }

    impl QuicEndpoint {
        pub async fn bind(cfg: QuicEndpointConfig) -> Result<Self, QuicTransportError> {
            let bind_addr = cfg.bind.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            let std_socket = std::net::UdpSocket::bind(bind_addr)?;
            Self::bind_with_socket(cfg, std_socket)
        }

        /// Bind a QUIC server using a caller-supplied `std::net::UdpSocket`.
        ///
        /// This lets the caller pre-bind the socket so it can do things on
        /// the underlying datagram socket (e.g. send a non-QUIC
        /// GATEWAY_REGISTER packet to a ZTLP relay) *before* handing
        /// ownership to Quinn. Pair with `try_clone()` on the original
        /// `std::net::UdpSocket` if you need to keep using the socket
        /// afterwards (the kernel socket is shared between both fds, so
        /// outbound packets all originate from the same `(ip, port)` —
        /// which is exactly what the relay's GATEWAY_REGISTER address
        /// mapping needs to match the gateway's QUIC listener).
        ///
        /// The supplied socket is automatically put into non-blocking mode
        /// for Quinn's tokio runtime.
        pub fn bind_with_socket(
            cfg: QuicEndpointConfig,
            std_socket: std::net::UdpSocket,
        ) -> Result<Self, QuicTransportError> {
            ensure_crypto();
            let (certs, key) = generate_self_signed();
            let mut server_crypto = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| {
                    QuicTransportError::Endpoint(std::io::Error::new(std::io::ErrorKind::Other, e))
                })?;

            server_crypto.alpn_protocols = cfg.alpn.clone();
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
            ));

            // v0.29.3: apply the idle-timeout / keepalive transport tuning so
            // gateway-side tunnels survive a 60s relay-sweeper tick and don't
            // get torn down by Quinn defaults under the relay's added RTT.
            // See QuicEndpointConfig field docs.
            let mut transport_config = apply_ztlp_transport_tuning(
                quinn::TransportConfig::default(),
                cfg.max_idle_timeout_ms,
                cfg.keep_alive_interval_ms,
            );
            server_config.transport_config(Arc::new(transport_config));

            // Quinn requires the socket be non-blocking for the tokio runtime.
            std_socket.set_nonblocking(true)?;

            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                std_socket,
                Arc::new(quinn::TokioRuntime),
            )?;

            Ok(Self {
                _cfg: cfg,
                inner: endpoint,
            })
        }

        /// Variant of `bind_with_socket` that accepts a custom
        /// [`quinn::Runtime`] instead of the default `TokioRuntime`.
        ///
        /// Used by `ztlp listen --punch` to install a
        /// [`crate::punch_socket::PunchRuntime`] that intercepts
        /// hole-punch protocol bytes before Quinn sees them. The
        /// runtime's `wrap_udp_socket` is called by quinn with the
        /// provided std socket, producing the AsyncUdpSocket that
        /// powers the endpoint.
        pub fn bind_with_socket_and_runtime(
            cfg: QuicEndpointConfig,
            std_socket: std::net::UdpSocket,
            runtime: Arc<dyn quinn::Runtime>,
        ) -> Result<Self, QuicTransportError> {
            ensure_crypto();
            let (certs, key) = generate_self_signed();
            let mut server_crypto = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| QuicTransportError::Endpoint(std::io::Error::other(e)))?;

            server_crypto.alpn_protocols = cfg.alpn.clone();
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
            ));

            let transport_config = apply_ztlp_transport_tuning(
                quinn::TransportConfig::default(),
                cfg.max_idle_timeout_ms,
                cfg.keep_alive_interval_ms,
            );
            server_config.transport_config(Arc::new(transport_config));

            std_socket.set_nonblocking(true)?;

            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                std_socket,
                runtime,
            )?;

            Ok(Self {
                _cfg: cfg,
                inner: endpoint,
            })
        }

        pub async fn connect_with_socket(
            cfg: QuicEndpointConfig,
            remote: SocketAddr,
            server_name: &str,
            std_socket: std::net::UdpSocket,
        ) -> Result<QuicConnection, QuicTransportError> {
            Self::connect_with_socket_for_service(
                cfg,
                remote,
                server_name,
                std_socket,
                None,
                super::CertExpectation::default(),
            )
            .await
        }

        /// Same as [`Self::connect_with_socket`], but a RELAYED dial passes
        /// `relayed_service = Some(service)` so the TOFU pin is scoped to that
        /// service instead of being shared by every service behind the relay
        /// (ZT-04, see [`pin_key_for_service`]). Direct dials pass `None`.
        pub async fn connect_with_socket_for_service(
            cfg: QuicEndpointConfig,
            remote: SocketAddr,
            server_name: &str,
            std_socket: std::net::UdpSocket,
            relayed_service: Option<&str>,
            expect: super::CertExpectation,
        ) -> Result<QuicConnection, QuicTransportError> {
            ensure_crypto();
            cleanup_legacy_pins_once(server_name);
            let mut client_crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TofuCertVerifier::with_expectation(
                    &pin_key_for_service(remote, server_name, relayed_service),
                    expect,
                )))
                .with_no_client_auth();

            client_crypto.alpn_protocols = cfg.alpn.clone();
            let mut client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
            ));

            // v0.29.3: matching transport tuning for the client side. See
            // QuicEndpointConfig field docs for rationale.
            let transport_config = apply_ztlp_transport_tuning(
                quinn::TransportConfig::default(),
                cfg.max_idle_timeout_ms,
                cfg.keep_alive_interval_ms,
            );
            client_config.transport_config(Arc::new(transport_config));

            std_socket.set_nonblocking(true)?;
            let mut endpoint = quinn::Endpoint::new(
                // Relay-routable CIDs: see RelayRoutableCidGenerator.
                super::client_endpoint_config(),
                None,
                std_socket,
                Arc::new(quinn::TokioRuntime),
            )?;
            endpoint.set_default_client_config(client_config);

            let conn = endpoint.connect(remote, server_name)?.await?;
            Ok(QuicConnection { inner: conn })
        }

        pub async fn connect(
            cfg: QuicEndpointConfig,
            remote: SocketAddr,
            server_name: &str,
        ) -> Result<QuicConnection, QuicTransportError> {
            ensure_crypto();
            cleanup_legacy_pins_once(server_name);
            let mut client_crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TofuCertVerifier::new(&pin_key_for(
                    remote,
                    server_name,
                ))))
                .with_no_client_auth();

            client_crypto.alpn_protocols = cfg.alpn.clone();
            let mut client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
            ));

            // v0.29.3: matching transport tuning for the OS-socket-managed
            // client path.
            let transport_config = apply_ztlp_transport_tuning(
                quinn::TransportConfig::default(),
                cfg.max_idle_timeout_ms,
                cfg.keep_alive_interval_ms,
            );
            client_config.transport_config(Arc::new(transport_config));

            let bind_addr = cfg.bind.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            let mut endpoint = client_endpoint_bind(bind_addr)?;
            endpoint.set_default_client_config(client_config);

            let conn = endpoint.connect(remote, server_name)?.await?;
            Ok(QuicConnection { inner: conn })
        }

        pub async fn accept(&self) -> Result<QuicConnection, QuicTransportError> {
            let incoming = self.inner.accept().await.ok_or_else(|| {
                QuicTransportError::Endpoint(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "endpoint closed",
                ))
            })?;
            Ok(QuicConnection {
                inner: incoming.await?,
            })
        }
    }

    /// Persistent QUIC **client** endpoint.
    ///
    /// Root-cause fix for the reconnect-churn instability (feature/
    /// quic-churn-stability, 2026-08-18 AWS `ztlp-test` validation):
    ///
    /// [`QuicEndpoint::connect`] / [`QuicEndpoint::connect_with_socket`]
    /// each create a *brand-new* `quinn::Endpoint` (a fresh UDP socket +
    /// a fresh driver task + a fresh connection-ID space) for every single
    /// connection. Quinn's `Endpoint` is designed to be **long-lived and
    /// host many connections** on one socket/driver — creating one per
    /// connection is both wasteful and the source of churn instability:
    /// under rapid reconnects (the `ztlp-client` benchmark opens a fresh
    /// tunnel per transfer size, and the auto-reconnect supervisor
    /// re-establishes the tunnel on every disconnect) the rapid
    /// socket-bind / driver-spawn / CID-space churn produces
    /// non-deterministic failures observed live on the AWS box —
    /// `discarding possible duplicate packet`, `failed to authenticate
    /// packet`, and `connect` timeouts on the 2nd+ rapid reconnect.
    ///
    /// This type owns ONE persistent `quinn::Endpoint` and opens many
    /// [`QuicConnection`]s on it via [`connect_peer`](Self::connect_peer).
    /// The socket, driver task, and CID space are stable across reconnects,
    /// so reconnect churn no longer tears down and rebuilds the transport.
    ///
    /// `Clone` is shallow: `quinn::Endpoint` is internally `Arc`-backed, so
    /// cloning shares the SAME underlying socket/driver/CID space — the
    /// clone is another handle to the one persistent endpoint (useful for
    /// concurrent reconnect tasks sharing the endpoint).
    #[derive(Debug, Clone)]
    pub struct QuicClientEndpoint {
        cfg: QuicEndpointConfig,
        inner: quinn::Endpoint,
        bind_addr: SocketAddr,
    }

    impl QuicClientEndpoint {
        /// Create a persistent client endpoint on an ephemeral loopback /
        /// wildcard bind (matching [`QuicEndpoint::connect`]'s bind
        /// behavior). Reuse this endpoint for the lifetime of the session;
        /// every reconnect calls [`connect_peer`](Self::connect_peer) on
        /// the SAME endpoint instead of rebuilding it.
        pub async fn new(cfg: QuicEndpointConfig) -> Result<Self, QuicTransportError> {
            ensure_crypto();
            let bind_addr = cfg.bind.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            let endpoint = client_endpoint_bind(bind_addr)?;
            let actual = endpoint.local_addr()?;
            Self::from_endpoint(cfg, endpoint, actual)
                .await
                .map(|mut e| {
                    e.bind_addr = actual;
                    e
                })
        }

        /// Create a persistent client endpoint over a caller-supplied UDP
        /// socket (matching [`QuicEndpoint::connect_with_socket`]). Use this
        /// when the caller needs to send non-QUIC bytes (relay
        /// `GATEWAY_REGISTER`) on the same socket before connecting.
        pub async fn new_with_socket(
            cfg: QuicEndpointConfig,
            std_socket: std::net::UdpSocket,
        ) -> Result<Self, QuicTransportError> {
            ensure_crypto();
            let bind_addr = std_socket.local_addr()?;
            std_socket.set_nonblocking(true)?;
            let endpoint = quinn::Endpoint::new(
                // Relay-routable CIDs: see RelayRoutableCidGenerator.
                super::client_endpoint_config(),
                None,
                std_socket,
                Arc::new(quinn::TokioRuntime),
            )?;
            Self::from_endpoint(cfg, endpoint, bind_addr).await
        }

        /// Shared setup: install the default client config (TOFU verifier +
        /// ZTLP transport tuning) on the given endpoint.
        async fn from_endpoint(
            cfg: QuicEndpointConfig,
            mut endpoint: quinn::Endpoint,
            bind_addr: SocketAddr,
        ) -> Result<Self, QuicTransportError> {
            // A fresh TOFU verifier per *endpoint* (not per connection) is
            // correct: the verifier pins the first server cert it sees for a
            // given server_name and enforces it thereafter. A persistent
            // endpoint keeps the pin across its connections, which is the
            // desired behavior (a MITM swapping the server cert mid-session
            // is rejected on the *next* connection on the same endpoint).
            //
            // The pin is keyed by a per-endpoint unique name (pid + clock) so
            // it never collides across runs / multiple persistent endpoints
            // (e.g. in tests, where a fresh server generates a fresh ephemeral
            // cert each run). The pin *value* is still enforced consistently
            // for the endpoint's lifetime.
            let pin_key = format!(
                "ztlp-persistent-client-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            );
            let mut client_crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TofuCertVerifier::new(&pin_key)))
                .with_no_client_auth();
            client_crypto.alpn_protocols = cfg.alpn.clone();
            let mut client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
            ));
            let transport_config = apply_ztlp_transport_tuning(
                quinn::TransportConfig::default(),
                cfg.max_idle_timeout_ms,
                cfg.keep_alive_interval_ms,
            );
            client_config.transport_config(Arc::new(transport_config));
            endpoint.set_default_client_config(client_config);
            Ok(Self {
                cfg,
                inner: endpoint,
                bind_addr,
            })
        }

        /// Open a NEW connection to `remote` on this persistent endpoint.
        ///
        /// This is the reconnect path: reuse the same socket / driver /
        /// CID space, only the connection is new. `server_name` is the
        /// ALPN / SNI name (ZTLP uses "localhost" for the inner Noise
        /// handshake; the real peer identity is established by the
        /// Noise_XX prologue over stream 0, not by this TLS layer).
        pub async fn connect_peer(
            &self,
            remote: SocketAddr,
            server_name: &str,
        ) -> Result<QuicConnection, QuicTransportError> {
            let conn = self.inner.connect(remote, server_name)?.await?;
            Ok(QuicConnection { inner: conn })
        }

        /// The local (ip, port) this endpoint is bound to. The relay's
        /// `GATEWAY_REGISTER` 5-tuple mapping and the NS `CLIENT_ROUTE`
        /// both key off the client's source address — callers must use
        /// THIS address (not a freshly-bound one) so the mapping stays
        /// consistent across reconnects on the same endpoint.
        pub fn local_addr(&self) -> Result<SocketAddr, QuicTransportError> {
            Ok(self.bind_addr)
        }

        /// The local (ip, port) from the live socket (authoritative —
        /// reflects the kernel-bound port after an ephemeral `:0` bind).
        pub fn actual_local_addr(&self) -> Result<SocketAddr, QuicTransportError> {
            Ok(self.inner.local_addr()?)
        }
    }

    #[cfg(test)]
    mod tofu_tests {
        use super::*;
        use rustls::client::danger::ServerCertVerifier;

        fn fake_cert(seed: u8) -> CertificateDer<'static> {
            // Not a real X.509 cert — TofuCertVerifier only hashes the
            // raw bytes, it never parses the cert structure (that's
            // the whole point: no PKI, just fingerprint pinning).
            CertificateDer::from(vec![seed; 64])
        }

        fn fixed_now() -> rustls::pki_types::UnixTime {
            rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(0))
        }

        fn fake_server_name() -> rustls::pki_types::ServerName<'static> {
            rustls::pki_types::ServerName::try_from("test.ztlp.local").unwrap()
        }

        #[test]
        fn test_first_connection_pins_and_accepts() {
            let tmp = tempfile_dir();
            let verifier = TofuCertVerifier::with_pin_dir("gw1.example.com", tmp.clone());
            let cert = fake_cert(0xAA);

            let result =
                verifier.verify_server_cert(&cert, &[], &fake_server_name(), &[], fixed_now());
            assert!(
                result.is_ok(),
                "first connection should be accepted and pinned"
            );

            // A pin file should now exist.
            let pin_path = verifier.pin_path();
            assert!(pin_path.exists(), "pin file should have been created");

            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn test_matching_cert_accepted_on_second_connection() {
            let tmp = tempfile_dir();
            let verifier = TofuCertVerifier::with_pin_dir("gw2.example.com", tmp.clone());
            let cert = fake_cert(0xBB);

            // First connection pins it.
            assert!(verifier
                .verify_server_cert(&cert, &[], &fake_server_name(), &[], fixed_now())
                .is_ok());

            // Second connection with the SAME cert must also succeed.
            let result =
                verifier.verify_server_cert(&cert, &[], &fake_server_name(), &[], fixed_now());
            assert!(
                result.is_ok(),
                "matching cert on 2nd connection should be accepted"
            );

            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn test_mismatched_cert_rejected_mitm_scenario() {
            let tmp = tempfile_dir();
            let verifier = TofuCertVerifier::with_pin_dir("gw3.example.com", tmp.clone());
            let real_cert = fake_cert(0xCC);
            let mitm_cert = fake_cert(0xDD); // different bytes = different fingerprint

            // First connection pins the REAL cert.
            assert!(verifier
                .verify_server_cert(&real_cert, &[], &fake_server_name(), &[], fixed_now())
                .is_ok());

            // A MITM presenting a DIFFERENT cert on a later connection
            // (attempt to the same server_name) must be REJECTED — this
            // is the exact scenario lqq-wjuo's NoCertVerifier failed to
            // stop.
            let result =
                verifier.verify_server_cert(&mitm_cert, &[], &fake_server_name(), &[], fixed_now());
            assert!(
                result.is_err(),
                "MITM presenting a different cert MUST be rejected, not silently accepted"
            );

            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn test_different_server_names_have_independent_pins() {
            let tmp = tempfile_dir();
            let verifier_a = TofuCertVerifier::with_pin_dir("host-a.example.com", tmp.clone());
            let verifier_b = TofuCertVerifier::with_pin_dir("host-b.example.com", tmp.clone());
            let cert_a = fake_cert(0x11);
            let cert_b = fake_cert(0x22);

            assert!(verifier_a
                .verify_server_cert(&cert_a, &[], &fake_server_name(), &[], fixed_now())
                .is_ok());
            assert!(verifier_b
                .verify_server_cert(&cert_b, &[], &fake_server_name(), &[], fixed_now())
                .is_ok());

            // host-a's pinned cert should NOT satisfy host-b's pin and
            // vice versa (independent files).
            assert_ne!(verifier_a.pin_path(), verifier_b.pin_path());

            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn test_server_name_sanitized_against_path_traversal() {
            let tmp = tempfile_dir();
            // A malicious/crafted server_name attempting path traversal.
            let verifier = TofuCertVerifier::with_pin_dir("../../etc/passwd", tmp.clone());
            let path = verifier.pin_path();

            // The resulting path must stay INSIDE tmp — no ".." components
            // should survive sanitization.
            assert!(
                path.starts_with(&tmp),
                "sanitized pin path must stay within the pin directory, got: {}",
                path.display()
            );
            assert!(
                !path.to_string_lossy().contains(".."),
                "sanitized pin path must not contain '..' components"
            );

            let _ = std::fs::remove_dir_all(&tmp);
        }

        // ── ZT-06: gateway cert survives a restart (2026-10-09) ────────────
        //
        // The gateway generated a fresh self-signed cert on every bind, so a
        // container recreate invalidated every client's TOFU pin and each
        // device had to clear a pin file by hand. With ZTLP_QUIC_CERT_DIR set
        // (a mounted volume) the same cert is reused.
        #[test]
        fn persisted_quic_cert_is_reused_across_binds() {
            let dir = tempfile_dir();
            let (c1, _k1) = load_or_generate_self_signed_in(&dir);
            let (c2, _k2) = load_or_generate_self_signed_in(&dir);
            assert_eq!(
                c1[0].as_ref(),
                c2[0].as_ref(),
                "second bind must serve the SAME cert so client pins stay valid"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn without_a_cert_dir_each_bind_still_gets_a_fresh_cert() {
            // historical behaviour must be unchanged when nothing is mounted
            let a = generate_ephemeral_self_signed();
            let b = generate_ephemeral_self_signed();
            assert_ne!(a.0[0].as_ref(), b.0[0].as_ref());
        }

        #[test]
        fn persisted_cert_files_are_written_and_the_key_is_private() {
            let dir = tempfile_dir();
            let _ = load_or_generate_self_signed_in(&dir);
            assert!(dir.join(QUIC_CERT_FILE).is_file());
            assert!(dir.join(QUIC_KEY_FILE).is_file());
            assert!(
                !dir.join(format!("{QUIC_CERT_FILE}.tmp")).exists()
                    && !dir.join(format!("{QUIC_KEY_FILE}.tmp")).exists(),
                "no temp files left behind"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(dir.join(QUIC_KEY_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "private key must not be group/world readable");
            }
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn corrupt_persisted_cert_is_regenerated_not_fatal() {
            let dir = tempfile_dir();
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(QUIC_CERT_FILE), b"not a certificate").unwrap();
            std::fs::write(dir.join(QUIC_KEY_FILE), b"not a key").unwrap();
            let (certs, key) = load_or_generate_self_signed_in(&dir);
            // must be a pair rustls can actually serve
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs.clone(), key)
                .expect("regenerated pair must be usable");
            // and it replaced the garbage, so the NEXT bind is stable again
            let (again, _) = load_or_generate_self_signed_in(&dir);
            assert_eq!(certs[0].as_ref(), again[0].as_ref());
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn unwritable_cert_dir_falls_back_to_a_working_cert() {
            // a path under a regular FILE cannot be created as a directory
            let base = tempfile_dir();
            std::fs::create_dir_all(&base).unwrap();
            let blocker = base.join("blocker");
            std::fs::write(&blocker, b"x").unwrap();
            let (certs, key) = load_or_generate_self_signed_in(&blocker.join("sub"));
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("must still serve a cert when persistence fails");
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn blank_cert_dir_env_means_no_persistence() {
            // exercised through the parser, not the process environment
            // (mutating env in a shared test binary races other tests)
            assert_eq!(parse_cert_dir(None), None);
            assert_eq!(parse_cert_dir(Some("")), None);
            assert_eq!(parse_cert_dir(Some("   ")), None);
            assert_eq!(
                parse_cert_dir(Some(" /data/quic ")),
                Some(std::path::PathBuf::from("/data/quic"))
            );
        }

        // ── ZT-04: relayed dials must pin per SERVICE (2026-10-09) ──────────
        //
        // Every service reached through the relay is dialed at the SAME
        // `relay_ip:23095` with the SNI "localhost", so `pin_key_for` gave
        // the admin gateway and the ChooseForce gateway ONE shared pin. Each
        // has its own self-signed cert, so whichever service a device used
        // first worked and every other relayed service failed with
        // "QUIC certificate fingerprint ... does not match the pinned value".
        // A relayed dial's pin identity therefore includes the service name.
        #[test]
        fn relay_pin_key_is_per_service() {
            let relay: SocketAddr = "198.51.100.7:23095".parse().unwrap();
            let admin = pin_key_for_service(relay, "localhost", Some("admin"));
            let www = pin_key_for_service(relay, "localhost", Some("www"));
            assert_ne!(
                admin, www,
                "two services behind one relay must not share a TOFU pin"
            );
            assert_eq!(
                admin,
                pin_key_for_service(relay, "localhost", Some("admin")),
                "stable for the same service"
            );
        }

        #[test]
        fn direct_pin_key_is_unchanged_so_upgrade_does_not_churn_pins() {
            let gw: SocketAddr = "10.20.30.40:23097".parse().unwrap();
            assert_eq!(
                pin_key_for_service(gw, "localhost", None),
                pin_key_for(gw, "localhost"),
                "a direct dial has its own address, so its key must not change"
            );
        }

        #[test]
        fn relay_pin_key_differs_from_the_unscoped_relay_key() {
            let relay: SocketAddr = "198.51.100.7:23095".parse().unwrap();
            assert_ne!(
                pin_key_for_service(relay, "localhost", Some("admin")),
                pin_key_for(relay, "localhost"),
                "the old shared key must not be reused: it may hold another service's cert"
            );
        }

        #[test]
        fn relay_pin_key_service_is_case_insensitive_and_cannot_escape_the_pin_dir() {
            let relay: SocketAddr = "198.51.100.7:23095".parse().unwrap();
            assert_eq!(
                pin_key_for_service(relay, "localhost", Some("WWW")),
                pin_key_for_service(relay, "localhost", Some("www"))
            );
            // the key becomes a filename: a hostile service name must stay inside it
            let tmp = tempfile_dir();
            let v = TofuCertVerifier::with_pin_dir(
                &pin_key_for_service(relay, "localhost", Some("../../etc/passwd")),
                tmp.clone(),
            );
            let p = v.pin_path();
            assert_eq!(p.parent().unwrap(), tmp.as_path(), "{p:?}");
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            assert!(
                !name.contains('/') && !name.contains('\\') && !name.contains(".."),
                "{name}"
            );
            let _ = std::fs::remove_dir_all(&tmp);
        }

        // ── Pin per GATEWAY ENDPOINT, not per SNI string (2026-10-05) ──────
        //
        // Every agent/CLI dial passes the fixed SNI "localhost" (gateways
        // serve a self-signed "localhost" cert). Keying the TOFU pin on the
        // SNI therefore produced ONE global pin: the first gateway ever
        // contacted was pinned and every other gateway was rejected as a
        // "fingerprint mismatch" (MITM-shaped failure). Found live with
        // direct-first dialing: the AI computer had the demo gateway pinned
        // under `localhost.pin`, so the ChooseForce gateway's direct dial
        // failed in 10 ms and fell back to the relay. `pin_key_for` derives
        // the pin identity from the dialed endpoint instead, so each
        // gateway gets its own TOFU pin while the wire SNI is unchanged.
        #[test]
        fn pin_key_is_per_remote_endpoint_not_per_sni() {
            let a: SocketAddr = "10.20.30.40:23097".parse().unwrap();
            let b: SocketAddr = "198.51.100.7:23095".parse().unwrap();
            let ka = pin_key_for(a, "localhost");
            let kb = pin_key_for(b, "localhost");
            assert_ne!(
                ka, kb,
                "two gateways behind the same SNI must not share a pin"
            );
            // stable for the same endpoint
            assert_eq!(ka, pin_key_for(a, "localhost"));
            // the SNI still participates (same ip:port, different SNI → different pin)
            assert_ne!(ka, pin_key_for(a, "gw.example"));
        }

        #[test]
        fn pin_key_sanitizes_into_a_single_safe_filename() {
            let tmp = tempfile_dir();
            let v6: SocketAddr = "[fe80::1]:23097".parse().unwrap();
            let key = pin_key_for(v6, "localhost");
            let verifier = TofuCertVerifier::with_pin_dir(&key, tmp.clone());
            let path = verifier.pin_path();
            assert!(path.starts_with(&tmp));
            assert_eq!(
                path.parent().unwrap(),
                tmp.as_path(),
                "no nested dirs from ':' or '[]'"
            );
            let _ = std::fs::remove_dir_all(&tmp);
        }

        // ── Legacy per-SNI pin cleanup (2026-10-05) ────────────────────────
        //
        // Installs that ran the per-SNI pinning left `<sni>.pin` files
        // (in practice one: `localhost.pin`). The new key never reads
        // them, so they are dead weight and, worse, misleading to anyone
        // debugging a pin problem. `remove_legacy_sni_pins` deletes exactly
        // the files the OLD scheme would have produced for `sni` and
        // nothing else: per-endpoint pins, backups and foreign files stay.
        #[test]
        fn legacy_cleanup_removes_only_the_old_sni_pin() {
            let tmp = tempfile_dir();
            std::fs::create_dir_all(&tmp).unwrap();
            let legacy = tmp.join("localhost.pin");
            let modern = tmp.join("localhost_10_20_30_40_23097.pin");
            let backup = tmp.join("localhost.pin.bak-demo");
            let other = tmp.join("gw_example.pin");
            for f in [&legacy, &modern, &backup, &other] {
                std::fs::write(f, "ab").unwrap();
            }
            let removed = remove_legacy_sni_pins(&tmp, "localhost");
            assert_eq!(removed, 1);
            assert!(!legacy.exists(), "legacy per-SNI pin must go");
            assert!(modern.exists(), "per-endpoint pin must stay");
            assert!(backup.exists(), "operator backups must stay");
            assert!(other.exists(), "unrelated pins must stay");
            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn legacy_cleanup_is_a_noop_when_nothing_to_remove() {
            let tmp = tempfile_dir();
            // dir does not exist yet: must not panic or create it
            assert_eq!(remove_legacy_sni_pins(&tmp, "localhost"), 0);
            assert!(!tmp.exists());
            std::fs::create_dir_all(&tmp).unwrap();
            assert_eq!(remove_legacy_sni_pins(&tmp, "localhost"), 0);
            let _ = std::fs::remove_dir_all(&tmp);
        }

        // CodeRabbit (PR #117): a single process-wide `Once` cleaned only the
        // FIRST SNI it saw; a later dial with a different SNI never got its
        // legacy pin removed. Track completion per SNI instead.
        #[test]
        fn legacy_cleanup_is_tracked_per_sni_not_once_per_process() {
            let tmp = tempfile_dir();
            std::fs::create_dir_all(&tmp).unwrap();
            let done = std::sync::Mutex::new(std::collections::HashSet::<String>::new());
            std::fs::write(tmp.join("localhost.pin"), "ab").unwrap();
            std::fs::write(tmp.join("gw-example.pin"), "cd").unwrap();

            // first SNI cleaned
            assert_eq!(cleanup_legacy_pin_for(&tmp, "localhost", &done), 1);
            // a DIFFERENT sni is still cleaned afterwards (the old Once skipped it)
            assert_eq!(cleanup_legacy_pin_for(&tmp, "gw-example", &done), 1);
            assert!(!tmp.join("localhost.pin").exists());
            assert!(!tmp.join("gw-example.pin").exists());
            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn legacy_cleanup_for_the_same_sni_runs_once() {
            let tmp = tempfile_dir();
            std::fs::create_dir_all(&tmp).unwrap();
            let done = std::sync::Mutex::new(std::collections::HashSet::<String>::new());
            std::fs::write(tmp.join("localhost.pin"), "ab").unwrap();
            assert_eq!(cleanup_legacy_pin_for(&tmp, "localhost", &done), 1);
            // a legacy file reappearing later in the same process is NOT touched
            // again (idempotent, no repeated filesystem work on the hot path)
            std::fs::write(tmp.join("localhost.pin"), "ab").unwrap();
            assert_eq!(cleanup_legacy_pin_for(&tmp, "localhost", &done), 0);
            assert!(tmp.join("localhost.pin").exists());
            let _ = std::fs::remove_dir_all(&tmp);
        }

        // ── Phase 1 (NS-anchored trust plan): the TLS CertificateVerify
        // signature must really be checked. Without it the pin proves
        // nothing: the cert is public, so a MITM can present the pinned
        // cert and sign the handshake with its own key.

        /// Sign `msg` with an rcgen key pair through the installed rustls
        /// provider (same code path a real QUIC server uses for
        /// CertificateVerify). Returns the scheme and signature bytes.
        fn sign_with(kp: &rcgen::KeyPair, msg: &[u8]) -> (rustls::SignatureScheme, Vec<u8>) {
            ensure_crypto();
            let provider = rustls::crypto::CryptoProvider::get_default().unwrap();
            let key = PrivateKeyDer::Pkcs8(kp.serialize_der().into());
            let signing_key = provider.key_provider.load_private_key(key).unwrap();
            let signer = signing_key
                .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
                .expect("rcgen default key is ECDSA P-256");
            (signer.scheme(), signer.sign(msg).unwrap())
        }

        /// rustls keeps `DigitallySignedStruct::new` crate-private; build one
        /// from its TLS wire form (scheme u16 | len u16 | sig), exactly as a
        /// CertificateVerify message arrives off the network.
        fn dss_from(
            scheme: rustls::SignatureScheme,
            sig: Vec<u8>,
        ) -> rustls::DigitallySignedStruct {
            use rustls::internal::msgs::codec::Codec;
            let mut wire = Vec::with_capacity(4 + sig.len());
            wire.extend_from_slice(&u16::from(scheme).to_be_bytes());
            wire.extend_from_slice(&(sig.len() as u16).to_be_bytes());
            wire.extend_from_slice(&sig);
            rustls::DigitallySignedStruct::read_bytes(&wire).unwrap()
        }

        fn real_cert_and_key() -> (CertificateDer<'static>, rcgen::KeyPair) {
            let real = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (real.cert.der().clone(), real.key_pair)
        }

        #[test]
        fn tls13_signature_from_a_different_key_is_rejected() {
            let (cert, _real_key) = real_cert_and_key();
            let attacker = rcgen::KeyPair::generate().unwrap();
            let msg = b"tls13 transcript stand-in";
            let (scheme, sig) = sign_with(&attacker, msg);
            let dss = dss_from(scheme, sig);
            let v = TofuCertVerifier::with_pin_dir("sig.example", tempfile_dir());
            assert!(
                v.verify_tls13_signature(msg, &cert, &dss).is_err(),
                "a CertificateVerify signed by a key other than the cert's must be rejected"
            );
        }

        #[test]
        fn tls12_signature_from_a_different_key_is_rejected() {
            let (cert, _real_key) = real_cert_and_key();
            let attacker = rcgen::KeyPair::generate().unwrap();
            let msg = b"tls12 transcript stand-in";
            let (scheme, sig) = sign_with(&attacker, msg);
            let dss = dss_from(scheme, sig);
            let v = TofuCertVerifier::with_pin_dir("sig.example", tempfile_dir());
            assert!(v.verify_tls12_signature(msg, &cert, &dss).is_err());
        }

        #[test]
        fn tls13_signature_from_the_cert_key_is_accepted() {
            let (cert, real_key) = real_cert_and_key();
            let msg = b"tls13 transcript stand-in";
            let (scheme, sig) = sign_with(&real_key, msg);
            let dss = dss_from(scheme, sig);
            let v = TofuCertVerifier::with_pin_dir("sig.example", tempfile_dir());
            assert!(v.verify_tls13_signature(msg, &cert, &dss).is_ok());
        }

        #[test]
        fn tls13_signature_over_a_different_message_is_rejected() {
            let (cert, real_key) = real_cert_and_key();
            let (scheme, sig) = sign_with(&real_key, b"what the server signed");
            let dss = dss_from(scheme, sig);
            let v = TofuCertVerifier::with_pin_dir("sig.example", tempfile_dir());
            assert!(v
                .verify_tls13_signature(b"what the client hashed", &cert, &dss)
                .is_err());
        }

        #[test]
        fn supported_schemes_come_from_the_provider() {
            ensure_crypto();
            let v = TofuCertVerifier::with_pin_dir("sig.example", tempfile_dir());
            let schemes = v.supported_verify_schemes();
            assert!(schemes.contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256));
            let provider = rustls::crypto::CryptoProvider::get_default().unwrap();
            assert_eq!(
                schemes,
                provider
                    .signature_verification_algorithms
                    .supported_schemes()
            );
        }

        /// Loopback server serving exactly what a gateway with
        /// `ZTLP_QUIC_CERT_DIR=<dir>` serves (no env mutation in tests).
        fn loopback_server(cert_dir: &std::path::Path) -> quinn::Endpoint {
            ensure_crypto();
            let (certs, key) = load_or_generate_self_signed_in(cert_dir);
            let mut sc = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            sc.alpn_protocols = vec![b"ztlp-test".to_vec()];
            let server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(sc).unwrap(),
            ));
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap()
        }

        async fn loopback_dial(
            server: &quinn::Endpoint,
            pin_dir: std::path::PathBuf,
        ) -> Result<(), String> {
            let mut cc = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TofuCertVerifier::with_pin_dir(
                    "loopback.example",
                    pin_dir,
                )))
                .with_no_client_auth();
            cc.alpn_protocols = vec![b"ztlp-test".to_vec()];
            let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
                .map_err(|e| e.to_string())?;
            client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(cc).unwrap(),
            )));
            let addr = server.local_addr().unwrap();
            let srv = server.clone();
            let accept = tokio::spawn(async move {
                if let Some(inc) = srv.accept().await {
                    let _ = inc.await;
                }
            });
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                client
                    .connect(addr, "localhost")
                    .map_err(|e| e.to_string())?,
            )
            .await
            .map_err(|_| "handshake timed out".to_string())?
            .map(|c| c.close(0u32.into(), b"done"))
            .map_err(|e| e.to_string());
            accept.abort();
            client.wait_idle().await;
            res
        }

        /// Task 1.4: with the CertificateVerify check now real, a genuine
        /// handshake against the gateway's persisted rcgen cert must still
        /// succeed (provider accepts rcgen's ECDSA P-256 leaf), both on first
        /// contact and on the pinned second contact. If this fails, every
        /// QUIC dial in the fleet would fail.
        #[tokio::test]
        async fn real_quic_handshake_passes_signature_check_twice() {
            let cert_dir = tempfile_dir();
            std::fs::create_dir_all(&cert_dir).unwrap();
            let pin_dir = tempfile_dir();
            let server = loopback_server(&cert_dir);
            loopback_dial(&server, pin_dir.clone())
                .await
                .expect("first contact must handshake");
            loopback_dial(&server, pin_dir.clone())
                .await
                .expect("pinned second contact must handshake");
            // And a restarted gateway on the same cert dir keeps the pin.
            drop(server);
            let server2 = loopback_server(&cert_dir);
            loopback_dial(&server2, pin_dir.clone())
                .await
                .expect("restart with persisted cert must keep working");
            let _ = std::fs::remove_dir_all(&cert_dir);
            let _ = std::fs::remove_dir_all(&pin_dir);
        }

        /// A gateway that comes back with a different cert is still refused
        /// by a real handshake (legacy pin behavior unchanged in Phase 1).
        #[tokio::test]
        async fn real_quic_handshake_rejects_a_changed_cert() {
            let pin_dir = tempfile_dir();
            let dir_a = tempfile_dir();
            let dir_b = tempfile_dir();
            std::fs::create_dir_all(&dir_a).unwrap();
            std::fs::create_dir_all(&dir_b).unwrap();
            let a = loopback_server(&dir_a);
            loopback_dial(&a, pin_dir.clone())
                .await
                .expect("pins cert A");
            let b = loopback_server(&dir_b);
            assert!(loopback_dial(&b, pin_dir.clone()).await.is_err());
            for d in [pin_dir, dir_a, dir_b] {
                let _ = std::fs::remove_dir_all(d);
            }
        }

        /// Task 3.4: the published fingerprint is the sha256 of the leaf the
        /// server really serves, stable across binds on the same cert dir.
        #[test]
        fn published_fingerprint_matches_the_served_leaf_and_is_stable() {
            ensure_crypto();
            let dir = tempfile_dir();
            std::fs::create_dir_all(&dir).unwrap();
            let (c1, _) = load_or_generate_self_signed_in(&dir);
            publish_server_cert(&c1, Some(&dir));
            let fp1 = published_server_cert_sha256().unwrap();
            assert_eq!(fp1, TofuCertVerifier::fingerprint(&c1[0]));
            assert_eq!(fp1.len(), 64);
            let (c2, _) = load_or_generate_self_signed_in(&dir);
            publish_server_cert(&c2, Some(&dir));
            assert_eq!(published_server_cert_sha256().unwrap(), fp1);
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[tokio::test]
        async fn published_fingerprint_equals_what_a_client_pins() {
            let cert_dir = tempfile_dir();
            std::fs::create_dir_all(&cert_dir).unwrap();
            let pin_dir = tempfile_dir();
            let server = loopback_server(&cert_dir);
            loopback_dial(&server, pin_dir.clone()).await.unwrap();
            let pinned = std::fs::read_dir(&pin_dir)
                .unwrap()
                .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
                .next()
                .unwrap();
            let (certs, _) = load_or_generate_self_signed_in(&cert_dir);
            assert_eq!(pinned.trim(), cert_sha256_hex(certs[0].as_ref()));
            let _ = std::fs::remove_dir_all(&cert_dir);
            let _ = std::fs::remove_dir_all(&pin_dir);
        }

        // ── Phase 5: verifier honours the NS record state ─────────────

        #[test]
        fn verified_fp_match_ignores_and_retires_a_stale_pin() {
            let tmp = tempfile_dir();
            let cert = fake_cert(0xAA);
            let fp = TofuCertVerifier::fingerprint(&cert);
            let legacy = TofuCertVerifier::with_pin_dir("gw.ns", tmp.clone());
            std::fs::create_dir_all(&tmp).unwrap();
            std::fs::write(legacy.pin_path(), "00".repeat(32)).unwrap();
            let v = TofuCertVerifier::with_pin_dir_and_expectation(
                "gw.ns",
                tmp.clone(),
                crate::quic_transport::CertExpectation {
                    record: crate::quic_transport::RecordState::Verified { fp: Some(fp) },
                    strict: true,
                },
            );
            assert!(v
                .verify_server_cert(&cert, &[], &fake_server_name(), &[], fixed_now())
                .is_ok());
            assert!(!v.pin_path().exists(), "pin retired once NS-backed");
            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn verified_fp_match_needs_no_pin_and_writes_none() {
            let tmp = tempfile_dir();
            let cert = fake_cert(0xAB);
            let v = TofuCertVerifier::with_pin_dir_and_expectation(
                "gw.ns2",
                tmp.clone(),
                crate::quic_transport::CertExpectation {
                    record: crate::quic_transport::RecordState::Verified {
                        fp: Some(TofuCertVerifier::fingerprint(&cert)),
                    },
                    strict: true,
                },
            );
            assert!(v
                .verify_server_cert(&cert, &[], &fake_server_name(), &[], fixed_now())
                .is_ok());
            assert!(!v.pin_path().exists());
            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn strict_unverified_rejects_even_with_a_matching_pin_and_never_says_delete_the_pin() {
            let tmp = tempfile_dir();
            let cert = fake_cert(0xAC);
            let legacy = TofuCertVerifier::with_pin_dir("gw.ns3", tmp.clone());
            std::fs::create_dir_all(&tmp).unwrap();
            std::fs::write(legacy.pin_path(), TofuCertVerifier::fingerprint(&cert)).unwrap();
            let v = TofuCertVerifier::with_pin_dir_and_expectation(
                "gw.ns3",
                tmp.clone(),
                crate::quic_transport::CertExpectation {
                    record: crate::quic_transport::RecordState::Unverified,
                    strict: true,
                },
            );
            let err = v
                .verify_server_cert(&cert, &[], &fake_server_name(), &[], fixed_now())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(crate::quic_transport::UNVERIFIED_MARKER),
                "{err}"
            );
            assert!(err.contains("gw.ns3"), "{err}");
            assert!(!err.contains("delete"), "{err}");
            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn ns_mismatch_names_the_gateway_and_carries_the_marker() {
            let tmp = tempfile_dir();
            let v = TofuCertVerifier::with_pin_dir_and_expectation(
                "gw.ns4",
                tmp.clone(),
                crate::quic_transport::CertExpectation {
                    record: crate::quic_transport::RecordState::Verified {
                        fp: Some("ab".repeat(32)),
                    },
                    strict: true,
                },
            );
            let err = v
                .verify_server_cert(&fake_cert(0xAD), &[], &fake_server_name(), &[], fixed_now())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(crate::quic_transport::NS_MISMATCH_MARKER),
                "{err}"
            );
            assert!(err.contains("gw.ns4") && !err.contains("delete"), "{err}");
            let _ = std::fs::remove_dir_all(&tmp);
        }

        async fn loopback_dial_expecting(
            server: &quinn::Endpoint,
            pin_dir: std::path::PathBuf,
            expect: crate::quic_transport::CertExpectation,
        ) -> Result<(), String> {
            let mut cc = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    TofuCertVerifier::with_pin_dir_and_expectation("loopback.ns", pin_dir, expect),
                ))
                .with_no_client_auth();
            cc.alpn_protocols = vec![b"ztlp-test".to_vec()];
            let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
                .map_err(|e| e.to_string())?;
            client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(cc).unwrap(),
            )));
            let addr = server.local_addr().unwrap();
            let srv = server.clone();
            let accept = tokio::spawn(async move {
                if let Some(inc) = srv.accept().await {
                    let _ = inc.await;
                }
            });
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                client
                    .connect(addr, "localhost")
                    .map_err(|e| e.to_string())?,
            )
            .await
            .map_err(|_| "handshake timed out".to_string())?
            .map(|c| c.close(0u32.into(), b"done"))
            .map_err(|e| e.to_string());
            accept.abort();
            client.wait_idle().await;
            res
        }

        /// Phase 5 over a real handshake: a gateway whose cert matches its
        /// NS-signed fingerprint is accepted with no pin file at all; after
        /// a cert change (restart without a persisted cert) the stale
        /// fingerprint is refused with the NS-mismatch marker the dialer's
        /// retry looks for, and the fresh one is accepted, never pinning.
        #[tokio::test]
        async fn real_handshake_follows_the_ns_fingerprint_without_pins() {
            use crate::quic_transport::{CertExpectation, RecordState, NS_MISMATCH_MARKER};
            let pin_dir = tempfile_dir();
            let (dir_a, dir_b) = (tempfile_dir(), tempfile_dir());
            std::fs::create_dir_all(&dir_a).unwrap();
            std::fs::create_dir_all(&dir_b).unwrap();
            let fp_of = |d: &std::path::Path| {
                let (c, _) = load_or_generate_self_signed_in(d);
                cert_sha256_hex(c[0].as_ref())
            };
            let (fp_a, fp_b) = (fp_of(&dir_a), fp_of(&dir_b));
            let exp = |fp: &str| CertExpectation {
                record: RecordState::Verified {
                    fp: Some(fp.to_string()),
                },
                strict: true,
            };

            let a = loopback_server(&dir_a);
            loopback_dial_expecting(&a, pin_dir.clone(), exp(&fp_a))
                .await
                .expect("matching NS fingerprint accepted");
            drop(a);

            let b = loopback_server(&dir_b); // "restarted with a new cert"
            let err = loopback_dial_expecting(&b, pin_dir.clone(), exp(&fp_a))
                .await
                .unwrap_err();
            assert!(err.contains(NS_MISMATCH_MARKER), "{err}");
            loopback_dial_expecting(&b, pin_dir.clone(), exp(&fp_b))
                .await
                .expect("re-resolved fingerprint accepted");
            assert!(
                !pin_dir.exists() || std::fs::read_dir(&pin_dir).unwrap().next().is_none(),
                "NS-backed dials never write pins"
            );
            for d in [pin_dir, dir_a, dir_b] {
                let _ = std::fs::remove_dir_all(d);
            }
        }

        #[tokio::test]
        async fn real_handshake_strict_device_without_a_record_is_refused() {
            use crate::quic_transport::{CertExpectation, RecordState, UNVERIFIED_MARKER};
            let dir = tempfile_dir();
            std::fs::create_dir_all(&dir).unwrap();
            let s = loopback_server(&dir);
            let err = loopback_dial_expecting(
                &s,
                tempfile_dir(),
                CertExpectation {
                    record: RecordState::None,
                    strict: true,
                },
            )
            .await
            .unwrap_err();
            assert!(err.contains(UNVERIFIED_MARKER), "{err}");
            let _ = std::fs::remove_dir_all(dir);
        }

        fn tempfile_dir() -> std::path::PathBuf {
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "ztlp_quic_pin_test_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            dir
        }
    }
}

pub mod noise_stream {
    use super::tokio_endpoint::QuicConnection;
    use super::QuicTransportError;
    use crate::handshake::{HandshakeContext, HandshakeResult};
    use crate::identity::{NodeId, NodeIdentity};

    pub const STREAM0_MAGIC_V1: u8 = super::STREAM0_MAGIC_V1;
    const MAX_FRAME_SIZE: usize = 65536;

    pub async fn read_ztlp_frame(
        recv: &mut quinn::RecvStream,
    ) -> Result<Vec<u8>, QuicTransportError> {
        let mut magic = [0u8; 1];
        recv.read_exact(&mut magic).await?;
        if magic[0] != STREAM0_MAGIC_V1 {
            return Err(QuicTransportError::BadMagic {
                expected: STREAM0_MAGIC_V1,
                got: magic[0],
            });
        }

        let mut len_bytes = [0u8; 2];
        recv.read_exact(&mut len_bytes).await?;
        let len = u16::from_be_bytes(len_bytes) as usize;

        if len > MAX_FRAME_SIZE {
            return Err(QuicTransportError::FrameTooLarge { sz: len });
        }

        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload).await?;
        Ok(payload)
    }

    pub async fn write_ztlp_frame(
        send: &mut quinn::SendStream,
        payload: &[u8],
    ) -> Result<(), QuicTransportError> {
        if payload.len() > MAX_FRAME_SIZE {
            return Err(QuicTransportError::FrameTooLarge { sz: payload.len() });
        }

        let len_bytes = (payload.len() as u16).to_be_bytes();
        let mut frame = Vec::with_capacity(1 + 2 + payload.len());
        frame.push(STREAM0_MAGIC_V1);
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(payload);

        send.write_all(&frame).await?;
        Ok(())
    }

    pub async fn run_initiator_handshake(
        conn: &QuicConnection,
        identity: &NodeIdentity,
        responder_id: NodeId,
        service_hash: [u8; 16],
    ) -> Result<HandshakeResult, QuicTransportError> {
        let (mut send, mut recv) = conn.open_bi().await?;
        let mut ctx = HandshakeContext::new_initiator(identity)?;

        let msg1 = ctx.write_message(&[])?;
        send.write_all(&service_hash).await?;
        write_ztlp_frame(&mut send, &msg1).await?;

        let mut sid_buf = [0u8; 12];
        recv.read_exact(&mut sid_buf).await?;
        let session_id = crate::packet::SessionId(sid_buf);

        let msg2 = read_ztlp_frame(&mut recv).await?;
        ctx.read_message(&msg2)?;

        let msg3 = ctx.write_message(&[])?;
        write_ztlp_frame(&mut send, &msg3).await?;

        let (_, init_sess) = ctx.finalize(responder_id, session_id)?;

        // Close our send side of stream-0 since handhshake is done
        // and we will multiplex data onto separate bi-streams mapped 1:1 to TCP connections
        let _ = send.finish();

        Ok(HandshakeResult {
            session: init_sess.clone(),
            // In a network handshake we only hold the local side's session.
            // Populate both alias fields with it so the struct stays exhaustive;
            // QUIC callers only read `.session` / `.session_id`.
            initiator_session: init_sess.clone(),
            responder_session: init_sess,
            session_id,
        })
    }

    pub async fn run_responder_handshake(
        conn: &QuicConnection,
        identity: &NodeIdentity,
        initiator_id: NodeId,
    ) -> Result<(HandshakeResult, [u8; 16], Option<String>), QuicTransportError> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut ctx = HandshakeContext::new_responder(identity)?;

        let mut service_hash = [0u8; 16];
        recv.read_exact(&mut service_hash).await?;
        let msg1 = read_ztlp_frame(&mut recv).await?;
        ctx.read_message(&msg1)?;

        let session_id = crate::packet::SessionId::generate();
        send.write_all(session_id.as_bytes()).await?;

        let msg2 = ctx.write_message(&[])?;
        write_ztlp_frame(&mut send, &msg2).await?;

        let msg3 = read_ztlp_frame(&mut recv).await?;
        ctx.read_message(&msg3)?;

        // The Noise IK handshake authenticates the initiator's static
        // X25519 key — capture it BEFORE finalize consumes the context.
        // This is the tunnel's cryptographic identity: callers map it to
        // an operator identity (e.g. admin email) for per-request header
        // injection without any additional per-request authentication.
        let peer_pubkey_hex = ctx.remote_static_hex();

        let (_, resp_sess) = ctx.finalize(initiator_id, session_id)?;

        let _ = send.finish();

        Ok((
            HandshakeResult {
                session: resp_sess.clone(),
                initiator_session: resp_sess.clone(),
                responder_session: resp_sess,
                session_id,
            },
            service_hash,
            peer_pubkey_hex,
        ))
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
    // Under `ios-sync`, we wrap quinn-proto. For Phase 4 placeholder tests,
    // we only need it to compile cleanly without pulling tokio.
    pub inner: Option<quinn_proto::Connection>,
}

impl SansIoConnection {
    /// Construct a new sans-io connection.
    pub fn new(_cfg: QuicEndpointConfig) -> Result<Self, QuicTransportError> {
        // We will initialize this from Swift / iOS FFI layer where the certs
        // or keys might come from the native system or our hand-rolled loop,
        // without tokio dependencies. For now, empty Option fulfills the iOS NE path.
        Ok(Self { inner: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── relay-routable client CIDs ───────────────────────────────────

    #[test]
    fn relay_cid_generator_stamps_one_prefix_on_every_cid() {
        use quinn_proto::ConnectionIdGenerator;
        let mut g = RelayRoutableCidGenerator::new();
        assert_eq!(g.cid_len(), RELAY_CID_LEN);
        assert_eq!(g.cid_lifetime(), None);
        let cids: Vec<_> = (0..16).map(|_| g.generate_cid()).collect();
        for c in &cids {
            assert_eq!(c.len(), RELAY_CID_LEN);
            assert_eq!(&c[..RELAY_CID_PREFIX_LEN], &g.prefix()[..]);
        }
        // the random tail must differ (16 draws of 32 bits: collision ~3e-8)
        let mut tails: Vec<_> = cids
            .iter()
            .map(|c| c[RELAY_CID_PREFIX_LEN..].to_vec())
            .collect();
        tails.sort();
        tails.dedup();
        assert_eq!(tails.len(), cids.len());
    }

    #[test]
    fn relay_cid_generators_get_independent_prefixes() {
        let prefixes: std::collections::HashSet<_> = (0..64)
            .map(|_| RelayRoutableCidGenerator::new().prefix())
            .collect();
        assert!(prefixes.len() >= 63, "prefixes must be random per endpoint");
    }

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

    /// v0.29.3 regression: the default transport-config knobs MUST set both
    /// a max_idle_timeout and a keep_alive_interval so:
    ///   - relayed QUIC tunnels survive a ~60s sweeper tick + jitter,
    ///   - and idle tunnels emit keepalives that refresh the relay's
    ///     `{:client_map, ...}` mapping. Removing either field would
    ///     reopen the v0.29.0..v0.29.2 handshake-flakiness window.
    #[test]
    fn default_config_has_quinn_transport_tuning() {
        let cfg = QuicEndpointConfig::default();
        assert_eq!(
            cfg.max_idle_timeout_ms,
            Some(60_000),
            "max_idle_timeout regression — see v0.29.3 release notes"
        );
        assert_eq!(
            cfg.keep_alive_interval_ms,
            Some(15_000),
            "keep_alive_interval regression — see v0.29.3 release notes"
        );
        // keepalive must be strictly less than idle timeout; otherwise the
        // peer's idle clock can fire between two keepalives and the tunnel
        // tears down prematurely.
        match (cfg.keep_alive_interval_ms, cfg.max_idle_timeout_ms) {
            (Some(ka), Some(idle)) => assert!(
                ka < idle,
                "keep_alive_interval ({ka}ms) must be < max_idle_timeout ({idle}ms)"
            ),
            _ => unreachable!("we just asserted both fields are Some above"),
        }
    }

    #[test]
    fn sans_io_constructor_returns_ok() {
        let conn = SansIoConnection::new(QuicEndpointConfig::default());
        assert!(conn.is_ok());
    }
}
