//! Integration tests for the experimental QUIC + Noise transport.
//!
//! These tests document the **Phase 1+ contract** of the future QUIC
//! transport. They are written TDD-style: the implementation does not
//! exist yet, so each test currently asserts the Phase-0 "not
//! implemented" contract and is annotated `#[ignore]` so CI stays
//! green. When an engineer starts a phase, they remove the `#[ignore]`,
//! watch the test fail for the right reason, then make it pass.
//!
//! See `docs/architecture/quic-noise-handshake.md` for the full spec.

#![cfg(feature = "quic-transport")]

use ztlp_proto::quic_transport::{
    QuicEndpointConfig, QuicTransportError, SansIoConnection, ZTLP_ALPN,
};

/// Sanity: the module is reachable and the ALPN constant is what the
/// design doc promises. This one runs in CI as the proof-of-life test
/// that nobody silently broke the feature gate.
#[test]
fn alpn_constant_is_reachable_from_integration_test() {
    assert_eq!(ZTLP_ALPN, b"ztlp/1");
}

/// Phase 1 contract: a tokio-backed `QuicEndpoint` accepts a connection
/// and yields a pre-opened stream-0 bidi stream into which the caller
/// writes Noise msg1 bytes.
///
/// Phase 0 status: asserts the not-implemented sentinel error. Remove
/// `#[ignore]` to start working Phase 1.
#[cfg(feature = "tokio-runtime")]
#[tokio::test]
#[ignore = "Phase 1 — QuicEndpoint::bind not implemented yet"]
async fn multi_stream_loopback_roundtrip() {
    use ztlp_proto::quic_transport::tokio_endpoint::QuicEndpoint;

    // Expected (Phase 1+) behaviour:
    //   1. Bind a server endpoint on 127.0.0.1:0.
    //   2. Client connects with ALPN=ztlp/1.
    //   3. Open 8 parallel bidi streams.
    //   4. Each stream carries a distinct 16-byte payload.
    //   5. All 8 payloads echo back without head-of-line blocking.
    //
    // Phase 0 placeholder:
    let server_cfg = QuicEndpointConfig {
        bind: Some("127.0.0.1:0".parse().expect("valid loopback addr")),
        ..Default::default()
    };
    let result = QuicEndpoint::bind(server_cfg).await;
    match result {
        Err(QuicTransportError::NotImplemented { phase, .. }) => assert_eq!(phase, 1),
        _ => panic!("expected NotImplemented sentinel from Phase 0 scaffold"),
    }
}

/// Phase 1 contract: Noise_XX msg1/msg2/msg3 ride QUIC stream 0,
/// length-prefixed by the `STREAM0_MAGIC_V1` byte, and both ends
/// converge on a `TransportState` afterward.
///
/// Phase 0 status: scaffold only. The point of having this test in the
/// tree at all is to lock the *shape* of the future call sites.
#[cfg(feature = "tokio-runtime")]
#[tokio::test]
#[ignore = "Phase 2 — Noise-over-QUIC not implemented yet"]
async fn noise_handshake_over_quic_stream_zero() {
    use ztlp_proto::quic_transport::tokio_endpoint::QuicEndpoint;

    // Phase 0: confirm the API surface exists; do not exercise it.
    let _ = QuicEndpoint::bind(QuicEndpointConfig::default()).await;
}

/// Phase 4 contract: the sans-io constructor compiles and works under
/// `--no-default-features --features ios-sync,quic-transport` — proving
/// no tokio leak into the iOS NE code path.
///
/// Phase 0 status: confirms the sentinel.  When Phase 4 lands and
/// `SansIoConnection::new` returns `Ok`, this test flips to assert
/// the happy path and a new test takes over the not-implemented role.
#[test]
fn sans_io_path_compiles_without_tokio() {
    let err = SansIoConnection::new(QuicEndpointConfig::default()).unwrap_err();
    let QuicTransportError::NotImplemented { phase, what } = err;
    assert_eq!(phase, 4);
    assert!(
        what.contains("SansIoConnection"),
        "error message must identify the missing capability, got: {what}"
    );
}
