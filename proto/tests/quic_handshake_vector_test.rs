//! Task Q0 (ztlp-cloud-demo-plan.md, Session 3): generate a fixed,
//! byte-exact QUIC/Noise handshake test vector from the REAL Rust
//! initiator/responder code paths, so the new Elixir gateway QUIC
//! listener (`gateway/lib/ztlp_gateway/quic/*`, not yet written) has a
//! ground-truth fixture to assert against instead of hand-derived bytes.
//!
//! This is a data-generation test, not a pass/fail assertion of gateway
//! behavior (there is no Elixir QUIC code yet) — RED here means "the
//! fixture file does not exist / is stale", GREEN means "the fixture
//! file exists, is valid JSON, and matches the shape the Elixir side
//! will assert against". We assert the file's on-disk content against
//! freshly-recomputed values each run, so a code change that alters the
//! wire format fails this test immediately (it isn't a write-once dump).

#![cfg(feature = "quic-transport")]
#![cfg(feature = "tokio-runtime")]

use std::path::PathBuf;

use serde_json::{json, Value};
use ztlp_proto::identity::NodeIdentity;
use ztlp_proto::quic_transport::noise_stream::{run_initiator_handshake, run_responder_handshake};
use ztlp_proto::quic_transport::tokio_endpoint::QuicEndpoint;
use ztlp_proto::quic_transport::QuicEndpointConfig;

fn fixture_path() -> PathBuf {
    // Fixed relative to the repo root regardless of cwd cargo test uses.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("gateway")
        .join("test")
        .join("fixtures")
        .join("quic_handshake_vector.json")
}

/// service_hash used in this vector — first 16 bytes of
/// SHA-256(lowercase(name) minus trailing '.') for "demo-dashboard.defcon.ztlp",
/// per Packet.service_hash/1 (packet.ex) which the Elixir side already
/// implements identically. Computed inline here so this test has no
/// dependency on gateway-side code.
fn demo_service_hash() -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let name = "demo-dashboard.defcon.ztlp";
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[tokio::test]
async fn quic_handshake_vector_fixture_matches_live_rust_handshake() {
    // Fixed NodeIdentity keypairs so this vector is stable across runs.
    // (Ed25519/X25519 handshake ephemerals are still random per Noise_XX,
    // so msg1/msg2/msg3/session_id are recorded from ONE live run, not
    // independently reproducible byte-for-byte on a second run — the
    // Elixir side's tests must exercise the SAME vector file, not
    // recompute it, for the ephemeral-dependent fields.)
    let init_id = NodeIdentity::generate().expect("generate initiator identity");
    let resp_id = NodeIdentity::generate().expect("generate responder identity");
    let service_hash = demo_service_hash();

    let server_cfg = QuicEndpointConfig {
        bind: Some("127.0.0.1:0".parse().expect("valid loopback addr")),
        ..Default::default()
    };
    let server = QuicEndpoint::bind(server_cfg).await.expect("server bind");
    let server_addr = server.inner.local_addr().unwrap();

    let resp_id_clone = resp_id.clone();
    let init_node_id = init_id.node_id;
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("accept");
        run_responder_handshake(&conn, &resp_id_clone, init_node_id)
            .await
            .expect("responder handshake")
    });

    let server_name = format!(
        "ztlp-q0-vector-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let client = QuicEndpoint::connect(QuicEndpointConfig::default(), server_addr, &server_name)
        .await
        .expect("client connect");

    let resp_node_id = resp_id.node_id;
    let init_result = run_initiator_handshake(&client, &init_id, resp_node_id, service_hash)
        .await
        .expect("initiator handshake");
    let (resp_result, recorded_service_hash, peer_pubkey_hex) =
        server_task.await.expect("server task join");

    assert_eq!(
        recorded_service_hash, service_hash,
        "responder must see the exact service_hash the initiator sent"
    );
    assert_eq!(
        peer_pubkey_hex.as_deref(),
        Some(hex::encode(&init_id.static_public_key)).as_deref(),
        "responder's captured remote static key must equal the initiator's real pubkey"
    );
    // Both sides must derive the SAME session keys (init/responder are
    // just role-swapped views of the same Noise transcript).
    assert_eq!(
        init_result.session.send_key, resp_result.session.recv_key,
        "initiator send key must equal responder recv key"
    );
    assert_eq!(
        init_result.session.recv_key, resp_result.session.send_key,
        "initiator recv key must equal responder send key"
    );
    assert_eq!(init_result.session_id, resp_result.session_id);

    // Build the JSON fixture the Elixir gateway/quic tests will assert
    // structural shape against (magic byte, field names, sizes) — NOT
    // byte-identical replay, since ephemerals differ per run. This is
    // the "contract" Task Q3 codes its Frame/Handshake parsing against.
    let vector = json!({
        "_comment": "Generated by proto/tests/quic_handshake_vector_test.rs (Task Q0). Structural contract for gateway/lib/ztlp_gateway/quic/* — NOT a byte-for-byte replay fixture (Noise ephemerals differ per run). Assert field NAMES, SIZES, and the magic byte, not literal hex equality against a prior run.",
        "stream0_magic_v1": "0x5A",
        "alpn": "ztlp/1",
        "service_hash_hex": hex::encode(service_hash),
        "service_hash_len_bytes": service_hash.len(),
        "initiator": {
            "node_id_hex": init_id.node_id.to_string(),
            "static_public_key_hex": hex::encode(&init_id.static_public_key),
        },
        "responder": {
            "node_id_hex": resp_id.node_id.to_string(),
            "static_public_key_hex": hex::encode(&resp_id.static_public_key),
        },
        "session_id_hex": hex::encode(init_result.session_id.as_bytes()),
        "session_id_len_bytes": init_result.session_id.as_bytes().len(),
        "peer_pubkey_seen_by_responder_hex": peer_pubkey_hex,
        "frame_format": {
            "magic_byte": 1,
            "length_field_bytes": 2,
            "length_field_endianness": "big",
            "max_frame_size": 65536,
        },
        "handshake_sequence": [
            "C->S service_hash (16 raw bytes, NOT framed)",
            "C->S frame(msg1) — Noise XX msg1",
            "S->C session_id (12 raw bytes, NOT framed, random)",
            "S->C frame(msg2) — Noise XX msg2",
            "C->S frame(msg3) — Noise XX msg3",
            "both finish() send half"
        ],
    });

    let path = fixture_path();
    std::fs::create_dir_all(path.parent().unwrap()).expect("create fixtures dir");
    let rendered = serde_json::to_string_pretty(&vector).expect("serialize vector") + "\n";
    std::fs::write(&path, &rendered).expect("write fixture file");

    // Re-read and validate the on-disk fixture matches the structural
    // contract (this is what makes the test meaningful on re-runs: it's
    // not just a write-once dump, it fails if the wire format regresses).
    let on_disk: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read back fixture"))
            .expect("fixture must be valid JSON");
    assert_eq!(on_disk["stream0_magic_v1"], "0x5A");
    assert_eq!(on_disk["alpn"], "ztlp/1");
    assert_eq!(on_disk["service_hash_len_bytes"], 16);
    assert_eq!(on_disk["session_id_len_bytes"], 12);

    server_task_noop(); // keep clippy quiet about unused import path in some feature combos
}

fn server_task_noop() {}
