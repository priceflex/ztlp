//! Recovery and failure-mode integration tests.
//!
//! These tests verify that ZTLP handles adverse conditions gracefully
//! without panicking or corrupting state. Every failure scenario that
//! could occur in production should have a test here.

use ztlp_proto::handshake::HandshakeContext;
use ztlp_proto::identity::{NodeId, NodeIdentity};
use ztlp_proto::packet::*;
use ztlp_proto::pipeline::{compute_header_auth_tag, AdmissionResult, Pipeline};
use ztlp_proto::session::SessionState;
use ztlp_proto::transport::TransportNode;

/// Helper: create a Pipeline with a registered session for testing.
fn make_pipeline(sid_bytes: [u8; 12], key: &[u8; 32]) -> Pipeline {
    let mut pipeline = Pipeline::new();
    let sid = SessionId(sid_bytes);
    let peer_id = NodeId::generate();
    let session = SessionState::new(sid, peer_id, *key, *key, false);
    pipeline.register_session(session);
    pipeline
}

// ─── Test 1: Malformed packets — truncated data header ───────────

#[tokio::test]
async fn test_truncated_data_header() {
    let short_packets: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x5A, 0x37],
        vec![0x5A, 0x37, 0x00, 0x00, 0x00],
        vec![0xFF; 5],
        vec![0x00; DATA_HEADER_SIZE - 1],
    ];

    for pkt in &short_packets {
        let result = DataHeader::deserialize(pkt);
        assert!(
            result.is_err(),
            "Expected Err for packet of len {}",
            pkt.len()
        );
    }
}

// ─── Test 2: Malformed packets — wrong magic bytes ───────────────

#[tokio::test]
async fn test_wrong_magic_bytes() {
    let key = [0x42u8; 32];
    let sid = [0x01u8; 12];
    let pipeline = make_pipeline(sid, &key);

    let mut bad_magic = vec![0x00; 64];
    bad_magic[0] = 0xDE;
    bad_magic[1] = 0xAD;

    let result = pipeline.process(&bad_magic);
    assert!(
        !matches!(result, AdmissionResult::Pass),
        "Wrong magic should not pass pipeline"
    );
}

// ─── Test 3: Malformed packets — corrupted auth tag ──────────────

#[tokio::test]
async fn test_corrupted_auth_tag() {
    let key = [0x42u8; 32];
    let sid = [0x01u8; 12];
    let pipeline = make_pipeline(sid, &key);

    // Build a valid packet
    let mut header = DataHeader::new(SessionId(sid), 1);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&key, &aad);
    let packet = header.serialize();

    // Valid packet should pass
    let result = pipeline.process(&packet);
    assert!(
        matches!(result, AdmissionResult::Pass),
        "Valid packet should pass"
    );

    // Corrupt the auth tag
    let mut corrupted = packet.clone();
    let tag_offset = DATA_HEADER_SIZE - 16;
    corrupted[tag_offset] ^= 0xFF;

    let result = pipeline.process(&corrupted);
    assert!(
        !matches!(result, AdmissionResult::Pass),
        "Corrupted auth tag should not pass pipeline"
    );
}

// ─── Test 4: Oversized packets ───────────────────────────────────

#[tokio::test]
async fn test_oversized_packet_handling() {
    let huge_packet = vec![0x5A; 65536];
    let result = DataHeader::deserialize(&huge_packet);
    let _ = result; // must not panic

    let enormous = vec![0xFF; 1_000_000];
    let result2 = DataHeader::deserialize(&enormous);
    let _ = result2; // must not panic
}

// ─── Test 5: Zero-length payload encryption/decryption ───────────

#[tokio::test]
async fn test_zero_length_payload() {
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

    let key_bytes = [0x42u8; 32];
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce_bytes = [0u8; 12];
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, &[] as &[u8]).unwrap();
    assert!(
        !ciphertext.is_empty(),
        "AEAD should produce auth tag even for empty plaintext"
    );

    let plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).unwrap();
    assert!(
        plaintext.is_empty(),
        "Decrypted empty payload should be empty"
    );
}

// ─── Test 6: Maximum-length payload ──────────────────────────────

#[tokio::test]
async fn test_maximum_length_payload() {
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

    let key_bytes = [0x42u8; 32];
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce_bytes = [0u8; 12];
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let payload = vec![0xAB; 1200];
    let ciphertext = cipher.encrypt(nonce, payload.as_slice()).unwrap();
    let decrypted = cipher.decrypt(nonce, ciphertext.as_slice()).unwrap();
    assert_eq!(decrypted, payload);
}

// ─── Test 7: Reassembly buffer limits ────────────────────────────

// ─── Test 8: Duplicate sequence numbers in reassembly ────────────

// ─── Test 9: Pipeline with all-zero packet ───────────────────────

#[tokio::test]
async fn test_pipeline_all_zeros() {
    let pipeline = make_pipeline([0u8; 12], &[0u8; 32]);

    let zeros = vec![0u8; 128];
    let result = pipeline.process(&zeros);
    assert!(
        !matches!(result, AdmissionResult::Pass),
        "All-zero packet should fail magic check"
    );
}

// ─── Test 10: Rapid handshake establishment ──────────────────────

#[tokio::test]
async fn test_rapid_handshake_establishment() {
    for i in 0..10 {
        let id_a = NodeIdentity::generate().unwrap();
        let id_b = NodeIdentity::generate().unwrap();

        let mut ctx_a = HandshakeContext::new_initiator(&id_a).unwrap();
        let mut ctx_b = HandshakeContext::new_responder(&id_b).unwrap();

        let msg1 = ctx_a.write_message(&[]).unwrap();
        ctx_b.read_message(&msg1).unwrap();

        let msg2 = ctx_b.write_message(&[]).unwrap();
        ctx_a.read_message(&msg2).unwrap();

        let msg3 = ctx_a.write_message(&[]).unwrap();
        ctx_b.read_message(&msg3).unwrap();

        assert!(ctx_a.is_finished(), "Handshake {} A should finish", i);
        assert!(ctx_b.is_finished(), "Handshake {} B should finish", i);
    }
}

// ─── Test 11: Handshake with corrupted messages ──────────────────

#[tokio::test]
async fn test_handshake_corrupted_messages() {
    let id_a = NodeIdentity::generate().unwrap();
    let id_b = NodeIdentity::generate().unwrap();

    let mut ctx_a = HandshakeContext::new_initiator(&id_a).unwrap();
    let mut ctx_b = HandshakeContext::new_responder(&id_b).unwrap();

    // Complete msg1 normally (it's just an ephemeral key, no auth yet)
    let msg1 = ctx_a.write_message(&[]).unwrap();
    ctx_b.read_message(&msg1).unwrap();

    // Get valid msg2 from responder
    let msg2 = ctx_b.write_message(&[]).unwrap();

    // Corrupt msg2 — this one has authenticated encryption (ee, se, s, es)
    let mut corrupted = msg2.clone();
    if corrupted.len() > 10 {
        corrupted[10] ^= 0xFF; // corrupt inside the encrypted portion
    }

    // Initiator should reject corrupted authenticated message
    let result = ctx_a.read_message(&corrupted);
    assert!(
        result.is_err(),
        "Corrupted authenticated handshake msg should fail"
    );
}

// ─── Test 12: Transport send to unreachable address ──────────────

#[tokio::test]
async fn test_transport_send_unreachable() {
    let transport = TransportNode::bind("127.0.0.1:0").await.unwrap();

    let unreachable: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let result = transport.send_raw(&[0x5A, 0x37, 0x00], unreachable).await;
    let _ = result; // must not panic
}

// ─── Test 13: NACK decode with malformed input ───────────────────

// ─── Test 14: Reassembly out-of-order delivery ───────────────────

// ─── Test 15: Handshake header parse with garbage ────────────────

#[tokio::test]
async fn test_handshake_header_garbage() {
    let garbage_inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xFF],
        vec![0x5A, 0x37],
        vec![0xFF; HANDSHAKE_HEADER_SIZE - 1],
        vec![0x00; HANDSHAKE_HEADER_SIZE],
        vec![0xFF; HANDSHAKE_HEADER_SIZE * 2],
    ];

    for input in &garbage_inputs {
        let result = HandshakeHeader::deserialize(input);
        let _ = result; // must not panic
    }
}
