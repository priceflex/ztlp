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
use ztlp_proto::tunnel::ReassemblyBuffer;

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

#[tokio::test]
async fn test_reassembly_buffer_limits() {
    let mut reasm = ReassemblyBuffer::new(0, 16);

    for i in (0..100u64).rev() {
        let _ = reasm.insert(i, vec![i as u8; 64]);
    }

    assert!(
        reasm.buffered_count() <= 16,
        "Reassembly buffer should respect max limit, got {}",
        reasm.buffered_count()
    );
}

// ─── Test 8: Duplicate sequence numbers in reassembly ────────────

#[tokio::test]
async fn test_reassembly_duplicate_sequences() {
    let mut reasm = ReassemblyBuffer::new(0, 64);

    let result1 = reasm.insert(0, vec![0xAA; 32]);
    assert!(result1.is_some(), "First in-order packet should deliver");

    let result2 = reasm.insert(0, vec![0xBB; 32]);
    assert!(result2.is_none(), "Duplicate seq should not deliver again");

    let result3 = reasm.insert(1, vec![0xCC; 32]);
    assert!(result3.is_some(), "Next in-order packet should deliver");
}

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

#[tokio::test]
async fn test_nack_decode_malformed() {
    use ztlp_proto::tunnel::decode_nack_payload;

    assert!(decode_nack_payload(&[]).is_none());
    assert!(decode_nack_payload(&[0x01]).is_none());

    let short = vec![0x00, 0x01]; // claims 1 entry, no data
    assert!(decode_nack_payload(&short).is_none());

    let mut truncated = vec![0x00, 0x64]; // claims 100 entries
    truncated.extend_from_slice(&[0u8; 8]); // only 1 entry
    assert!(decode_nack_payload(&truncated).is_none());

    let zero_count = vec![0x00, 0x00];
    let result = decode_nack_payload(&zero_count);
    assert!(result.is_some());
    assert!(result.unwrap().is_empty());
}

// ─── Test 14: Reassembly out-of-order delivery ───────────────────

#[tokio::test]
async fn test_reassembly_out_of_order() {
    let mut reasm = ReassemblyBuffer::new(0, 64);

    // Insert seq 2 first (out of order) — buffered, returns empty deliverable
    let result = reasm.insert(2, vec![0x02; 32]);
    assert!(result.is_some(), "Out-of-order returns Some(empty)");
    assert!(result.unwrap().is_empty(), "Nothing deliverable yet");

    // Insert seq 1 (still out of order) — buffered
    let result = reasm.insert(1, vec![0x01; 32]);
    assert!(result.is_some(), "Out-of-order returns Some(empty)");
    assert!(result.unwrap().is_empty(), "Still waiting for seq 0");

    // Insert seq 0 — should trigger delivery of 0, 1, 2
    let result = reasm.insert(0, vec![0x00; 32]);
    assert!(result.is_some(), "seq 0 should trigger cascade delivery");
    let delivered = result.unwrap();
    assert_eq!(delivered.len(), 3, "Should deliver 3 packets in order");
    assert_eq!(delivered[0].0, 0);
    assert_eq!(delivered[1].0, 1);
    assert_eq!(delivered[2].0, 2);
}

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
