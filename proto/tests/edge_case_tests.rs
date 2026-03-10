//! Edge case and stress tests — boundary conditions, malformed packets,
//! replay attacks, key direction correctness, and pipeline resilience.

use ztlp_proto::handshake::perform_handshake;
use ztlp_proto::identity::{NodeId, NodeIdentity};
use ztlp_proto::packet::*;
use ztlp_proto::pipeline::*;
use ztlp_proto::session::{ReplayWindow, SessionState, DEFAULT_REPLAY_WINDOW};

// ─── Packet Edge Cases ──────────────────────────────────────────────

#[test]
fn test_handshake_header_exact_95_bytes() {
    let h = HandshakeHeader::new(MsgType::Hello);
    let bytes = h.serialize();
    assert_eq!(bytes.len(), 95, "handshake header MUST be exactly 95 bytes");
}

#[test]
fn test_data_header_exact_42_bytes() {
    let h = DataHeader::new(SessionId::generate(), 0);
    let bytes = h.serialize();
    assert_eq!(bytes.len(), 42, "data header MUST be exactly 42 bytes");
}

#[test]
fn test_version_field_max_4_bits() {
    // Version is 4 bits — max value is 15
    let mut h = HandshakeHeader::new(MsgType::Data);
    h.version = 0x0F;
    h.hdr_len = 0x0FFF; // max 12-bit value
    let bytes = h.serialize();
    let packed = u16::from_be_bytes([bytes[2], bytes[3]]);
    assert_eq!(packed, 0xFFFF, "Ver(0xF)|HdrLen(0xFFF) should pack to 0xFFFF");

    // Deserialization should reject version != 1
    let result = HandshakeHeader::deserialize(&bytes);
    assert!(result.is_err(), "version 0x0F should be rejected");
}

#[test]
fn test_hdrlen_boundary_values() {
    let mut h = DataHeader::new(SessionId::generate(), 0);

    // HdrLen 0
    h.hdr_len = 0;
    let bytes = h.serialize();
    let restored = DataHeader::deserialize(&bytes).unwrap();
    assert_eq!(restored.hdr_len, 0);

    // HdrLen max (0xFFF = 4095)
    h.hdr_len = 0x0FFF;
    let bytes = h.serialize();
    // Will fail version check since version is still 1 → packed is 0x1FFF
    let restored = DataHeader::deserialize(&bytes).unwrap();
    assert_eq!(restored.hdr_len, 0x0FFF);
}

#[test]
fn test_all_flags_roundtrip() {
    let all_flags = flags::HAS_EXT
        | flags::ACK_REQ
        | flags::REKEY
        | flags::MIGRATE
        | flags::MULTIPATH
        | flags::RELAY_HOP;

    let mut h = HandshakeHeader::new(MsgType::Data);
    h.flags = all_flags;
    let bytes = h.serialize();
    let restored = HandshakeHeader::deserialize(&bytes).unwrap();
    assert_eq!(restored.flags, all_flags, "all flags should survive roundtrip");

    let mut dh = DataHeader::new(SessionId::generate(), 0);
    dh.flags = all_flags;
    let bytes = dh.serialize();
    let restored = DataHeader::deserialize(&bytes).unwrap();
    assert_eq!(restored.flags, all_flags, "all data flags should survive roundtrip");
}

#[test]
fn test_packet_seq_max_value() {
    let h = DataHeader::new(SessionId::generate(), u64::MAX);
    let bytes = h.serialize();
    let restored = DataHeader::deserialize(&bytes).unwrap();
    assert_eq!(restored.packet_seq, u64::MAX);
}

#[test]
fn test_packet_seq_zero() {
    let h = DataHeader::new(SessionId::generate(), 0);
    let bytes = h.serialize();
    let restored = DataHeader::deserialize(&bytes).unwrap();
    assert_eq!(restored.packet_seq, 0);
}

#[test]
fn test_timestamp_max_value() {
    let mut h = HandshakeHeader::new(MsgType::Data);
    h.timestamp = u64::MAX;
    let bytes = h.serialize();
    let restored = HandshakeHeader::deserialize(&bytes).unwrap();
    assert_eq!(restored.timestamp, u64::MAX);
}

#[test]
fn test_session_id_zero_roundtrip() {
    let sid = SessionId::zero();
    let h = DataHeader::new(sid, 0);
    let bytes = h.serialize();
    let restored = DataHeader::deserialize(&bytes).unwrap();
    assert!(restored.session_id.is_zero());
}

#[test]
fn test_node_id_all_ones() {
    let mut h = HandshakeHeader::new(MsgType::Hello);
    h.src_node_id = [0xFF; 16];
    h.dst_svc_id = [0xFF; 16];
    let bytes = h.serialize();
    let restored = HandshakeHeader::deserialize(&bytes).unwrap();
    assert_eq!(restored.src_node_id, [0xFF; 16]);
    assert_eq!(restored.dst_svc_id, [0xFF; 16]);
}

#[test]
fn test_deserialization_with_trailing_data() {
    // Extra bytes after header should be ignored (they're payload)
    let h = HandshakeHeader::new(MsgType::Hello);
    let mut bytes = h.serialize();
    bytes.extend_from_slice(&[0xAA; 100]); // trailing "payload"
    let restored = HandshakeHeader::deserialize(&bytes).unwrap();
    assert_eq!(restored.msg_type, MsgType::Hello);
}

#[test]
fn test_data_header_deserialization_with_payload() {
    let h = DataHeader::new(SessionId::generate(), 42);
    let mut bytes = h.serialize();
    bytes.extend_from_slice(&[0xBB; 200]); // encrypted payload
    let restored = DataHeader::deserialize(&bytes).unwrap();
    assert_eq!(restored.packet_seq, 42);
}

#[test]
fn test_invalid_msg_type_byte() {
    let mut bytes = HandshakeHeader::new(MsgType::Data).serialize();
    bytes[6] = 0xFF; // invalid MsgType
    let result = HandshakeHeader::deserialize(&bytes);
    assert!(result.is_err());
}

// ─── Replay Window Edge Cases ────────────────────────────────────────

#[test]
fn test_replay_window_exact_boundary() {
    let mut w = ReplayWindow::new(DEFAULT_REPLAY_WINDOW);
    // Fill window to position 63
    assert!(w.check_and_record(63));
    // Position 0 is exactly 63 behind (within 64-packet window)
    assert!(w.check_and_record(0));
    // Position 0 again is a replay
    assert!(!w.check_and_record(0));
}

#[test]
fn test_replay_window_one_past_boundary() {
    let mut w = ReplayWindow::new(DEFAULT_REPLAY_WINDOW);
    // Advance to position 64
    assert!(w.check_and_record(64));
    // Position 0 is now 64 behind — exactly at window edge
    assert!(!w.check_and_record(0), "seq 0 should be outside 64-packet window when highest is 64");
}

#[test]
fn test_replay_window_massive_jump() {
    let mut w = ReplayWindow::new(DEFAULT_REPLAY_WINDOW);
    assert!(w.check_and_record(0));
    // Jump way ahead
    assert!(w.check_and_record(1_000_000));
    // Old seq should be rejected
    assert!(!w.check_and_record(0));
    // Recent seq just before the jump should also be rejected (outside window)
    assert!(!w.check_and_record(999_900));
    // But seq just before the latest should be ok
    assert!(w.check_and_record(999_999));
}

#[test]
fn test_replay_window_interleaved_order() {
    let mut w = ReplayWindow::new(DEFAULT_REPLAY_WINDOW);
    // Simulate out-of-order arrivals
    let order = vec![5, 2, 8, 1, 10, 3, 7, 4, 6, 9];
    for seq in &order {
        assert!(w.check_and_record(*seq), "seq {} should be accepted", seq);
    }
    // All should be marked as seen now
    for seq in &order {
        assert!(!w.check_and_record(*seq), "seq {} should be rejected as replay", seq);
    }
}

#[test]
fn test_replay_window_monotonic_stress() {
    let mut w = ReplayWindow::new(DEFAULT_REPLAY_WINDOW);
    // Send 10000 sequential packets
    for i in 0..10_000u64 {
        assert!(w.check_and_record(i), "seq {} should be accepted", i);
    }
    // Last 64 should be marked seen
    for i in (10_000 - 64)..10_000u64 {
        assert!(!w.check_and_record(i), "seq {} should be duplicate", i);
    }
}

// ─── Key Direction Tests ─────────────────────────────────────────────

#[test]
fn test_key_direction_correctness() {
    let id_a = NodeIdentity::generate().unwrap();
    let id_b = NodeIdentity::generate().unwrap();

    let result = perform_handshake(&id_a, &id_b).unwrap();

    // Initiator send == Responder recv
    assert_eq!(
        result.initiator_session.send_key,
        result.responder_session.recv_key,
        "I.send must equal R.recv"
    );
    // Initiator recv == Responder send
    assert_eq!(
        result.initiator_session.recv_key,
        result.responder_session.send_key,
        "I.recv must equal R.send"
    );
    // Send and recv keys must be DIFFERENT (directional isolation)
    assert_ne!(
        result.initiator_session.send_key,
        result.initiator_session.recv_key,
        "send and recv keys must differ"
    );
}

#[test]
fn test_different_identity_pairs_produce_different_keys() {
    let id_a1 = NodeIdentity::generate().unwrap();
    let id_b1 = NodeIdentity::generate().unwrap();
    let id_a2 = NodeIdentity::generate().unwrap();
    let id_b2 = NodeIdentity::generate().unwrap();

    let r1 = perform_handshake(&id_a1, &id_b1).unwrap();
    let r2 = perform_handshake(&id_a2, &id_b2).unwrap();

    assert_ne!(
        r1.initiator_session.send_key,
        r2.initiator_session.send_key,
        "different identity pairs should produce different keys"
    );
}

#[test]
fn test_same_identities_different_sessions_different_keys() {
    // Even with the same identities, ephemeral keys differ each handshake
    let id_a = NodeIdentity::generate().unwrap();
    let id_b = NodeIdentity::generate().unwrap();

    let r1 = perform_handshake(&id_a, &id_b).unwrap();
    let r2 = perform_handshake(&id_a, &id_b).unwrap();

    assert_ne!(
        r1.initiator_session.send_key,
        r2.initiator_session.send_key,
        "same identities should still produce different session keys (PFS)"
    );
}

// ─── Pipeline Edge Cases ─────────────────────────────────────────────

#[test]
fn test_pipeline_hdrlen_discrimination() {
    // Verify that pipeline correctly distinguishes data vs handshake packets
    // by HdrLen, not by packet size
    let mut pipeline = Pipeline::new();
    let sid = SessionId::generate();
    let recv_key = [0xBB; 32];
    let session = SessionState::new(
        sid,
        NodeId::generate(),
        [0xAA; 32],
        recv_key,
        false,
    );
    pipeline.register_session(session);

    // Data packet with payload (total size > 95 bytes, but HdrLen = 11)
    let mut header = DataHeader::new(sid, 1);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&recv_key, &aad);
    let mut bytes = header.serialize();
    bytes.extend_from_slice(&[0xCC; 200]); // large payload makes total > 95

    assert_eq!(bytes.len(), 42 + 200, "total packet should be 242 bytes");
    assert_eq!(
        pipeline.process(&bytes),
        AdmissionResult::Pass,
        "data packet with large payload should pass (HdrLen=11, not misidentified as handshake)"
    );
}

#[test]
fn test_pipeline_many_sessions() {
    let mut pipeline = Pipeline::new();
    let mut session_ids = Vec::new();

    // Register 1000 sessions
    for _ in 0..1000 {
        let sid = SessionId::generate();
        let recv_key = [0xBB; 32];
        let session = SessionState::new(
            sid,
            NodeId::generate(),
            [0xAA; 32],
            recv_key,
            false,
        );
        pipeline.register_session(session);
        session_ids.push((sid, recv_key));
    }

    // Verify each session can pass
    for (sid, recv_key) in &session_ids {
        let mut header = DataHeader::new(*sid, 0);
        let aad = header.aad_bytes();
        header.header_auth_tag = compute_header_auth_tag(recv_key, &aad);
        let bytes = header.serialize();
        assert_eq!(pipeline.process(&bytes), AdmissionResult::Pass);
    }

    let snap = pipeline.counters.snapshot();
    assert_eq!(snap.passed, 1000);
}

#[test]
fn test_pipeline_correct_key_for_auth() {
    // Ensure Layer 3 uses the session's recv_key (not send_key)
    let mut pipeline = Pipeline::new();
    let sid = SessionId::generate();
    let send_key = [0xAA; 32];
    let recv_key = [0xBB; 32];
    let session = SessionState::new(
        sid,
        NodeId::generate(),
        send_key,
        recv_key,
        false,
    );
    pipeline.register_session(session);

    // Sign with recv_key (what the remote's send_key would be) → should pass
    let mut header = DataHeader::new(sid, 0);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&recv_key, &aad);
    assert_eq!(
        pipeline.process(&header.serialize()),
        AdmissionResult::Pass,
        "packet signed with recv_key should pass"
    );

    // Sign with send_key → should fail Layer 3
    let mut header2 = DataHeader::new(sid, 1);
    let aad2 = header2.aad_bytes();
    header2.header_auth_tag = compute_header_auth_tag(&send_key, &aad2);
    assert_eq!(
        pipeline.process(&header2.serialize()),
        AdmissionResult::Drop,
        "packet signed with wrong key should fail Layer 3"
    );
}

#[test]
fn test_pipeline_hello_ack_passes_without_session() {
    let pipeline = Pipeline::new();
    let header = HandshakeHeader::new(MsgType::HelloAck);
    let bytes = header.serialize();

    // HELLO_ACK should pass Layer 2 (establishing sessions)
    assert_eq!(
        pipeline.layer2_session_check(&bytes),
        AdmissionResult::Pass,
        "HELLO_ACK should pass Layer 2"
    );
}

#[test]
fn test_pipeline_3_byte_packet() {
    // 3 bytes: enough for magic check but not for layer 2
    let pipeline = Pipeline::new();
    let data = vec![0x5A, 0x37, 0x10]; // valid magic, then truncated
    assert_eq!(pipeline.layer1_magic_check(&data), AdmissionResult::Pass);
    assert_eq!(pipeline.layer2_session_check(&data), AdmissionResult::Drop);
}

// ─── Auth Tag Tests ──────────────────────────────────────────────────

#[test]
fn test_auth_tag_deterministic() {
    let key = [0x42; 32];
    let aad = b"some authenticated data";
    let tag1 = compute_header_auth_tag(&key, aad);
    let tag2 = compute_header_auth_tag(&key, aad);
    assert_eq!(tag1, tag2, "same key + AAD should produce same tag");
}

#[test]
fn test_auth_tag_different_keys() {
    let key1 = [0x42; 32];
    let key2 = [0x43; 32];
    let aad = b"same data";
    let tag1 = compute_header_auth_tag(&key1, aad);
    let tag2 = compute_header_auth_tag(&key2, aad);
    assert_ne!(tag1, tag2, "different keys should produce different tags");
}

#[test]
fn test_auth_tag_different_aad() {
    let key = [0x42; 32];
    let tag1 = compute_header_auth_tag(&key, b"data A");
    let tag2 = compute_header_auth_tag(&key, b"data B");
    assert_ne!(tag1, tag2, "different AAD should produce different tags");
}

#[test]
fn test_auth_tag_empty_aad() {
    let key = [0x42; 32];
    let tag = compute_header_auth_tag(&key, b"");
    assert_ne!(tag, [0u8; 16], "even empty AAD should produce non-zero tag");
}

// ─── Session State Tests ─────────────────────────────────────────────

#[test]
fn test_session_send_seq_increments() {
    let mut session = SessionState::new(
        SessionId::generate(),
        NodeId::generate(),
        [0xAA; 32],
        [0xBB; 32],
        false,
    );

    assert_eq!(session.next_send_seq(), 0);
    assert_eq!(session.next_send_seq(), 1);
    assert_eq!(session.next_send_seq(), 2);
    assert_eq!(session.next_send_seq(), 3);
}

#[test]
fn test_session_replay_check_integration() {
    let mut session = SessionState::new(
        SessionId::generate(),
        NodeId::generate(),
        [0xAA; 32],
        [0xBB; 32],
        false,
    );

    assert!(session.check_replay(0), "first packet should be accepted");
    assert!(session.check_replay(1), "sequential packet should be accepted");
    assert!(!session.check_replay(0), "replay should be rejected");
    assert!(session.check_replay(5), "skip should be accepted");
    assert!(session.check_replay(3), "fill gap should be accepted");
}

// ─── Identity Edge Cases ─────────────────────────────────────────────

#[test]
fn test_node_id_uniqueness_bulk() {
    use std::collections::HashSet;
    let mut ids = HashSet::new();
    for _ in 0..10_000 {
        let id = NodeId::generate();
        assert!(ids.insert(id), "NodeID collision in 10K generations!");
    }
}

#[test]
fn test_session_id_uniqueness_bulk() {
    use std::collections::HashSet;
    let mut ids = HashSet::new();
    for _ in 0..10_000 {
        let id = SessionId::generate();
        assert!(ids.insert(id), "SessionID collision in 10K generations!");
    }
}

#[test]
fn test_identity_keys_are_32_bytes() {
    let ident = NodeIdentity::generate().unwrap();
    assert_eq!(ident.static_private_key.len(), 32, "private key must be 32 bytes");
    assert_eq!(ident.static_public_key.len(), 32, "public key must be 32 bytes");
}

#[test]
fn test_identity_keys_are_not_all_zeros() {
    let ident = NodeIdentity::generate().unwrap();
    assert_ne!(ident.static_private_key, vec![0u8; 32]);
    assert_ne!(ident.static_public_key, vec![0u8; 32]);
}

#[test]
fn test_different_identities_have_different_keys() {
    let id1 = NodeIdentity::generate().unwrap();
    let id2 = NodeIdentity::generate().unwrap();
    assert_ne!(id1.static_private_key, id2.static_private_key);
    assert_ne!(id1.static_public_key, id2.static_public_key);
    assert_ne!(id1.node_id, id2.node_id);
}
