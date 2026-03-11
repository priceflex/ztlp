//! Pipeline admission tests — each layer tested independently with crafted packets.

use ztlp_proto::identity::NodeId;
use ztlp_proto::packet::*;
use ztlp_proto::pipeline::*;
use ztlp_proto::session::SessionState;

fn make_test_session(session_id: SessionId) -> SessionState {
    let send_key = [0xAA; 32];
    let recv_key = [0xBB; 32];
    SessionState::new(session_id, NodeId::generate(), send_key, recv_key, false)
}

#[test]
fn test_layer1_rejects_garbage() {
    let pipeline = Pipeline::new();

    // Random garbage — no ZTLP magic
    let garbage = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    assert_eq!(
        pipeline.layer1_magic_check(&garbage),
        AdmissionResult::Drop,
        "garbage should fail layer 1"
    );
}

#[test]
fn test_layer1_rejects_empty() {
    let pipeline = Pipeline::new();
    assert_eq!(
        pipeline.layer1_magic_check(&[]),
        AdmissionResult::Drop,
        "empty packet should fail layer 1"
    );
}

#[test]
fn test_layer1_rejects_single_byte() {
    let pipeline = Pipeline::new();
    assert_eq!(
        pipeline.layer1_magic_check(&[0x5A]),
        AdmissionResult::Drop,
        "single byte should fail layer 1"
    );
}

#[test]
fn test_layer1_passes_valid_magic() {
    let pipeline = Pipeline::new();

    // Valid ZTLP magic
    let mut packet = vec![0x5A, 0x37];
    packet.extend_from_slice(&[0u8; 93]); // pad to handshake header size
    assert_eq!(
        pipeline.layer1_magic_check(&packet),
        AdmissionResult::Pass,
        "valid magic should pass layer 1"
    );
}

#[test]
fn test_layer2_rejects_unknown_session() {
    let pipeline = Pipeline::new();

    // Create a data header with a random SessionID (not registered)
    let header = DataHeader::new(SessionId::generate(), 0);
    let bytes = header.serialize();

    assert_eq!(
        pipeline.layer2_session_check(&bytes),
        AdmissionResult::Drop,
        "unknown session should fail layer 2"
    );
}

#[test]
fn test_layer2_passes_known_session() {
    let mut pipeline = Pipeline::new();
    let sid = SessionId::generate();
    pipeline.register_session(make_test_session(sid));

    // Data header with the registered SessionID
    let header = DataHeader::new(sid, 0);
    let bytes = header.serialize();

    assert_eq!(
        pipeline.layer2_session_check(&bytes),
        AdmissionResult::Pass,
        "known session should pass layer 2"
    );
}

#[test]
fn test_layer2_passes_hello() {
    let pipeline = Pipeline::new();

    // HELLO message should pass Layer 2 even without a session
    let header = HandshakeHeader::new(MsgType::Hello);
    let bytes = header.serialize();

    assert_eq!(
        pipeline.layer2_session_check(&bytes),
        AdmissionResult::Pass,
        "HELLO should pass layer 2"
    );
}

#[test]
fn test_layer3_rejects_bad_auth_tag() {
    let mut pipeline = Pipeline::new();
    let sid = SessionId::generate();
    pipeline.register_session(make_test_session(sid));

    // Data header with wrong auth tag
    let mut header = DataHeader::new(sid, 0);
    header.header_auth_tag = [0xFF; 16]; // bad tag
    let bytes = header.serialize();

    assert_eq!(
        pipeline.layer3_auth_check(&bytes),
        AdmissionResult::Drop,
        "bad auth tag should fail layer 3"
    );
}

#[test]
fn test_layer3_passes_valid_auth_tag() {
    let mut pipeline = Pipeline::new();
    let sid = SessionId::generate();
    let recv_key = [0xBB; 32];
    let session = SessionState::new(sid, NodeId::generate(), [0xAA; 32], recv_key, false);
    pipeline.register_session(session);

    // Create a data header and compute the correct auth tag
    let mut header = DataHeader::new(sid, 0);
    let aad = header.aad_bytes();
    // The pipeline verifies with recv_key, so we sign with recv_key
    header.header_auth_tag = compute_header_auth_tag(&recv_key, &aad);
    let bytes = header.serialize();

    assert_eq!(
        pipeline.layer3_auth_check(&bytes),
        AdmissionResult::Pass,
        "valid auth tag should pass layer 3"
    );
}

#[test]
fn test_full_pipeline_pass() {
    let mut pipeline = Pipeline::new();
    let sid = SessionId::generate();
    let recv_key = [0xBB; 32];
    let session = SessionState::new(sid, NodeId::generate(), [0xAA; 32], recv_key, false);
    pipeline.register_session(session);

    // Build a valid data packet
    let mut header = DataHeader::new(sid, 1);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&recv_key, &aad);
    let bytes = header.serialize();

    assert_eq!(
        pipeline.process(&bytes),
        AdmissionResult::Pass,
        "fully valid packet should pass all layers"
    );

    let snap = pipeline.counters.snapshot();
    assert_eq!(snap.passed, 1);
    assert_eq!(snap.layer1_drops, 0);
    assert_eq!(snap.layer2_drops, 0);
    assert_eq!(snap.layer3_drops, 0);
}

#[test]
fn test_full_pipeline_drop_counters() {
    let mut pipeline = Pipeline::new();
    let sid = SessionId::generate();
    let recv_key = [0xBB; 32];
    let session = SessionState::new(sid, NodeId::generate(), [0xAA; 32], recv_key, false);
    pipeline.register_session(session);

    // Layer 1 drop: bad magic
    let garbage = vec![0xFF, 0xFF, 0x00, 0x00];
    pipeline.process(&garbage);

    // Layer 2 drop: unknown session
    let unknown = DataHeader::new(SessionId::generate(), 0).serialize();
    pipeline.process(&unknown);

    // Layer 3 drop: bad auth tag
    let mut bad_auth = DataHeader::new(sid, 0);
    bad_auth.header_auth_tag = [0xFF; 16];
    pipeline.process(&bad_auth.serialize());

    let snap = pipeline.counters.snapshot();
    assert_eq!(snap.layer1_drops, 1, "should have 1 L1 drop");
    assert_eq!(snap.layer2_drops, 1, "should have 1 L2 drop");
    assert_eq!(snap.layer3_drops, 1, "should have 1 L3 drop");
    assert_eq!(snap.passed, 0, "nothing should have passed");
}

#[test]
fn test_pipeline_session_removal() {
    let mut pipeline = Pipeline::new();
    let sid = SessionId::generate();
    pipeline.register_session(make_test_session(sid));

    // Should exist
    assert!(pipeline.get_session(&sid).is_some());

    // Remove it
    pipeline.remove_session(&sid);
    assert!(pipeline.get_session(&sid).is_none());

    // Now layer 2 should reject it
    let header = DataHeader::new(sid, 0);
    let bytes = header.serialize();
    assert_eq!(pipeline.layer2_session_check(&bytes), AdmissionResult::Drop,);
}
