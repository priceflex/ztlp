//! Handshake tests — full Noise_XX exchange in-process (no network).

use ztlp_proto::handshake::*;
use ztlp_proto::identity::NodeIdentity;
use ztlp_proto::packet::SessionId;

#[test]
fn test_full_handshake_in_process() {
    let initiator_id = NodeIdentity::generate().expect("generate initiator identity");
    let responder_id = NodeIdentity::generate().expect("generate responder identity");

    let result = perform_handshake(&initiator_id, &responder_id)
        .expect("handshake should succeed");

    // Both sides should have valid sessions
    assert!(
        !result.initiator_session.session_id.is_zero(),
        "initiator should have a non-zero SessionID"
    );
    assert!(
        !result.responder_session.session_id.is_zero(),
        "responder should have a non-zero SessionID"
    );

    // Peer NodeIDs should be correct
    assert_eq!(
        result.initiator_session.peer_node_id,
        responder_id.node_id,
        "initiator should know responder's NodeID"
    );
    assert_eq!(
        result.responder_session.peer_node_id,
        initiator_id.node_id,
        "responder should know initiator's NodeID"
    );

    // Keys should be non-zero
    assert_ne!(result.initiator_session.send_key, [0u8; 32]);
    assert_ne!(result.initiator_session.recv_key, [0u8; 32]);
    assert_ne!(result.responder_session.send_key, [0u8; 32]);
    assert_ne!(result.responder_session.recv_key, [0u8; 32]);

    // Initiator's send key should equal responder's recv key (and vice versa)
    assert_eq!(
        result.initiator_session.send_key,
        result.responder_session.recv_key,
        "initiator send key should match responder recv key"
    );
    assert_eq!(
        result.initiator_session.recv_key,
        result.responder_session.send_key,
        "initiator recv key should match responder send key"
    );
}

#[test]
fn test_handshake_message_flow() {
    let initiator_id = NodeIdentity::generate().expect("generate initiator");
    let responder_id = NodeIdentity::generate().expect("generate responder");

    let mut initiator = HandshakeContext::new_initiator(&initiator_id)
        .expect("create initiator");
    let mut responder = HandshakeContext::new_responder(&responder_id)
        .expect("create responder");

    assert_eq!(initiator.role, Role::Initiator);
    assert_eq!(responder.role, Role::Responder);
    assert!(!initiator.is_finished());
    assert!(!responder.is_finished());

    // Message 1: I → R
    let msg1 = initiator.write_message(&[]).expect("msg1");
    assert!(!msg1.is_empty(), "message 1 should contain data");
    let _p1 = responder.read_message(&msg1).expect("read msg1");

    // Message 2: R → I
    let msg2 = responder.write_message(&[]).expect("msg2");
    assert!(!msg2.is_empty(), "message 2 should contain data");
    let _p2 = initiator.read_message(&msg2).expect("read msg2");

    // Message 3: I → R
    let msg3 = initiator.write_message(&[]).expect("msg3");
    let _p3 = responder.read_message(&msg3).expect("read msg3");

    // Both should be finished
    assert!(initiator.is_finished(), "initiator should be finished");
    assert!(responder.is_finished(), "responder should be finished");
}

#[test]
fn test_handshake_with_payload() {
    let initiator_id = NodeIdentity::generate().expect("generate initiator");
    let responder_id = NodeIdentity::generate().expect("generate responder");

    let mut initiator = HandshakeContext::new_initiator(&initiator_id)
        .expect("create initiator");
    let mut responder = HandshakeContext::new_responder(&responder_id)
        .expect("create responder");

    // Message 1 with no payload (Noise_XX first message can't carry encrypted payload)
    let msg1 = initiator.write_message(&[]).expect("msg1");
    let _p1 = responder.read_message(&msg1).expect("read msg1");

    // Message 2 can carry encrypted payload
    let msg2 = responder.write_message(b"hello from responder").expect("msg2");
    let p2 = initiator.read_message(&msg2).expect("read msg2");
    assert_eq!(&p2, b"hello from responder");

    // Message 3 can carry encrypted payload
    let msg3 = initiator.write_message(b"hello from initiator").expect("msg3");
    let p3 = responder.read_message(&msg3).expect("read msg3");
    assert_eq!(&p3, b"hello from initiator");
}

#[test]
fn test_handshake_finalize_before_complete() {
    let initiator_id = NodeIdentity::generate().expect("generate initiator");
    let responder_id = NodeIdentity::generate().expect("generate responder");

    let mut initiator = HandshakeContext::new_initiator(&initiator_id)
        .expect("create initiator");
    let mut _responder = HandshakeContext::new_responder(&responder_id)
        .expect("create responder");

    // Only do message 1
    let _msg1 = initiator.write_message(&[]).expect("msg1");

    // Try to finalize before handshake is complete — should fail
    let result = initiator.finalize(responder_id.node_id, SessionId::generate());
    assert!(result.is_err(), "finalize before completion should fail");
}

#[test]
fn test_multiple_handshakes_produce_different_keys() {
    let initiator_id = NodeIdentity::generate().expect("generate initiator");
    let responder_id = NodeIdentity::generate().expect("generate responder");

    let result1 = perform_handshake(&initiator_id, &responder_id)
        .expect("handshake 1");
    let result2 = perform_handshake(&initiator_id, &responder_id)
        .expect("handshake 2");

    // Different sessions should have different keys (ephemeral key exchange)
    assert_ne!(
        result1.initiator_session.send_key,
        result2.initiator_session.send_key,
        "different handshakes should produce different keys"
    );
    assert_ne!(
        result1.initiator_session.session_id,
        result2.initiator_session.session_id,
        "different handshakes should produce different session IDs"
    );
}
