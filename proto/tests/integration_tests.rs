//! Integration tests — end-to-end protocol flows over real UDP sockets.
//!
//! These tests exercise the full stack: identity → handshake → session →
//! pipeline → transport, using actual async UDP on localhost.

use std::time::Duration;
use tokio::time::{sleep, timeout};

use ztlp_proto::handshake::HandshakeContext;
use ztlp_proto::identity::NodeIdentity;
use ztlp_proto::packet::*;
use ztlp_proto::session::SessionState;
use ztlp_proto::transport::TransportNode;

/// Helper: perform a full handshake over UDP and return established sessions.
async fn setup_session() -> (
    TransportNode,
    TransportNode,
    NodeIdentity,
    NodeIdentity,
    SessionId,
) {
    let id_a = NodeIdentity::generate().unwrap();
    let id_b = NodeIdentity::generate().unwrap();

    let node_a = TransportNode::bind("127.0.0.1:0").await.unwrap();
    let node_b = TransportNode::bind("127.0.0.1:0").await.unwrap();
    let addr_a = node_a.local_addr;
    let addr_b = node_b.local_addr;

    // Noise_XX handshake
    let mut init_ctx = HandshakeContext::new_initiator(&id_a).unwrap();
    let mut resp_ctx = HandshakeContext::new_responder(&id_b).unwrap();

    // Message 1: A → B
    let msg1 = init_ctx.write_message(&[]).unwrap();
    let mut hdr1 = HandshakeHeader::new(MsgType::Hello);
    hdr1.src_node_id = *id_a.node_id.as_bytes();
    hdr1.payload_len = msg1.len() as u16;
    let mut pkt1 = hdr1.serialize();
    pkt1.extend_from_slice(&msg1);
    node_a.send_raw(&pkt1, addr_b).await.unwrap();

    let (recv1, _) = node_b.recv_raw().await.unwrap();
    let noise1 = &recv1[HANDSHAKE_HEADER_SIZE..];
    resp_ctx.read_message(noise1).unwrap();

    // Message 2: B → A
    let msg2 = resp_ctx.write_message(&[]).unwrap();
    let mut hdr2 = HandshakeHeader::new(MsgType::HelloAck);
    hdr2.src_node_id = *id_b.node_id.as_bytes();
    hdr2.payload_len = msg2.len() as u16;
    let mut pkt2 = hdr2.serialize();
    pkt2.extend_from_slice(&msg2);
    node_b.send_raw(&pkt2, addr_a).await.unwrap();

    let (recv2, _) = node_a.recv_raw().await.unwrap();
    let noise2 = &recv2[HANDSHAKE_HEADER_SIZE..];
    init_ctx.read_message(noise2).unwrap();

    // Message 3: A → B
    let msg3 = init_ctx.write_message(&[]).unwrap();
    let mut hdr3 = HandshakeHeader::new(MsgType::Data);
    hdr3.src_node_id = *id_a.node_id.as_bytes();
    hdr3.payload_len = msg3.len() as u16;
    let mut pkt3 = hdr3.serialize();
    pkt3.extend_from_slice(&msg3);
    node_a.send_raw(&pkt3, addr_b).await.unwrap();

    let (recv3, _) = node_b.recv_raw().await.unwrap();
    let noise3 = &recv3[HANDSHAKE_HEADER_SIZE..];
    resp_ctx.read_message(noise3).unwrap();

    assert!(init_ctx.is_finished());
    assert!(resp_ctx.is_finished());

    // Establish session
    let session_id = SessionId::generate();
    let (_, init_session) = init_ctx.finalize(id_b.node_id, session_id).unwrap();
    let (_, resp_session) = resp_ctx.finalize(id_a.node_id, session_id).unwrap();

    let a_session = SessionState::new(
        session_id,
        id_b.node_id,
        init_session.send_key,
        init_session.recv_key,
        false,
    );
    let b_session = SessionState::new(
        session_id,
        id_a.node_id,
        resp_session.send_key,
        resp_session.recv_key,
        false,
    );

    {
        let mut pipe_a = node_a.pipeline.lock().await;
        pipe_a.register_session(a_session);
    }
    {
        let mut pipe_b = node_b.pipeline.lock().await;
        pipe_b.register_session(b_session);
    }

    (node_a, node_b, id_a, id_b, session_id)
}

// ─── Data Exchange Tests ─────────────────────────────────────────────

#[tokio::test]
async fn test_encrypted_data_a_to_b() {
    let (node_a, node_b, _, _, session_id) = setup_session().await;
    let addr_b = node_b.local_addr;

    let plaintext = b"Hello from Node A!";
    node_a.send_data(session_id, plaintext, addr_b).await.unwrap();

    let result = timeout(Duration::from_secs(2), node_b.recv_data()).await;
    let received = result.expect("timeout").expect("recv error");
    assert!(received.is_some(), "should receive data");
    let (data, _from) = received.unwrap();
    assert_eq!(data, plaintext, "decrypted data should match plaintext");
}

#[tokio::test]
async fn test_encrypted_data_b_to_a() {
    let (node_a, node_b, _, _, session_id) = setup_session().await;
    let addr_a = node_a.local_addr;

    let plaintext = b"Hello from Node B!";
    node_b.send_data(session_id, plaintext, addr_a).await.unwrap();

    let result = timeout(Duration::from_secs(2), node_a.recv_data()).await;
    let received = result.expect("timeout").expect("recv error");
    assert!(received.is_some(), "should receive data");
    let (data, _from) = received.unwrap();
    assert_eq!(data, plaintext, "decrypted data should match plaintext");
}

#[tokio::test]
async fn test_bidirectional_data_exchange() {
    let (node_a, node_b, _, _, session_id) = setup_session().await;
    let addr_a = node_a.local_addr;
    let addr_b = node_b.local_addr;

    // A → B
    node_a.send_data(session_id, b"ping", addr_b).await.unwrap();
    sleep(Duration::from_millis(20)).await;
    let recv = timeout(Duration::from_secs(2), node_b.recv_data())
        .await.unwrap().unwrap();
    assert_eq!(recv.unwrap().0, b"ping");

    // B → A
    node_b.send_data(session_id, b"pong", addr_a).await.unwrap();
    sleep(Duration::from_millis(20)).await;
    let recv = timeout(Duration::from_secs(2), node_a.recv_data())
        .await.unwrap().unwrap();
    assert_eq!(recv.unwrap().0, b"pong");
}

#[tokio::test]
async fn test_multiple_messages_sequential() {
    let (node_a, node_b, _, _, session_id) = setup_session().await;
    let addr_b = node_b.local_addr;

    for i in 0..10u32 {
        let msg = format!("message {}", i);
        node_a.send_data(session_id, msg.as_bytes(), addr_b).await.unwrap();
        sleep(Duration::from_millis(10)).await;

        let recv = timeout(Duration::from_secs(2), node_b.recv_data())
            .await.unwrap().unwrap();
        let (data, _) = recv.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&data),
            msg,
            "message {} mismatch",
            i
        );
    }
}

#[tokio::test]
async fn test_empty_payload() {
    let (node_a, node_b, _, _, session_id) = setup_session().await;
    let addr_b = node_b.local_addr;

    node_a.send_data(session_id, b"", addr_b).await.unwrap();
    sleep(Duration::from_millis(20)).await;

    let recv = timeout(Duration::from_secs(2), node_b.recv_data())
        .await.unwrap().unwrap();
    let (data, _) = recv.unwrap();
    assert_eq!(data.len(), 0, "empty payload should decrypt to empty");
}

#[tokio::test]
async fn test_large_payload() {
    let (node_a, node_b, _, _, session_id) = setup_session().await;
    let addr_b = node_b.local_addr;

    // 8KB payload (well within UDP limits)
    let payload: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
    node_a.send_data(session_id, &payload, addr_b).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    let recv = timeout(Duration::from_secs(2), node_b.recv_data())
        .await.unwrap().unwrap();
    let (data, _) = recv.unwrap();
    assert_eq!(data, payload, "large payload should survive encrypt/decrypt");
}

// ─── Pipeline Rejection Tests (over real UDP) ────────────────────────

#[tokio::test]
async fn test_garbage_dropped_over_udp() {
    let (node_a, node_b, _, _, _session_id) = setup_session().await;
    let addr_b = node_b.local_addr;

    // Send garbage
    let garbage: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
    node_a.send_raw(&garbage, addr_b).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    // recv_data should return None (dropped by pipeline)
    let result = timeout(Duration::from_millis(200), node_b.recv_data()).await;
    match result {
        Ok(Ok(None)) => {} // expected: dropped
        Ok(Ok(Some(_))) => panic!("garbage should not pass pipeline"),
        _ => {} // timeout is also acceptable (packet was dropped)
    }

    let pipe = node_b.pipeline.lock().await;
    let snap = pipe.counters.snapshot();
    assert!(snap.layer1_drops >= 1, "should have at least 1 L1 drop");
}

#[tokio::test]
async fn test_wrong_session_dropped_over_udp() {
    let (node_a, node_b, _, _, _session_id) = setup_session().await;
    let addr_b = node_b.local_addr;

    // Valid magic/format but fake SessionID
    let fake_header = DataHeader::new(SessionId::generate(), 0);
    let fake_bytes = fake_header.serialize();
    node_a.send_raw(&fake_bytes, addr_b).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    let result = timeout(Duration::from_millis(200), node_b.recv_data()).await;
    match result {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(_))) => panic!("wrong session should not pass pipeline"),
        _ => {}
    }

    let pipe = node_b.pipeline.lock().await;
    let snap = pipe.counters.snapshot();
    assert!(snap.layer2_drops >= 1, "should have at least 1 L2 drop");
}

// ─── Identity Persistence Tests ──────────────────────────────────────

#[tokio::test]
async fn test_identity_save_and_reload() {
    let tmpdir = std::env::temp_dir().join(format!("ztlp-test-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&tmpdir).unwrap();
    let path = tmpdir.join("test_identity.json");

    let original = NodeIdentity::generate().unwrap();
    original.save(&path).unwrap();

    let loaded = NodeIdentity::load(&path).unwrap();
    assert_eq!(original.node_id, loaded.node_id);
    assert_eq!(original.static_private_key, loaded.static_private_key);
    assert_eq!(original.static_public_key, loaded.static_public_key);

    // Loaded identity should work for handshakes
    let other = NodeIdentity::generate().unwrap();
    let mut init = HandshakeContext::new_initiator(&loaded).unwrap();
    let mut resp = HandshakeContext::new_responder(&other).unwrap();

    let m1 = init.write_message(&[]).unwrap();
    resp.read_message(&m1).unwrap();
    let m2 = resp.write_message(&[]).unwrap();
    init.read_message(&m2).unwrap();
    let m3 = init.write_message(&[]).unwrap();
    resp.read_message(&m3).unwrap();

    assert!(init.is_finished());
    assert!(resp.is_finished());

    // Cleanup
    std::fs::remove_dir_all(&tmpdir).ok();
}
