//! Relay support tests.
//!
//! Tests cover:
//! - RELAY_HOP flag setting/checking on DataHeader and HandshakeHeader
//! - `send_data_via_relay` sends correctly formatted packets
//! - Simulated relay forwarding
//! - Relay-forwarded packets decrypt correctly end-to-end

#![deny(unsafe_code)]

use tokio::time::{sleep, Duration};

use ztlp_proto::handshake::perform_handshake;
use ztlp_proto::identity::NodeIdentity;
use ztlp_proto::packet::{
    flags, DataHeader, HandshakeHeader, MsgType, SessionId, DATA_HEADER_SIZE,
};
use ztlp_proto::relay::SimulatedRelay;
use ztlp_proto::transport::TransportNode;

// ── RELAY_HOP flag tests ─────────────────────────────────────────────

#[test]
fn test_data_header_relay_hop_default_unset() {
    let header = DataHeader::new(SessionId::generate(), 0);
    assert!(!header.is_relay_hop());
}

#[test]
fn test_data_header_set_relay_hop() {
    let mut header = DataHeader::new(SessionId::generate(), 0);
    header.set_relay_hop();
    assert!(header.is_relay_hop());
    // Verify the flag bit is correct
    assert_ne!(header.flags & flags::RELAY_HOP, 0);
}

#[test]
fn test_data_header_relay_hop_survives_serialize_roundtrip() {
    let mut header = DataHeader::new(SessionId::generate(), 42);
    header.set_relay_hop();
    let bytes = header.serialize();
    let deserialized = DataHeader::deserialize(&bytes).expect("deserialize");
    assert!(deserialized.is_relay_hop());
    assert_eq!(deserialized.packet_seq, 42);
}

#[test]
fn test_data_header_relay_hop_preserves_other_flags() {
    let mut header = DataHeader::new(SessionId::generate(), 0);
    header.flags = flags::ACK_REQ | flags::MULTIPATH;
    header.set_relay_hop();
    assert!(header.is_relay_hop());
    assert_ne!(header.flags & flags::ACK_REQ, 0);
    assert_ne!(header.flags & flags::MULTIPATH, 0);
}

#[test]
fn test_handshake_header_relay_hop_default_unset() {
    let header = HandshakeHeader::new(MsgType::Hello);
    assert!(!header.is_relay_hop());
}

#[test]
fn test_handshake_header_set_relay_hop() {
    let mut header = HandshakeHeader::new(MsgType::Hello);
    header.set_relay_hop();
    assert!(header.is_relay_hop());
}

#[test]
fn test_handshake_header_relay_hop_survives_serialize_roundtrip() {
    let mut header = HandshakeHeader::new(MsgType::HelloAck);
    header.set_relay_hop();
    let bytes = header.serialize();
    let deserialized = HandshakeHeader::deserialize(&bytes).expect("deserialize");
    assert!(deserialized.is_relay_hop());
    assert_eq!(deserialized.msg_type, MsgType::HelloAck);
}

// ── send_data_via_relay tests ────────────────────────────────────────

#[tokio::test]
async fn test_send_data_via_relay_produces_valid_packet() {
    // Set up two nodes and a session
    let node_a = TransportNode::bind("127.0.0.1:0").await.expect("bind A");
    let node_b = TransportNode::bind("127.0.0.1:0").await.expect("bind B");

    let id_a = NodeIdentity::generate().expect("identity A");
    let id_b = NodeIdentity::generate().expect("identity B");

    let result = perform_handshake(&id_a, &id_b).expect("handshake");

    let session_id = result.initiator_session.session_id;

    // Register sessions
    {
        let mut pipe = node_a.pipeline.lock().await;
        pipe.register_session(result.initiator_session);
    }
    {
        let mut pipe = node_b.pipeline.lock().await;
        pipe.register_session(result.responder_session);
    }

    // Use a "relay" address — in this test, we just send to node_b directly
    // to verify the packet format is identical.
    let relay_addr = node_b.local_addr;

    node_a
        .send_data_via_relay(session_id, b"test relay payload", relay_addr)
        .await
        .expect("send via relay");

    sleep(Duration::from_millis(50)).await;

    // B should be able to decrypt it — proving the packet format is the same
    let received = node_b.recv_data().await.expect("recv data");
    let (plaintext, _from) = received.expect("should have data");
    assert_eq!(plaintext, b"test relay payload");
}

// ── Simulated relay forwarding tests ─────────────────────────────────

#[tokio::test]
async fn test_simulated_relay_pairs_and_forwards() {
    let relay = SimulatedRelay::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay.local_addr;

    // Spawn relay loop
    tokio::spawn(async move {
        relay.run().await.expect("relay loop");
    });

    // Two plain UDP sockets to simulate peers
    let sock_a = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind A");
    let sock_b = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind B");

    let session_id = SessionId::generate();

    // Build a data packet with the shared session ID
    let build_data_packet = |sid: SessionId, seq: u64, payload: &[u8]| -> Vec<u8> {
        let header = DataHeader::new(sid, seq);
        let mut buf = header.serialize();
        buf.extend_from_slice(payload);
        buf
    };

    // A sends to relay (first peer — becomes pending)
    let pkt_a = build_data_packet(session_id, 1, b"from_a");
    sock_a
        .send_to(&pkt_a, relay_addr)
        .await
        .expect("A send to relay");
    sleep(Duration::from_millis(30)).await;

    // B sends to relay (second peer — relay pairs them, forwards B's pkt to A)
    let pkt_b = build_data_packet(session_id, 2, b"from_b");
    sock_b
        .send_to(&pkt_b, relay_addr)
        .await
        .expect("B send to relay");
    sleep(Duration::from_millis(30)).await;

    // A should receive B's packet (forwarded by relay)
    let mut buf = vec![0u8; 65535];
    let (len, _from) = tokio::time::timeout(Duration::from_millis(200), sock_a.recv_from(&mut buf))
        .await
        .expect("timeout waiting for relay forward to A")
        .expect("recv from relay");
    let received_payload = &buf[DATA_HEADER_SIZE..len];
    assert_eq!(received_payload, b"from_b");

    // Now A sends again — relay forwards to B
    let pkt_a2 = build_data_packet(session_id, 3, b"from_a_again");
    sock_a
        .send_to(&pkt_a2, relay_addr)
        .await
        .expect("A send again");
    sleep(Duration::from_millis(30)).await;

    let (len2, _from2) =
        tokio::time::timeout(Duration::from_millis(200), sock_b.recv_from(&mut buf))
            .await
            .expect("timeout waiting for relay forward to B")
            .expect("recv from relay");
    let received_payload2 = &buf[DATA_HEADER_SIZE..len2];
    assert_eq!(received_payload2, b"from_a_again");
}

#[tokio::test]
async fn test_relay_forwards_handshake_packets() {
    let relay = SimulatedRelay::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay.local_addr;

    tokio::spawn(async move {
        relay.run().await.expect("relay loop");
    });

    let sock_a = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind A");
    let sock_b = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind B");

    let session_id = SessionId::generate();

    // Build a handshake packet
    let build_hs_packet = |sid: SessionId, msg_type: MsgType, payload: &[u8]| -> Vec<u8> {
        let mut header = HandshakeHeader::new(msg_type);
        header.session_id = sid;
        header.payload_len = payload.len() as u16;
        let mut buf = header.serialize();
        buf.extend_from_slice(payload);
        buf
    };

    // A sends HELLO to relay
    let hello = build_hs_packet(session_id, MsgType::Hello, b"noise_msg1");
    sock_a
        .send_to(&hello, relay_addr)
        .await
        .expect("send HELLO");
    sleep(Duration::from_millis(30)).await;

    // B sends registration to relay (same SessionID)
    let reg = build_hs_packet(session_id, MsgType::Hello, b"register");
    sock_b
        .send_to(&reg, relay_addr)
        .await
        .expect("send registration");
    sleep(Duration::from_millis(30)).await;

    // A should receive B's registration (forwarded by relay)
    let mut buf = vec![0u8; 65535];
    let (len, _) = tokio::time::timeout(Duration::from_millis(200), sock_a.recv_from(&mut buf))
        .await
        .expect("timeout")
        .expect("recv");

    // Verify it's a valid handshake packet with correct session ID
    let header = HandshakeHeader::deserialize(&buf[..len]).expect("deserialize");
    assert_eq!(header.session_id, session_id);
}

// ── End-to-end relay encryption test ─────────────────────────────────

#[tokio::test]
async fn test_relay_forwarded_packets_decrypt_correctly() {
    // Full end-to-end: handshake → session → encrypted data through relay
    let relay = SimulatedRelay::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay.local_addr;

    tokio::spawn(async move {
        relay.run().await.expect("relay loop");
    });

    let id_a = NodeIdentity::generate().expect("identity A");
    let id_b = NodeIdentity::generate().expect("identity B");

    let node_a = TransportNode::bind("127.0.0.1:0").await.expect("bind A");
    let node_b = TransportNode::bind("127.0.0.1:0").await.expect("bind B");

    // Perform in-process handshake (we already tested relay handshake forwarding above)
    let hs_result = perform_handshake(&id_a, &id_b).expect("handshake");
    let session_id = hs_result.initiator_session.session_id;

    // Register with relay by sending dummy packets
    let reg_a = DataHeader::new(session_id, 0).serialize();
    node_a
        .send_raw(&reg_a, relay_addr)
        .await
        .expect("register A with relay");
    sleep(Duration::from_millis(20)).await;

    let reg_b = DataHeader::new(session_id, 0).serialize();
    node_b
        .send_raw(&reg_b, relay_addr)
        .await
        .expect("register B with relay");
    sleep(Duration::from_millis(20)).await;

    // Drain the forwarded registration packet
    let _ = tokio::time::timeout(Duration::from_millis(100), node_a.recv_raw()).await;

    // Register sessions in pipelines
    {
        let mut pipe = node_a.pipeline.lock().await;
        pipe.register_session(hs_result.initiator_session);
    }
    {
        let mut pipe = node_b.pipeline.lock().await;
        pipe.register_session(hs_result.responder_session);
    }

    // A sends encrypted data through relay
    node_a
        .send_data_via_relay(session_id, b"secret message via relay", relay_addr)
        .await
        .expect("send via relay");

    sleep(Duration::from_millis(50)).await;

    // B receives and decrypts
    let received = node_b.recv_data().await.expect("recv data");
    let (plaintext, from_addr) = received.expect("should have data");
    assert_eq!(plaintext, b"secret message via relay");

    // Verify the packet came from the relay, not from A directly
    assert_eq!(from_addr, relay_addr, "packet should come from relay address");

    // Now test B → A direction
    node_b
        .send_data_via_relay(session_id, b"reply through relay", relay_addr)
        .await
        .expect("send reply via relay");

    sleep(Duration::from_millis(50)).await;

    let reply = node_a.recv_data().await.expect("recv reply");
    let (reply_text, reply_from) = reply.expect("should have reply");
    assert_eq!(reply_text, b"reply through relay");
    assert_eq!(reply_from, relay_addr, "reply should come from relay address");
}
