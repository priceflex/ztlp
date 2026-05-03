//! Stress tests for the ZTLP protocol core.
//!
//! Nebula-pivot R4: the original reliability-focused tests (reassembly, ACK/
//! NACK/SACK, retransmission, congestion control under loss — ~460 LOC) were
//! removed when the reliability layer was deleted. What remains here are the
//! pieces that still apply to the fire-and-forget Nebula-style core:
//! encrypted-pipeline burst throughput, session-manager capacity/cleanup,
//! policy-engine sanity, and concurrent handshakes.

use std::collections::HashSet;
use std::time::Duration;

use tokio::time::{timeout, Instant};

use ztlp_proto::handshake::HandshakeContext;
use ztlp_proto::identity::NodeIdentity;
use ztlp_proto::packet::*;
use ztlp_proto::session::SessionState;
use ztlp_proto::transport::TransportNode;

// ─── Encrypted burst throughput ─────────────────────────────────────────────

#[tokio::test]
async fn test_encrypted_burst_500_packets() {
    // Set up a full handshake using the same pattern as integration_tests.rs
    let id_a = NodeIdentity::generate().expect("keygen");
    let id_b = NodeIdentity::generate().expect("keygen");

    let node_a = TransportNode::bind("127.0.0.1:0").await.expect("bind A");
    let node_b = TransportNode::bind("127.0.0.1:0").await.expect("bind B");
    let addr_a = node_a.local_addr;
    let addr_b = node_b.local_addr;

    let mut init_ctx = HandshakeContext::new_initiator(&id_a).expect("init");
    let mut resp_ctx = HandshakeContext::new_responder(&id_b).expect("resp");

    // Msg 1: A → B
    let msg1 = init_ctx.write_message(&[]).expect("msg1");
    let mut hdr1 = HandshakeHeader::new(MsgType::Hello);
    hdr1.src_node_id = *id_a.node_id.as_bytes();
    hdr1.payload_len = msg1.len() as u16;
    let mut pkt1 = hdr1.serialize();
    pkt1.extend_from_slice(&msg1);
    node_a.send_raw(&pkt1, addr_b).await.expect("send1");
    let (r1, _) = node_b.recv_raw().await.expect("recv1");
    resp_ctx
        .read_message(&r1[HANDSHAKE_HEADER_SIZE..])
        .expect("read1");

    // Msg 2: B → A
    let msg2 = resp_ctx.write_message(&[]).expect("msg2");
    let mut hdr2 = HandshakeHeader::new(MsgType::HelloAck);
    hdr2.src_node_id = *id_b.node_id.as_bytes();
    hdr2.payload_len = msg2.len() as u16;
    let mut pkt2 = hdr2.serialize();
    pkt2.extend_from_slice(&msg2);
    node_b.send_raw(&pkt2, addr_a).await.expect("send2");
    let (r2, _) = node_a.recv_raw().await.expect("recv2");
    init_ctx
        .read_message(&r2[HANDSHAKE_HEADER_SIZE..])
        .expect("read2");

    // Msg 3: A → B
    let msg3 = init_ctx.write_message(&[]).expect("msg3");
    let mut hdr3 = HandshakeHeader::new(MsgType::Data);
    hdr3.src_node_id = *id_a.node_id.as_bytes();
    hdr3.payload_len = msg3.len() as u16;
    let mut pkt3 = hdr3.serialize();
    pkt3.extend_from_slice(&msg3);
    node_a.send_raw(&pkt3, addr_b).await.expect("send3");
    let (r3, _) = node_b.recv_raw().await.expect("recv3");
    resp_ctx
        .read_message(&r3[HANDSHAKE_HEADER_SIZE..])
        .expect("read3");

    assert!(init_ctx.is_finished());
    assert!(resp_ctx.is_finished());

    let session_id = SessionId::generate();
    let (_, init_session) = init_ctx
        .finalize(id_b.node_id, session_id)
        .expect("finalize init");
    let (_, resp_session) = resp_ctx
        .finalize(id_a.node_id, session_id)
        .expect("finalize resp");

    // Register sessions in the transport nodes' pipelines
    {
        let mut pipe_a = node_a.pipeline.lock().await;
        pipe_a.register_session(SessionState::new(
            session_id,
            id_b.node_id,
            init_session.send_key,
            init_session.recv_key,
            false,
        ));
    }
    {
        let mut pipe_b = node_b.pipeline.lock().await;
        pipe_b.register_session(SessionState::new(
            session_id,
            id_a.node_id,
            resp_session.send_key,
            resp_session.recv_key,
            false,
        ));
    }

    let packet_count = 500usize;

    // Use a concurrent send/receive approach to avoid UDP buffer overflow.
    // Spawn the receiver first, then send in batches with small delays.
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let received = Arc::new(Mutex::new(HashSet::new()));
    let recv_count = packet_count;

    // Spawn receiver task
    let received_clone = received.clone();
    let recv_handle = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            {
                let r = received_clone.lock().await;
                if r.len() >= recv_count {
                    break;
                }
            }
            if Instant::now() > deadline {
                break;
            }

            match timeout(Duration::from_millis(500), node_b.recv_data()).await {
                Ok(Ok(Some((data, _from)))) => {
                    let msg = String::from_utf8_lossy(&data);
                    if let Some(suffix) = msg.strip_prefix("stress-") {
                        if let Ok(idx) = suffix.parse::<usize>() {
                            let mut r = received_clone.lock().await;
                            r.insert(idx);
                        }
                    }
                }
                Ok(Ok(None)) | Ok(Err(_)) | Err(_) => continue,
            }
        }
    });

    // Send in batches of 50 with a small delay between batches
    for batch in 0..(packet_count / 50) {
        let start = batch * 50;
        let end = (start + 50).min(packet_count);
        for i in start..end {
            let payload = format!("stress-{:06}", i);
            node_a
                .send_data(session_id, payload.as_bytes(), addr_b)
                .await
                .expect("send");
        }
        // Small delay between batches to avoid kernel buffer overflow
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Wait for receiver to finish
    let _ = timeout(Duration::from_secs(20), recv_handle).await;

    let final_received = received.lock().await;
    // On localhost UDP, some packets may still be dropped under load.
    // We require at least 90% delivery — this tests the encrypted pipeline
    // is correct and can handle sustained bursts.
    let min_expected = (packet_count * 90) / 100;
    assert!(
        final_received.len() >= min_expected,
        "received only {}/{} packets (minimum {})",
        final_received.len(),
        packet_count,
        min_expected
    );
}

// ─── Session manager capacity / cleanup ─────────────────────────────────────

/// Verify that the session manager enforces max sessions.
#[tokio::test]
async fn test_session_manager_capacity_enforcement() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use ztlp_proto::session_manager::SessionManager;

    let mgr = SessionManager::new(50);

    // Register 50 sessions — all should succeed
    let mut receivers = Vec::new();
    for i in 0..50 {
        let sid = SessionId::generate();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10000 + i);
        let rx = mgr.register(sid, addr, 32).await;
        assert!(rx.is_some(), "session {} should register", i);
        receivers.push(rx);
    }

    assert_eq!(mgr.count(), 50);
    assert!(!mgr.can_accept());

    // 51st should be rejected
    let sid51 = SessionId::generate();
    let addr51 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 60000);
    let rx51 = mgr.register(sid51, addr51, 32).await;
    assert!(rx51.is_none(), "51st session should be rejected");
}

/// Verify that sessions are properly cleaned up after removal.
#[tokio::test]
async fn test_session_cleanup_no_leaks() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use ztlp_proto::session_manager::SessionManager;

    let mgr = SessionManager::new(50);

    // Register 50 sessions
    let mut sids = Vec::new();
    for i in 0..50u16 {
        let sid = SessionId::generate();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 20000 + i);
        let _rx = mgr.register(sid, addr, 32).await.expect("register");
        sids.push(sid);
    }

    assert_eq!(mgr.count(), 50);

    // Remove all sessions
    for sid in &sids {
        mgr.remove(sid).await;
    }

    // Verify cleanup
    assert_eq!(mgr.count(), 0);
    assert!(mgr.can_accept());

    // Verify we can register new sessions (no leaked slots)
    for i in 0..50u16 {
        let sid = SessionId::generate();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30000 + i);
        let rx = mgr.register(sid, addr, 32).await;
        assert!(rx.is_some(), "re-register {} should succeed", i);
    }

    assert_eq!(mgr.count(), 50);
}

// ─── Policy engine stress test ──────────────────────────────────────────────

#[test]
fn test_policy_engine_many_rules() {
    use ztlp_proto::policy::PolicyEngine;

    let mut toml = String::from("default = \"deny\"\n\n");

    // Generate 100 services with various patterns
    for i in 0..100 {
        toml.push_str(&format!(
            "[[services]]\nname = \"svc-{}\"\nallow = [\"*.zone-{}.ztlp\", \"admin.ops.ztlp\"]\n\n",
            i, i
        ));
    }

    let engine = PolicyEngine::from_toml(&toml).expect("parse");
    assert_eq!(engine.len(), 100);

    // Verify each service allows its zone
    for i in 0..100 {
        assert!(engine.authorize(&format!("host.zone-{}.ztlp", i), &format!("svc-{}", i)));
        assert!(engine.authorize("admin.ops.ztlp", &format!("svc-{}", i)));
        // Cross-zone should be denied
        let other = (i + 1) % 100;
        assert!(!engine.authorize(&format!("host.zone-{}.ztlp", other), &format!("svc-{}", i)));
    }
}

#[test]
fn test_policy_reject_reason_coverage() {
    use ztlp_proto::reject::{RejectFrame, RejectReason};

    let reasons = [
        RejectReason::PolicyDenied,
        RejectReason::CapacityFull,
        RejectReason::ServiceUnavailable,
        RejectReason::RateLimited,
    ];

    for reason in &reasons {
        let frame = RejectFrame::from_reason(*reason);
        let encoded = frame.encode();
        let decoded = RejectFrame::decode(&encoded).expect("decode");
        assert_eq!(decoded.reason, *reason);
        assert!(!decoded.message.is_empty());
    }
}

// ─── Concurrent handshake stress ────────────────────────────────────────────

#[tokio::test]
async fn test_concurrent_handshakes_50() {
    // Perform 50 handshakes concurrently on separate port pairs
    let handles: Vec<_> = (0..50)
        .map(|_| {
            tokio::spawn(async {
                let id_a = NodeIdentity::generate().expect("keygen");
                let id_b = NodeIdentity::generate().expect("keygen");

                let node_a = TransportNode::bind("127.0.0.1:0").await.expect("bind");
                let node_b = TransportNode::bind("127.0.0.1:0").await.expect("bind");
                let addr_b = node_b.local_addr;
                let addr_a = node_a.local_addr;

                let mut init = HandshakeContext::new_initiator(&id_a).expect("init");
                let mut resp = HandshakeContext::new_responder(&id_b).expect("resp");

                // Msg 1
                let msg1 = init.write_message(&[]).expect("msg1");
                let mut hdr1 = HandshakeHeader::new(MsgType::Hello);
                hdr1.src_node_id = *id_a.node_id.as_bytes();
                hdr1.payload_len = msg1.len() as u16;
                let mut pkt1 = hdr1.serialize();
                pkt1.extend_from_slice(&msg1);
                node_a.send_raw(&pkt1, addr_b).await.expect("send1");

                let (r1, _) = node_b.recv_raw().await.expect("recv1");
                resp.read_message(&r1[HANDSHAKE_HEADER_SIZE..])
                    .expect("read1");

                // Msg 2
                let msg2 = resp.write_message(&[]).expect("msg2");
                let mut hdr2 = HandshakeHeader::new(MsgType::HelloAck);
                hdr2.src_node_id = *id_b.node_id.as_bytes();
                hdr2.payload_len = msg2.len() as u16;
                let mut pkt2 = hdr2.serialize();
                pkt2.extend_from_slice(&msg2);
                node_b.send_raw(&pkt2, addr_a).await.expect("send2");

                let (r2, _) = node_a.recv_raw().await.expect("recv2");
                init.read_message(&r2[HANDSHAKE_HEADER_SIZE..])
                    .expect("read2");

                // Msg 3
                let msg3 = init.write_message(&[]).expect("msg3");
                let mut hdr3 = HandshakeHeader::new(MsgType::Data);
                hdr3.src_node_id = *id_a.node_id.as_bytes();
                hdr3.payload_len = msg3.len() as u16;
                let mut pkt3 = hdr3.serialize();
                pkt3.extend_from_slice(&msg3);
                node_a.send_raw(&pkt3, addr_b).await.expect("send3");

                let (r3, _) = node_b.recv_raw().await.expect("recv3");
                resp.read_message(&r3[HANDSHAKE_HEADER_SIZE..])
                    .expect("read3");

                assert!(init.is_finished());
                assert!(resp.is_finished());
            })
        })
        .collect();

    let results = timeout(Duration::from_secs(30), async {
        for handle in handles {
            handle.await.expect("task panicked");
        }
    })
    .await;

    assert!(results.is_ok(), "50 concurrent handshakes timed out");
}
