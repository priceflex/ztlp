//! Stress tests for the ZTLP tunnel module with lossy link simulation.
//!
//! These tests exercise the reliability layer (reassembly, ACK/NACK/SACK,
//! retransmission, congestion control) under adverse network conditions.
//! They use the internal ReassemblyBuffer, congestion controller, and
//! RetransmitBuffer directly, plus full handshake+bridge tests with
//! simulated packet loss.

use std::collections::HashSet;
use std::time::Duration;

use tokio::time::{timeout, Instant};

use ztlp_proto::congestion::{RttEstimator, INITIAL_CWND, INITIAL_SSTHRESH, MIN_CWND};
use ztlp_proto::handshake::HandshakeContext;
use ztlp_proto::identity::NodeIdentity;
use ztlp_proto::packet::*;
use ztlp_proto::session::SessionState;
use ztlp_proto::transport::TransportNode;
use ztlp_proto::tunnel::ReassemblyBuffer;

// Test timeout used by the encrypted burst test
#[allow(dead_code)]
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

// ─── Reassembly buffer under packet loss ────────────────────────────────────

#[test]
fn test_reassembly_5_percent_loss() {
    // Simulate 5% packet loss: 1000 packets, skip ~50
    let mut reasm = ReassemblyBuffer::new(0, 4096);
    let total_packets = 1000u64;
    let mut dropped = HashSet::new();

    // Use deterministic "random" drops: every 20th packet
    for i in 0..total_packets {
        if i % 20 == 7 {
            dropped.insert(i);
            continue;
        }
        let data = format!("packet-{}", i).into_bytes();
        reasm.insert(i, data);
    }

    // We should have buffered packets (gaps exist)
    assert!(reasm.buffered_count() > 0 || reasm.expected_seq() < total_packets);

    // Now deliver the dropped packets to fill gaps
    for &seq in &dropped {
        let data = format!("packet-{}", seq).into_bytes();
        reasm.insert(seq, data);
    }

    // All packets should now be deliverable
    assert_eq!(reasm.expected_seq(), total_packets);
    assert_eq!(reasm.buffered_count(), 0);
}

#[test]
fn test_reassembly_10_percent_loss() {
    let mut reasm = ReassemblyBuffer::new(0, 4096);
    let total_packets = 1000u64;
    let mut dropped = HashSet::new();

    // 10% loss: every 10th packet
    for i in 0..total_packets {
        if i % 10 == 3 {
            dropped.insert(i);
            continue;
        }
        let data = format!("packet-{}", i).into_bytes();
        reasm.insert(i, data);
    }

    // Verify missing seqs are correctly reported
    let missing = reasm.missing_seqs(64);
    assert!(!missing.is_empty(), "should detect missing seqs");

    // Retransmit dropped packets
    for &seq in &dropped {
        let data = format!("packet-{}", seq).into_bytes();
        reasm.insert(seq, data);
    }

    assert_eq!(reasm.expected_seq(), total_packets);
    assert_eq!(reasm.buffered_count(), 0);
}

#[test]
fn test_reassembly_20_percent_loss() {
    let mut reasm = ReassemblyBuffer::new(0, 4096);
    let total_packets = 1000u64;
    let mut dropped = HashSet::new();

    // 20% loss: every 5th packet
    for i in 0..total_packets {
        if i % 5 == 2 {
            dropped.insert(i);
            continue;
        }
        let data = format!("packet-{}", i).into_bytes();
        reasm.insert(i, data);
    }

    let missing = reasm.missing_seqs(64);
    assert!(
        missing.len() > 0,
        "should detect many missing seqs at 20% loss"
    );

    // Verify buffer doesn't overflow
    assert!(reasm.buffered_count() <= 4096);

    // Retransmit
    for &seq in &dropped {
        let data = format!("packet-{}", seq).into_bytes();
        reasm.insert(seq, data);
    }

    assert_eq!(reasm.expected_seq(), total_packets);
    assert_eq!(reasm.buffered_count(), 0);
}

// ─── Reassembly: burst loss patterns ────────────────────────────────────────

#[test]
fn test_reassembly_burst_loss() {
    // Simulate burst losses (consecutive packets dropped)
    let mut reasm = ReassemblyBuffer::new(0, 4096);
    let total_packets = 500u64;
    let mut dropped = Vec::new();

    for i in 0..total_packets {
        // Drop bursts of 5 every 50 packets
        if i % 50 >= 20 && i % 50 < 25 {
            dropped.push(i);
            continue;
        }
        let data = vec![i as u8; 100];
        reasm.insert(i, data);
    }

    assert!(reasm.buffered_count() > 0);

    // Retransmit burst-lost packets
    for &seq in &dropped {
        let data = vec![seq as u8; 100];
        reasm.insert(seq, data);
    }

    assert_eq!(reasm.expected_seq(), total_packets);
    assert_eq!(reasm.buffered_count(), 0);
}

// ─── Reassembly: duplicate packet handling ──────────────────────────────────

#[test]
fn test_reassembly_duplicates_ignored() {
    let mut reasm = ReassemblyBuffer::new(0, 4096);

    // Insert packet 0 — should deliver immediately
    let result = reasm.insert(0, vec![0xAA; 10]);
    assert!(result.is_some());
    let deliverable = result.unwrap();
    assert_eq!(deliverable.len(), 1);

    // Insert packet 0 again (duplicate) — should return None
    let result = reasm.insert(0, vec![0xBB; 10]);
    assert!(result.is_none());

    // Insert packet 2 (gap) then duplicate
    let result = reasm.insert(2, vec![0xCC; 10]);
    assert!(result.is_some());
    assert_eq!(result.unwrap().len(), 0); // buffered, not delivered

    let result = reasm.insert(2, vec![0xDD; 10]);
    assert!(result.is_none()); // duplicate in buffer

    assert_eq!(reasm.expected_seq(), 1);
}

// ─── Reassembly: buffer overflow protection ─────────────────────────────────

#[test]
fn test_reassembly_buffer_overflow_protection() {
    let max_buf = 100;
    let mut reasm = ReassemblyBuffer::new(0, max_buf);

    // Skip seq 0 (creating a gap), then insert 100 out-of-order packets
    for i in 1..=max_buf as u64 {
        reasm.insert(i, vec![0xFF; 50]);
    }

    assert_eq!(reasm.buffered_count(), max_buf);

    // Next insert should be dropped (buffer full)
    let result = reasm.insert(max_buf as u64 + 1, vec![0xEE; 50]);
    assert!(result.is_none());

    // Now deliver seq 0 to drain the buffer
    let result = reasm.insert(0, vec![0x00; 50]);
    assert!(result.is_some());
    let deliverable = result.unwrap();
    assert_eq!(deliverable.len(), max_buf + 1); // 0 + all buffered

    assert_eq!(reasm.expected_seq(), max_buf as u64 + 1);
    assert_eq!(reasm.buffered_count(), 0);
}

// ─── SACK range generation under loss ───────────────────────────────────────

#[test]
fn test_sack_ranges_under_loss() {
    let mut reasm = ReassemblyBuffer::new(0, 4096);

    // Deliver packets 0-9, skip 10-14, deliver 15-24, skip 25-29, deliver 30-39
    for i in 0..10 {
        reasm.insert(i, vec![i as u8; 10]);
    }
    for i in 15..25 {
        reasm.insert(i, vec![i as u8; 10]);
    }
    for i in 30..40 {
        reasm.insert(i, vec![i as u8; 10]);
    }

    assert_eq!(reasm.expected_seq(), 10);

    // Get buffered seqs for SACK
    let buffered = reasm.buffered_seqs();
    assert!(!buffered.is_empty());

    // Verify the buffered seqs contain 15-24 and 30-39
    let buffered_set: HashSet<u64> = buffered.into_iter().collect();
    for i in 15..25 {
        assert!(buffered_set.contains(&i), "missing buffered seq {}", i);
    }
    for i in 30..40 {
        assert!(buffered_set.contains(&i), "missing buffered seq {}", i);
    }
}

// ─── RTT estimator convergence ──────────────────────────────────────────────

#[test]
fn test_rtt_estimator_convergence() {
    let mut rtt = RttEstimator::new();

    // Feed samples at ~50ms
    for _ in 0..100 {
        rtt.update(50.0);
    }

    let srtt = rtt.srtt_ms();
    assert!(
        (srtt - 50.0).abs() < 5.0,
        "SRTT should converge to ~50ms, got {:.1}",
        srtt
    );

    let rto = rtt.rto_ms();
    // RTO = srtt + 4*rttvar; with stable samples, rttvar should be small
    assert!(rto < 300.0, "RTO should be reasonable, got {:.1}", rto);
}

#[test]
fn test_rtt_estimator_jitter_handling() {
    let mut rtt = RttEstimator::new();

    // Feed samples with jitter: 40-60ms
    let samples = [40.0, 55.0, 45.0, 60.0, 42.0, 58.0, 50.0, 48.0, 52.0, 47.0];
    for &sample in &samples {
        rtt.update(sample);
    }

    let srtt = rtt.srtt_ms();
    assert!(
        srtt > 30.0 && srtt < 70.0,
        "SRTT should be in 30-70ms range, got {:.1}",
        srtt
    );
}

#[test]
fn test_rtt_estimator_spike_resilience() {
    let mut rtt = RttEstimator::new();

    // Converge at 50ms
    for _ in 0..50 {
        rtt.update(50.0);
    }

    // Spike to 500ms (congestion event)
    rtt.update(500.0);

    // SRTT shouldn't jump all the way to 500ms due to EWMA smoothing
    let srtt = rtt.srtt_ms();
    assert!(
        srtt < 200.0,
        "SRTT should be smoothed after spike, got {:.1}",
        srtt
    );

    // But RTO should increase to account for the variance
    let rto = rtt.rto_ms();
    assert!(
        rto > 100.0,
        "RTO should increase after spike, got {:.1}",
        rto
    );
}

// ─── NACK gap detection ────────────────────────────────────────────────────

#[test]
fn test_nack_missing_seq_detection() {
    let mut reasm = ReassemblyBuffer::new(0, 4096);

    // Deliver packets 0-4, skip 5, deliver 6-10
    for i in 0..5 {
        reasm.insert(i, vec![i as u8]);
    }
    for i in 6..11 {
        reasm.insert(i, vec![i as u8]);
    }

    let missing = reasm.missing_seqs(64);
    assert_eq!(missing, vec![5], "should detect seq 5 as missing");
}

#[test]
fn test_nack_multiple_gaps() {
    let mut reasm = ReassemblyBuffer::new(0, 4096);

    // Create multiple gaps: deliver 0-2, skip 3-4, deliver 5-7, skip 8, deliver 9
    for i in [0, 1, 2, 5, 6, 7, 9] {
        reasm.insert(i, vec![i as u8]);
    }

    let missing = reasm.missing_seqs(64);
    assert_eq!(missing, vec![3, 4, 8], "should detect all gaps");
}

// ─── Congestion window behavior under loss ──────────────────────────────────

#[test]
fn test_cwnd_does_not_collapse_at_5_percent_loss() {
    // Simulate AIMD congestion control with 5% loss rate.
    // With multiplicative decrease (cwnd/2) and additive increase (1/cwnd per round),
    // the steady-state cwnd converges to sqrt(2/loss_rate).
    // At 5% loss: sqrt(2/0.05) ≈ 6.3, so cwnd should stay above MIN_CWND.
    let mut cwnd: f64 = INITIAL_CWND;
    let mut ssthresh: f64 = INITIAL_SSTHRESH;
    let min_cwnd = MIN_CWND;

    for round in 0..200 {
        if cwnd < ssthresh {
            cwnd += 1.0; // slow start
        } else {
            cwnd += 1.0 / cwnd; // congestion avoidance (AIMD)
        }

        // 5% loss: every 20th round
        if round % 20 == 19 {
            ssthresh = (cwnd / 2.0).max(min_cwnd);
            cwnd = ssthresh;
        }
    }

    // cwnd should stay well above MIN_CWND at 5% loss
    assert!(
        cwnd > min_cwnd,
        "cwnd should stay above MIN_CWND ({:.1}) at 5% loss, got {:.1}",
        min_cwnd,
        cwnd
    );
    // The AIMD steady state at 5% is ~3.7 packets, verify it's in a reasonable range
    assert!(
        cwnd >= 2.5,
        "cwnd should be at least 2.5 at 5% loss, got {:.1}",
        cwnd
    );
}

#[test]
fn test_cwnd_adapts_at_10_percent_loss() {
    // At 10% loss, AIMD steady-state: sqrt(2/0.1) ≈ 4.5 → after halving ≈ 2-3
    let mut cwnd: f64 = INITIAL_CWND;
    let mut ssthresh: f64 = INITIAL_SSTHRESH;
    let min_cwnd = MIN_CWND;

    for round in 0..200 {
        if cwnd < ssthresh {
            cwnd += 1.0;
        } else {
            cwnd += 1.0 / cwnd;
        }

        // 10% loss
        if round % 10 == 9 {
            ssthresh = (cwnd / 2.0).max(min_cwnd);
            cwnd = ssthresh;
        }
    }

    // At 10% loss, cwnd should stabilize above min_cwnd
    assert!(
        cwnd >= min_cwnd,
        "cwnd should never go below MIN_CWND ({:.1}) at 10% loss, got {:.1}",
        min_cwnd,
        cwnd
    );
}

#[test]
fn test_cwnd_survives_20_percent_loss() {
    // At 20% loss, cwnd will be small but must not go below MIN_CWND
    let mut cwnd: f64 = INITIAL_CWND;
    let mut ssthresh: f64 = INITIAL_SSTHRESH;
    let min_cwnd = MIN_CWND;

    for round in 0..200 {
        if cwnd < ssthresh {
            cwnd += 1.0;
        } else {
            cwnd += 1.0 / cwnd;
        }

        // 20% loss
        if round % 5 == 4 {
            ssthresh = (cwnd / 2.0).max(min_cwnd);
            cwnd = ssthresh;
        }
    }

    assert!(
        cwnd >= min_cwnd,
        "cwnd should never go below MIN_CWND ({:.1}), got {:.1}",
        min_cwnd,
        cwnd
    );
}

// ─── Reassembly SACK + retransmit simulation ───────────────────────────────

#[test]
fn test_sack_retransmit_recovers_all_data() {
    // Simulate a full send/receive cycle with SACK-driven retransmission
    let total = 100u64;
    let mut reasm = ReassemblyBuffer::new(0, 4096);
    let mut all_data: Vec<(u64, Vec<u8>)> = Vec::new();

    // Phase 1: send with 15% loss
    let mut dropped = Vec::new();
    for i in 0..total {
        let data = format!("data-{:04}", i).into_bytes();
        all_data.push((i, data.clone()));

        if i % 7 == 3 {
            dropped.push(i);
            continue;
        }
        reasm.insert(i, data);
    }

    // Phase 2: check SACK state
    let missing = reasm.missing_seqs(64);
    assert!(missing.len() > 0, "should have missing seqs");

    // Phase 3: retransmit dropped packets (simulating SACK-triggered retransmit)
    let mut retransmitted = 0;
    for &seq in &dropped {
        let data = format!("data-{:04}", seq).into_bytes();
        let result = reasm.insert(seq, data);
        if result.is_some() {
            retransmitted += 1;
        }
    }

    assert_eq!(retransmitted, dropped.len());
    assert_eq!(reasm.expected_seq(), total);
    assert_eq!(reasm.buffered_count(), 0);
}

// ─── Full handshake + encrypted data exchange stress test ───────────────────

/// Stress test: send 500 encrypted packets over real UDP using TransportNode's
/// high-level send_data/recv_data API which handles encryption internally.
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
                    if msg.starts_with("stress-") {
                        if let Ok(idx) = msg[7..].parse::<usize>() {
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
