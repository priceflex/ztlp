//! Contract tests for the Nebula-pivot R1 stub modules (`congestion`,
//! `pacing`, `send_controller`). These modules are deliberately inert — the
//! real implementations were deleted and `tunnel.rs` / `vip.rs` still call
//! into them. These tests pin the "does nothing, never blocks, never gates"
//! contract so that a partial re-implementation (or a stub that accidentally
//! starts gating sends) is caught rather than silently changing wire
//! behaviour. When R2/R3 delete the stubs, delete this file with them.

use std::net::SocketAddr;
use std::time::Duration;

use ztlp_proto::congestion::*;
use ztlp_proto::pacing::{self, SystemProfile, TARGET_BUFFER_SIZE};
use ztlp_proto::packet::SessionId;
use ztlp_proto::send_controller::SendController;
use ztlp_proto::transport::TransportNode;

fn addr() -> SocketAddr {
    "127.0.0.1:1".parse().unwrap()
}

// ─── send_controller stub ────────────────────────────────────────────────

#[tokio::test]
async fn send_controller_stub_drops_everything_and_never_sends() {
    let transport = std::sync::Arc::new(TransportNode::bind("127.0.0.1:0").await.unwrap());
    // Peer socket: if the stub ever sends, this would receive it.
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let (ack_tx, ack_rx) = tokio::sync::mpsc::unbounded_channel::<u64>();

    let mut sc = SendController::new(transport, SessionId([9u8; 12]), peer_addr, ack_rx);
    sc.enqueue(vec![1, 2, 3]);
    sc.enqueue_priority(vec![4, 5, 6]);
    // The stub does not retain the ack receiver, so the channel is already
    // closed: ACKs from the tunnel go nowhere. Pin that.
    assert!(ack_tx.send(1).is_err(), "stub drops the ack receiver on construction");
    sc.process_acks();
    sc.flush().await.expect("flush is Ok(())");
    sc.check_retransmit().await.expect("check_retransmit is Ok(())");
    sc.purge_stream(7);

    let mut buf = [0u8; 64];
    let got = tokio::time::timeout(Duration::from_millis(200), peer.recv_from(&mut buf)).await;
    assert!(got.is_err(), "stub must never put bytes on the wire");
}

// ─── congestion stub ─────────────────────────────────────────────────────

#[test]
fn acc_new_has_documented_initial_state() {
    let cc = AdvancedCongestionController::new();
    assert_eq!(cc.cwnd, INITIAL_CWND);
    assert_eq!(cc.ssthresh, INITIAL_SSTHRESH);
    assert_eq!(cc.phase, CongestionPhase::SlowStart);
    let d = AdvancedCongestionController::default();
    assert_eq!(d.cwnd, cc.cwnd);
    assert_eq!(d.phase, cc.phase);
}

#[test]
fn acc_never_gates_sends() {
    let mut cc = AdvancedCongestionController::new();
    cc.on_loss(Some(5));
    cc.on_loss(None);
    cc.on_rto();
    cc.on_ack(1000);
    cc.on_spurious_detected();
    cc.update_rtt(250.0);
    assert!(!cc.on_nack_received(&[1, 2, 3]));
    // Stub must remain wide open regardless of events fed in.
    assert_eq!(cc.effective_window(), u64::MAX);
    assert_eq!(cc.paced_send_count(0), 0);
    assert_eq!(cc.paced_send_count(1234), 1234);
    assert_eq!(cc.phase, CongestionPhase::SlowStart, "no phase transitions");
    assert_eq!(cc.cwnd, INITIAL_CWND, "cwnd never moves");
    assert_eq!(cc.srtt_ms(), 0.0);
    assert_eq!(cc.rto_ms(), 1000.0);
    assert_eq!(cc.gap_threshold(), Duration::from_millis(NACK_MIN_THRESHOLD_MS));
}

#[test]
fn congestion_constants_are_sane() {
    assert!(MIN_CWND <= INITIAL_CWND && INITIAL_CWND <= INITIAL_SSTHRESH);
    assert!(MIN_RTO_MS < MAX_RTO_MS);
    assert!(SEND_WINDOW > 0);
}

#[test]
fn sack_scoreboard_stub_acks_nothing() {
    let mut sb = SackScoreboard;
    assert!(!sb.is_acked(0));
    assert!(!sb.update_from_sack(10, &[SackRange { start: 1, end: 2 }]));
    assert!(!sb.is_acked(1), "update must not have recorded anything");
    let _ = SackScoreboard::default();
}

#[test]
fn spurious_detector_stub_never_flags() {
    let mut sd = SpuriousDetector;
    sd.record_retransmit(7, 100.0);
    assert!(!sd.check_ack(7));
    let _ = SpuriousDetector::default();
}

#[test]
fn rtt_estimator_stub_is_static() {
    let mut r = RttEstimator::new();
    assert_eq!(r.srtt_ms(), 0);
    r.update(500);
    r.update(5);
    assert_eq!(r.srtt_ms(), 0, "update is a no-op");
    assert_eq!(r.rto_ms(), 1000);
    let r2 = RttEstimator { srtt_ms: 42, rttvar_ms: 3 };
    assert_eq!(r2.srtt_ms(), 42, "srtt_ms getter reads the field");
    assert_eq!(r2.rttvar_ms, 3);
}

#[test]
fn receiver_sack_state_stub_reports_no_ranges() {
    let mut s = ReceiverSackState::new();
    assert!(s.ranges().is_empty());
    s.update_from_reassembly(10, vec![11u64, 12, 13]);
    s.update_from_reassembly(10, ());
    assert!(s.ranges().is_empty());
    assert!(ReceiverSackState::default().ranges().is_empty());
}

#[test]
fn sack_frame_codec_stub_is_inert() {
    assert!(encode_sack_frame(0, &[]).is_empty());
    assert!(encode_sack_frame(99, &[SackRange { start: 1, end: 9 }]).is_empty());
    assert!(decode_sack_payload(&[]).is_none());
    assert!(decode_sack_payload(&[1, 2, 3, 4, 5, 6, 7, 8]).is_none());
}

#[test]
fn sack_range_and_phase_derive_traits() {
    let r = SackRange::default();
    assert_eq!((r.start, r.end), (0, 0));
    let r2 = r; // Copy
    assert!(format!("{r2:?}").contains("SackRange"));
    assert_ne!(CongestionPhase::Recovery, CongestionPhase::CongestionAvoidance);
    assert!(format!("{:?}", CongestionPhase::Recovery).contains("Recovery"));
}

// ─── pacing stub ─────────────────────────────────────────────────────────

#[test]
fn pacing_detect_system_returns_default_profile_without_probing() {
    let start = std::time::Instant::now();
    let p = pacing::detect_system(addr(), None, Duration::from_secs(30));
    assert!(start.elapsed() < Duration::from_secs(1), "must not actually probe/sleep");
    assert_eq!(p.max_sub_batch, 64);
    let d = SystemProfile::default();
    assert_eq!(d.max_sub_batch, p.max_sub_batch);
    assert!(format!("{p:?}").contains("SystemProfile"));
}

#[test]
fn pacing_detect_system_accepts_a_real_socket() {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let p = pacing::detect_system(addr(), Some(&sock), Duration::from_millis(1));
    assert_eq!(p.max_sub_batch, 64);
}

#[test]
fn pacing_pace_is_a_noop_for_any_type() {
    let start = std::time::Instant::now();
    pacing::pace(&SystemProfile::default().pacing);
    pacing::pace(&42u8);
    pacing::pace(&"anything");
    assert!(start.elapsed() < Duration::from_millis(100));
    assert_eq!(TARGET_BUFFER_SIZE, 7 * 1024 * 1024);
}
