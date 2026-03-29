//! Tests for PLPMTUD (Packetization Layer Path MTU Discovery, RFC 8899).

use ztlp_proto::transport::{PmtudPhase, PmtudState, BASE_PLPMTU, PROBE_SIZES};
use ztlp_proto::tunnel::{FRAME_PMTU_PROBE, FRAME_PMTU_PROBE_ACK};

// ─── 1. New PmtudState starts at 1200 MTU ──────────────────────────────────

#[test]
fn test_new_state_starts_at_base_mtu() {
    let state = PmtudState::new();
    assert_eq!(state.effective_mtu(), BASE_PLPMTU);
    assert_eq!(state.effective_mtu(), 1200);
    assert_eq!(state.phase(), PmtudPhase::Base);
}

// ─── 2. should_probe returns false initially ────────────────────────────────

#[test]
fn test_should_probe_false_initially() {
    let state = PmtudState::new();
    // New state has next_probe_time set 10s in the future
    assert!(!state.should_probe());
}

// ─── 3. create_probe generates correct wire format ──────────────────────────

#[test]
fn test_create_probe_wire_format() {
    let mut state = PmtudState::new();
    let probe = state.create_probe();

    // First byte is FRAME_PMTU_PROBE
    assert_eq!(probe[0], FRAME_PMTU_PROBE);

    // Bytes 1-2: probe_size as big-endian u16 (probe_index starts at 1 → 1280)
    let probe_size = u16::from_be_bytes([probe[1], probe[2]]);
    assert_eq!(probe_size, 1280);

    // Bytes 3-4: probe_seq as big-endian u16 (first probe → seq 1)
    let probe_seq = u16::from_be_bytes([probe[3], probe[4]]);
    assert_eq!(probe_seq, 1);

    // Total length equals the probe size
    assert_eq!(probe.len(), 1280);

    // Padding bytes are 0xAA
    for &b in &probe[5..] {
        assert_eq!(b, 0xAA);
    }
}

// ─── 4. handle_probe_ack updates effective MTU ──────────────────────────────

#[test]
fn test_handle_probe_ack_updates_mtu() {
    let mut state = PmtudState::new();
    let probe = state.create_probe();
    let size = u16::from_be_bytes([probe[1], probe[2]]);
    let seq = u16::from_be_bytes([probe[3], probe[4]]);

    assert!(state.handle_probe_ack(size, seq));
    assert_eq!(state.effective_mtu(), 1280);
}

// ─── 5. handle_probe_ack rejects wrong seq ──────────────────────────────────

#[test]
fn test_handle_probe_ack_rejects_wrong_seq() {
    let mut state = PmtudState::new();
    let probe = state.create_probe();
    let size = u16::from_be_bytes([probe[1], probe[2]]);

    // Wrong sequence number
    assert!(!state.handle_probe_ack(size, 9999));
    // MTU should not change
    assert_eq!(state.effective_mtu(), BASE_PLPMTU);
}

// ─── 6. handle_probe_ack advances to next probe size ────────────────────────

#[test]
fn test_handle_probe_ack_advances_probe_index() {
    let mut state = PmtudState::new();

    // First probe: index 1 → size 1280
    let probe1 = state.create_probe();
    let size1 = u16::from_be_bytes([probe1[1], probe1[2]]);
    let seq1 = u16::from_be_bytes([probe1[3], probe1[4]]);
    assert_eq!(size1, 1280);
    assert!(state.handle_probe_ack(size1, seq1));
    assert_eq!(state.effective_mtu(), 1280);
    assert_eq!(state.phase(), PmtudPhase::Searching);

    // Second probe: index 2 → size 1400
    let probe2 = state.create_probe();
    let size2 = u16::from_be_bytes([probe2[1], probe2[2]]);
    let seq2 = u16::from_be_bytes([probe2[3], probe2[4]]);
    assert_eq!(size2, 1400);
    assert!(state.handle_probe_ack(size2, seq2));
    assert_eq!(state.effective_mtu(), 1400);
}

// ─── 7. handle_probe_ack transitions to SearchComplete at max size ──────────

#[test]
fn test_search_complete_at_max_size() {
    let mut state = PmtudState::new();

    // Walk through all probe sizes from index 1 to the last
    for i in 1..PROBE_SIZES.len() {
        let probe = state.create_probe();
        let size = u16::from_be_bytes([probe[1], probe[2]]);
        let seq = u16::from_be_bytes([probe[3], probe[4]]);
        assert_eq!(size, PROBE_SIZES[i]);
        assert!(state.handle_probe_ack(size, seq));
    }

    assert_eq!(state.effective_mtu(), *PROBE_SIZES.last().unwrap());
    assert_eq!(state.phase(), PmtudPhase::SearchComplete);
}

// ─── 8. handle_probe_timeout increments failure count ───────────────────────

#[test]
fn test_handle_probe_timeout_increments_failures() {
    let mut state = PmtudState::new();
    assert_eq!(state.probe_failures(), 0);

    state.handle_probe_timeout();
    assert_eq!(state.probe_failures(), 1);

    state.handle_probe_timeout();
    assert_eq!(state.probe_failures(), 2);
}

// ─── 9. handle_probe_timeout stops after max_failures ───────────────────────

#[test]
fn test_handle_probe_timeout_stops_after_max_failures() {
    let mut state = PmtudState::new();

    // Trigger max failures (3)
    state.handle_probe_timeout();
    state.handle_probe_timeout();
    state.handle_probe_timeout();

    assert_eq!(state.phase(), PmtudPhase::SearchComplete);
    // Effective MTU stays at base since no probes succeeded
    assert_eq!(state.effective_mtu(), BASE_PLPMTU);
}

// ─── 10. SearchComplete re-probes after 600s interval ───────────────────────

#[test]
fn test_search_complete_reprobe_interval() {
    let mut state = PmtudState::new();

    // Walk to SearchComplete by exhausting failures
    state.handle_probe_timeout();
    state.handle_probe_timeout();
    state.handle_probe_timeout();

    assert_eq!(state.phase(), PmtudPhase::SearchComplete);
    // Should not probe immediately — next_probe_time is 600s away
    assert!(!state.should_probe());
}

// ─── 11. Probe sizes are in ascending order ─────────────────────────────────

#[test]
fn test_probe_sizes_ascending() {
    for window in PROBE_SIZES.windows(2) {
        assert!(
            window[0] < window[1],
            "PROBE_SIZES not ascending: {} >= {}",
            window[0],
            window[1]
        );
    }
}

// ─── 12. Full search sequence ───────────────────────────────────────────────

#[test]
fn test_full_search_sequence_with_failure() {
    let mut state = PmtudState::new();

    // Succeed at 1280, 1400, 1452, 1472
    for expected_size in &[1280u16, 1400, 1452, 1472] {
        let probe = state.create_probe();
        let size = u16::from_be_bytes([probe[1], probe[2]]);
        let seq = u16::from_be_bytes([probe[3], probe[4]]);
        assert_eq!(size, *expected_size);
        assert!(state.handle_probe_ack(size, seq));
    }
    assert_eq!(state.effective_mtu(), 1472);
    assert_eq!(state.phase(), PmtudPhase::Searching);

    // Fail at 1500 (3 consecutive failures)
    let _probe = state.create_probe(); // create the 1500-byte probe
    state.handle_probe_timeout();
    state.handle_probe_timeout();
    state.handle_probe_timeout();

    assert_eq!(state.phase(), PmtudPhase::SearchComplete);
    // Effective MTU stays at the last successfully probed size
    assert_eq!(state.effective_mtu(), 1472);
}

// ─── 13. FRAME_PMTU_PROBE and FRAME_PMTU_PROBE_ACK constants ───────────────

#[test]
fn test_frame_constants() {
    assert_eq!(FRAME_PMTU_PROBE, 0x0C);
    assert_eq!(FRAME_PMTU_PROBE_ACK, 0x0D);
    // Ensure they don't collide with other known frame types
    assert_ne!(FRAME_PMTU_PROBE, FRAME_PMTU_PROBE_ACK);
}

// ─── Additional: create_probe_ack wire format ───────────────────────────────

#[test]
fn test_create_probe_ack_wire_format() {
    let ack = PmtudState::create_probe_ack(1400, 42);
    assert_eq!(ack.len(), 5);
    assert_eq!(ack[0], FRAME_PMTU_PROBE_ACK);
    let size = u16::from_be_bytes([ack[1], ack[2]]);
    assert_eq!(size, 1400);
    let seq = u16::from_be_bytes([ack[3], ack[4]]);
    assert_eq!(seq, 42);
}

// ─── Additional: parse_probe_payload ────────────────────────────────────────

#[test]
fn test_parse_probe_payload() {
    // Valid payload
    let payload = [0x05, 0x78, 0x00, 0x2A]; // size=1400, seq=42
    let result = PmtudState::parse_probe_payload(&payload);
    assert_eq!(result, Some((1400, 42)));

    // Too short
    assert_eq!(PmtudState::parse_probe_payload(&[0x01, 0x02, 0x03]), None);
    assert_eq!(PmtudState::parse_probe_payload(&[]), None);
}

// ─── Additional: handle_probe_ack rejects wrong size ────────────────────────

#[test]
fn test_handle_probe_ack_rejects_wrong_size() {
    let mut state = PmtudState::new();
    let probe = state.create_probe();
    let seq = u16::from_be_bytes([probe[3], probe[4]]);

    // ACK with wrong size
    assert!(!state.handle_probe_ack(9999, seq));
    assert_eq!(state.effective_mtu(), BASE_PLPMTU);
}

// ─── Additional: is_probe_pending ───────────────────────────────────────────

#[test]
fn test_is_probe_pending() {
    let mut state = PmtudState::new();
    // Base phase — not pending
    assert!(!state.is_probe_pending());

    // Create a probe and ACK it to enter Searching
    let probe = state.create_probe();
    let size = u16::from_be_bytes([probe[1], probe[2]]);
    let seq = u16::from_be_bytes([probe[3], probe[4]]);
    state.handle_probe_ack(size, seq);
    assert_eq!(state.phase(), PmtudPhase::Searching);

    // Now it should be pending (searching with 0 failures)
    assert!(state.is_probe_pending());
}

// ─── Additional: Default trait ──────────────────────────────────────────────

#[test]
fn test_default_trait() {
    let state = PmtudState::default();
    assert_eq!(state.effective_mtu(), BASE_PLPMTU);
    assert_eq!(state.phase(), PmtudPhase::Base);
}

// ─── Additional: probe_seq wrapping ─────────────────────────────────────────

#[test]
fn test_probe_seq_wraps() {
    let mut state = PmtudState::new();

    // Create first probe (seq becomes 1)
    let probe1 = state.create_probe();
    let seq1 = u16::from_be_bytes([probe1[3], probe1[4]]);
    assert_eq!(seq1, 1);

    // Create second probe (seq becomes 2)
    let probe2 = state.create_probe();
    let seq2 = u16::from_be_bytes([probe2[3], probe2[4]]);
    assert_eq!(seq2, 2);

    // Sequence numbers should increment
    assert_eq!(seq2, seq1 + 1);
}
