//! Nebula-pivot R1 STUB.
//!
//! The real 1,959-LOC congestion-control module (AIMD/PRR/SACK scoreboard/
//! Jacobson-Karels RTT/spurious-detect/token-bucket pacer) was deleted in
//! Phase R1 of the Nebula-style pivot. This file exists only so the 120+
//! call sites in `tunnel.rs` that reference `crate::congestion::*` continue
//! to type-check. Every method is a no-op or trivial-value return.
//!
//! TODO(nebula-pivot-R3): R3 rewrites `tunnel.rs::run_bridge_inner` without
//! any CC/retransmit/SACK logic. When that lands, delete this file outright
//! along with the `pub mod congestion;` declaration in `lib.rs`.
//!
//! See `docs/plans/nebula-pivot-audit/01-rust-proto.md` §DELETE-ENTIRELY.

#![allow(dead_code, unused_variables, non_snake_case, clippy::upper_case_acronyms)]

use std::time::Duration;

pub const INITIAL_CWND: f64 = 10.0;
pub const INITIAL_SSTHRESH: f64 = 64.0;
pub const MIN_CWND: f64 = 2.0;
pub const MAX_RTO_MS: u64 = 60_000;
pub const MIN_RTO_MS: u64 = 200;
pub const SEND_WINDOW: u64 = 1024;
pub const NACK_MIN_THRESHOLD_MS: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionPhase {
    SlowStart,
    CongestionAvoidance,
    Recovery,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SackRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Default)]
pub struct SackScoreboard;
impl SackScoreboard {
    pub fn is_acked(&self, _seq: u64) -> bool {
        false
    }
    pub fn update_from_sack(&mut self, _cum_ack: u64, _ranges: &[SackRange]) -> bool {
        false
    }
}

#[derive(Default)]
pub struct SpuriousDetector;
impl SpuriousDetector {
    pub fn record_retransmit(&mut self, _seq: u64, _srtt_ms: f64) {}
    pub fn check_ack(&mut self, _seq: u64) -> bool {
        false
    }
}

#[derive(Default)]
pub struct RttEstimator {
    pub srtt_ms: u64,
    pub rttvar_ms: u64,
}
impl RttEstimator {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn update(&mut self, _rtt_ms: u64) {}
    pub fn srtt_ms(&self) -> u64 {
        self.srtt_ms
    }
    pub fn rto_ms(&self) -> u64 {
        1000
    }
}

pub struct AdvancedCongestionController {
    pub cwnd: f64,
    pub ssthresh: f64,
    pub phase: CongestionPhase,
    pub scoreboard: SackScoreboard,
    pub spurious: SpuriousDetector,
}

impl Default for AdvancedCongestionController {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvancedCongestionController {
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            phase: CongestionPhase::SlowStart,
            scoreboard: SackScoreboard,
            spurious: SpuriousDetector,
        }
    }
    pub fn on_loss(&mut self, _data_seq: Option<u64>) {}
    pub fn on_ack(&mut self, _n: u64) {}
    pub fn on_rto(&mut self) {}
    pub fn on_nack_received(&mut self, _missing: &[u64]) -> bool {
        false
    }
    pub fn on_spurious_detected(&mut self) {}
    pub fn update_rtt(&mut self, _rtt_ms: f64) {}
    pub fn effective_window(&self) -> u64 {
        u64::MAX
    }
    pub fn paced_send_count(&self, remaining: usize) -> usize {
        remaining
    }
    pub fn srtt_ms(&self) -> f64 {
        0.0
    }
    pub fn rto_ms(&self) -> f64 {
        1000.0
    }
    pub fn gap_threshold(&self) -> Duration {
        Duration::from_millis(NACK_MIN_THRESHOLD_MS)
    }
}

#[derive(Default)]
pub struct ReceiverSackState {
    ranges_: Vec<SackRange>,
}
impl ReceiverSackState {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn update_from_reassembly<T>(&mut self, _expected_seq: u64, _buffered: T) {}
    pub fn ranges(&self) -> &[SackRange] {
        &self.ranges_
    }
}

pub fn decode_sack_payload(_payload: &[u8]) -> Option<(u64, Vec<SackRange>)> {
    None
}

pub fn encode_sack_frame(_cum_ack: u64, _ranges: &[SackRange]) -> Vec<u8> {
    Vec::new()
}
