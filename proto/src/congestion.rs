//! Advanced congestion control and selective acknowledgment (SACK) module.
//!
//! Implements modern TCP-like congestion control with:
//! - Jacobson/Karels RTT smoothing (SRTT + RTTVAR)
//! - Fast retransmit (3 duplicate ACKs/NACKs = loss without waiting for RTO)
//! - Proportional Rate Reduction (PRR) for smoother loss recovery
//! - Token bucket pacing to spread packets across RTT
//! - Spurious retransmission detection (Eifel-like algorithm)
//! - SACK scoreboard for efficient selective retransmission
//! - RTT-adaptive gap detection thresholds

#![deny(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::Instant;
use tracing::debug;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Initial congestion window (in packets). Large IW for high-BDP paths.
pub const INITIAL_CWND: f64 = 256.0;

/// Initial slow-start threshold. Start high — let actual loss set the
/// threshold. This avoids artificially capping throughput on high-bandwidth links.
pub const INITIAL_SSTHRESH: f64 = 512.0;

/// Minimum retransmission timeout in milliseconds.
pub const MIN_RTO_MS: f64 = 200.0;

/// Maximum retransmission timeout in milliseconds (4 seconds, not 60).
pub const MAX_RTO_MS: f64 = 4000.0;

/// Initial smoothed RTT estimate in milliseconds.
pub const INITIAL_SRTT_MS: f64 = 100.0;

/// Minimum congestion window (packets). Never go below this.
pub const MIN_CWND: f64 = 2.0;

/// Number of duplicate NACKs that trigger fast retransmit.
pub const FAST_RETRANSMIT_THRESHOLD: u32 = 3;

/// Maximum SACK ranges in a single frame.
pub const MAX_SACK_RANGES: usize = 32;

/// Maximum sequence numbers in a single NACK frame (kept for compatibility).
pub const MAX_NACK_SEQS: usize = 64;

/// Minimum gap detection threshold in milliseconds.
pub const NACK_MIN_THRESHOLD_MS: u64 = 50;

/// Maximum entries in the retransmit buffer (matches send window).
pub const RETRANSMIT_BUF_MAX: usize = 65536;

/// Maximum send window (in packets). Matches tunnel::SEND_WINDOW.
pub const SEND_WINDOW: u64 = 65535;

/// Token bucket refill happens per-RTT. This is the minimum pacing interval.
const MIN_PACING_INTERVAL_US: u64 = 100;

/// RTO backoff multiplier on consecutive timeouts.
const RTO_BACKOFF_FACTOR: f64 = 2.0;

/// Maximum consecutive RTO backoffs before capping.
const MAX_RTO_BACKOFFS: u32 = 6;

// ─── Congestion State ───────────────────────────────────────────────────────

/// Congestion control state machine phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionPhase {
    /// Exponential growth: cwnd doubles each RTT.
    SlowStart,
    /// Linear growth: cwnd grows ~1 packet per RTT.
    CongestionAvoidance,
    /// Loss recovery with PRR: reducing flight size proportionally.
    Recovery,
}

impl std::fmt::Display for CongestionPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CongestionPhase::SlowStart => write!(f, "SlowStart"),
            CongestionPhase::CongestionAvoidance => write!(f, "CongAvoid"),
            CongestionPhase::Recovery => write!(f, "Recovery"),
        }
    }
}

// ─── RTT Estimator (Jacobson/Karels) ────────────────────────────────────────

/// RTT estimator using the Jacobson/Karels algorithm (RFC 6298).
///
/// Maintains smoothed RTT (SRTT) and RTT variance (RTTVAR) to compute
/// a retransmission timeout (RTO) that adapts to network conditions.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT in milliseconds.
    srtt_ms: f64,
    /// RTT variance in milliseconds.
    rttvar_ms: f64,
    /// Computed RTO in milliseconds.
    rto_ms: f64,
    /// Whether we've received the first RTT sample.
    has_sample: bool,
    /// Number of consecutive RTO timeouts (for exponential backoff).
    rto_backoffs: u32,
    /// Minimum RTT observed (for spurious detection).
    min_rtt_ms: f64,
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            srtt_ms: INITIAL_SRTT_MS,
            rttvar_ms: INITIAL_SRTT_MS / 2.0,
            rto_ms: INITIAL_SRTT_MS + 4.0 * (INITIAL_SRTT_MS / 2.0),
            has_sample: false,
            rto_backoffs: 0,
            min_rtt_ms: f64::MAX,
        }
    }

    /// Update RTT estimate with a new sample.
    ///
    /// Uses Jacobson/Karels algorithm (RFC 6298):
    /// - First sample: SRTT = sample, RTTVAR = sample/2
    /// - Subsequent: RTTVAR = (1-β)·RTTVAR + β·|SRTT - sample|, β=1/4;
    ///   SRTT = (1-α)·SRTT + α·sample, α=1/8
    /// - RTO = SRTT + max(G, 4·RTTVAR), clamped to [MIN_RTO, MAX_RTO]
    pub fn update(&mut self, sample_ms: f64) {
        if sample_ms <= 0.0 {
            return;
        }

        // Track minimum RTT for spurious retransmission detection
        if sample_ms < self.min_rtt_ms {
            self.min_rtt_ms = sample_ms;
        }

        if !self.has_sample {
            // First sample: RFC 6298 section 2.2
            self.srtt_ms = sample_ms;
            self.rttvar_ms = sample_ms / 2.0;
            self.has_sample = true;
        } else {
            // Subsequent samples: RFC 6298 section 2.3
            let diff = (self.srtt_ms - sample_ms).abs();
            self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * diff;
            self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * sample_ms;
        }

        // Recompute RTO (reset backoff on new sample)
        self.rto_backoffs = 0;
        self.recompute_rto();
    }

    /// Recompute RTO from current SRTT and RTTVAR.
    fn recompute_rto(&mut self) {
        let base_rto = self.srtt_ms + 4.0 * self.rttvar_ms;
        let backoff = RTO_BACKOFF_FACTOR.powi(self.rto_backoffs.min(MAX_RTO_BACKOFFS) as i32);
        self.rto_ms = (base_rto * backoff).clamp(MIN_RTO_MS, MAX_RTO_MS);
    }

    /// Called when an RTO fires without receiving an ACK.
    /// Doubles the RTO (exponential backoff per RFC 6298 section 5.5).
    pub fn on_rto_timeout(&mut self) {
        self.rto_backoffs = (self.rto_backoffs + 1).min(MAX_RTO_BACKOFFS);
        self.recompute_rto();
        debug!(
            "RTO backoff #{}: rto now {:.1}ms",
            self.rto_backoffs, self.rto_ms
        );
    }

    /// Current RTO in milliseconds.
    pub fn rto_ms(&self) -> f64 {
        self.rto_ms
    }

    /// Current smoothed RTT in milliseconds.
    pub fn srtt_ms(&self) -> f64 {
        self.srtt_ms
    }

    /// Current RTT variance in milliseconds.
    pub fn rttvar_ms(&self) -> f64 {
        self.rttvar_ms
    }

    /// Minimum observed RTT (for spurious retransmission detection).
    pub fn min_rtt_ms(&self) -> f64 {
        self.min_rtt_ms
    }

    /// RTO as a Duration.
    pub fn rto_duration(&self) -> Duration {
        Duration::from_millis(self.rto_ms.max(MIN_RTO_MS) as u64)
    }

    /// NACK/gap detection threshold: adaptive to RTT.
    /// Uses max(2×SRTT, NACK_MIN_THRESHOLD_MS).
    pub fn gap_threshold(&self) -> Duration {
        let threshold_ms = (2.0 * self.srtt_ms).max(NACK_MIN_THRESHOLD_MS as f64) as u64;
        Duration::from_millis(threshold_ms)
    }

    /// NACK rate limit interval: one NACK per SRTT.
    pub fn nack_interval(&self) -> Duration {
        let interval_ms = self.srtt_ms.max(NACK_MIN_THRESHOLD_MS as f64) as u64;
        Duration::from_millis(interval_ms)
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Spurious Retransmission Detector ───────────────────────────────────────

/// Eifel-like spurious retransmission detector.
///
/// Detects when a retransmission was unnecessary by checking if the ACK
/// for the retransmitted packet arrives faster than expected. If so,
/// the original packet wasn't lost — just delayed.
#[derive(Debug, Clone)]
pub struct SpuriousDetector {
    /// Map of data_seq → (retransmit_time, expected_rtt_ms).
    /// When we retransmit, we record when and what RTT we expected.
    retransmit_records: BTreeMap<u64, (Instant, f64)>,
    /// Total spurious retransmissions detected (diagnostic).
    pub spurious_count: u64,
    /// Maximum records to track (prevents unbounded growth).
    max_records: usize,
}

impl SpuriousDetector {
    pub fn new(max_records: usize) -> Self {
        Self {
            retransmit_records: BTreeMap::new(),
            spurious_count: 0,
            max_records,
        }
    }

    /// Record a retransmission for later spurious detection.
    pub fn record_retransmit(&mut self, data_seq: u64, expected_rtt_ms: f64) {
        if self.retransmit_records.len() >= self.max_records {
            // Evict oldest
            if let Some(&oldest) = self.retransmit_records.keys().next() {
                self.retransmit_records.remove(&oldest);
            }
        }
        self.retransmit_records
            .insert(data_seq, (Instant::now(), expected_rtt_ms));
    }

    /// Check if an ACK for a retransmitted packet indicates spurious retransmission.
    ///
    /// Returns true if the retransmission was likely spurious (the original
    /// packet arrived, not the retransmit).
    ///
    /// Eifel algorithm: if the ACK arrives in less time than the expected RTT
    /// from the retransmit point, the original packet must have arrived first.
    pub fn check_ack(&mut self, data_seq: u64) -> bool {
        if let Some((retransmit_time, expected_rtt_ms)) = self.retransmit_records.remove(&data_seq)
        {
            let elapsed_ms = retransmit_time.elapsed().as_secs_f64() * 1000.0;
            // If ACK arrived in less than half the expected RTT from retransmit,
            // the original packet likely arrived — retransmit was spurious.
            if elapsed_ms < expected_rtt_ms * 0.5 {
                self.spurious_count += 1;
                debug!(
                    "spurious retransmit detected for seq {}: ack arrived in {:.1}ms, expected {:.1}ms",
                    data_seq, elapsed_ms, expected_rtt_ms
                );
                return true;
            }
        }
        false
    }

    /// Prune records for sequences that have been fully acknowledged.
    pub fn prune_up_to(&mut self, acked_seq: u64) {
        self.retransmit_records.retain(|&seq, _| seq > acked_seq);
    }
}

// ─── Token Bucket Pacer ─────────────────────────────────────────────────────

/// Token bucket pacer that spreads packet sends across the RTT.
///
/// Instead of bursting the entire congestion window at once, the pacer
/// releases tokens at a rate of cwnd/RTT packets per second.
#[derive(Debug, Clone)]
pub struct TokenBucketPacer {
    /// Available tokens (fractional packets allowed).
    tokens: f64,
    /// Maximum tokens (burst capacity).
    max_tokens: f64,
    /// Last time tokens were replenished.
    last_refill: Instant,
    /// Whether pacing is enabled (disabled during slow start for fast ramp).
    enabled: bool,
}

impl TokenBucketPacer {
    pub fn new() -> Self {
        Self {
            tokens: INITIAL_CWND, // Start with full window available
            max_tokens: INITIAL_CWND,
            last_refill: Instant::now(),
            enabled: false, // Disabled during slow start
        }
    }

    /// Refill tokens based on elapsed time, cwnd, and RTT.
    ///
    /// Rate = cwnd / srtt_ms * elapsed_ms
    pub fn refill(&mut self, cwnd: f64, srtt_ms: f64) {
        if !self.enabled || srtt_ms <= 0.0 {
            return;
        }

        let now = Instant::now();
        let elapsed_us = now.duration_since(self.last_refill).as_micros() as f64;
        if elapsed_us < MIN_PACING_INTERVAL_US as f64 {
            return;
        }

        let elapsed_ms = elapsed_us / 1000.0;
        let rate = cwnd / srtt_ms; // packets per ms
        let new_tokens = rate * elapsed_ms;

        // Burst cap: allow up to 10 packets or cwnd/4 burst
        self.max_tokens = (cwnd / 4.0).max(10.0);
        self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
        self.last_refill = now;
    }

    /// Try to consume `count` tokens. Returns how many can be sent now.
    pub fn try_consume(&mut self, count: usize) -> usize {
        if !self.enabled {
            return count; // No pacing
        }

        let available = self.tokens.floor() as usize;
        let can_send = count.min(available).max(1); // Always allow at least 1
        self.tokens -= can_send as f64;
        can_send
    }

    /// Enable pacing (called when entering congestion avoidance or recovery).
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable pacing (called during slow start).
    pub fn disable(&mut self) {
        self.enabled = false;
        self.tokens = self.max_tokens;
    }

    /// How long to wait before the next token is available.
    pub fn time_until_token(&self, cwnd: f64, srtt_ms: f64) -> Duration {
        if !self.enabled || self.tokens >= 1.0 || cwnd <= 0.0 || srtt_ms <= 0.0 {
            return Duration::ZERO;
        }

        let needed = 1.0 - self.tokens;
        let rate = cwnd / srtt_ms; // packets per ms
        if rate <= 0.0 {
            return Duration::from_millis(1);
        }
        let wait_ms = needed / rate;
        Duration::from_micros((wait_ms * 1000.0) as u64)
    }

    /// Check if pacing is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for TokenBucketPacer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── SACK Ranges ────────────────────────────────────────────────────────────

/// A contiguous range of received sequence numbers [start, end] (inclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackRange {
    pub start: u64,
    pub end: u64,
}

impl SackRange {
    pub fn new(start: u64, end: u64) -> Self {
        debug_assert!(start <= end);
        Self { start, end }
    }

    /// Number of sequence numbers in this range.
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Whether this range is empty (impossible if well-formed, but defensive).
    pub fn is_empty(&self) -> bool {
        self.end < self.start
    }

    /// Whether this range contains a specific sequence number.
    pub fn contains(&self, seq: u64) -> bool {
        seq >= self.start && seq <= self.end
    }
}

/// Encode SACK ranges into a frame payload.
///
/// Format: [FRAME_SACK | cumulative_ack: u64 BE | count: u16 BE | (start: u64 BE, end: u64 BE) × count]
///
/// We reuse FRAME_NACK (0x03) for backwards-compat detection but encode differently.
/// Actually, we'll add a new frame type FRAME_SACK = 0x05.
pub const FRAME_SACK: u8 = 0x05;

/// Encode a SACK frame.
///
/// `cumulative_ack`: highest contiguous seq delivered (like ACK).
/// `ranges`: additional non-contiguous received ranges above cumulative_ack.
pub fn encode_sack_frame(cumulative_ack: u64, ranges: &[SackRange]) -> Vec<u8> {
    let count = ranges.len().min(MAX_SACK_RANGES) as u16;
    let mut frame = Vec::with_capacity(1 + 8 + 2 + (count as usize) * 16);
    frame.push(FRAME_SACK);
    frame.extend_from_slice(&cumulative_ack.to_be_bytes());
    frame.extend_from_slice(&count.to_be_bytes());
    for range in ranges.iter().take(MAX_SACK_RANGES) {
        frame.extend_from_slice(&range.start.to_be_bytes());
        frame.extend_from_slice(&range.end.to_be_bytes());
    }
    frame
}

/// Decode a SACK frame payload (after the FRAME_SACK type byte).
///
/// Returns (cumulative_ack, ranges) or None if malformed.
pub fn decode_sack_payload(payload: &[u8]) -> Option<(u64, Vec<SackRange>)> {
    if payload.len() < 10 {
        // Need at least 8 (cumulative_ack) + 2 (count)
        return None;
    }

    let cumulative_ack = u64::from_be_bytes(match payload[..8].try_into() {
        Ok(b) => b,
        Err(_) => return None,
    });

    let count = u16::from_be_bytes([payload[8], payload[9]]) as usize;
    if count > MAX_SACK_RANGES {
        return None;
    }

    let expected_len = 10 + count * 16;
    if payload.len() < expected_len {
        return None;
    }

    let mut ranges = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 10 + i * 16;
        let start = u64::from_be_bytes(match payload[offset..offset + 8].try_into() {
            Ok(b) => b,
            Err(_) => return None,
        });
        let end = u64::from_be_bytes(match payload[offset + 8..offset + 16].try_into() {
            Ok(b) => b,
            Err(_) => return None,
        });
        if end < start {
            return None; // Invalid range
        }
        ranges.push(SackRange::new(start, end));
    }

    Some((cumulative_ack, ranges))
}

// ─── SACK Scoreboard ────────────────────────────────────────────────────────

/// Sender-side SACK scoreboard that tracks which packets the receiver has.
///
/// Used to avoid retransmitting packets that the receiver already received
/// (just out of order). Only retransmit packets in gaps.
#[derive(Debug, Clone)]
pub struct SackScoreboard {
    /// Ranges of sequences the receiver has confirmed via SACK.
    /// Sorted by start, non-overlapping after merge.
    received_ranges: Vec<SackRange>,
    /// Highest cumulative ACK received.
    cumulative_ack: Option<u64>,
    /// Count of times each gap-seq was NACKed (for fast retransmit).
    nack_counts: BTreeMap<u64, u32>,
}

impl SackScoreboard {
    pub fn new() -> Self {
        Self {
            received_ranges: Vec::new(),
            cumulative_ack: None,
            nack_counts: BTreeMap::new(),
        }
    }

    /// Update the scoreboard from a SACK frame.
    pub fn update_from_sack(&mut self, cumulative_ack: u64, ranges: &[SackRange]) {
        // Update cumulative ACK
        match self.cumulative_ack {
            Some(prev) if cumulative_ack > prev => self.cumulative_ack = Some(cumulative_ack),
            None => self.cumulative_ack = Some(cumulative_ack),
            _ => {}
        }

        // Add new ranges
        for range in ranges {
            self.add_range(*range);
        }

        // Prune ranges below cumulative_ack
        if let Some(ca) = self.cumulative_ack {
            self.received_ranges.retain(|r| r.end > ca);
            self.nack_counts.retain(|&seq, _| seq > ca);
        }
    }

    /// Update from a legacy NACK (list of missing seqs).
    /// We infer received ranges from what's NOT in the missing list.
    pub fn update_from_nack(&mut self, missing_seqs: &[u64]) {
        for &seq in missing_seqs {
            let count = self.nack_counts.entry(seq).or_insert(0);
            *count += 1;
        }
    }

    /// Add a received range, merging with existing ranges.
    fn add_range(&mut self, new: SackRange) {
        self.received_ranges.push(new);
        self.merge_ranges();
    }

    /// Merge overlapping/adjacent ranges.
    fn merge_ranges(&mut self) {
        if self.received_ranges.len() <= 1 {
            return;
        }

        self.received_ranges.sort_by_key(|r| r.start);
        let mut merged = Vec::with_capacity(self.received_ranges.len());

        let mut current = self.received_ranges[0];
        for &range in &self.received_ranges[1..] {
            if range.start <= current.end + 1 {
                // Overlapping or adjacent — merge
                current.end = current.end.max(range.end);
            } else {
                merged.push(current);
                current = range;
            }
        }
        merged.push(current);

        self.received_ranges = merged;
    }

    /// Check if the receiver has acknowledged a specific sequence number.
    pub fn is_acked(&self, seq: u64) -> bool {
        // Below cumulative ACK
        if let Some(ca) = self.cumulative_ack {
            if seq <= ca {
                return true;
            }
        }

        // In a SACK range
        self.received_ranges.iter().any(|r| r.contains(seq))
    }

    /// Get sequences that need retransmission (in gaps between SACK ranges).
    /// Returns sequences between cumulative_ack and the highest SACK range
    /// that are NOT covered by any SACK range.
    ///
    /// `max_count`: maximum number of sequences to return.
    pub fn get_missing_seqs(&self, max_count: usize) -> Vec<u64> {
        let ca = match self.cumulative_ack {
            Some(ca) => ca,
            None => return Vec::new(),
        };

        if self.received_ranges.is_empty() {
            return Vec::new();
        }

        let mut missing = Vec::new();
        let mut seq = ca + 1;

        for range in &self.received_ranges {
            while seq < range.start && missing.len() < max_count {
                missing.push(seq);
                seq += 1;
            }
            seq = seq.max(range.end + 1);
        }

        missing
    }

    /// Get sequences that have been NACKed >= threshold times (fast retransmit candidates).
    pub fn get_fast_retransmit_candidates(&self, threshold: u32) -> Vec<u64> {
        self.nack_counts
            .iter()
            .filter(|(_, &count)| count >= threshold)
            .map(|(&seq, _)| seq)
            .collect()
    }

    /// Reset NACK count for a sequence (after retransmitting it).
    pub fn reset_nack_count(&mut self, seq: u64) {
        self.nack_counts.remove(&seq);
    }

    /// Get the cumulative ACK value.
    pub fn cumulative_ack(&self) -> Option<u64> {
        self.cumulative_ack
    }

    /// Current SACK ranges for diagnostics.
    pub fn ranges(&self) -> &[SackRange] {
        &self.received_ranges
    }

    /// Process incoming SACK blocks from an ACK frame.
    ///
    /// Each block `(start, end)` is an inclusive range of sequences the
    /// receiver has confirmed. Adds them to the scoreboard and merges
    /// overlapping/adjacent ranges.
    pub fn process_sack_blocks(&mut self, blocks: &[(u64, u64)]) {
        for &(start, end) in blocks {
            if end >= start {
                self.add_range(SackRange::new(start, end));
            }
        }
    }
}

impl Default for SackScoreboard {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Retransmit Tracker ─────────────────────────────────────────────────────

/// Tracks per-packet retransmission state to limit retransmit rate.
///
/// Enforces: max 1 retransmit per RTT per lost packet.
#[derive(Debug, Clone)]
pub struct RetransmitTracker {
    /// Map of data_seq → last retransmit time.
    last_retransmit: BTreeMap<u64, Instant>,
    /// Maximum tracked entries.
    max_entries: usize,
}

impl RetransmitTracker {
    pub fn new(max_entries: usize) -> Self {
        Self {
            last_retransmit: BTreeMap::new(),
            max_entries,
        }
    }

    /// Check if a packet can be retransmitted (respecting rate limit).
    ///
    /// Returns true if enough time has passed since the last retransmit
    /// of this specific sequence number.
    pub fn can_retransmit(&self, data_seq: u64, min_interval: Duration) -> bool {
        match self.last_retransmit.get(&data_seq) {
            Some(last) => last.elapsed() >= min_interval,
            None => true,
        }
    }

    /// Record that a packet was retransmitted.
    pub fn record_retransmit(&mut self, data_seq: u64) {
        if self.last_retransmit.len() >= self.max_entries {
            // Evict oldest
            if let Some(&oldest) = self.last_retransmit.keys().next() {
                self.last_retransmit.remove(&oldest);
            }
        }
        self.last_retransmit.insert(data_seq, Instant::now());
    }

    /// Prune entries for sequences that have been fully acknowledged.
    pub fn prune_up_to(&mut self, acked_seq: u64) {
        self.last_retransmit.retain(|&seq, _| seq > acked_seq);
    }

    /// Check if a data_seq should be skipped for retransmit because the
    /// receiver already has it (confirmed via SACK).
    pub fn should_skip_sacked(&self, data_seq: u64, scoreboard: &SackScoreboard) -> bool {
        scoreboard.is_acked(data_seq)
    }
}

// ─── Advanced Congestion Controller ─────────────────────────────────────────

/// Advanced congestion controller with PRR, fast retransmit, and pacing.
///
/// Integrates all congestion control components:
/// - Jacobson/Karels RTT estimation
/// - Slow start / congestion avoidance / recovery phases
/// - Proportional Rate Reduction (PRR) during recovery
/// - Fast retransmit on 3 duplicate NACKs
/// - Token bucket pacing
/// - Spurious retransmission detection
pub struct AdvancedCongestionController {
    /// Congestion window (packets).
    pub cwnd: f64,
    /// Slow-start threshold (packets).
    pub ssthresh: f64,
    /// Current phase.
    pub phase: CongestionPhase,
    /// RTT estimator.
    pub rtt: RttEstimator,
    /// Token bucket pacer.
    pub pacer: TokenBucketPacer,
    /// Spurious retransmission detector.
    pub spurious: SpuriousDetector,
    /// SACK scoreboard.
    pub scoreboard: SackScoreboard,
    /// Retransmit rate limiter.
    pub retransmit_tracker: RetransmitTracker,

    // ── PRR state ───────────────────────────────────────────────────
    /// cwnd at the time recovery started (pipe_prev).
    recovery_cwnd: f64,
    /// Number of packets delivered (ACKed) since recovery started.
    prr_delivered: u64,
    /// Number of packets sent during recovery.
    prr_out: u64,
    /// Sequence number that triggered recovery (recovery ends when
    /// cumulative ACK passes this).
    recovery_seq: Option<u64>,

    // ── Fast retransmit state ───────────────────────────────────────
    /// Number of duplicate NACKs/SACKs received for the same gap.
    dup_nack_count: u32,
    /// The sequence that triggered the current dup count tracking.
    dup_nack_trigger_seq: Option<u64>,

    // ── Diagnostics ─────────────────────────────────────────────────
    /// Total loss events.
    pub loss_events: u64,
    /// Total fast retransmits triggered.
    pub fast_retransmits: u64,
    /// Total spurious retransmits undone.
    pub spurious_recoveries: u64,
}

impl AdvancedCongestionController {
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            phase: CongestionPhase::SlowStart,
            rtt: RttEstimator::new(),
            pacer: TokenBucketPacer::new(),
            spurious: SpuriousDetector::new(256),
            scoreboard: SackScoreboard::new(),
            retransmit_tracker: RetransmitTracker::new(RETRANSMIT_BUF_MAX),
            recovery_cwnd: 0.0,
            prr_delivered: 0,
            prr_out: 0,
            recovery_seq: None,
            dup_nack_count: 0,
            dup_nack_trigger_seq: None,
            loss_events: 0,
            fast_retransmits: 0,
            spurious_recoveries: 0,
        }
    }

    /// Effective send window: min(cwnd, SEND_WINDOW).
    pub fn effective_window(&self) -> u64 {
        let cw = self.cwnd as u64;
        cw.min(SEND_WINDOW)
    }

    /// Called when an ACK advances the cumulative acknowledgment.
    ///
    /// `newly_acked`: number of new packets this ACK covers.
    pub fn on_ack(&mut self, newly_acked: u64) {
        match self.phase {
            CongestionPhase::SlowStart => {
                self.cwnd += newly_acked as f64;
                if self.cwnd >= self.ssthresh {
                    self.phase = CongestionPhase::CongestionAvoidance;
                    self.pacer.enable();
                    debug!(
                        "congestion: SlowStart → CongAvoid (cwnd={:.1}, ssthresh={:.1})",
                        self.cwnd, self.ssthresh
                    );
                }
            }
            CongestionPhase::CongestionAvoidance => {
                // Reno-style: cwnd += newly_acked / cwnd ≈ 1 pkt per RTT
                self.cwnd += (newly_acked as f64) / self.cwnd;
            }
            CongestionPhase::Recovery => {
                // PRR: proportional rate reduction
                self.prr_delivered += newly_acked;
                self.apply_prr();

                // Check if recovery is complete
                if let Some(rec_seq) = self.recovery_seq {
                    if let Some(ca) = self.scoreboard.cumulative_ack() {
                        if ca >= rec_seq {
                            // Recovery complete
                            self.phase = CongestionPhase::CongestionAvoidance;
                            self.cwnd = self.ssthresh;
                            self.recovery_seq = None;
                            debug!("congestion: Recovery complete, cwnd={:.1}", self.cwnd);
                        }
                    }
                }
            }
        }

        // Refill pacer tokens
        self.pacer.refill(self.cwnd, self.rtt.srtt_ms());
    }

    /// Apply Proportional Rate Reduction.
    ///
    /// PRR sends packets at a rate proportional to the ratio of
    /// new_ssthresh to old_cwnd, smoothly reducing the flight size
    /// instead of immediately halving it.
    fn apply_prr(&mut self) {
        if self.recovery_cwnd <= 0.0 {
            return;
        }

        // pipe_target = ssthresh
        // allowed = (prr_delivered * ssthresh / recovery_cwnd) - prr_out
        let allowed = ((self.prr_delivered as f64 * self.ssthresh) / self.recovery_cwnd)
            - self.prr_out as f64;

        if allowed >= 1.0 {
            // Can send more packets during recovery
            self.prr_out += allowed.floor() as u64;
        }
    }

    /// Called when loss is detected (NACK, SACK gap, or RTO).
    ///
    /// `highest_sent_seq`: the highest data_seq we've sent.
    pub fn on_loss(&mut self, highest_sent_seq: Option<u64>) {
        self.loss_events += 1;

        if self.phase == CongestionPhase::Recovery {
            // Already in recovery — don't reduce again
            debug!("congestion: additional loss during recovery, ignoring");
            return;
        }

        // Enter recovery
        self.recovery_cwnd = self.cwnd;
        self.ssthresh = (self.cwnd / 2.0).max(MIN_CWND);
        self.phase = CongestionPhase::Recovery;
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.recovery_seq = highest_sent_seq;
        self.pacer.enable();

        debug!(
            "congestion: loss detected, entering Recovery (cwnd={:.1} → ssthresh={:.1}, recovery_seq={:?})",
            self.recovery_cwnd, self.ssthresh, self.recovery_seq
        );
    }

    /// Called when an RTO fires (no ACK received within RTO period).
    pub fn on_rto(&mut self) {
        self.loss_events += 1;
        self.rtt.on_rto_timeout();

        // RTO is more severe: reset to slow start
        self.ssthresh = (self.cwnd / 2.0).max(MIN_CWND);
        self.cwnd = MIN_CWND; // Go back to minimum
        self.phase = CongestionPhase::SlowStart;
        self.pacer.disable();
        self.recovery_seq = None;

        debug!(
            "congestion: RTO timeout, back to SlowStart (cwnd={:.1}, ssthresh={:.1})",
            self.cwnd, self.ssthresh
        );
    }

    /// Process a NACK for fast retransmit detection.
    ///
    /// Returns true if fast retransmit should be triggered.
    pub fn on_nack_received(&mut self, missing_seqs: &[u64]) -> bool {
        // Track duplicate NACKs for the same gap
        let trigger_seq = missing_seqs.first().copied();
        if trigger_seq == self.dup_nack_trigger_seq {
            self.dup_nack_count += 1;
        } else {
            self.dup_nack_trigger_seq = trigger_seq;
            self.dup_nack_count = 1;
        }

        // Update scoreboard
        self.scoreboard.update_from_nack(missing_seqs);

        // Fast retransmit threshold
        if self.dup_nack_count >= FAST_RETRANSMIT_THRESHOLD
            && self.phase != CongestionPhase::Recovery
        {
            self.fast_retransmits += 1;
            debug!(
                "fast retransmit triggered ({} dup NACKs)",
                self.dup_nack_count
            );
            self.dup_nack_count = 0;
            return true;
        }

        false
    }

    /// Handle spurious retransmission detection result.
    ///
    /// If the retransmission was spurious, undo the congestion response.
    pub fn on_spurious_detected(&mut self) {
        self.spurious_recoveries += 1;

        if self.phase == CongestionPhase::Recovery {
            // Undo: restore cwnd to pre-recovery value
            self.cwnd = self.recovery_cwnd;
            self.ssthresh = self.recovery_cwnd;
            self.phase = CongestionPhase::CongestionAvoidance;
            self.recovery_seq = None;

            debug!("spurious recovery: restoring cwnd to {:.1}", self.cwnd);
        }
    }

    /// Update RTT from a measurement sample.
    pub fn update_rtt(&mut self, sample_ms: f64) {
        self.rtt.update(sample_ms);
    }

    /// NACK/gap detection threshold (RTT-adaptive).
    pub fn gap_threshold(&self) -> Duration {
        self.rtt.gap_threshold()
    }

    /// NACK rate limit interval.
    pub fn nack_interval(&self) -> Duration {
        self.rtt.nack_interval()
    }

    /// Current RTO in milliseconds.
    pub fn rto_ms(&self) -> f64 {
        self.rtt.rto_ms()
    }

    /// Current SRTT in milliseconds.
    pub fn srtt_ms(&self) -> f64 {
        self.rtt.srtt_ms()
    }

    /// How many packets the pacer allows right now.
    pub fn paced_send_count(&mut self, requested: usize) -> usize {
        self.pacer.refill(self.cwnd, self.rtt.srtt_ms());
        self.pacer.try_consume(requested)
    }
}

impl Default for AdvancedCongestionController {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Receiver SACK State ────────────────────────────────────────────────────

/// Receiver-side state for generating SACK information.
///
/// The receiver tracks which sequences it has received (including
/// out-of-order) and can generate SACK ranges to send to the sender.
#[derive(Debug)]
pub struct ReceiverSackState {
    /// The highest contiguous delivered sequence.
    cumulative_ack: Option<u64>,
    /// Non-contiguous received ranges above cumulative_ack.
    /// Generated from the reassembly buffer's state.
    sack_ranges: Vec<SackRange>,
}

impl ReceiverSackState {
    pub fn new() -> Self {
        Self {
            cumulative_ack: None,
            sack_ranges: Vec::new(),
        }
    }

    /// Update SACK state from the reassembly buffer.
    ///
    /// `expected_seq`: the next expected (= cumulative_ack + 1).
    /// `buffered_seqs`: the sequence numbers currently in the out-of-order buffer.
    pub fn update_from_reassembly(&mut self, expected_seq: u64, buffered_seqs: &[u64]) {
        self.cumulative_ack = if expected_seq > 0 {
            Some(expected_seq - 1)
        } else {
            None
        };

        self.sack_ranges.clear();
        if buffered_seqs.is_empty() {
            return;
        }

        // Build ranges from sorted buffered seqs
        let mut sorted = buffered_seqs.to_vec();
        sorted.sort_unstable();

        let mut range_start = sorted[0];
        let mut range_end = sorted[0];

        for &seq in &sorted[1..] {
            if seq == range_end + 1 {
                range_end = seq;
            } else {
                self.sack_ranges
                    .push(SackRange::new(range_start, range_end));
                range_start = seq;
                range_end = seq;
            }
        }
        self.sack_ranges
            .push(SackRange::new(range_start, range_end));

        // Limit to MAX_SACK_RANGES
        self.sack_ranges.truncate(MAX_SACK_RANGES);
    }

    /// Generate a SACK frame payload.
    pub fn encode_sack_frame(&self) -> Option<Vec<u8>> {
        self.cumulative_ack
            .map(|ca| encode_sack_frame(ca, &self.sack_ranges))
    }

    /// Get current cumulative ACK.
    pub fn cumulative_ack(&self) -> Option<u64> {
        self.cumulative_ack
    }

    /// Get current SACK ranges.
    pub fn ranges(&self) -> &[SackRange] {
        &self.sack_ranges
    }

    /// Generate SACK blocks as `(start, end)` tuples for the ACK frame.
    ///
    /// Returns up to `max_blocks` contiguous received ranges above the
    /// cumulative ACK. These are the ranges the sender should NOT retransmit.
    pub fn get_sack_blocks(&self, max_blocks: usize) -> Vec<(u64, u64)> {
        self.sack_ranges
            .iter()
            .take(max_blocks)
            .map(|r| (r.start, r.end))
            .collect()
    }
}

impl Default for ReceiverSackState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── RTT Estimator tests ─────────────────────────────────────────

    #[test]
    fn test_rtt_estimator_initial_state() {
        let rtt = RttEstimator::new();
        assert_eq!(rtt.srtt_ms(), INITIAL_SRTT_MS);
        assert!((rtt.rttvar_ms() - INITIAL_SRTT_MS / 2.0).abs() < 0.01);
        assert!(!rtt.has_sample);
    }

    #[test]
    fn test_rtt_estimator_first_sample() {
        let mut rtt = RttEstimator::new();
        rtt.update(50.0);

        assert!(rtt.has_sample);
        assert_eq!(rtt.srtt_ms(), 50.0);
        assert_eq!(rtt.rttvar_ms(), 25.0); // sample / 2
                                           // RTO = 50 + 4*25 = 150, but clamped to MIN_RTO_MS
        assert!((rtt.rto_ms() - MIN_RTO_MS).abs() < 0.01);
    }

    #[test]
    fn test_rtt_estimator_jacobson_karels() {
        let mut rtt = RttEstimator::new();

        // First sample
        rtt.update(100.0);
        assert_eq!(rtt.srtt_ms(), 100.0);
        assert_eq!(rtt.rttvar_ms(), 50.0);

        // Second sample: 80ms
        rtt.update(80.0);
        // srtt = 0.875 * 100 + 0.125 * 80 = 97.5
        assert!((rtt.srtt_ms() - 97.5).abs() < 0.01);
        // rttvar = 0.75 * 50 + 0.25 * |100 - 80| = 42.5
        assert!((rtt.rttvar_ms() - 42.5).abs() < 0.01);
        // rto = 97.5 + 4 * 42.5 = 267.5
        assert!((rtt.rto_ms() - 267.5).abs() < 0.01);
    }

    #[test]
    fn test_rtt_estimator_convergence() {
        let mut rtt = RttEstimator::new();

        // Feed steady 50ms samples
        for _ in 0..100 {
            rtt.update(50.0);
        }

        // SRTT should converge close to 50ms
        assert!((rtt.srtt_ms() - 50.0).abs() < 1.0);
        // RTTVAR should be very small (steady RTT)
        assert!(rtt.rttvar_ms() < 5.0);
    }

    #[test]
    fn test_rtt_estimator_rto_clamping() {
        let mut rtt = RttEstimator::new();

        // Very small RTT → RTO clamped to MIN_RTO_MS
        for _ in 0..100 {
            rtt.update(1.0);
        }
        assert!(rtt.rto_ms() >= MIN_RTO_MS);

        // Very large RTT → RTO clamped to MAX_RTO_MS
        let mut rtt2 = RttEstimator::new();
        for _ in 0..100 {
            rtt2.update(50000.0);
        }
        assert!(rtt2.rto_ms() <= MAX_RTO_MS);
    }

    #[test]
    fn test_rtt_estimator_backoff() {
        let mut rtt = RttEstimator::new();
        rtt.update(100.0);
        let base_rto = rtt.rto_ms();

        // First backoff: 2x
        rtt.on_rto_timeout();
        assert!((rtt.rto_ms() - base_rto * 2.0).abs() < 1.0);

        // Second backoff: 4x
        rtt.on_rto_timeout();
        assert!((rtt.rto_ms() - base_rto * 4.0).abs() < 1.0);

        // New sample resets backoff
        rtt.update(100.0);
        assert_eq!(rtt.rto_backoffs, 0);
    }

    #[test]
    fn test_rtt_estimator_min_rtt_tracking() {
        let mut rtt = RttEstimator::new();
        rtt.update(100.0);
        rtt.update(50.0);
        rtt.update(80.0);
        rtt.update(30.0);
        rtt.update(60.0);

        assert_eq!(rtt.min_rtt_ms(), 30.0);
    }

    #[test]
    fn test_rtt_estimator_gap_threshold_adaptive() {
        let mut rtt = RttEstimator::new();

        // Default: 2*100 = 200ms
        assert_eq!(rtt.gap_threshold(), Duration::from_millis(200));

        // Low RTT: clamped to NACK_MIN_THRESHOLD_MS
        for _ in 0..50 {
            rtt.update(10.0);
        }
        // 2*~10 = ~20, but min is NACK_MIN_THRESHOLD_MS
        assert!(rtt.gap_threshold().as_millis() >= NACK_MIN_THRESHOLD_MS as u128);
    }

    #[test]
    fn test_rtt_estimator_ignores_zero_sample() {
        let mut rtt = RttEstimator::new();
        let srtt_before = rtt.srtt_ms();
        rtt.update(0.0);
        assert_eq!(rtt.srtt_ms(), srtt_before);
        rtt.update(-5.0);
        assert_eq!(rtt.srtt_ms(), srtt_before);
    }

    // ── SACK Range tests ────────────────────────────────────────────

    #[test]
    fn test_sack_range_basic() {
        let r = SackRange::new(5, 10);
        assert_eq!(r.len(), 6);
        assert!(!r.is_empty());
        assert!(r.contains(5));
        assert!(r.contains(10));
        assert!(!r.contains(4));
        assert!(!r.contains(11));
    }

    #[test]
    fn test_sack_range_single() {
        let r = SackRange::new(42, 42);
        assert_eq!(r.len(), 1);
        assert!(r.contains(42));
        assert!(!r.contains(41));
        assert!(!r.contains(43));
    }

    // ── SACK Encode/Decode tests ────────────────────────────────────

    #[test]
    fn test_sack_encode_decode_roundtrip() {
        let ranges = vec![
            SackRange::new(10, 15),
            SackRange::new(20, 25),
            SackRange::new(30, 30),
        ];
        let frame = encode_sack_frame(5, &ranges);

        assert_eq!(frame[0], FRAME_SACK);

        let (ca, decoded_ranges) = decode_sack_payload(&frame[1..]).unwrap();
        assert_eq!(ca, 5);
        assert_eq!(decoded_ranges.len(), 3);
        assert_eq!(decoded_ranges[0], SackRange::new(10, 15));
        assert_eq!(decoded_ranges[1], SackRange::new(20, 25));
        assert_eq!(decoded_ranges[2], SackRange::new(30, 30));
    }

    #[test]
    fn test_sack_encode_decode_empty_ranges() {
        let frame = encode_sack_frame(100, &[]);
        let (ca, ranges) = decode_sack_payload(&frame[1..]).unwrap();
        assert_eq!(ca, 100);
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_sack_decode_malformed() {
        // Too short
        assert!(decode_sack_payload(&[]).is_none());
        assert!(decode_sack_payload(&[0; 5]).is_none());

        // Count says 1 but no range data
        let mut bad = vec![0u8; 10];
        bad[9] = 1; // count = 1
        assert!(decode_sack_payload(&bad).is_none());

        // Invalid range (end < start) — manually build a corrupt frame
        let mut bad_frame = Vec::new();
        bad_frame.extend_from_slice(&0u64.to_be_bytes()); // cumulative_ack
        bad_frame.extend_from_slice(&1u16.to_be_bytes()); // count = 1
        bad_frame.extend_from_slice(&10u64.to_be_bytes()); // start = 10
        bad_frame.extend_from_slice(&5u64.to_be_bytes()); // end = 5 (invalid)
        assert!(decode_sack_payload(&bad_frame).is_none());
    }

    #[test]
    fn test_sack_truncation_at_max() {
        let ranges: Vec<SackRange> = (0..50)
            .map(|i| SackRange::new(i * 10, i * 10 + 5))
            .collect();
        let frame = encode_sack_frame(0, &ranges);
        let (_, decoded) = decode_sack_payload(&frame[1..]).unwrap();
        assert_eq!(decoded.len(), MAX_SACK_RANGES);
    }

    // ── SACK Scoreboard tests ───────────────────────────────────────

    #[test]
    fn test_scoreboard_empty() {
        let sb = SackScoreboard::new();
        assert_eq!(sb.cumulative_ack(), None);
        assert!(!sb.is_acked(0));
        assert!(sb.get_missing_seqs(10).is_empty());
    }

    #[test]
    fn test_scoreboard_cumulative_ack() {
        let mut sb = SackScoreboard::new();
        sb.update_from_sack(10, &[]);

        assert_eq!(sb.cumulative_ack(), Some(10));
        assert!(sb.is_acked(0));
        assert!(sb.is_acked(10));
        assert!(!sb.is_acked(11));
    }

    #[test]
    fn test_scoreboard_with_ranges() {
        let mut sb = SackScoreboard::new();
        sb.update_from_sack(5, &[SackRange::new(8, 10), SackRange::new(15, 20)]);

        assert!(sb.is_acked(5));
        assert!(!sb.is_acked(6));
        assert!(!sb.is_acked(7));
        assert!(sb.is_acked(8));
        assert!(sb.is_acked(10));
        assert!(!sb.is_acked(11));
        assert!(sb.is_acked(15));
        assert!(sb.is_acked(20));
        assert!(!sb.is_acked(21));

        let missing = sb.get_missing_seqs(100);
        assert_eq!(missing, vec![6, 7, 11, 12, 13, 14]);
    }

    #[test]
    fn test_scoreboard_range_merging() {
        let mut sb = SackScoreboard::new();
        sb.update_from_sack(0, &[SackRange::new(5, 8)]);
        sb.update_from_sack(0, &[SackRange::new(7, 12)]); // overlaps with previous

        // After merging: should have [5, 12]
        assert!(sb.is_acked(5));
        assert!(sb.is_acked(8));
        assert!(sb.is_acked(10));
        assert!(sb.is_acked(12));
    }

    #[test]
    fn test_scoreboard_adjacent_range_merging() {
        let mut sb = SackScoreboard::new();
        sb.update_from_sack(0, &[SackRange::new(5, 7)]);
        sb.update_from_sack(0, &[SackRange::new(8, 10)]); // adjacent

        // After merging: should have [5, 10]
        assert!(sb.is_acked(5));
        assert!(sb.is_acked(7));
        assert!(sb.is_acked(8));
        assert!(sb.is_acked(10));
    }

    #[test]
    fn test_scoreboard_pruning_on_cumulative_advance() {
        let mut sb = SackScoreboard::new();
        sb.update_from_sack(5, &[SackRange::new(8, 10)]);
        sb.update_from_sack(12, &[]); // cumulative advances past the SACK range

        // Range [8, 10] should be pruned (all <= 12)
        assert!(sb.ranges().is_empty() || sb.ranges().iter().all(|r| r.end > 12));
    }

    #[test]
    fn test_scoreboard_fast_retransmit_candidates() {
        let mut sb = SackScoreboard::new();

        // Simulate 3 NACKs for seq 5
        sb.update_from_nack(&[5]);
        assert!(sb.get_fast_retransmit_candidates(3).is_empty());
        sb.update_from_nack(&[5]);
        assert!(sb.get_fast_retransmit_candidates(3).is_empty());
        sb.update_from_nack(&[5]);
        assert_eq!(sb.get_fast_retransmit_candidates(3), vec![5]);

        // Reset
        sb.reset_nack_count(5);
        assert!(sb.get_fast_retransmit_candidates(3).is_empty());
    }

    // ── Spurious Detector tests ─────────────────────────────────────

    #[test]
    fn test_spurious_detector_no_retransmit() {
        let mut sd = SpuriousDetector::new(100);
        assert!(!sd.check_ack(42));
        assert_eq!(sd.spurious_count, 0);
    }

    #[test]
    fn test_spurious_detector_legitimate_retransmit() {
        let mut sd = SpuriousDetector::new(100);
        sd.record_retransmit(42, 100.0); // expected RTT = 100ms

        // Wait longer than expected RTT before ACK
        std::thread::sleep(Duration::from_millis(60));
        assert!(!sd.check_ack(42)); // Not spurious (arrived after 60ms, threshold is 50ms)
    }

    #[test]
    fn test_spurious_detector_prune() {
        let mut sd = SpuriousDetector::new(100);
        sd.record_retransmit(1, 100.0);
        sd.record_retransmit(5, 100.0);
        sd.record_retransmit(10, 100.0);

        sd.prune_up_to(5);
        assert!(!sd.retransmit_records.contains_key(&1));
        assert!(!sd.retransmit_records.contains_key(&5));
        assert!(sd.retransmit_records.contains_key(&10));
    }

    // ── Token Bucket Pacer tests ────────────────────────────────────

    #[test]
    fn test_pacer_disabled_by_default() {
        let mut pacer = TokenBucketPacer::new();
        assert!(!pacer.is_enabled());
        // When disabled, always returns full requested count
        assert_eq!(pacer.try_consume(100), 100);
    }

    #[test]
    fn test_pacer_enabled_limiting() {
        let mut pacer = TokenBucketPacer::new();
        pacer.enable();
        pacer.tokens = 5.0;
        pacer.max_tokens = 10.0;

        // Can consume up to available tokens
        assert_eq!(pacer.try_consume(3), 3);
        assert_eq!(pacer.try_consume(10), 2); // only 2 left (5 - 3)
        assert_eq!(pacer.try_consume(10), 1); // always at least 1
    }

    #[test]
    fn test_pacer_refill() {
        let mut pacer = TokenBucketPacer::new();
        pacer.enable();
        pacer.tokens = 0.0;
        pacer.last_refill = Instant::now() - Duration::from_millis(100);

        // cwnd=100, srtt=100ms → rate = 1 pkt/ms → 100ms = 100 tokens
        pacer.refill(100.0, 100.0);

        // Should have refilled substantially (capped by max_tokens = cwnd/4 = 25)
        assert!(pacer.tokens > 0.0);
        assert!(pacer.tokens <= 25.0);
    }

    #[test]
    fn test_pacer_time_until_token() {
        let mut pacer = TokenBucketPacer::new();
        pacer.enable();
        pacer.tokens = 0.5;

        let wait = pacer.time_until_token(100.0, 100.0);
        // Need 0.5 more tokens, rate = 1 pkt/ms → 0.5ms
        assert!(wait < Duration::from_millis(2));
    }

    // ── Retransmit Tracker tests ────────────────────────────────────

    #[test]
    fn test_retransmit_tracker_rate_limiting() {
        let mut tracker = RetransmitTracker::new(100);
        let interval = Duration::from_millis(50);

        assert!(tracker.can_retransmit(42, interval));
        tracker.record_retransmit(42);
        assert!(!tracker.can_retransmit(42, interval));

        std::thread::sleep(Duration::from_millis(60));
        assert!(tracker.can_retransmit(42, interval));
    }

    #[test]
    fn test_retransmit_tracker_prune() {
        let mut tracker = RetransmitTracker::new(100);
        tracker.record_retransmit(1);
        tracker.record_retransmit(5);
        tracker.record_retransmit(10);

        tracker.prune_up_to(5);
        assert!(!tracker.last_retransmit.contains_key(&1));
        assert!(!tracker.last_retransmit.contains_key(&5));
        assert!(tracker.last_retransmit.contains_key(&10));
    }

    // ── Advanced Congestion Controller tests ────────────────────────

    #[test]
    fn test_acc_initial_state() {
        let cc = AdvancedCongestionController::new();
        assert_eq!(cc.phase, CongestionPhase::SlowStart);
        assert_eq!(cc.cwnd, INITIAL_CWND);
        assert_eq!(cc.ssthresh, INITIAL_SSTHRESH);
        assert_eq!(cc.loss_events, 0);
    }

    #[test]
    fn test_acc_slow_start_to_congestion_avoidance() {
        let mut cc = AdvancedCongestionController::new();
        cc.ssthresh = 15.0; // Low enough that INITIAL_CWND(10) + 10 acks = 20 >= 15

        // Grow past ssthresh
        cc.on_ack(10);
        assert_eq!(cc.phase, CongestionPhase::CongestionAvoidance);
        assert!(cc.pacer.is_enabled());
    }

    #[test]
    fn test_acc_congestion_avoidance_linear() {
        let mut cc = AdvancedCongestionController::new();
        cc.phase = CongestionPhase::CongestionAvoidance;
        cc.cwnd = 100.0;

        let initial = cc.cwnd;
        for _ in 0..100 {
            cc.on_ack(1);
        }
        // Should grow by ~1 packet in 100 ACKs
        assert!((cc.cwnd - initial - 1.0).abs() < 0.5);
    }

    #[test]
    fn test_acc_loss_enters_recovery() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 100.0;

        cc.on_loss(Some(200));
        assert_eq!(cc.phase, CongestionPhase::Recovery);
        assert_eq!(cc.ssthresh, 50.0);
        assert_eq!(cc.recovery_cwnd, 100.0);
        assert_eq!(cc.recovery_seq, Some(200));
        assert_eq!(cc.loss_events, 1);
    }

    #[test]
    fn test_acc_no_double_reduction_in_recovery() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 100.0;

        cc.on_loss(Some(200));
        let ssthresh_after_first = cc.ssthresh;

        // Another loss during recovery: should NOT reduce again
        cc.on_loss(Some(250));
        assert_eq!(cc.ssthresh, ssthresh_after_first);
        assert_eq!(cc.loss_events, 2); // counted but not acted upon
    }

    #[test]
    fn test_acc_rto_resets_to_slow_start() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 100.0;
        cc.phase = CongestionPhase::CongestionAvoidance;

        cc.on_rto();
        assert_eq!(cc.phase, CongestionPhase::SlowStart);
        assert_eq!(cc.cwnd, MIN_CWND);
        assert_eq!(cc.ssthresh, 50.0);
        assert!(!cc.pacer.is_enabled());
    }

    #[test]
    fn test_acc_fast_retransmit() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 100.0;

        // First 2 NACKs: no trigger
        assert!(!cc.on_nack_received(&[5]));
        assert!(!cc.on_nack_received(&[5]));

        // 3rd NACK for same gap: triggers fast retransmit
        assert!(cc.on_nack_received(&[5]));
        assert_eq!(cc.fast_retransmits, 1);
    }

    #[test]
    fn test_acc_fast_retransmit_different_gaps() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 100.0;

        // NACKs for different gaps don't accumulate
        assert!(!cc.on_nack_received(&[5]));
        assert!(!cc.on_nack_received(&[5]));
        assert!(!cc.on_nack_received(&[10])); // different gap, resets count
        assert!(!cc.on_nack_received(&[10]));
        assert!(cc.on_nack_received(&[10])); // 3rd for seq 10
    }

    #[test]
    fn test_acc_spurious_recovery() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 100.0;

        // Enter recovery
        cc.on_loss(Some(200));
        assert_eq!(cc.phase, CongestionPhase::Recovery);
        let recovery_cwnd = cc.recovery_cwnd;

        // Detect spurious
        cc.on_spurious_detected();
        assert_eq!(cc.phase, CongestionPhase::CongestionAvoidance);
        assert_eq!(cc.cwnd, recovery_cwnd);
        assert_eq!(cc.spurious_recoveries, 1);
    }

    #[test]
    fn test_acc_recovery_completes_on_cumulative_advance() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 100.0;

        // Enter recovery at seq 200
        cc.on_loss(Some(200));
        assert_eq!(cc.phase, CongestionPhase::Recovery);

        // Update scoreboard cumulative ACK past recovery_seq
        cc.scoreboard.update_from_sack(201, &[]);
        cc.on_ack(50);

        assert_eq!(cc.phase, CongestionPhase::CongestionAvoidance);
        assert_eq!(cc.cwnd, cc.ssthresh);
    }

    #[test]
    fn test_acc_full_lifecycle() {
        let mut cc = AdvancedCongestionController::new();
        cc.ssthresh = 20.0; // Low enough for INITIAL_CWND(10) + 10 acks = 20

        // 1. Slow start: grow to ssthresh
        for _ in 0..10 {
            cc.on_ack(1);
        }
        // cwnd = 10 + 10 = 20 >= ssthresh(20)
        assert_eq!(cc.phase, CongestionPhase::CongestionAvoidance);

        // 2. Congestion avoidance: linear growth
        for _ in 0..200 {
            cc.on_ack(1);
        }
        let cwnd_before = cc.cwnd;

        // 3. Loss → recovery
        cc.on_loss(Some(500));
        assert_eq!(cc.phase, CongestionPhase::Recovery);
        assert!(cc.cwnd == cc.recovery_cwnd); // cwnd hasn't changed yet (PRR controls sending)

        // 4. ACKs during recovery (PRR)
        cc.scoreboard.update_from_sack(501, &[]);
        cc.on_ack(100);
        assert_eq!(cc.phase, CongestionPhase::CongestionAvoidance);

        // 5. Recovery complete, back to congestion avoidance at ssthresh
        assert!(cc.cwnd <= cwnd_before);
        assert!(cc.cwnd >= MIN_CWND);
    }

    // ── Receiver SACK State tests ───────────────────────────────────

    #[test]
    fn test_receiver_sack_no_data() {
        let state = ReceiverSackState::new();
        assert_eq!(state.cumulative_ack(), None);
        assert!(state.ranges().is_empty());
        assert!(state.encode_sack_frame().is_none());
    }

    #[test]
    fn test_receiver_sack_contiguous() {
        let mut state = ReceiverSackState::new();
        state.update_from_reassembly(10, &[]);

        assert_eq!(state.cumulative_ack(), Some(9));
        assert!(state.ranges().is_empty());
    }

    #[test]
    fn test_receiver_sack_with_gaps() {
        let mut state = ReceiverSackState::new();
        // expected_seq = 5, buffered: [8, 9, 10, 15, 16]
        state.update_from_reassembly(5, &[8, 9, 10, 15, 16]);

        assert_eq!(state.cumulative_ack(), Some(4));
        assert_eq!(state.ranges().len(), 2);
        assert_eq!(state.ranges()[0], SackRange::new(8, 10));
        assert_eq!(state.ranges()[1], SackRange::new(15, 16));
    }

    #[test]
    fn test_receiver_sack_encode_roundtrip() {
        let mut state = ReceiverSackState::new();
        state.update_from_reassembly(5, &[8, 9, 15]);

        let frame = state.encode_sack_frame().unwrap();
        assert_eq!(frame[0], FRAME_SACK);

        let (ca, ranges) = decode_sack_payload(&frame[1..]).unwrap();
        assert_eq!(ca, 4);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], SackRange::new(8, 9));
        assert_eq!(ranges[1], SackRange::new(15, 15));
    }

    // ── Integration: simulate lossy link ────────────────────────────

    #[test]
    fn test_lossy_link_simulation() {
        // Simulate sending 1000 packets with 5% random loss
        // Verify the congestion controller adapts gracefully
        let mut cc = AdvancedCongestionController::new();
        cc.ssthresh = 128.0;
        let mut rng_state: u64 = 42;

        let mut total_sent = 0u64;
        let mut total_lost = 0u64;

        for data_seq in 0u64..1000 {
            // Simple LCG for deterministic "random" loss
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let loss = (rng_state >> 32) % 100 < 5; // 5% loss rate

            if loss {
                total_lost += 1;
                cc.on_loss(Some(data_seq));
            } else {
                total_sent += 1;
                cc.on_ack(1);
                cc.update_rtt(50.0 + (rng_state % 20) as f64); // 50-70ms RTT
            }
        }

        // Cwnd should be positive and reasonable (not collapsed to 0)
        assert!(cc.cwnd >= MIN_CWND);
        // Should have experienced loss events
        assert!(cc.loss_events > 0);
        // Throughput shouldn't have collapsed
        assert!(total_sent > total_lost * 10);

        // SRTT should be in the expected range
        assert!(cc.srtt_ms() > 40.0 && cc.srtt_ms() < 80.0);
    }

    #[test]
    fn test_congestion_window_recovery_after_loss() {
        let mut cc = AdvancedCongestionController::new();
        cc.ssthresh = 80.0;

        // Grow to 100
        cc.cwnd = 100.0;
        cc.phase = CongestionPhase::CongestionAvoidance;

        // Loss
        cc.on_loss(Some(200));
        let post_loss_ssthresh = cc.ssthresh;
        assert_eq!(post_loss_ssthresh, 50.0);

        // Complete recovery
        cc.scoreboard.update_from_sack(201, &[]);
        cc.on_ack(100);
        assert_eq!(cc.phase, CongestionPhase::CongestionAvoidance);
        assert_eq!(cc.cwnd, post_loss_ssthresh);

        // Now grow back
        for _ in 0..1000 {
            cc.on_ack(1);
        }

        // Should have recovered significantly
        assert!(cc.cwnd > post_loss_ssthresh + 5.0);
    }

    // ── ReceiverSackState get_sack_blocks tests ─────────────────────

    #[test]
    fn test_receiver_sack_get_sack_blocks_empty() {
        let state = ReceiverSackState::new();
        assert!(state.get_sack_blocks(3).is_empty());
    }

    #[test]
    fn test_receiver_sack_get_sack_blocks_contiguous() {
        let mut state = ReceiverSackState::new();
        state.update_from_reassembly(10, &[]); // no out-of-order packets
        assert!(state.get_sack_blocks(3).is_empty());
    }

    #[test]
    fn test_receiver_sack_get_sack_blocks_with_gaps() {
        let mut state = ReceiverSackState::new();
        // expected_seq = 5 (cumulative_ack = 4), buffered = [8, 9, 10, 15, 16]
        state.update_from_reassembly(5, &[8, 9, 10, 15, 16]);

        let blocks = state.get_sack_blocks(3);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], (8, 10));
        assert_eq!(blocks[1], (15, 16));
    }

    #[test]
    fn test_receiver_sack_get_sack_blocks_max_capped() {
        let mut state = ReceiverSackState::new();
        // Create 4 separate ranges: [3], [6], [9], [12]
        state.update_from_reassembly(1, &[3, 6, 9, 12]);

        // Request max 2 blocks
        let blocks = state.get_sack_blocks(2);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], (3, 3));
        assert_eq!(blocks[1], (6, 6));

        // Request max 10 — should get all 4
        let all_blocks = state.get_sack_blocks(10);
        assert_eq!(all_blocks.len(), 4);
    }

    // ── SackScoreboard process_sack_blocks tests ────────────────────

    #[test]
    fn test_scoreboard_process_sack_blocks_empty() {
        let mut sb = SackScoreboard::new();
        sb.process_sack_blocks(&[]);
        assert!(sb.ranges().is_empty());
    }

    #[test]
    fn test_scoreboard_process_sack_blocks_single() {
        let mut sb = SackScoreboard::new();
        sb.cumulative_ack = Some(4);
        sb.process_sack_blocks(&[(6, 8)]);

        assert!(sb.is_acked(6));
        assert!(sb.is_acked(7));
        assert!(sb.is_acked(8));
        assert!(!sb.is_acked(5));
        assert!(!sb.is_acked(9));
    }

    #[test]
    fn test_scoreboard_process_sack_blocks_multiple() {
        let mut sb = SackScoreboard::new();
        sb.cumulative_ack = Some(4);
        sb.process_sack_blocks(&[(6, 8), (11, 15)]);

        // Gaps at 5, 9, 10 should not be acked
        assert!(!sb.is_acked(5));
        assert!(sb.is_acked(6));
        assert!(sb.is_acked(8));
        assert!(!sb.is_acked(9));
        assert!(!sb.is_acked(10));
        assert!(sb.is_acked(11));
        assert!(sb.is_acked(15));

        let missing = sb.get_missing_seqs(100);
        assert_eq!(missing, vec![5, 9, 10]);
    }

    #[test]
    fn test_scoreboard_process_sack_blocks_merges_with_existing() {
        let mut sb = SackScoreboard::new();
        sb.cumulative_ack = Some(0);
        sb.process_sack_blocks(&[(5, 7)]);
        sb.process_sack_blocks(&[(8, 10)]); // adjacent to [5,7]

        // Should merge into [5, 10]
        assert!(sb.is_acked(5));
        assert!(sb.is_acked(7));
        assert!(sb.is_acked(8));
        assert!(sb.is_acked(10));
        assert_eq!(sb.ranges().len(), 1);
        assert_eq!(sb.ranges()[0].start, 5);
        assert_eq!(sb.ranges()[0].end, 10);
    }

    // ── RetransmitTracker should_skip_sacked tests ──────────────────

    #[test]
    fn test_retransmit_tracker_skip_sacked_empty_scoreboard() {
        let tracker = RetransmitTracker::new(100);
        let sb = SackScoreboard::new();
        // Nothing is acked, so nothing should be skipped
        assert!(!tracker.should_skip_sacked(5, &sb));
    }

    #[test]
    fn test_retransmit_tracker_skip_sacked_below_cumulative() {
        let tracker = RetransmitTracker::new(100);
        let mut sb = SackScoreboard::new();
        sb.update_from_sack(10, &[]);
        // seq 5 is below cumulative ACK 10 → should be skipped
        assert!(tracker.should_skip_sacked(5, &sb));
        // seq 11 is above → should NOT be skipped
        assert!(!tracker.should_skip_sacked(11, &sb));
    }

    #[test]
    fn test_retransmit_tracker_skip_sacked_in_sack_range() {
        let tracker = RetransmitTracker::new(100);
        let mut sb = SackScoreboard::new();
        sb.update_from_sack(4, &[SackRange::new(6, 8)]);
        // seq 7 is in SACK range [6,8] → should be skipped
        assert!(tracker.should_skip_sacked(7, &sb));
        // seq 5 is NOT in any range → should NOT be skipped
        assert!(!tracker.should_skip_sacked(5, &sb));
        // seq 9 is NOT in any range → should NOT be skipped
        assert!(!tracker.should_skip_sacked(9, &sb));
    }

    #[test]
    fn test_retransmit_tracker_skip_sacked_integration() {
        // Simulate: send_buffer has data_seqs 5-15
        // cumulative_ack = 4, SACK ranges [6,8] and [11,15]
        // Only 5, 9, 10 should NOT be skipped (they're the gaps)
        let tracker = RetransmitTracker::new(100);
        let mut sb = SackScoreboard::new();
        sb.update_from_sack(4, &[SackRange::new(6, 8), SackRange::new(11, 15)]);

        let data_seqs: Vec<u64> = (5..=15).collect();
        let to_retransmit: Vec<u64> = data_seqs
            .iter()
            .filter(|&&ds| !tracker.should_skip_sacked(ds, &sb))
            .copied()
            .collect();

        assert_eq!(to_retransmit, vec![5, 9, 10]);
    }
}
