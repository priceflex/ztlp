//! Anti-replay protection using a sliding bitmap window.
//!
//! Prevents replayed packets from being accepted. Uses a bitmap-based
//! sliding window (RFC 6479 / IPsec style) that tracks which sequence
//! numbers have been seen.
//!
//! ## Algorithm
//!
//! Maintains a bitmap of `WINDOW_SIZE` bits (default 256) plus a
//! `max_seq` tracking the highest accepted sequence number.
//!
//! For an incoming packet with sequence `seq`:
//! - If `seq > max_seq`: accept, advance window, mark `seq` as seen
//! - If `seq == max_seq`: reject (duplicate)
//! - If `seq < max_seq - WINDOW_SIZE`: reject (too old)
//! - If `seq` in window and already seen: reject (replay)
//! - If `seq` in window and not seen: accept, mark as seen
//!
//! ## Thread Safety
//!
//! `ReplayWindow` is `Send` but NOT `Sync`. Each session should have
//! its own window (which is the normal ZTLP usage pattern — one
//! window per peer per direction).

#![deny(unsafe_code)]

/// Default window size in bits. Must be a multiple of 64.
/// 256 bits tracks the last 256 sequence numbers — matches the ZTLP spec.
const WINDOW_SIZE: u64 = 256;

/// Number of u64 blocks needed for the window bitmap.
const BITMAP_BLOCKS: usize = (WINDOW_SIZE / 64) as usize;

/// Result of checking a sequence number against the replay window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheck {
    /// Sequence number is valid (not seen before, within window).
    Ok,
    /// Sequence number is a duplicate (already seen).
    Duplicate,
    /// Sequence number is too old (before the window).
    TooOld,
}

/// Sliding bitmap window for anti-replay protection.
///
/// Uses a fixed 256-bit bitmap (4 × u64) to track seen sequence numbers.
/// The window slides forward as higher sequence numbers are accepted.
#[derive(Clone)]
pub struct ReplayWindow {
    /// Bitmap tracking seen sequence numbers within the window.
    bitmap: [u64; BITMAP_BLOCKS],
    /// Highest accepted sequence number. Starts at 0.
    max_seq: u64,
    /// Whether any packet has been accepted yet.
    initialized: bool,
    /// Total number of packets checked.
    total_checked: u64,
    /// Total number of accepted packets.
    total_accepted: u64,
    /// Total number of rejected packets (duplicate + too_old).
    total_rejected: u64,
}

impl ReplayWindow {
    /// Create a new replay window. No packets have been seen yet.
    pub fn new() -> Self {
        Self {
            bitmap: [0u64; BITMAP_BLOCKS],
            max_seq: 0,
            initialized: false,
            total_checked: 0,
            total_accepted: 0,
            total_rejected: 0,
        }
    }

    /// Check and record a sequence number.
    ///
    /// If the sequence number is valid, it's marked as seen and `ReplayCheck::Ok`
    /// is returned. If it's a replay or too old, it's rejected.
    ///
    /// **Important:** This method has side effects — it updates the window
    /// state on `Ok`. Don't call it speculatively; only call it after the
    /// packet has been authenticated (MAC verified).
    pub fn check_and_update(&mut self, seq: u64) -> ReplayCheck {
        self.total_checked += 1;

        // First packet ever
        if !self.initialized {
            self.initialized = true;
            self.max_seq = seq;
            self.bitmap = [0u64; BITMAP_BLOCKS];
            self.set_bit(0);
            self.total_accepted += 1;
            return ReplayCheck::Ok;
        }

        if seq > self.max_seq {
            // New highest — advance the window
            let advance = seq - self.max_seq;
            self.advance_window(advance);
            self.max_seq = seq;
            self.set_bit(0); // Mark current max_seq position as seen
            self.total_accepted += 1;
            ReplayCheck::Ok
        } else if seq == self.max_seq {
            // Exact duplicate of the highest seen
            self.total_rejected += 1;
            ReplayCheck::Duplicate
        } else {
            let delta = self.max_seq - seq;
            if delta >= WINDOW_SIZE {
                // Too old — outside the window
                self.total_rejected += 1;
                ReplayCheck::TooOld
            } else if self.get_bit(delta as usize) {
                // Already seen — duplicate
                self.total_rejected += 1;
                ReplayCheck::Duplicate
            } else {
                // Within window, not seen — accept
                self.set_bit(delta as usize);
                self.total_accepted += 1;
                ReplayCheck::Ok
            }
        }
    }

    /// Check without updating (read-only peek).
    pub fn check(&self, seq: u64) -> ReplayCheck {
        if !self.initialized {
            return ReplayCheck::Ok;
        }

        if seq > self.max_seq {
            ReplayCheck::Ok
        } else if seq == self.max_seq {
            ReplayCheck::Duplicate
        } else {
            let delta = self.max_seq - seq;
            if delta >= WINDOW_SIZE {
                ReplayCheck::TooOld
            } else if self.get_bit(delta as usize) {
                ReplayCheck::Duplicate
            } else {
                ReplayCheck::Ok
            }
        }
    }

    /// Get the highest accepted sequence number.
    pub fn max_seq(&self) -> u64 {
        self.max_seq
    }

    /// Get statistics.
    pub fn stats(&self) -> ReplayStats {
        ReplayStats {
            max_seq: self.max_seq,
            total_checked: self.total_checked,
            total_accepted: self.total_accepted,
            total_rejected: self.total_rejected,
        }
    }

    /// Reset the window (e.g., after rekeying).
    pub fn reset(&mut self) {
        self.bitmap = [0u64; BITMAP_BLOCKS];
        self.max_seq = 0;
        self.initialized = false;
        // Keep stats across resets for diagnostic visibility
    }

    // ── Internal bitmap operations ──────────────────────────────────

    /// Set bit at position `pos` (0 = most recent = max_seq).
    fn set_bit(&mut self, pos: usize) {
        let block = pos / 64;
        let bit = pos % 64;
        if block < BITMAP_BLOCKS {
            self.bitmap[block] |= 1u64 << bit;
        }
    }

    /// Get bit at position `pos`.
    fn get_bit(&self, pos: usize) -> bool {
        let block = pos / 64;
        let bit = pos % 64;
        if block < BITMAP_BLOCKS {
            self.bitmap[block] & (1u64 << bit) != 0
        } else {
            false
        }
    }

    /// Advance the window by `count` positions.
    ///
    /// Shifts the bitmap to make room for `count` new positions at the front.
    fn advance_window(&mut self, count: u64) {
        if count >= WINDOW_SIZE {
            // Complete reset — everything in old window is now too old
            self.bitmap = [0u64; BITMAP_BLOCKS];
            return;
        }

        let count = count as usize;
        let block_shift = count / 64;
        let bit_shift = count % 64;

        // Shift whole blocks first (from high to low to avoid clobbering)
        if block_shift > 0 {
            for i in (0..BITMAP_BLOCKS).rev() {
                self.bitmap[i] = if i >= block_shift {
                    self.bitmap[i - block_shift]
                } else {
                    0
                };
            }
        }

        // Shift bits within blocks
        if bit_shift > 0 {
            for i in (0..BITMAP_BLOCKS).rev() {
                self.bitmap[i] <<= bit_shift;
                if i > 0 {
                    // Carry high bits from the block below
                    self.bitmap[i] |= self.bitmap[i - 1] >> (64 - bit_shift);
                }
            }
            // Zero out the bits that shouldn't carry in the lowest block
            // (already handled by the shift)
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ReplayWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayWindow")
            .field("max_seq", &self.max_seq)
            .field("accepted", &self.total_accepted)
            .field("rejected", &self.total_rejected)
            .finish()
    }
}

/// Statistics from the replay window.
#[derive(Debug, Clone, Copy)]
pub struct ReplayStats {
    pub max_seq: u64,
    pub total_checked: u64,
    pub total_accepted: u64,
    pub total_rejected: u64,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_window_accepts_first_packet() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(1), ReplayCheck::Ok);
        assert_eq!(w.max_seq(), 1);
    }

    #[test]
    fn test_sequential_packets() {
        let mut w = ReplayWindow::new();
        for seq in 1..=100 {
            assert_eq!(
                w.check_and_update(seq),
                ReplayCheck::Ok,
                "seq {} should be Ok",
                seq
            );
        }
        assert_eq!(w.max_seq(), 100);
        let stats = w.stats();
        assert_eq!(stats.total_accepted, 100);
        assert_eq!(stats.total_rejected, 0);
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(10), ReplayCheck::Ok);
        assert_eq!(w.check_and_update(10), ReplayCheck::Duplicate);
    }

    #[test]
    fn test_older_packet_within_window() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(100), ReplayCheck::Ok);
        assert_eq!(w.check_and_update(50), ReplayCheck::Ok); // Within window (100-50=50 < 256)
        assert_eq!(w.check_and_update(50), ReplayCheck::Duplicate); // Now it's a replay
    }

    #[test]
    fn test_too_old_rejected() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(500), ReplayCheck::Ok);
        // 500 - 256 = 244, anything with delta >= 256 is too old
        assert_eq!(w.check_and_update(200), ReplayCheck::TooOld);
        assert_eq!(w.check_and_update(1), ReplayCheck::TooOld);
    }

    #[test]
    fn test_window_boundary_exact() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(256), ReplayCheck::Ok);
        // delta = 256 - 1 = 255, which is < 256, so within window
        assert_eq!(w.check_and_update(1), ReplayCheck::Ok);
        // delta = 256 - 0 = 256, which is >= 256, so too old
        assert_eq!(w.check_and_update(0), ReplayCheck::TooOld);
    }

    #[test]
    fn test_out_of_order_arrivals() {
        let mut w = ReplayWindow::new();
        // Simulate real-world out-of-order delivery
        let sequence = vec![1, 3, 2, 5, 4, 8, 6, 7, 10, 9];
        for seq in &sequence {
            assert_eq!(
                w.check_and_update(*seq),
                ReplayCheck::Ok,
                "seq {} should be Ok",
                seq
            );
        }
        // All should be seen as duplicates now
        for seq in &sequence {
            let result = w.check_and_update(*seq);
            assert_ne!(result, ReplayCheck::Ok, "seq {} should be rejected", seq);
        }
    }

    #[test]
    fn test_large_gap_advances_window() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(1), ReplayCheck::Ok);
        // Jump way ahead
        assert_eq!(w.check_and_update(1000), ReplayCheck::Ok);
        // Old packets are now too old
        assert_eq!(w.check_and_update(1), ReplayCheck::TooOld);
        assert_eq!(w.check_and_update(700), ReplayCheck::TooOld);
        // But recent ones (within 256 of 1000) should work
        assert_eq!(w.check_and_update(800), ReplayCheck::Ok);
        assert_eq!(w.check_and_update(999), ReplayCheck::Ok);
    }

    #[test]
    fn test_check_is_readonly() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(10), ReplayCheck::Ok);
        // check() shouldn't modify state
        assert_eq!(w.check(15), ReplayCheck::Ok);
        assert_eq!(w.check(15), ReplayCheck::Ok); // Still Ok since check doesn't update
                                                  // But check_and_update does
        assert_eq!(w.check_and_update(15), ReplayCheck::Ok);
        assert_eq!(w.check(15), ReplayCheck::Duplicate);
    }

    #[test]
    fn test_reset() {
        let mut w = ReplayWindow::new();
        for seq in 1..=50 {
            w.check_and_update(seq);
        }
        assert_eq!(w.max_seq(), 50);
        w.reset();
        assert_eq!(w.max_seq(), 0);
        // Can accept packets again
        assert_eq!(w.check_and_update(1), ReplayCheck::Ok);
    }

    #[test]
    fn test_stats_tracking() {
        let mut w = ReplayWindow::new();
        w.check_and_update(1); // accepted
        w.check_and_update(2); // accepted
        w.check_and_update(1); // rejected (duplicate, within window, delta=1)
        w.check_and_update(3); // accepted

        let stats = w.stats();
        assert_eq!(stats.total_checked, 4);
        assert_eq!(stats.total_accepted, 3);
        assert_eq!(stats.total_rejected, 1);
    }

    #[test]
    fn test_window_fills_completely() {
        let mut w = ReplayWindow::new();
        // First, set max_seq to 256
        assert_eq!(w.check_and_update(256), ReplayCheck::Ok);
        // Then fill in all gaps from 1 to 255 (all within window)
        for seq in 1..256 {
            assert_eq!(
                w.check_and_update(seq),
                ReplayCheck::Ok,
                "seq {} failed",
                seq
            );
        }
        let stats = w.stats();
        assert_eq!(stats.total_accepted, 256);
    }

    #[test]
    fn test_high_sequence_numbers() {
        let mut w = ReplayWindow::new();
        let high = u64::MAX - 100;
        assert_eq!(w.check_and_update(high), ReplayCheck::Ok);
        assert_eq!(w.check_and_update(high + 1), ReplayCheck::Ok);
        assert_eq!(w.check_and_update(high), ReplayCheck::Duplicate);
    }

    #[test]
    fn test_zero_sequence() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(0), ReplayCheck::Ok);
        assert_eq!(w.check_and_update(0), ReplayCheck::Duplicate);
        assert_eq!(w.check_and_update(1), ReplayCheck::Ok);
    }

    #[test]
    fn test_stress_sequential_10k() {
        let mut w = ReplayWindow::new();
        for seq in 1..=10_000 {
            assert_eq!(w.check_and_update(seq), ReplayCheck::Ok);
        }
        assert_eq!(w.max_seq(), 10_000);
        // Recent packets should be marked as seen
        assert_eq!(w.check_and_update(10_000), ReplayCheck::Duplicate);
        assert_eq!(w.check_and_update(9_999), ReplayCheck::Duplicate);
        // Very old ones are too old
        assert_eq!(w.check_and_update(1), ReplayCheck::TooOld);
    }

    #[test]
    fn test_realistic_packet_loss_scenario() {
        let mut w = ReplayWindow::new();
        // Simulate: packets arrive, some are lost and retransmitted later
        // Arrivals: 1, 2, 4, 5, 7, 8, ...
        // Retransmissions: 3, 6, 9, ...
        let arrival_order: Vec<u64> = vec![
            1, 2, 4, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 26, 28, 29, 31, 32, 34,
            35, 37, 38, 40, // Now "retransmissions" of lost packets
            3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39,
        ];
        for seq in &arrival_order {
            assert_eq!(
                w.check_and_update(*seq),
                ReplayCheck::Ok,
                "seq {} should be Ok",
                seq
            );
        }
        // Replaying any of them should fail
        for seq in &arrival_order {
            let result = w.check_and_update(*seq);
            assert_ne!(result, ReplayCheck::Ok, "replay of {} should fail", seq);
        }
    }

    #[test]
    fn test_adversarial_replay_attack() {
        let mut w = ReplayWindow::new();
        // Normal traffic
        for seq in 1..=50 {
            w.check_and_update(seq);
        }
        // Attacker replays packets 25-50
        for seq in 25..=50 {
            assert_eq!(
                w.check_and_update(seq),
                ReplayCheck::Duplicate,
                "replay of seq {} should be caught",
                seq
            );
        }
        // Attacker replays very old packet (seq 1 is within window since max=50, delta=49)
        assert_eq!(w.check_and_update(1), ReplayCheck::Duplicate);
    }

    #[test]
    fn test_burst_then_gap_then_burst() {
        let mut w = ReplayWindow::new();
        // First burst: 1-100
        for seq in 1..=100 {
            w.check_and_update(seq);
        }
        // Big gap: jump to 500
        assert_eq!(w.check_and_update(500), ReplayCheck::Ok);
        // Packets from first burst are now too old (delta >= 256)
        assert_eq!(w.check_and_update(50), ReplayCheck::TooOld);
        // But near-500 packets work (delta=100 < 256)
        assert_eq!(w.check_and_update(400), ReplayCheck::Ok);
        // Second burst: 501-600
        for seq in 501..=600 {
            assert_eq!(w.check_and_update(seq), ReplayCheck::Ok);
        }
    }

    #[test]
    fn test_performance_100k_packets() {
        let mut w = ReplayWindow::new();
        let start = std::time::Instant::now();
        for seq in 1..=100_000u64 {
            w.check_and_update(seq);
        }
        let elapsed = start.elapsed();
        // Should complete in well under 100ms
        assert!(
            elapsed.as_millis() < 100,
            "100K lookups took {}ms",
            elapsed.as_millis()
        );
        assert_eq!(w.stats().total_accepted, 100_000);
    }

    #[test]
    fn test_alternating_in_out_of_window() {
        let mut w = ReplayWindow::new();
        // Alternate between advancing and checking old packets
        for i in 0..20u64 {
            let new_seq = (i + 1) * 300; // Each jump is 300, outside window
            assert_eq!(w.check_and_update(new_seq), ReplayCheck::Ok);
            // Previous jump is now too old (delta=300 >= 256)
            if i > 0 {
                let old_seq = i * 300;
                assert_eq!(w.check_and_update(old_seq), ReplayCheck::TooOld);
            }
        }
    }

    #[test]
    fn test_default_trait() {
        let w = ReplayWindow::default();
        assert_eq!(w.max_seq(), 0);
    }

    #[test]
    fn test_debug_format() {
        let mut w = ReplayWindow::new();
        w.check_and_update(42);
        let debug = format!("{:?}", w);
        assert!(debug.contains("max_seq: 42"));
        assert!(debug.contains("accepted: 1"));
    }

    #[test]
    fn test_advance_by_one() {
        let mut w = ReplayWindow::new();
        // Seq 5, then 6 — should shift by 1
        assert_eq!(w.check_and_update(5), ReplayCheck::Ok);
        assert_eq!(w.check_and_update(6), ReplayCheck::Ok);
        // 5 should still be in window (delta=1)
        assert_eq!(w.check_and_update(5), ReplayCheck::Duplicate);
    }

    #[test]
    fn test_advance_by_64_exactly() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_update(1), ReplayCheck::Ok);
        assert_eq!(w.check_and_update(65), ReplayCheck::Ok);
        // 1 is still in window (delta=64 < 256)
        assert_eq!(w.check_and_update(1), ReplayCheck::Duplicate);
    }

    #[test]
    fn test_advance_crosses_block_boundary() {
        let mut w = ReplayWindow::new();
        // Set some bits in the first block
        for seq in 1..=10 {
            w.check_and_update(seq);
        }
        // Jump to 70 (crosses first u64 block boundary)
        assert_eq!(w.check_and_update(70), ReplayCheck::Ok);
        // Old packets should still be tracked (delta < 256)
        for seq in 1..=10 {
            assert_eq!(
                w.check_and_update(seq),
                ReplayCheck::Duplicate,
                "seq {} should be dup",
                seq
            );
        }
    }
}
