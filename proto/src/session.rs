//! Session state management.
//!
//! A ZTLP session represents an established, mutually authenticated,
//! encrypted communication channel between two nodes.
//!
//! Session state includes:
//! - SessionID (96-bit random, assigned during handshake)
//! - Peer NodeID
//! - Send/receive symmetric keys
//! - Packet sequence counters
//! - Anti-replay window

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::identity::NodeId;
use crate::packet::SessionId;

/// Default anti-replay window size (number of packets to track).
pub const DEFAULT_REPLAY_WINDOW: u64 = 64;

/// Multipath anti-replay window size.
pub const MULTIPATH_REPLAY_WINDOW: u64 = 1024;

/// Anti-replay window using a bitmap.
///
/// Tracks which packet sequence numbers have been seen to prevent replay attacks.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// The highest sequence number we've seen.
    highest_seq: u64,
    /// Bitmap of seen packets relative to highest_seq.
    /// Bit i represents (highest_seq - i).
    bitmap: u64,
    /// Window size in packets.
    window_size: u64,
}

impl ReplayWindow {
    /// Create a new replay window.
    pub fn new(window_size: u64) -> Self {
        Self {
            highest_seq: 0,
            bitmap: 0,
            window_size: window_size.min(64), // bitmap is u64, so max 64 bits
        }
    }

    /// Check if a packet sequence number is valid (not replayed) and record it.
    ///
    /// Returns `true` if the packet is fresh, `false` if it's a replay.
    pub fn check_and_record(&mut self, seq: u64) -> bool {
        if seq == 0 {
            // Sequence 0 is the first packet — always accept
            if self.highest_seq == 0 && self.bitmap == 0 {
                self.highest_seq = 0;
                self.bitmap = 1;
                return true;
            }
        }

        if seq > self.highest_seq {
            // New packet ahead of the window — shift bitmap
            let shift = seq - self.highest_seq;
            if shift >= 64 {
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift;
            }
            self.bitmap |= 1;
            self.highest_seq = seq;
            true
        } else {
            // Packet is within or behind the window
            let diff = self.highest_seq - seq;
            if diff >= self.window_size {
                // Too old — outside the window
                false
            } else if diff >= 64 {
                // Outside bitmap range
                false
            } else {
                let mask = 1u64 << diff;
                if self.bitmap & mask != 0 {
                    // Already seen — replay
                    false
                } else {
                    // New packet within window — record it
                    self.bitmap |= mask;
                    true
                }
            }
        }
    }
}

/// State for an established ZTLP session.
#[derive(Debug, Clone)]
pub struct SessionState {
    /// 96-bit session identifier.
    pub session_id: SessionId,
    /// Peer's NodeID.
    pub peer_node_id: NodeId,
    /// Key for encrypting outbound packets (send direction).
    pub send_key: [u8; 32],
    /// Key for decrypting/verifying inbound packets (receive direction).
    pub recv_key: [u8; 32],
    /// Next outbound packet sequence number (atomic for sharing with ACK sender thread).
    pub send_seq: Arc<AtomicU64>,
    /// Anti-replay window for inbound packets.
    pub replay_window: ReplayWindow,
    /// Whether this session uses multipath.
    pub multipath: bool,
}

impl SessionState {
    /// Create a new session state.
    pub fn new(
        session_id: SessionId,
        peer_node_id: NodeId,
        send_key: [u8; 32],
        recv_key: [u8; 32],
        multipath: bool,
    ) -> Self {
        let window_size = if multipath {
            MULTIPATH_REPLAY_WINDOW
        } else {
            DEFAULT_REPLAY_WINDOW
        };

        Self {
            session_id,
            peer_node_id,
            send_key,
            recv_key,
            send_seq: Arc::new(AtomicU64::new(0)),
            replay_window: ReplayWindow::new(window_size),
            multipath,
        }
    }

    /// Get and atomically increment the send sequence number.
    /// Thread-safe: can be called from both the async transport and the
    /// OS-thread ACK sender (via the shared Arc<AtomicU64>).
    pub fn next_send_seq(&mut self) -> u64 {
        self.send_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Get a clone of the atomic send_seq counter for sharing with the
    /// ACK sender OS thread.
    pub fn send_seq_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.send_seq)
    }

    /// Check a received packet's sequence number against the replay window.
    pub fn check_replay(&mut self, seq: u64) -> bool {
        self.replay_window.check_and_record(seq)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_window_sequential() {
        let mut w = ReplayWindow::new(DEFAULT_REPLAY_WINDOW);
        // Sequential packets should all be accepted
        for i in 0..100 {
            assert!(w.check_and_record(i), "seq {i} should be accepted");
        }
    }

    #[test]
    fn test_replay_window_duplicate() {
        let mut w = ReplayWindow::new(DEFAULT_REPLAY_WINDOW);
        assert!(w.check_and_record(1));
        assert!(w.check_and_record(2));
        assert!(!w.check_and_record(1), "duplicate seq 1 should be rejected");
        assert!(!w.check_and_record(2), "duplicate seq 2 should be rejected");
    }

    #[test]
    fn test_replay_window_out_of_order() {
        let mut w = ReplayWindow::new(DEFAULT_REPLAY_WINDOW);
        assert!(w.check_and_record(5));
        assert!(w.check_and_record(3)); // within window, not seen
        assert!(w.check_and_record(4)); // within window, not seen
        assert!(!w.check_and_record(3)); // duplicate
    }

    #[test]
    fn test_replay_window_too_old() {
        let mut w = ReplayWindow::new(DEFAULT_REPLAY_WINDOW);
        assert!(w.check_and_record(100));
        // Seq 0 is now (100 - 0) = 100 behind, > window of 64
        assert!(!w.check_and_record(0), "too-old packet should be rejected");
        // Seq 50 is 50 behind, within window
        assert!(w.check_and_record(50));
    }
}
