//! In-session rekeying for ZTLP tunnels.
//!
//! Provides forward secrecy by periodically rotating the session's
//! symmetric encryption keys without a full Noise_XX re-handshake.
//!
//! ## Mechanism
//!
//! Uses BLAKE2s key derivation to derive new keys from the current
//! transport key + a monotonic rekey counter:
//!
//! ```text
//! new_key = BLAKE2s(current_key || rekey_counter || "ztlp-rekey-v1")
//! ```
//!
//! Both sides derive the same new key because they share the transport
//! key and track the rekey counter synchronously.
//!
//! ## Triggers
//!
//! Rekeying is triggered by whichever comes first:
//! 1. **Byte limit:** After 2^38 bytes (~256 GB) encrypted with the same key
//! 2. **Time limit:** After 3600 seconds (1 hour) with the same key
//! 3. **Packet limit:** After 2^32 packets (4 billion) — nonce exhaustion prevention
//!
//! ## Wire Protocol
//!
//! The initiator sends a REKEY frame (type 0x0E) containing:
//! - 4 bytes: rekey counter (little-endian u32)
//! - 32 bytes: BLAKE2s commitment hash (proves the sender computed the same new key)
//!
//! The responder verifies the commitment, derives the same new key,
//! and sends a REKEY_ACK frame (type 0x0F) with the same counter.
//!
//! Both sides switch to the new key after the ACK is confirmed.
//! Packets in flight with the old key are still accepted for a brief
//! grace period (5 seconds).

#![deny(unsafe_code)]

use std::time::{Duration, Instant};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Domain separator for key derivation.
const REKEY_DOMAIN: &[u8] = b"ztlp-rekey-v1";

/// Maximum bytes before mandatory rekey (2^38 = ~256 GB).
const MAX_BYTES_PER_KEY: u64 = 1 << 38;

/// Maximum time before mandatory rekey.
const MAX_TIME_PER_KEY: Duration = Duration::from_secs(3600);

/// Maximum packets before mandatory rekey (2^32 — nonce space).
const MAX_PACKETS_PER_KEY: u64 = 1 << 32;

/// Grace period: old key remains valid for this long after rekey.
const OLD_KEY_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Maximum number of rekeys before requiring full re-handshake.
/// After 2^16 rekeys, derive a completely fresh key via handshake.
const MAX_REKEY_COUNT: u32 = 1 << 16;

/// Warn when approaching limits (at 90%).
const WARN_THRESHOLD: f64 = 0.9;

/// Frame type for rekey request.
pub const FRAME_REKEY: u8 = 0x0E;
/// Frame type for rekey acknowledgment.
pub const FRAME_REKEY_ACK: u8 = 0x0F;

// ─── Rekey Manager ──────────────────────────────────────────────────────────

/// Tracks key usage and triggers rekeying when limits are approached.
#[derive(Debug)]
pub struct RekeyManager {
    /// When the current key was installed.
    key_installed_at: Instant,
    /// Total bytes encrypted with current key.
    bytes_encrypted: u64,
    /// Total packets encrypted with current key.
    packets_encrypted: u64,
    /// Current rekey counter (monotonic, both sides track).
    rekey_counter: u32,
    /// Whether we've initiated a rekey that's pending ACK.
    pending_rekey: bool,
    /// When the pending rekey was initiated.
    pending_since: Option<Instant>,
    /// Timeout for pending rekey (5 seconds).
    pending_timeout: Duration,
    /// Whether the old key is still valid (grace period).
    old_key_valid: bool,
    /// When the old key should expire.
    old_key_expires: Option<Instant>,
    /// Whether rekeying is enabled.
    enabled: bool,
}

/// What action the tunnel should take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RekeyAction {
    /// Nothing needed.
    None,
    /// Initiate a rekey: derive new key and send REKEY frame.
    InitiateRekey { counter: u32 },
    /// Rekey is urgent (close to hard limit) — must complete before sending more data.
    UrgentRekey { counter: u32 },
    /// Hard limit reached — stop sending until rekey completes.
    HardLimit,
    /// Max rekeys reached — need full re-handshake.
    RehandshakeRequired,
}

/// Result of processing a received REKEY frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RekeyResponse {
    /// Accept: derive new key and send REKEY_ACK.
    Accept { counter: u32 },
    /// Reject: counter mismatch or other error.
    Reject { reason: &'static str },
}

impl RekeyManager {
    /// Create a new rekey manager.
    pub fn new() -> Self {
        Self {
            key_installed_at: Instant::now(),
            bytes_encrypted: 0,
            packets_encrypted: 0,
            rekey_counter: 0,
            pending_rekey: false,
            pending_since: None,
            pending_timeout: Duration::from_secs(5),
            old_key_valid: false,
            old_key_expires: None,
            enabled: true,
        }
    }

    /// Record that we encrypted some data.
    pub fn record_encrypt(&mut self, bytes: u64) {
        self.bytes_encrypted += bytes;
        self.packets_encrypted += 1;
    }

    /// Check if a rekey is needed. Call this periodically or after each packet.
    pub fn check(&self) -> RekeyAction {
        if !self.enabled {
            return RekeyAction::None;
        }

        if self.pending_rekey {
            return RekeyAction::None; // Already in progress
        }

        if self.rekey_counter >= MAX_REKEY_COUNT {
            return RekeyAction::RehandshakeRequired;
        }

        let elapsed = Instant::now().duration_since(self.key_installed_at);

        // Hard limits — must stop
        if self.bytes_encrypted >= MAX_BYTES_PER_KEY
            || self.packets_encrypted >= MAX_PACKETS_PER_KEY
        {
            return RekeyAction::HardLimit;
        }

        // Urgent — approaching limits
        if self.bytes_encrypted as f64 >= MAX_BYTES_PER_KEY as f64 * WARN_THRESHOLD
            || self.packets_encrypted as f64 >= MAX_PACKETS_PER_KEY as f64 * WARN_THRESHOLD
            || elapsed.as_secs_f64() >= MAX_TIME_PER_KEY.as_secs_f64() * WARN_THRESHOLD
        {
            return RekeyAction::UrgentRekey {
                counter: self.rekey_counter + 1,
            };
        }

        // Time-based rekey
        if elapsed >= MAX_TIME_PER_KEY {
            return RekeyAction::InitiateRekey {
                counter: self.rekey_counter + 1,
            };
        }

        RekeyAction::None
    }

    /// Mark that we've initiated a rekey.
    pub fn mark_initiated(&mut self) {
        self.pending_rekey = true;
        self.pending_since = Some(Instant::now());
    }

    /// Check if the pending rekey has timed out.
    pub fn is_pending_timed_out(&self) -> bool {
        if let Some(since) = self.pending_since {
            Instant::now().duration_since(since) >= self.pending_timeout
        } else {
            false
        }
    }

    /// Process a received REKEY frame from the peer.
    pub fn handle_received_rekey(&mut self, counter: u32) -> RekeyResponse {
        let expected = self.rekey_counter + 1;

        if counter != expected {
            return RekeyResponse::Reject {
                reason: "counter mismatch",
            };
        }

        if counter >= MAX_REKEY_COUNT {
            return RekeyResponse::Reject {
                reason: "max rekey count exceeded",
            };
        }

        RekeyResponse::Accept { counter }
    }

    /// Complete the rekey (after ACK is sent/received).
    ///
    /// Call this after both sides have derived the new key.
    pub fn complete_rekey(&mut self) {
        self.rekey_counter += 1;
        self.bytes_encrypted = 0;
        self.packets_encrypted = 0;
        self.key_installed_at = Instant::now();
        self.pending_rekey = false;
        self.pending_since = None;

        // Old key remains valid briefly for in-flight packets
        self.old_key_valid = true;
        self.old_key_expires = Some(Instant::now() + OLD_KEY_GRACE_PERIOD);
    }

    /// Check if the old key should still be accepted for decryption.
    pub fn is_old_key_valid(&self) -> bool {
        if !self.old_key_valid {
            return false;
        }
        if let Some(expires) = self.old_key_expires {
            Instant::now() < expires
        } else {
            false
        }
    }

    /// Expire the old key (call periodically).
    pub fn expire_old_key(&mut self) {
        if self.old_key_valid {
            if let Some(expires) = self.old_key_expires {
                if Instant::now() >= expires {
                    self.old_key_valid = false;
                    self.old_key_expires = None;
                }
            }
        }
    }

    /// Get the current rekey counter.
    pub fn counter(&self) -> u32 {
        self.rekey_counter
    }

    /// Get key usage stats.
    pub fn stats(&self) -> RekeyStats {
        let elapsed = Instant::now().duration_since(self.key_installed_at);
        RekeyStats {
            rekey_counter: self.rekey_counter,
            bytes_encrypted: self.bytes_encrypted,
            packets_encrypted: self.packets_encrypted,
            key_age: elapsed,
            pending_rekey: self.pending_rekey,
            bytes_remaining: MAX_BYTES_PER_KEY.saturating_sub(self.bytes_encrypted),
            time_remaining: MAX_TIME_PER_KEY.saturating_sub(elapsed),
        }
    }

    /// Disable rekeying (for testing or when not needed).
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Enable rekeying.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Whether rekeying is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for RekeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about key usage.
#[derive(Debug, Clone)]
pub struct RekeyStats {
    pub rekey_counter: u32,
    pub bytes_encrypted: u64,
    pub packets_encrypted: u64,
    pub key_age: Duration,
    pub pending_rekey: bool,
    pub bytes_remaining: u64,
    pub time_remaining: Duration,
}

// ─── Key Derivation ─────────────────────────────────────────────────────────

/// Derive a new session key from the current key and rekey counter.
///
/// Uses BLAKE2s (32-byte output) with the pattern:
/// `new_key = BLAKE2s(current_key || counter_le_bytes || domain_separator)`
///
/// This is a one-way derivation: knowing the new key doesn't reveal the old one.
pub fn derive_rekey(current_key: &[u8; 32], counter: u32) -> [u8; 32] {
    use blake2::digest::Mac;
    use blake2::Blake2sMac256;

    let mut mac = Blake2sMac256::new_from_slice(current_key).expect("BLAKE2s accepts 32-byte keys");
    mac.update(&counter.to_le_bytes());
    mac.update(REKEY_DOMAIN);
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

/// Compute the commitment hash for a rekey (included in REKEY frame).
///
/// The initiator sends this to prove they've computed the correct new key.
/// The responder computes the same hash and verifies it matches.
pub fn rekey_commitment(new_key: &[u8; 32]) -> [u8; 32] {
    use blake2::digest::Mac;
    use blake2::Blake2sMac256;

    let mut mac = Blake2sMac256::new_from_slice(b"ztlp-rekey-commitment-v1--------")
        .expect("BLAKE2s accepts 32-byte keys");
    mac.update(new_key);
    let result = mac.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result.into_bytes());
    hash
}

/// Encode a REKEY frame payload.
///
/// Format: counter (4 bytes LE) + commitment (32 bytes) = 36 bytes
pub fn encode_rekey_frame(counter: u32, commitment: &[u8; 32]) -> [u8; 36] {
    let mut frame = [0u8; 36];
    frame[..4].copy_from_slice(&counter.to_le_bytes());
    frame[4..].copy_from_slice(commitment);
    frame
}

/// Decode a REKEY frame payload.
///
/// Returns (counter, commitment) or None if the frame is malformed.
pub fn decode_rekey_frame(data: &[u8]) -> Option<(u32, [u8; 32])> {
    if data.len() < 36 {
        return None;
    }
    let counter = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&data[4..36]);
    Some((counter, commitment))
}

/// Encode a REKEY_ACK frame payload.
///
/// Format: counter (4 bytes LE) = 4 bytes
pub fn encode_rekey_ack(counter: u32) -> [u8; 4] {
    counter.to_le_bytes()
}

/// Decode a REKEY_ACK frame payload.
pub fn decode_rekey_ack(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rekey_manager_initial_state() {
        let mgr = RekeyManager::new();
        assert_eq!(mgr.counter(), 0);
        assert!(!mgr.is_old_key_valid());
        assert!(mgr.is_enabled());
        assert_eq!(mgr.check(), RekeyAction::None);
    }

    #[test]
    fn test_rekey_disabled() {
        let mut mgr = RekeyManager::new();
        mgr.disable();
        mgr.bytes_encrypted = MAX_BYTES_PER_KEY + 1;
        assert_eq!(mgr.check(), RekeyAction::None);
    }

    #[test]
    fn test_rekey_time_trigger() {
        let mut mgr = RekeyManager::new();
        mgr.key_installed_at = Instant::now() - MAX_TIME_PER_KEY - Duration::from_secs(1);
        let action = mgr.check();
        assert!(matches!(action, RekeyAction::InitiateRekey { counter: 1 }));
    }

    #[test]
    fn test_rekey_bytes_urgent() {
        let mut mgr = RekeyManager::new();
        mgr.bytes_encrypted = (MAX_BYTES_PER_KEY as f64 * 0.95) as u64;
        let action = mgr.check();
        assert!(matches!(action, RekeyAction::UrgentRekey { counter: 1 }));
    }

    #[test]
    fn test_rekey_bytes_hard_limit() {
        let mut mgr = RekeyManager::new();
        mgr.bytes_encrypted = MAX_BYTES_PER_KEY;
        let action = mgr.check();
        assert_eq!(action, RekeyAction::HardLimit);
    }

    #[test]
    fn test_rekey_packets_hard_limit() {
        let mut mgr = RekeyManager::new();
        mgr.packets_encrypted = MAX_PACKETS_PER_KEY;
        let action = mgr.check();
        assert_eq!(action, RekeyAction::HardLimit);
    }

    #[test]
    fn test_rekey_max_count() {
        let mut mgr = RekeyManager::new();
        mgr.rekey_counter = MAX_REKEY_COUNT;
        let action = mgr.check();
        assert_eq!(action, RekeyAction::RehandshakeRequired);
    }

    #[test]
    fn test_mark_initiated() {
        let mut mgr = RekeyManager::new();
        mgr.key_installed_at = Instant::now() - MAX_TIME_PER_KEY - Duration::from_secs(1);
        mgr.mark_initiated();
        // Should return None while pending
        assert_eq!(mgr.check(), RekeyAction::None);
    }

    #[test]
    fn test_pending_timeout() {
        let mut mgr = RekeyManager::new();
        mgr.pending_rekey = true;
        mgr.pending_since = Some(Instant::now() - Duration::from_secs(6));
        assert!(mgr.is_pending_timed_out());
    }

    #[test]
    fn test_handle_received_rekey_valid() {
        let mut mgr = RekeyManager::new();
        let resp = mgr.handle_received_rekey(1);
        assert_eq!(resp, RekeyResponse::Accept { counter: 1 });
    }

    #[test]
    fn test_handle_received_rekey_wrong_counter() {
        let mut mgr = RekeyManager::new();
        let resp = mgr.handle_received_rekey(5); // Expected 1
        assert!(matches!(resp, RekeyResponse::Reject { .. }));
    }

    #[test]
    fn test_handle_received_rekey_max_exceeded() {
        let mut mgr = RekeyManager::new();
        mgr.rekey_counter = MAX_REKEY_COUNT - 1;
        let resp = mgr.handle_received_rekey(MAX_REKEY_COUNT);
        assert!(matches!(resp, RekeyResponse::Reject { .. }));
    }

    #[test]
    fn test_complete_rekey() {
        let mut mgr = RekeyManager::new();
        mgr.bytes_encrypted = 1_000_000;
        mgr.packets_encrypted = 1000;
        mgr.pending_rekey = true;
        mgr.complete_rekey();

        assert_eq!(mgr.counter(), 1);
        assert_eq!(mgr.stats().bytes_encrypted, 0);
        assert_eq!(mgr.stats().packets_encrypted, 0);
        assert!(!mgr.stats().pending_rekey);
        assert!(mgr.is_old_key_valid()); // Grace period
    }

    #[test]
    fn test_old_key_grace_period() {
        let mut mgr = RekeyManager::new();
        mgr.complete_rekey();
        assert!(mgr.is_old_key_valid());

        // Simulate grace period expiry
        mgr.old_key_expires = Some(Instant::now() - Duration::from_secs(1));
        mgr.expire_old_key();
        assert!(!mgr.is_old_key_valid());
    }

    #[test]
    fn test_multiple_rekeys() {
        let mut mgr = RekeyManager::new();
        for i in 1..=10u32 {
            mgr.key_installed_at = Instant::now() - MAX_TIME_PER_KEY - Duration::from_secs(1);
            let action = mgr.check();
            assert!(
                matches!(action, RekeyAction::InitiateRekey { counter } if counter == i),
                "rekey {} failed: {:?}",
                i,
                action
            );
            mgr.mark_initiated();
            mgr.complete_rekey();
            assert_eq!(mgr.counter(), i);
        }
    }

    #[test]
    fn test_record_encrypt() {
        let mut mgr = RekeyManager::new();
        mgr.record_encrypt(1500);
        mgr.record_encrypt(1500);
        let stats = mgr.stats();
        assert_eq!(stats.bytes_encrypted, 3000);
        assert_eq!(stats.packets_encrypted, 2);
    }

    #[test]
    fn test_stats_remaining() {
        let mgr = RekeyManager::new();
        let stats = mgr.stats();
        assert_eq!(stats.bytes_remaining, MAX_BYTES_PER_KEY);
        assert!(stats.time_remaining <= MAX_TIME_PER_KEY);
    }

    // ── Key Derivation Tests ────────────────────────────────────────

    #[test]
    fn test_derive_rekey_deterministic() {
        let key = [0xAA; 32];
        let k1 = derive_rekey(&key, 1);
        let k2 = derive_rekey(&key, 1);
        assert_eq!(k1, k2); // Same inputs → same output
    }

    #[test]
    fn test_derive_rekey_different_counters() {
        let key = [0xBB; 32];
        let k1 = derive_rekey(&key, 1);
        let k2 = derive_rekey(&key, 2);
        assert_ne!(k1, k2); // Different counters → different keys
    }

    #[test]
    fn test_derive_rekey_different_keys() {
        let key1 = [0xCC; 32];
        let key2 = [0xDD; 32];
        let k1 = derive_rekey(&key1, 1);
        let k2 = derive_rekey(&key2, 1);
        assert_ne!(k1, k2); // Different base keys → different derived keys
    }

    #[test]
    fn test_derive_rekey_not_identity() {
        let key = [0xEE; 32];
        let derived = derive_rekey(&key, 1);
        assert_ne!(key, derived); // Derived key is different from input
    }

    #[test]
    fn test_derive_rekey_chain() {
        // Simulate a chain of rekeys
        let mut current = [0xFF; 32];
        let mut seen = vec![current];
        for counter in 1..=100 {
            current = derive_rekey(&current, counter);
            assert!(
                !seen.contains(&current),
                "key collision at counter {}",
                counter
            );
            seen.push(current);
        }
    }

    #[test]
    fn test_rekey_commitment() {
        let key = [0x42; 32];
        let c1 = rekey_commitment(&key);
        let c2 = rekey_commitment(&key);
        assert_eq!(c1, c2); // Deterministic

        let key2 = [0x43; 32];
        let c3 = rekey_commitment(&key2);
        assert_ne!(c1, c3); // Different keys → different commitments
    }

    // ── Wire Format Tests ───────────────────────────────────────────

    #[test]
    fn test_encode_decode_rekey_frame() {
        let counter = 42u32;
        let commitment = [0xAB; 32];
        let frame = encode_rekey_frame(counter, &commitment);
        let (dec_counter, dec_commitment) = decode_rekey_frame(&frame).unwrap();
        assert_eq!(dec_counter, counter);
        assert_eq!(dec_commitment, commitment);
    }

    #[test]
    fn test_decode_rekey_frame_too_short() {
        assert!(decode_rekey_frame(&[0; 35]).is_none());
        assert!(decode_rekey_frame(&[]).is_none());
    }

    #[test]
    fn test_encode_decode_rekey_ack() {
        let counter = 99u32;
        let ack = encode_rekey_ack(counter);
        let decoded = decode_rekey_ack(&ack).unwrap();
        assert_eq!(decoded, counter);
    }

    #[test]
    fn test_decode_rekey_ack_too_short() {
        assert!(decode_rekey_ack(&[0; 3]).is_none());
        assert!(decode_rekey_ack(&[]).is_none());
    }

    // ── Full Rekey Flow Test ────────────────────────────────────────

    #[test]
    fn test_full_rekey_flow() {
        let base_key = [0x42; 32];

        // Initiator detects time limit
        let mut initiator = RekeyManager::new();
        initiator.key_installed_at = Instant::now() - MAX_TIME_PER_KEY - Duration::from_secs(1);
        let action = initiator.check();
        let counter = match action {
            RekeyAction::InitiateRekey { counter } => counter,
            other => panic!("expected InitiateRekey, got {:?}", other),
        };

        // Initiator derives new key and creates commitment
        let new_key = derive_rekey(&base_key, counter);
        let commitment = rekey_commitment(&new_key);
        let frame = encode_rekey_frame(counter, &commitment);
        initiator.mark_initiated();

        // Responder receives REKEY frame
        let mut responder = RekeyManager::new();
        let (rx_counter, rx_commitment) = decode_rekey_frame(&frame).unwrap();
        let response = responder.handle_received_rekey(rx_counter);
        assert_eq!(response, RekeyResponse::Accept { counter: 1 });

        // Responder derives the same new key and verifies commitment
        let responder_new_key = derive_rekey(&base_key, rx_counter);
        let responder_commitment = rekey_commitment(&responder_new_key);
        assert_eq!(rx_commitment, responder_commitment); // Both derived the same key

        // Responder sends ACK
        let ack = encode_rekey_ack(rx_counter);
        responder.complete_rekey();

        // Initiator receives ACK
        let ack_counter = decode_rekey_ack(&ack).unwrap();
        assert_eq!(ack_counter, counter);
        initiator.complete_rekey();

        // Both sides are now using the new key
        assert_eq!(initiator.counter(), 1);
        assert_eq!(responder.counter(), 1);
        assert_eq!(new_key, responder_new_key);
    }
}
