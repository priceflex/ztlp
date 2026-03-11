//! Security event types and structured audit logging helpers.
//!
//! Provides a [`SecurityEvent`] enum covering all security-relevant events in
//! the ZTLP pipeline and tunnel. Each event is emitted at `warn!` level with
//! structured `tracing` fields for downstream analysis (SIEM, log aggregation).
//!
//! ## Usage
//!
//! ```rust,no_run
//! use ztlp_proto::security::{SecurityEvent, log_security_event};
//!
//! log_security_event(&SecurityEvent::MalformedPacket {
//!     reason: "buffer too short".into(),
//!     peer_addr: Some("10.0.0.1:5000".into()),
//!     bytes_received: Some(3),
//! });
//! ```

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use std::fmt;

/// Security-relevant events in the ZTLP protocol stack.
///
/// Each variant carries enough context for meaningful audit logging
/// without including sensitive key material.
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    /// Noise_XX handshake failed (bad key, protocol error, etc.).
    HandshakeFailed {
        /// Human-readable reason for the failure.
        reason: String,
        /// Remote peer address, if known.
        peer_addr: Option<String>,
        /// Session ID (hex), if assigned.
        session_id: Option<String>,
    },

    /// Header authentication tag did not verify (Layer 3 rejection).
    AuthTagInvalid {
        /// Remote peer address.
        peer_addr: Option<String>,
        /// Session ID (hex).
        session_id: Option<String>,
        /// Direction: "rx" or "tx".
        direction: String,
    },

    /// Packet sequence number was replayed (anti-replay window hit).
    ReplayDetected {
        /// The replayed sequence number.
        packet_seq: u64,
        /// Session ID (hex).
        session_id: Option<String>,
        /// Remote peer address.
        peer_addr: Option<String>,
    },

    /// Session has expired (TTL exceeded, idle timeout, etc.).
    SessionExpired {
        /// Session ID (hex).
        session_id: String,
        /// Reason for expiration.
        reason: String,
    },

    /// Policy engine denied this operation.
    PolicyDenied {
        /// Which policy rule triggered the denial.
        rule: String,
        /// The source node or address.
        source: Option<String>,
        /// The destination service or address.
        destination: Option<String>,
    },

    /// Inbound packet was malformed and could not be parsed.
    MalformedPacket {
        /// What specifically was wrong.
        reason: String,
        /// Remote peer address, if known.
        peer_addr: Option<String>,
        /// Number of bytes received.
        bytes_received: Option<usize>,
    },

    /// Rate limit exceeded (HELLO flood, connection storm, etc.).
    RateLimitExceeded {
        /// What was rate-limited.
        kind: String,
        /// Remote peer address.
        peer_addr: Option<String>,
        /// Current rate (events/sec or similar).
        rate: Option<f64>,
    },
}

impl fmt::Display for SecurityEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandshakeFailed { reason, .. } => write!(f, "handshake_failed: {}", reason),
            Self::AuthTagInvalid { direction, .. } => {
                write!(f, "auth_tag_invalid ({})", direction)
            }
            Self::ReplayDetected { packet_seq, .. } => {
                write!(f, "replay_detected: seq={}", packet_seq)
            }
            Self::SessionExpired { session_id, reason } => {
                write!(f, "session_expired: {} ({})", session_id, reason)
            }
            Self::PolicyDenied { rule, .. } => write!(f, "policy_denied: {}", rule),
            Self::MalformedPacket { reason, .. } => write!(f, "malformed_packet: {}", reason),
            Self::RateLimitExceeded { kind, .. } => write!(f, "rate_limit_exceeded: {}", kind),
        }
    }
}

impl SecurityEvent {
    /// Returns a static string identifying the event type, suitable for metrics.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::HandshakeFailed { .. } => "handshake_failed",
            Self::AuthTagInvalid { .. } => "auth_tag_invalid",
            Self::ReplayDetected { .. } => "replay_detected",
            Self::SessionExpired { .. } => "session_expired",
            Self::PolicyDenied { .. } => "policy_denied",
            Self::MalformedPacket { .. } => "malformed_packet",
            Self::RateLimitExceeded { .. } => "rate_limit_exceeded",
        }
    }

    /// Extract the peer address if present.
    pub fn peer_addr(&self) -> Option<&str> {
        match self {
            Self::HandshakeFailed { peer_addr, .. }
            | Self::AuthTagInvalid { peer_addr, .. }
            | Self::ReplayDetected { peer_addr, .. }
            | Self::MalformedPacket { peer_addr, .. }
            | Self::RateLimitExceeded { peer_addr, .. } => peer_addr.as_deref(),
            Self::SessionExpired { .. } | Self::PolicyDenied { .. } => None,
        }
    }

    /// Extract the session ID if present.
    pub fn session_id(&self) -> Option<&str> {
        match self {
            Self::HandshakeFailed { session_id, .. }
            | Self::AuthTagInvalid { session_id, .. }
            | Self::ReplayDetected { session_id, .. } => session_id.as_deref(),
            Self::SessionExpired { session_id, .. } => Some(session_id.as_str()),
            Self::PolicyDenied { .. }
            | Self::MalformedPacket { .. }
            | Self::RateLimitExceeded { .. } => None,
        }
    }
}

/// Emit a security event as a structured `tracing` warning.
///
/// Each event is logged at `warn!` level with these structured fields:
/// - `security_event`: event type string
/// - `peer_addr`: remote address (if available)
/// - `session_id`: session identifier (if available)
/// - Additional event-specific fields
pub fn log_security_event(event: &SecurityEvent) {
    let event_type = event.event_type();
    let peer = event.peer_addr().unwrap_or("-");
    let sid = event.session_id().unwrap_or("-");

    match event {
        SecurityEvent::HandshakeFailed { reason, .. } => {
            tracing::warn!(
                security_event = event_type,
                peer_addr = peer,
                session_id = sid,
                reason = reason.as_str(),
                "SECURITY: {}",
                event
            );
        }
        SecurityEvent::AuthTagInvalid { direction, .. } => {
            tracing::warn!(
                security_event = event_type,
                peer_addr = peer,
                session_id = sid,
                direction = direction.as_str(),
                "SECURITY: {}",
                event
            );
        }
        SecurityEvent::ReplayDetected { packet_seq, .. } => {
            tracing::warn!(
                security_event = event_type,
                peer_addr = peer,
                session_id = sid,
                packet_seq = packet_seq,
                "SECURITY: {}",
                event
            );
        }
        SecurityEvent::SessionExpired { reason, .. } => {
            tracing::warn!(
                security_event = event_type,
                session_id = sid,
                reason = reason.as_str(),
                "SECURITY: {}",
                event
            );
        }
        SecurityEvent::PolicyDenied {
            rule,
            source,
            destination,
        } => {
            tracing::warn!(
                security_event = event_type,
                rule = rule.as_str(),
                source = source.as_deref().unwrap_or("-"),
                destination = destination.as_deref().unwrap_or("-"),
                "SECURITY: {}",
                event
            );
        }
        SecurityEvent::MalformedPacket {
            reason,
            bytes_received,
            ..
        } => {
            tracing::warn!(
                security_event = event_type,
                peer_addr = peer,
                reason = reason.as_str(),
                bytes_received = bytes_received.unwrap_or(0),
                "SECURITY: {}",
                event
            );
        }
        SecurityEvent::RateLimitExceeded { kind, rate, .. } => {
            tracing::warn!(
                security_event = event_type,
                peer_addr = peer,
                kind = kind.as_str(),
                rate = rate.unwrap_or(0.0),
                "SECURITY: {}",
                event
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_display() {
        let event = SecurityEvent::HandshakeFailed {
            reason: "noise protocol error".into(),
            peer_addr: Some("10.0.0.1:5000".into()),
            session_id: None,
        };
        assert_eq!(
            event.to_string(),
            "handshake_failed: noise protocol error"
        );
    }

    #[test]
    fn test_security_event_type() {
        let event = SecurityEvent::AuthTagInvalid {
            peer_addr: None,
            session_id: Some("aabbccdd".into()),
            direction: "rx".into(),
        };
        assert_eq!(event.event_type(), "auth_tag_invalid");
    }

    #[test]
    fn test_security_event_peer_addr() {
        let event = SecurityEvent::ReplayDetected {
            packet_seq: 42,
            session_id: None,
            peer_addr: Some("192.168.1.1:3000".into()),
        };
        assert_eq!(event.peer_addr(), Some("192.168.1.1:3000"));
    }

    #[test]
    fn test_security_event_session_id() {
        let event = SecurityEvent::SessionExpired {
            session_id: "deadbeef".into(),
            reason: "idle timeout".into(),
        };
        assert_eq!(event.session_id(), Some("deadbeef"));
    }

    #[test]
    fn test_all_event_variants_display() {
        // Ensure all variants can be displayed without panic
        let events = vec![
            SecurityEvent::HandshakeFailed {
                reason: "test".into(),
                peer_addr: None,
                session_id: None,
            },
            SecurityEvent::AuthTagInvalid {
                peer_addr: None,
                session_id: None,
                direction: "rx".into(),
            },
            SecurityEvent::ReplayDetected {
                packet_seq: 0,
                session_id: None,
                peer_addr: None,
            },
            SecurityEvent::SessionExpired {
                session_id: "x".into(),
                reason: "ttl".into(),
            },
            SecurityEvent::PolicyDenied {
                rule: "deny-all".into(),
                source: None,
                destination: None,
            },
            SecurityEvent::MalformedPacket {
                reason: "too short".into(),
                peer_addr: None,
                bytes_received: Some(3),
            },
            SecurityEvent::RateLimitExceeded {
                kind: "hello_flood".into(),
                peer_addr: None,
                rate: Some(1000.0),
            },
        ];
        for e in &events {
            let _ = e.to_string();
            let _ = e.event_type();
            let _ = e.peer_addr();
            let _ = e.session_id();
        }
    }

    #[test]
    fn test_log_security_event_does_not_panic() {
        // Just verify logging doesn't panic (output goes to tracing subscriber)
        let event = SecurityEvent::MalformedPacket {
            reason: "test logging".into(),
            peer_addr: Some("127.0.0.1:1234".into()),
            bytes_received: Some(10),
        };
        log_security_event(&event);
    }
}
