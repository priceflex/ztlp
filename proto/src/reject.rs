//! REJECT frame for clean client rejection after Noise_XX handshake.
//!
//! When a server denies a client (policy, capacity, rate limit, etc.),
//! it sends a REJECT frame before closing the connection. This lets the
//! client display a meaningful error instead of a cryptic timeout.
//!
//! ## Frame format (within ZTLP data packet payload)
//!
//! ```text
//! | Frame type | Reason code | Reason message (UTF-8, optional) |
//! | 1 byte     | 1 byte      | remaining bytes                  |
//! | 0x08       | 0x01-0x04   | human-readable text              |
//! ```
//!
//! The REJECT frame is sent as an encrypted ZTLP data packet (after
//! the Noise_XX handshake completes), so only the intended recipient
//! can read the rejection reason.

#![deny(unsafe_code)]

/// Frame type byte for REJECT.
pub const FRAME_REJECT: u8 = 0x08;

/// Rejection reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectReason {
    /// Authenticated but not authorized by policy.
    PolicyDenied = 0x01,
    /// Server at maximum session capacity.
    CapacityFull = 0x02,
    /// Requested service not available on this server.
    ServiceUnavailable = 0x03,
    /// Too many connection attempts from this client.
    RateLimited = 0x04,
    /// Identity has been revoked.
    Revoked = 0x05,
}

impl RejectReason {
    /// Parse a u8 into a RejectReason.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::PolicyDenied),
            0x02 => Some(Self::CapacityFull),
            0x03 => Some(Self::ServiceUnavailable),
            0x04 => Some(Self::RateLimited),
            0x05 => Some(Self::Revoked),
            _ => None,
        }
    }

    /// Human-readable description of the reason.
    pub fn description(&self) -> &'static str {
        match self {
            Self::PolicyDenied => "policy denied: authenticated but not authorized",
            Self::CapacityFull => "server at maximum session capacity",
            Self::ServiceUnavailable => "requested service not available",
            Self::RateLimited => "rate limited: too many connection attempts",
            Self::Revoked => "identity has been revoked",
        }
    }
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// A parsed REJECT frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectFrame {
    /// The rejection reason code.
    pub reason: RejectReason,
    /// Optional human-readable message with additional details.
    pub message: String,
}

impl RejectFrame {
    /// Create a new REJECT frame with a reason and optional message.
    pub fn new(reason: RejectReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    /// Create a REJECT frame with just a reason (default message).
    pub fn from_reason(reason: RejectReason) -> Self {
        Self {
            reason,
            message: reason.description().to_string(),
        }
    }

    /// Encode the REJECT frame into bytes (frame_type + reason + message).
    pub fn encode(&self) -> Vec<u8> {
        let msg_bytes = self.message.as_bytes();
        let mut buf = Vec::with_capacity(2 + msg_bytes.len());
        buf.push(FRAME_REJECT);
        buf.push(self.reason as u8);
        buf.extend_from_slice(msg_bytes);
        buf
    }

    /// Decode a REJECT frame from bytes.
    ///
    /// The `data` slice should include the frame type byte (0x08).
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        if data[0] != FRAME_REJECT {
            return None;
        }
        let reason = RejectReason::from_u8(data[1])?;
        let message = if data.len() > 2 {
            String::from_utf8_lossy(&data[2..]).to_string()
        } else {
            reason.description().to_string()
        };
        Some(Self { reason, message })
    }

    /// Check if a plaintext payload is a REJECT frame.
    pub fn is_reject(data: &[u8]) -> bool {
        !data.is_empty() && data[0] == FRAME_REJECT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_reason_roundtrip() {
        let reasons = [
            RejectReason::PolicyDenied,
            RejectReason::CapacityFull,
            RejectReason::ServiceUnavailable,
            RejectReason::RateLimited,
            RejectReason::Revoked,
        ];
        for reason in &reasons {
            let byte = *reason as u8;
            assert_eq!(RejectReason::from_u8(byte), Some(*reason));
        }
    }

    #[test]
    fn test_reject_reason_invalid() {
        assert_eq!(RejectReason::from_u8(0x00), None);
        assert_eq!(RejectReason::from_u8(0x06), None);
        assert_eq!(RejectReason::from_u8(0xFF), None);
    }

    #[test]
    fn test_reject_frame_encode_decode() {
        let frame = RejectFrame::new(RejectReason::PolicyDenied, "access denied for user X");
        let encoded = frame.encode();

        assert_eq!(encoded[0], FRAME_REJECT);
        assert_eq!(encoded[1], 0x01);
        assert_eq!(&encoded[2..], b"access denied for user X");

        let decoded = RejectFrame::decode(&encoded).expect("should decode");
        assert_eq!(decoded.reason, RejectReason::PolicyDenied);
        assert_eq!(decoded.message, "access denied for user X");
    }

    #[test]
    fn test_reject_frame_from_reason() {
        let frame = RejectFrame::from_reason(RejectReason::CapacityFull);
        assert_eq!(frame.reason, RejectReason::CapacityFull);
        assert_eq!(frame.message, "server at maximum session capacity");

        let encoded = frame.encode();
        let decoded = RejectFrame::decode(&encoded).expect("should decode");
        assert_eq!(decoded.reason, RejectReason::CapacityFull);
    }

    #[test]
    fn test_reject_frame_minimal() {
        // Encode with no message
        let data = vec![FRAME_REJECT, 0x03];
        let decoded = RejectFrame::decode(&data).expect("should decode");
        assert_eq!(decoded.reason, RejectReason::ServiceUnavailable);
        assert_eq!(decoded.message, "requested service not available");
    }

    #[test]
    fn test_reject_frame_too_short() {
        assert!(RejectFrame::decode(&[]).is_none());
        assert!(RejectFrame::decode(&[FRAME_REJECT]).is_none());
    }

    #[test]
    fn test_reject_frame_wrong_type() {
        assert!(RejectFrame::decode(&[0x00, 0x01]).is_none());
    }

    #[test]
    fn test_is_reject() {
        assert!(RejectFrame::is_reject(&[FRAME_REJECT, 0x01]));
        assert!(!RejectFrame::is_reject(&[0x00, 0x01]));
        assert!(!RejectFrame::is_reject(&[]));
    }

    #[test]
    fn test_reject_reason_display() {
        assert_eq!(
            format!("{}", RejectReason::PolicyDenied),
            "policy denied: authenticated but not authorized"
        );
        assert_eq!(
            format!("{}", RejectReason::RateLimited),
            "rate limited: too many connection attempts"
        );
    }

    #[test]
    fn test_reject_reason_revoked() {
        assert_eq!(RejectReason::from_u8(0x05), Some(RejectReason::Revoked));
        let frame = RejectFrame::from_reason(RejectReason::Revoked);
        assert_eq!(frame.reason, RejectReason::Revoked);
        assert_eq!(frame.message, "identity has been revoked");

        let encoded = frame.encode();
        assert_eq!(encoded[0], FRAME_REJECT);
        assert_eq!(encoded[1], 0x05);
        let decoded = RejectFrame::decode(&encoded).expect("should decode");
        assert_eq!(decoded.reason, RejectReason::Revoked);
    }

    #[test]
    fn test_reject_reason_revoked_with_message() {
        let frame = RejectFrame::new(
            RejectReason::Revoked,
            "user steve@zone.ztlp has been revoked",
        );
        let encoded = frame.encode();
        let decoded = RejectFrame::decode(&encoded).expect("should decode");
        assert_eq!(decoded.reason, RejectReason::Revoked);
        assert_eq!(decoded.message, "user steve@zone.ztlp has been revoked");
    }

    #[test]
    fn test_reject_frame_with_utf8_message() {
        let frame = RejectFrame::new(RejectReason::PolicyDenied, "accès refusé — доступ запрещён");
        let encoded = frame.encode();
        let decoded = RejectFrame::decode(&encoded).expect("should decode");
        assert_eq!(decoded.message, "accès refusé — доступ запрещён");
    }

    #[test]
    fn test_all_reason_codes_have_descriptions() {
        let reasons = [
            RejectReason::PolicyDenied,
            RejectReason::CapacityFull,
            RejectReason::ServiceUnavailable,
            RejectReason::RateLimited,
            RejectReason::Revoked,
        ];
        for reason in &reasons {
            assert!(!reason.description().is_empty());
        }
    }
}
