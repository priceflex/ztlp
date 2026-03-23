//! Relay Admission Token (RAT) support.
//!
//! RATs are short-lived, cryptographically signed tokens that prove a node
//! has been authenticated by an ingress relay. Transit relays accept
//! pre-authenticated traffic by verifying the RAT MAC without requiring
//! a separate handshake.
//!
//! ## Token Structure (93 bytes)
//!
//! ```text
//! Version:      1 byte  (0x01)
//! NodeID:      16 bytes (authenticated node)
//! IssuerID:    16 bytes (issuing relay's NodeID)
//! IssuedAt:     8 bytes (Unix timestamp seconds, big-endian)
//! ExpiresAt:    8 bytes (Unix timestamp seconds, big-endian)
//! SessionScope: 12 bytes (SessionID scope, or all-zeros for any)
//! MAC:         32 bytes (HMAC-BLAKE2s over all preceding fields)
//! ```
//!
//! ## HMAC-BLAKE2s
//!
//! Uses RFC 2104 HMAC construction with BLAKE2s as the hash function.
//! Block size for BLAKE2s is 64 bytes, output size is 32 bytes.
//! Byte-compatible with the Elixir relay implementation.

#![deny(unsafe_code)]

use blake2::{Blake2s256, Digest};
use subtle::ConstantTimeEq;

/// RAT version byte.
pub const RAT_VERSION: u8 = 0x01;

/// Total RAT size in bytes.
pub const RAT_SIZE: usize = 93;

/// Size of the data portion (everything before the MAC).
pub const RAT_DATA_SIZE: usize = 61;

/// Size of the HMAC-BLAKE2s MAC.
pub const RAT_MAC_SIZE: usize = 32;

/// BLAKE2s block size (for HMAC construction).
const BLAKE2S_BLOCK_SIZE: usize = 64;

/// Default TTL for issued tokens (5 minutes).
pub const DEFAULT_TTL_SECONDS: u64 = 300;

/// Handshake extension type for RAT.
pub const EXT_TYPE_RAT: u8 = 0x01;

/// A parsed Relay Admission Token.
#[derive(Debug, Clone)]
pub struct RelayAdmissionToken {
    /// Token version (currently 0x01).
    pub version: u8,
    /// 128-bit NodeID of the authenticated node.
    pub node_id: [u8; 16],
    /// 128-bit NodeID of the issuing relay.
    pub issuer_id: [u8; 16],
    /// Unix timestamp (seconds) when the token was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the token expires.
    pub expires_at: u64,
    /// SessionID this token is scoped to (all-zeros = any session).
    pub session_scope: [u8; 12],
    /// HMAC-BLAKE2s MAC over the data fields.
    pub mac: [u8; 32],
}

impl RelayAdmissionToken {
    /// Parse a RAT from exactly 93 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, AdmissionError> {
        if data.len() != RAT_SIZE {
            return Err(AdmissionError::InvalidTokenSize {
                expected: RAT_SIZE,
                actual: data.len(),
            });
        }

        let version = data[0];
        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&data[1..17]);
        let mut issuer_id = [0u8; 16];
        issuer_id.copy_from_slice(&data[17..33]);
        let issued_at = u64::from_be_bytes([
            data[33], data[34], data[35], data[36], data[37], data[38], data[39], data[40],
        ]);
        let expires_at = u64::from_be_bytes([
            data[41], data[42], data[43], data[44], data[45], data[46], data[47], data[48],
        ]);
        let mut session_scope = [0u8; 12];
        session_scope.copy_from_slice(&data[49..61]);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[61..93]);

        Ok(Self {
            version,
            node_id,
            issuer_id,
            issued_at,
            expires_at,
            session_scope,
            mac,
        })
    }

    /// Serialize the token to exactly 93 bytes.
    pub fn serialize(&self) -> [u8; RAT_SIZE] {
        let mut buf = [0u8; RAT_SIZE];
        buf[0] = self.version;
        buf[1..17].copy_from_slice(&self.node_id);
        buf[17..33].copy_from_slice(&self.issuer_id);
        buf[33..41].copy_from_slice(&self.issued_at.to_be_bytes());
        buf[41..49].copy_from_slice(&self.expires_at.to_be_bytes());
        buf[49..61].copy_from_slice(&self.session_scope);
        buf[61..93].copy_from_slice(&self.mac);
        buf
    }

    /// Verify the MAC using HMAC-BLAKE2s (constant-time comparison).
    pub fn verify(&self, secret: &[u8; 32]) -> bool {
        let data = &self.serialize()[..RAT_DATA_SIZE];
        let expected_mac = hmac_blake2s(secret, data);
        self.mac.ct_eq(&expected_mac).into()
    }

    /// Check if the token has expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at
    }

    /// Check if the token is valid for a specific session.
    ///
    /// Returns `true` if the token's session scope is all-zeros (any session)
    /// or matches the provided session ID exactly.
    pub fn valid_for_session(&self, session_id: &[u8; 12]) -> bool {
        let any_session = [0u8; 12];
        if self.session_scope == any_session {
            return true;
        }
        self.session_scope == *session_id
    }

    /// Issue a new token (for Rust-native relays or testing).
    pub fn issue(
        node_id: [u8; 16],
        issuer_id: [u8; 16],
        session_scope: [u8; 12],
        ttl_seconds: u64,
        secret: &[u8; 32],
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at = now + ttl_seconds;

        Self::issue_at(node_id, issuer_id, session_scope, now, expires_at, secret)
    }

    /// Issue a token with explicit timestamps (useful for testing and
    /// cross-language verification with deterministic values).
    pub fn issue_at(
        node_id: [u8; 16],
        issuer_id: [u8; 16],
        session_scope: [u8; 12],
        issued_at: u64,
        expires_at: u64,
        secret: &[u8; 32],
    ) -> Self {
        let mut token = Self {
            version: RAT_VERSION,
            node_id,
            issuer_id,
            issued_at,
            expires_at,
            session_scope,
            mac: [0u8; 32],
        };

        // Compute MAC over the data fields
        let serialized = token.serialize();
        let data = &serialized[..RAT_DATA_SIZE];
        token.mac = hmac_blake2s(secret, data);

        token
    }

    /// Pretty-print the token for inspection.
    pub fn display(&self) -> String {
        let scope_str = if self.session_scope == [0u8; 12] {
            "any".to_string()
        } else {
            hex::encode(self.session_scope)
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expiry_str = if now >= self.expires_at {
            format!("EXPIRED ({}s ago)", now - self.expires_at)
        } else {
            format!("in {}s", self.expires_at - now)
        };

        format!(
            "RAT v{}\n\
             \x20 NodeID:    {}\n\
             \x20 IssuerID:  {}\n\
             \x20 IssuedAt:  {} ({})\n\
             \x20 ExpiresAt: {} ({})\n\
             \x20 Scope:     {}\n\
             \x20 MAC:       {}...",
            self.version,
            hex::encode(self.node_id),
            hex::encode(self.issuer_id),
            self.issued_at,
            format_timestamp(self.issued_at),
            self.expires_at,
            expiry_str,
            scope_str,
            hex::encode(&self.mac[..16]),
        )
    }

    /// Return the remaining time-to-live in seconds, or 0 if expired.
    pub fn ttl_seconds(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.expires_at.saturating_sub(now)
    }
}

/// HMAC-BLAKE2s per RFC 2104.
///
/// ```text
/// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
/// ```
///
/// Where:
/// - H is BLAKE2s (block_size = 64 bytes, output = 32 bytes)
/// - K' is key padded/hashed to block_size
/// - ipad = 0x36 repeated block_size times
/// - opad = 0x5C repeated block_size times
///
/// This implementation is byte-compatible with the Elixir relay.
pub fn hmac_blake2s(key: &[u8], message: &[u8]) -> [u8; 32] {
    // If key is longer than block size, hash it first
    let key_prime: Vec<u8> = if key.len() > BLAKE2S_BLOCK_SIZE {
        let mut hasher = Blake2s256::new();
        hasher.update(key);
        let hash = hasher.finalize();
        let mut padded = vec![0u8; BLAKE2S_BLOCK_SIZE];
        padded[..32].copy_from_slice(&hash);
        padded
    } else {
        // Pad key with zeros to block size
        let mut padded = vec![0u8; BLAKE2S_BLOCK_SIZE];
        padded[..key.len()].copy_from_slice(key);
        padded
    };

    // Compute ipad and opad
    let mut ipad = [0x36u8; BLAKE2S_BLOCK_SIZE];
    let mut opad = [0x5Cu8; BLAKE2S_BLOCK_SIZE];
    for i in 0..BLAKE2S_BLOCK_SIZE {
        ipad[i] ^= key_prime[i];
        opad[i] ^= key_prime[i];
    }

    // Inner hash: H(ipad || message)
    let mut inner_hasher = Blake2s256::new();
    inner_hasher.update(ipad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H(opad || inner_hash)
    let mut outer_hasher = Blake2s256::new();
    outer_hasher.update(opad);
    outer_hasher.update(inner_hash);
    let outer_hash = outer_hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer_hash);
    result
}

/// Errors related to admission tokens.
#[derive(Debug, Clone)]
pub enum AdmissionError {
    /// Token data is not the expected size.
    InvalidTokenSize { expected: usize, actual: usize },
    /// Token version is not supported.
    UnsupportedVersion(u8),
    /// MAC verification failed.
    InvalidMac,
    /// Token has expired.
    Expired,
    /// Token session scope doesn't match.
    SessionScopeMismatch,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTokenSize { expected, actual } => {
                write!(
                    f,
                    "invalid token size: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported token version: 0x{:02x}", v)
            }
            Self::InvalidMac => write!(f, "invalid MAC"),
            Self::Expired => write!(f, "token expired"),
            Self::SessionScopeMismatch => write!(f, "session scope mismatch"),
        }
    }
}

impl std::error::Error for AdmissionError {}

/// Simple timestamp formatter (seconds since epoch → human-readable).
fn format_timestamp(unix_secs: u64) -> String {
    if unix_secs == 0 {
        return "N/A".to_string();
    }
    let secs_per_day: u64 = 86400;
    let days_since_epoch = unix_secs / secs_per_day;
    let time_of_day = unix_secs % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days_since_epoch);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Handshake extension types.
#[derive(Debug, Clone)]
pub enum HandshakeExtension {
    /// Relay Admission Token (type 0x01).
    AdmissionToken(RelayAdmissionToken),
}

impl HandshakeExtension {
    /// Serialize to bytes: ExtType (1 byte) + ExtData.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::AdmissionToken(rat) => {
                let mut buf = Vec::with_capacity(1 + RAT_SIZE);
                buf.push(EXT_TYPE_RAT);
                buf.extend_from_slice(&rat.serialize());
                buf
            }
        }
    }

    /// Parse from extension bytes (ExtType + ExtData).
    pub fn parse(data: &[u8]) -> Result<Self, AdmissionError> {
        if data.is_empty() {
            return Err(AdmissionError::InvalidTokenSize {
                expected: 1,
                actual: 0,
            });
        }

        match data[0] {
            EXT_TYPE_RAT => {
                if data.len() != 1 + RAT_SIZE {
                    return Err(AdmissionError::InvalidTokenSize {
                        expected: 1 + RAT_SIZE,
                        actual: data.len(),
                    });
                }
                let token = RelayAdmissionToken::parse(&data[1..])?;
                Ok(Self::AdmissionToken(token))
            }
            other => Err(AdmissionError::UnsupportedVersion(other)),
        }
    }

    /// The total byte length of this extension (type byte + data).
    pub fn wire_len(&self) -> usize {
        match self {
            Self::AdmissionToken(_) => 1 + RAT_SIZE, // 94 bytes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test HMAC-BLAKE2s with a known key and message.
    /// This vector can be validated against the Elixir implementation.
    #[test]
    fn test_hmac_blake2s_deterministic() {
        let key = [0xAA; 32];
        let message = b"hello world";

        let mac1 = hmac_blake2s(&key, message);
        let mac2 = hmac_blake2s(&key, message);

        // Same inputs must produce same output
        assert_eq!(mac1, mac2);

        // Different key must produce different output
        let key2 = [0xBB; 32];
        let mac3 = hmac_blake2s(&key2, message);
        assert_ne!(mac1, mac3);

        // Different message must produce different output
        let mac4 = hmac_blake2s(&key, b"hello worlD");
        assert_ne!(mac1, mac4);
    }

    /// Test HMAC-BLAKE2s with key longer than block size.
    #[test]
    fn test_hmac_blake2s_long_key() {
        let long_key = [0xCC; 128]; // longer than 64-byte block size
        let message = b"test";
        let mac = hmac_blake2s(&long_key, message);

        // Should produce a valid 32-byte MAC
        assert_eq!(mac.len(), 32);
        assert_ne!(mac, [0u8; 32]); // should not be all zeros

        // Consistent with itself
        assert_eq!(mac, hmac_blake2s(&long_key, message));
    }

    /// Test HMAC-BLAKE2s with empty message.
    #[test]
    fn test_hmac_blake2s_empty_message() {
        let key = [0x42; 32];
        let mac = hmac_blake2s(&key, b"");
        assert_eq!(mac.len(), 32);
        assert_ne!(mac, [0u8; 32]);
    }

    /// Test HMAC-BLAKE2s with empty key (padded to block size with zeros).
    #[test]
    fn test_hmac_blake2s_empty_key() {
        let mac = hmac_blake2s(&[], b"test message");
        assert_eq!(mac.len(), 32);
        assert_ne!(mac, [0u8; 32]);
    }

    /// Cross-language test vector: deterministic RAT with known values.
    ///
    /// Both Rust and Elixir should produce the same MAC for these inputs.
    /// To verify: run the Elixir equivalent with the same secret, node_id,
    /// issuer_id, timestamps, and session_scope.
    #[test]
    fn test_cross_language_known_vector() {
        // Known secret key
        let secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        // Known fields
        let node_id = [0xAA; 16];
        let issuer_id = [0xBB; 16];
        let issued_at: u64 = 1700000000;
        let expires_at: u64 = 1700000300;
        let session_scope = [0u8; 12]; // any session

        let token = RelayAdmissionToken::issue_at(
            node_id,
            issuer_id,
            session_scope,
            issued_at,
            expires_at,
            &secret,
        );

        // Verify the token roundtrips correctly
        assert_eq!(token.version, RAT_VERSION);
        assert_eq!(token.node_id, node_id);
        assert_eq!(token.issuer_id, issuer_id);
        assert_eq!(token.issued_at, issued_at);
        assert_eq!(token.expires_at, expires_at);
        assert_eq!(token.session_scope, session_scope);
        assert!(token.verify(&secret));

        // Serialize and re-parse
        let bytes = token.serialize();
        assert_eq!(bytes.len(), RAT_SIZE);

        let parsed = RelayAdmissionToken::parse(&bytes).unwrap();
        assert_eq!(parsed.version, token.version);
        assert_eq!(parsed.node_id, token.node_id);
        assert_eq!(parsed.issuer_id, token.issuer_id);
        assert_eq!(parsed.issued_at, token.issued_at);
        assert_eq!(parsed.expires_at, token.expires_at);
        assert_eq!(parsed.session_scope, token.session_scope);
        assert_eq!(parsed.mac, token.mac);
        assert!(parsed.verify(&secret));

        // Print the known vector for cross-language verification
        eprintln!("Cross-language test vector:");
        eprintln!("  Secret:  {}", hex::encode(secret));
        eprintln!("  Token:   {}", hex::encode(bytes));
        eprintln!("  MAC:     {}", hex::encode(token.mac));
    }

    /// Round-trip: issue → serialize → parse → verify.
    #[test]
    fn test_roundtrip_issue_serialize_parse_verify() {
        let secret = [0x42u8; 32];
        let node_id = [0x11; 16];
        let issuer_id = [0x22; 16];
        let session_scope = [0u8; 12];

        let token = RelayAdmissionToken::issue(node_id, issuer_id, session_scope, 300, &secret);

        let bytes = token.serialize();
        assert_eq!(bytes.len(), RAT_SIZE);

        let parsed = RelayAdmissionToken::parse(&bytes).unwrap();
        assert!(parsed.verify(&secret));
        assert!(!parsed.is_expired());
        assert_eq!(parsed.version, RAT_VERSION);
        assert_eq!(parsed.node_id, node_id);
        assert_eq!(parsed.issuer_id, issuer_id);
    }

    /// Expired token detection.
    #[test]
    fn test_expired_token() {
        let secret = [0x42u8; 32];
        let node_id = [0x11; 16];
        let issuer_id = [0x22; 16];
        let session_scope = [0u8; 12];

        // Issue a token that expired in the past
        let token = RelayAdmissionToken::issue_at(
            node_id,
            issuer_id,
            session_scope,
            1000000, // issued long ago
            1000010, // expired long ago
            &secret,
        );

        assert!(token.verify(&secret)); // MAC is still valid
        assert!(token.is_expired()); // but it's expired
    }

    /// Session scope validation.
    #[test]
    fn test_session_scope_validation() {
        let secret = [0x42u8; 32];
        let node_id = [0x11; 16];
        let issuer_id = [0x22; 16];

        // Token scoped to any session
        let any_token = RelayAdmissionToken::issue(node_id, issuer_id, [0u8; 12], 300, &secret);
        assert!(any_token.valid_for_session(&[0xFF; 12]));
        assert!(any_token.valid_for_session(&[0x00; 12]));

        // Token scoped to a specific session
        let specific_scope = [0xAA; 12];
        let scoped_token =
            RelayAdmissionToken::issue(node_id, issuer_id, specific_scope, 300, &secret);
        assert!(scoped_token.valid_for_session(&specific_scope));
        assert!(!scoped_token.valid_for_session(&[0xBB; 12]));
        assert!(!scoped_token.valid_for_session(&[0x00; 12]));
    }

    /// Tampered token rejection.
    #[test]
    fn test_tampered_token_rejected() {
        let secret = [0x42u8; 32];
        let node_id = [0x11; 16];
        let issuer_id = [0x22; 16];

        let token = RelayAdmissionToken::issue(node_id, issuer_id, [0u8; 12], 300, &secret);

        // Tamper with the node_id
        let mut bytes = token.serialize();
        bytes[1] ^= 0xFF; // flip bits in node_id
        let tampered = RelayAdmissionToken::parse(&bytes).unwrap();
        assert!(!tampered.verify(&secret));

        // Tamper with the expires_at
        let mut bytes = token.serialize();
        bytes[41] ^= 0xFF; // flip bits in expires_at
        let tampered = RelayAdmissionToken::parse(&bytes).unwrap();
        assert!(!tampered.verify(&secret));

        // Tamper with the MAC itself
        let mut bytes = token.serialize();
        bytes[61] ^= 0xFF; // flip bits in MAC
        let tampered = RelayAdmissionToken::parse(&bytes).unwrap();
        assert!(!tampered.verify(&secret));
    }

    /// Wrong secret key should fail verification.
    #[test]
    fn test_wrong_secret_rejected() {
        let secret = [0x42u8; 32];
        let wrong_secret = [0x99u8; 32];

        let token = RelayAdmissionToken::issue([0x11; 16], [0x22; 16], [0u8; 12], 300, &secret);

        assert!(token.verify(&secret));
        assert!(!token.verify(&wrong_secret));
    }

    /// Invalid token sizes should be rejected.
    #[test]
    fn test_invalid_size_rejected() {
        assert!(RelayAdmissionToken::parse(&[0u8; 0]).is_err());
        assert!(RelayAdmissionToken::parse(&[0u8; 92]).is_err());
        assert!(RelayAdmissionToken::parse(&[0u8; 94]).is_err());
        assert!(RelayAdmissionToken::parse(&[0u8; 200]).is_err());
    }

    /// Test display output is reasonable.
    #[test]
    fn test_display() {
        let secret = [0x42u8; 32];
        let token = RelayAdmissionToken::issue([0x11; 16], [0x22; 16], [0u8; 12], 300, &secret);
        let display = token.display();
        assert!(display.contains("RAT v1"));
        assert!(display.contains("1111111111111111")); // node_id hex
        assert!(display.contains("2222222222222222")); // issuer_id hex
        assert!(display.contains("any")); // session scope
    }

    /// Test TTL computation.
    #[test]
    fn test_ttl_seconds() {
        let secret = [0x42u8; 32];

        // Token with 300s TTL
        let token = RelayAdmissionToken::issue([0x11; 16], [0x22; 16], [0u8; 12], 300, &secret);
        let ttl = token.ttl_seconds();
        assert!(ttl <= 300);
        assert!(ttl >= 298); // allow a couple seconds for test runtime

        // Expired token should have 0 TTL
        let expired = RelayAdmissionToken::issue_at(
            [0x11; 16], [0x22; 16], [0u8; 12], 1000000, 1000010, &secret,
        );
        assert_eq!(expired.ttl_seconds(), 0);
    }

    /// Test HandshakeExtension round-trip.
    #[test]
    fn test_extension_roundtrip() {
        let secret = [0x42u8; 32];
        let token = RelayAdmissionToken::issue([0x11; 16], [0x22; 16], [0u8; 12], 300, &secret);

        let ext = HandshakeExtension::AdmissionToken(token.clone());
        let bytes = ext.serialize();
        assert_eq!(bytes.len(), 1 + RAT_SIZE); // 94 bytes
        assert_eq!(bytes[0], EXT_TYPE_RAT);

        let parsed = HandshakeExtension::parse(&bytes).unwrap();
        match parsed {
            HandshakeExtension::AdmissionToken(parsed_token) => {
                assert_eq!(parsed_token.node_id, token.node_id);
                assert_eq!(parsed_token.mac, token.mac);
                assert!(parsed_token.verify(&secret));
            }
        }
    }

    /// Test HandshakeExtension wire length.
    #[test]
    fn test_extension_wire_len() {
        let secret = [0x42u8; 32];
        let token = RelayAdmissionToken::issue([0x11; 16], [0x22; 16], [0u8; 12], 300, &secret);
        let ext = HandshakeExtension::AdmissionToken(token);
        assert_eq!(ext.wire_len(), 94);
    }

    // ── Security audit tests ────────────────────────────────────────────

    /// SECURITY: Verify that HMAC comparison uses constant-time equality
    /// (subtle::ConstantTimeEq). This test confirms the verify() method
    /// correctly rejects invalid MACs — the constant-time property is
    /// ensured by the use of ct_eq from the `subtle` crate.
    #[test]
    fn test_verify_uses_constant_time_comparison() {
        let secret = [0x42u8; 32];
        let token = RelayAdmissionToken::issue([0x11; 16], [0x22; 16], [0u8; 12], 300, &secret);

        // Valid MAC should pass
        assert!(token.verify(&secret));

        // Flip each byte of the MAC — every single-byte change must be detected.
        // This exercises the constant-time compare path for near-match MACs.
        for byte_idx in 0..32 {
            let mut tampered = token.clone();
            tampered.mac[byte_idx] ^= 0x01; // flip just one bit
            assert!(
                !tampered.verify(&secret),
                "flipping MAC byte {} should fail verification",
                byte_idx
            );
        }
    }

    /// SECURITY: Verify that an expired token with a manipulated timestamp
    /// still has a valid MAC (preventing the "extend expiry" attack).
    /// Changing expires_at invalidates the MAC.
    #[test]
    fn test_expired_token_cannot_extend_expiry() {
        let secret = [0x42u8; 32];

        // Issue an expired token
        let token = RelayAdmissionToken::issue_at(
            [0x11; 16], [0x22; 16], [0u8; 12], 1000000, 1000010, // expired long ago
            &secret,
        );
        assert!(token.verify(&secret));
        assert!(token.is_expired());

        // Try to extend the expiry by modifying the timestamp
        let mut bytes = token.serialize();
        // Set expires_at to far future (year 2100)
        let far_future: u64 = 4102444800;
        bytes[41..49].copy_from_slice(&far_future.to_be_bytes());

        let tampered = RelayAdmissionToken::parse(&bytes).unwrap();
        // The MAC must be invalid because expires_at is covered by the MAC
        assert!(
            !tampered.verify(&secret),
            "extending expires_at must invalidate the MAC"
        );
    }

    /// SECURITY: Verify that timestamp overflow doesn't cause issues.
    #[test]
    fn test_timestamp_boundary_values() {
        let secret = [0x42u8; 32];

        // Max u64 timestamps
        let token = RelayAdmissionToken::issue_at(
            [0x11; 16],
            [0x22; 16],
            [0u8; 12],
            u64::MAX - 1,
            u64::MAX,
            &secret,
        );
        assert!(token.verify(&secret));
        // This token is "expired" because expires_at (u64::MAX) < now in practice
        // Actually u64::MAX > any reasonable now, so it's NOT expired
        // The important thing is it doesn't panic

        // Zero timestamps
        let token_zero =
            RelayAdmissionToken::issue_at([0x11; 16], [0x22; 16], [0u8; 12], 0, 0, &secret);
        assert!(token_zero.verify(&secret));
        assert!(token_zero.is_expired()); // expires_at = 0 is definitely expired
    }

    /// SECURITY: Verify that an empty extension payload is properly rejected.
    #[test]
    fn test_extension_parse_empty_data() {
        let result = HandshakeExtension::parse(&[]);
        assert!(result.is_err());
    }

    /// SECURITY: Verify that a truncated extension payload is rejected.
    #[test]
    fn test_extension_parse_truncated() {
        // Just the type byte, no token data
        let result = HandshakeExtension::parse(&[EXT_TYPE_RAT]);
        assert!(result.is_err());
    }
}
