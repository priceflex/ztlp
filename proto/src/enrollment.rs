//! # ZTLP Enrollment Token
//!
//! Enrollment tokens are short-lived, pre-authorized capabilities that allow
//! new devices to join a ZTLP network. An admin generates tokens using a
//! zone's enrollment secret; devices present tokens to NS during registration.
//!
//! ## Wire Format (variable length, typically ~120-200 bytes)
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │  version       : u8        (0x01)                         │
//! │  flags         : u8        (bit 0: has gateway addr)      │
//! │  zone_len      : u16       (big-endian)                   │
//! │  zone          : [u8; zone_len]                           │
//! │  ns_addr_len   : u16       (big-endian)                   │
//! │  ns_addr       : [u8; ns_addr_len]  (e.g. "10.0.0.5:23096") │
//! │  relay_count   : u8                                       │
//! │  relay_addrs   : [u16 len + addr] × relay_count           │
//! │  gateway_addr_len : u16    (only if flag bit 0 set)       │
//! │  gateway_addr  : [u8; gateway_addr_len]                   │
//! │  max_uses      : u16       (0 = unlimited)                │
//! │  expires_at    : u64       (unix timestamp, big-endian)   │
//! │  nonce         : [u8; 16]  (random, prevents replay)      │
//! │  mac           : [u8; 32]  (HMAC-BLAKE2s over all above)  │
//! └────────────────────────────────────────────────────────────┘
//! ```

#![deny(clippy::unwrap_used)]

use rand::RngCore;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Current enrollment token version.
const TOKEN_VERSION: u8 = 0x01;

/// Flag: token includes a gateway address.
const FLAG_HAS_GATEWAY: u8 = 0x01;

/// An enrollment token that authorizes a device to join a ZTLP zone.
#[derive(Debug, Clone)]
pub struct EnrollmentToken {
    pub version: u8,
    pub zone: String,
    pub ns_addr: String,
    pub relay_addrs: Vec<String>,
    pub gateway_addr: Option<String>,
    pub max_uses: u16,
    pub expires_at: u64,
    pub nonce: [u8; 16],
    pub mac: [u8; 32],
    /// Token identifier (hex string from query-param URI `token` parameter).
    /// Used for enrollment confirmation callback.
    pub token_id: Option<String>,
    /// Optional callback URL for the CLI to confirm enrollment usage
    /// (populated from query-param URI `callback` parameter).
    pub callback_url: Option<String>,
}

/// Result of token validation.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenValidation {
    Valid,
    Expired,
    InvalidMac,
    InvalidVersion,
    Malformed(String),
}

impl std::fmt::Display for TokenValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenValidation::Valid => write!(f, "valid"),
            TokenValidation::Expired => write!(f, "token expired"),
            TokenValidation::InvalidMac => write!(f, "invalid MAC (wrong secret?)"),
            TokenValidation::InvalidVersion => write!(f, "unsupported token version"),
            TokenValidation::Malformed(msg) => write!(f, "malformed: {}", msg),
        }
    }
}

impl EnrollmentToken {
    /// Create a new enrollment token for a zone.
    ///
    /// The caller provides the zone enrollment secret to compute the MAC.
    pub fn create(
        zone: &str,
        ns_addr: &str,
        relay_addrs: &[String],
        gateway_addr: Option<&str>,
        max_uses: u16,
        expires_at: u64,
        secret: &[u8; 32],
    ) -> Self {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut token = Self {
            version: TOKEN_VERSION,
            zone: zone.to_string(),
            ns_addr: ns_addr.to_string(),
            relay_addrs: relay_addrs.to_vec(),
            gateway_addr: gateway_addr.map(String::from),
            max_uses,
            expires_at,
            nonce,
            mac: [0u8; 32],
            token_id: None,
            callback_url: None,
        };

        // Serialize everything except the MAC field, then compute MAC
        let data = token.serialize_without_mac();
        token.mac = hmac_blake2s(secret, &data);
        token
    }

    /// Serialize the token to binary wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = self.serialize_without_mac();
        buf.extend_from_slice(&self.mac);
        buf
    }

    /// Serialize to base64url for use in CLI tokens and QR codes.
    pub fn to_base64url(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.serialize())
    }

    /// Serialize with `ztlp://enroll/` URI prefix.
    pub fn to_uri(&self) -> String {
        format!("ztlp://enroll/{}", self.to_base64url())
    }

    /// Parse a token from binary wire format.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        let mut pos = 0;

        // Version
        if data.is_empty() {
            return Err("empty token data".to_string());
        }
        let version = data[pos];
        pos += 1;

        if version != TOKEN_VERSION {
            return Err(format!("unsupported version: 0x{:02x}", version));
        }

        // Flags
        if pos >= data.len() {
            return Err("truncated at flags".to_string());
        }
        let flags = data[pos];
        pos += 1;

        // Zone
        let zone = read_len_prefixed_string(data, &mut pos)?;

        // NS address
        let ns_addr = read_len_prefixed_string(data, &mut pos)?;

        // Relay addresses
        if pos >= data.len() {
            return Err("truncated at relay count".to_string());
        }
        let relay_count = data[pos] as usize;
        pos += 1;

        let mut relay_addrs = Vec::with_capacity(relay_count);
        for i in 0..relay_count {
            let addr = read_len_prefixed_string(data, &mut pos)
                .map_err(|e| format!("relay addr {}: {}", i, e))?;
            relay_addrs.push(addr);
        }

        // Gateway address (optional)
        let gateway_addr = if flags & FLAG_HAS_GATEWAY != 0 {
            Some(read_len_prefixed_string(data, &mut pos)?)
        } else {
            None
        };

        // Max uses
        if pos + 2 > data.len() {
            return Err("truncated at max_uses".to_string());
        }
        let max_uses = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // Expires at
        if pos + 8 > data.len() {
            return Err("truncated at expires_at".to_string());
        }
        let expires_at = u64::from_be_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        pos += 8;

        // Nonce
        if pos + 16 > data.len() {
            return Err("truncated at nonce".to_string());
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;

        // MAC
        if pos + 32 > data.len() {
            return Err("truncated at mac".to_string());
        }
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[pos..pos + 32]);

        Ok(Self {
            version,
            zone,
            ns_addr,
            relay_addrs,
            gateway_addr,
            max_uses,
            expires_at,
            nonce,
            mac,
            token_id: None,     // Binary tokens don't carry token IDs
            callback_url: None, // Binary tokens don't carry callback URLs
        })
    }

    /// Parse from base64url string, `ztlp://enroll/<base64>` URI, or
    /// `ztlp://enroll/?zone=...&token=...` query-param URI (Bootstrap format).
    pub fn from_base64url(input: &str) -> Result<Self, String> {
        use base64::Engine;

        // Handle Bootstrap-style query-param URIs:
        // ztlp://enroll/?zone=foo.ztlp&ns=1.2.3.4:23096&relay=5.6.7.8:23095&token=abcd&expires=1773728471
        if input.contains("?") && input.contains("token=") {
            return Self::from_query_param_uri(input);
        }

        let b64 = if let Some(stripped) = input.strip_prefix("ztlp://enroll/") {
            stripped
        } else {
            input
        };

        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| format!("base64 decode error: {}", e))?;

        Self::deserialize(&bytes)
    }

    /// Parse from Bootstrap-style query-param URI.
    /// Format: ztlp://enroll/?zone=<zone>&ns=<host:port>&relay=<host:port>&token=<hex>&expires=<unix>
    ///         [&gateway=<host:port>][&callback=<url>][&nonce=<32hex>&mac=<64hex>]
    ///
    /// **Signed form (v0.30.10+):** when `&nonce=` and `&mac=` are present,
    /// the token's `nonce` and `mac` fields are populated from those params
    /// instead of being zeroed. This lets the NS verify the token via its
    /// existing HMAC-BLAKE2s path with `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=true`.
    ///
    /// **Legacy form:** without `&nonce=` and `&mac=`, the token has a
    /// zeroed MAC and zero nonce. The NS must run with
    /// `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false` to accept it. The Bootstrap
    /// app tracks token validity server-side in that case.
    fn from_query_param_uri(input: &str) -> Result<Self, String> {
        // Extract query string
        let query = input
            .split('?')
            .nth(1)
            .ok_or_else(|| "no query string in URI".to_string())?;

        let mut zone = None;
        let mut ns_addr = None;
        let mut relay_addrs = Vec::new();
        let mut token_hex = None;
        let mut expires = None;
        let mut gateway_addr = None;
        let mut callback_url = None;
        let mut nonce_hex: Option<String> = None;
        let mut mac_hex: Option<String> = None;

        for pair in query.split('&') {
            let mut kv = pair.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let val = kv.next().unwrap_or("");
            match key {
                "zone" => zone = Some(val.to_string()),
                "ns" => ns_addr = Some(val.to_string()),
                "relay" => relay_addrs.push(val.to_string()),
                "gateway" => gateway_addr = Some(val.to_string()),
                "token" => token_hex = Some(val.to_string()),
                "expires" => {
                    expires = Some(
                        val.parse::<u64>()
                            .map_err(|_| "invalid expires timestamp".to_string())?,
                    )
                }
                "callback" => callback_url = Some(val.to_string()),
                "nonce" => nonce_hex = Some(val.to_string()),
                "mac" => mac_hex = Some(val.to_string()),
                _ => {} // ignore unknown params
            }
        }

        let zone = zone.ok_or("missing zone parameter")?;
        let ns_addr = ns_addr.ok_or("missing ns parameter")?;
        let token_id = token_hex.ok_or("missing token parameter")?;
        let expires_at = expires.ok_or("missing expires parameter")?;

        // Decode signed-form params if present. Both must appear together
        // or neither; one without the other is a malformed URI.
        let (nonce_bytes, mac_bytes) = match (nonce_hex.as_deref(), mac_hex.as_deref()) {
            (Some(n), Some(m)) => {
                let n_bytes = hex_decode_fixed::<16>(n, "nonce")?;
                let m_bytes = hex_decode_fixed::<32>(m, "mac")?;
                (n_bytes, m_bytes)
            }
            (Some(_), None) => {
                return Err("URI has &nonce= but no &mac=; signed form requires both".to_string());
            }
            (None, Some(_)) => {
                return Err("URI has &mac= but no &nonce=; signed form requires both".to_string());
            }
            (None, None) => ([0u8; 16], [0u8; 32]),
        };

        Ok(EnrollmentToken {
            version: TOKEN_VERSION,
            zone,
            ns_addr,
            relay_addrs,
            gateway_addr,
            max_uses: 1,
            expires_at,
            nonce: nonce_bytes,
            mac: mac_bytes,
            token_id: Some(token_id),
            callback_url,
        })
    }

    /// Validate the token: check version, MAC, and expiration.
    pub fn validate(&self, secret: &[u8; 32]) -> TokenValidation {
        if self.version != TOKEN_VERSION {
            return TokenValidation::InvalidVersion;
        }

        // Verify MAC
        let data = self.serialize_without_mac();
        let expected_mac = hmac_blake2s(secret, &data);
        if !constant_time_eq(&self.mac, &expected_mac) {
            return TokenValidation::InvalidMac;
        }

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if self.expires_at > 0 && now > self.expires_at {
            return TokenValidation::Expired;
        }

        TokenValidation::Valid
    }

    /// Check if the token is expired (without MAC verification).
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now > self.expires_at
    }

    /// Human-readable expiry description.
    pub fn expires_in_human(&self) -> String {
        if self.expires_at == 0 {
            return "never".to_string();
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now > self.expires_at {
            return "expired".to_string();
        }
        let remaining = self.expires_at - now;
        if remaining < 60 {
            format!("{}s", remaining)
        } else if remaining < 3600 {
            format!("{}m", remaining / 60)
        } else if remaining < 86400 {
            format!("{}h", remaining / 3600)
        } else {
            format!("{}d", remaining / 86400)
        }
    }

    // ── Internal ────────────────────────────────────────────────────

    fn serialize_without_mac(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // Version
        buf.push(self.version);

        // Flags
        let flags = if self.gateway_addr.is_some() {
            FLAG_HAS_GATEWAY
        } else {
            0
        };
        buf.push(flags);

        // Zone
        write_len_prefixed_string(&mut buf, &self.zone);

        // NS address
        write_len_prefixed_string(&mut buf, &self.ns_addr);

        // Relay addresses
        buf.push(self.relay_addrs.len() as u8);
        for addr in &self.relay_addrs {
            write_len_prefixed_string(&mut buf, addr);
        }

        // Gateway address (if present)
        if let Some(ref gw) = self.gateway_addr {
            write_len_prefixed_string(&mut buf, gw);
        }

        // Max uses
        buf.extend_from_slice(&self.max_uses.to_be_bytes());

        // Expires at
        buf.extend_from_slice(&self.expires_at.to_be_bytes());

        // Nonce
        buf.extend_from_slice(&self.nonce);

        buf
    }
}

// ── Wire format helpers ─────────────────────────────────────────────

fn write_len_prefixed_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Decode a lowercase hex string into a fixed-size byte array.
///
/// Used by `from_query_param_uri` to parse the v0.30.10 `&nonce=` and
/// `&mac=` URI params. Strict: rejects odd-length input, non-hex chars,
/// and wrong byte count. The `field` argument is folded into the error
/// message so misformatted URIs blame the right param.
fn hex_decode_fixed<const N: usize>(s: &str, field: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2 {
        return Err(format!(
            "{} param must be {} hex chars ({} bytes), got {} chars",
            field,
            N * 2,
            N,
            s.len()
        ));
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or_else(|| format!("{} param: invalid hex", field))?;
        let lo = hex_nibble(chunk[1]).ok_or_else(|| format!("{} param: invalid hex", field))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn read_len_prefixed_string(data: &[u8], pos: &mut usize) -> Result<String, String> {
    if *pos + 2 > data.len() {
        return Err("truncated length prefix".to_string());
    }
    let len = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;

    if *pos + len > data.len() {
        return Err(format!(
            "truncated string: need {} bytes at offset {}, have {}",
            len,
            *pos,
            data.len()
        ));
    }
    let s = String::from_utf8(data[*pos..*pos + len].to_vec())
        .map_err(|e| format!("invalid UTF-8: {}", e))?;
    *pos += len;
    Ok(s)
}

// ── HMAC-BLAKE2s ────────────────────────────────────────────────────

/// Compute HMAC-BLAKE2s-256 per RFC 2104.
///
/// **CRITICAL:** This is the standard HMAC construction (with ipad/opad), NOT
/// BLAKE2s's native keyed-hash mode. The Elixir NS at `ZtlpNs.Enrollment.hmac_blake2s/2`
/// uses RFC 2104 HMAC, so any deviation here breaks token verification across
/// the Rust/Elixir boundary.
///
/// Historical bug: prior to the v0.30.0 fix this function used BLAKE2s keyed
/// mode (`Blake2sMac256::new_from_slice(key)`), which produces a *different*
/// 32-byte MAC from RFC 2104 HMAC even though both are "BLAKE2s with a key".
/// Tokens minted by the buggy Rust side were silently rejected by NS with the
/// uninformative `0x08 0x03` "invalid token" wire error. See PR adding this
/// comment for the full diagnosis.
///
/// Delegates to `admission::hmac_blake2s` which already had the correct
/// RFC 2104 implementation and is byte-compatible with the Elixir relay.
pub fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    crate::admission::hmac_blake2s(key, data)
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Generate a random 32-byte enrollment secret.
pub fn generate_enrollment_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

/// Pin a gateway's static Noise public key to the config file.
///
/// Reads the existing config, adds the key (base64-encoded) to the
/// `pinned_gateway_keys` list if not already present, and writes it back.
///
/// This is called after a successful first enrollment to bind the client
/// to the specific gateway it enrolled with. Subsequent connections will
/// reject gateways with different static keys.
pub fn pin_gateway_key(
    config_path: &Path,
    key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;

    let encoded = base64::engine::general_purpose::STANDARD.encode(key);

    // Read existing config content (or start fresh)
    let contents = if config_path.exists() {
        std::fs::read_to_string(config_path)?
    } else {
        String::new()
    };

    // Check if this key is already pinned
    if contents.contains(&encoded) {
        return Ok(());
    }

    // Parse existing pinned_gateway_keys if present
    let mut existing_keys: Vec<String> = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("pinned_gateway_keys") {
            // Parse the array value — handle simple cases
            if let Some(arr_start) = trimmed.find('[') {
                let arr_str = &trimmed[arr_start..];
                if let Some(arr_end) = arr_str.find(']') {
                    let inner = &arr_str[1..arr_end];
                    for item in inner.split(',') {
                        let key_str = item.trim().trim_matches('"').trim();
                        if !key_str.is_empty() {
                            existing_keys.push(key_str.to_string());
                        }
                    }
                }
            }
        }
    }

    existing_keys.push(encoded);

    // Build the new pinned_gateway_keys line
    let keys_toml = format!(
        "pinned_gateway_keys = [{}]",
        existing_keys
            .iter()
            .map(|k| format!("\"{}\"", k))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Replace or append
    let new_contents = if contents.contains("pinned_gateway_keys") {
        let mut result = String::new();
        for line in contents.lines() {
            if line.trim().starts_with("pinned_gateway_keys") {
                result.push_str(&keys_toml);
            } else {
                result.push_str(line);
            }
            result.push('\n');
        }
        result
    } else {
        let mut result = contents;
        if !result.is_empty() && !result.ends_with('\n') {
            result.push('\n');
        }
        result.push_str(&keys_toml);
        result.push('\n');
        result
    };

    std::fs::write(config_path, new_contents)?;
    Ok(())
}

/// Parse a duration string like "24h", "7d", "30m", "3600s" into seconds.
pub fn parse_duration_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('d') {
        (n, 86400u64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else {
        // Assume seconds if no suffix
        (s, 1u64)
    };

    let num: u64 = num_str
        .parse()
        .map_err(|e| format!("invalid number '{}': {}", num_str, e))?;

    Ok(num * multiplier)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = 0x42;
        s[31] = 0xFF;
        s
    }

    #[test]
    fn test_create_and_serialize_roundtrip() {
        let secret = test_secret();
        let token = EnrollmentToken::create(
            "office.acme.ztlp",
            "10.0.0.5:23096",
            &["10.0.0.5:23095".to_string()],
            Some("10.0.0.5:23097"),
            10,
            u64::MAX, // far future
            &secret,
        );

        let bytes = token.serialize();
        let parsed = EnrollmentToken::deserialize(&bytes).expect("should parse");

        assert_eq!(parsed.version, TOKEN_VERSION);
        assert_eq!(parsed.zone, "office.acme.ztlp");
        assert_eq!(parsed.ns_addr, "10.0.0.5:23096");
        assert_eq!(parsed.relay_addrs, vec!["10.0.0.5:23095"]);
        assert_eq!(parsed.gateway_addr, Some("10.0.0.5:23097".to_string()));
        assert_eq!(parsed.max_uses, 10);
        assert_eq!(parsed.nonce, token.nonce);
        assert_eq!(parsed.mac, token.mac);
    }

    #[test]
    fn test_base64url_roundtrip() {
        let secret = test_secret();
        let token = EnrollmentToken::create(
            "test.ztlp",
            "127.0.0.1:23096",
            &["127.0.0.1:23095".to_string()],
            None,
            1,
            u64::MAX,
            &secret,
        );

        let b64 = token.to_base64url();
        let parsed = EnrollmentToken::from_base64url(&b64).expect("should parse");
        assert_eq!(parsed.zone, "test.ztlp");
        assert_eq!(parsed.gateway_addr, None);
    }

    #[test]
    fn test_uri_roundtrip() {
        let secret = test_secret();
        let token = EnrollmentToken::create(
            "test.ztlp",
            "127.0.0.1:23096",
            &[],
            None,
            0,
            u64::MAX,
            &secret,
        );

        let uri = token.to_uri();
        assert!(uri.starts_with("ztlp://enroll/"));
        let parsed = EnrollmentToken::from_base64url(&uri).expect("should parse URI");
        assert_eq!(parsed.zone, "test.ztlp");
    }

    #[test]
    fn test_validate_valid_token() {
        let secret = test_secret();
        let token = EnrollmentToken::create(
            "test.ztlp",
            "127.0.0.1:23096",
            &[],
            None,
            0,
            u64::MAX,
            &secret,
        );

        assert_eq!(token.validate(&secret), TokenValidation::Valid);
    }

    #[test]
    fn test_validate_wrong_secret() {
        let secret = test_secret();
        let token = EnrollmentToken::create(
            "test.ztlp",
            "127.0.0.1:23096",
            &[],
            None,
            0,
            u64::MAX,
            &secret,
        );

        let wrong_secret = [0xAA; 32];
        assert_eq!(token.validate(&wrong_secret), TokenValidation::InvalidMac);
    }

    #[test]
    fn test_validate_expired_token() {
        let secret = test_secret();
        let token = EnrollmentToken::create(
            "test.ztlp",
            "127.0.0.1:23096",
            &[],
            None,
            0,
            1, // expired: unix timestamp 1
            &secret,
        );

        assert_eq!(token.validate(&secret), TokenValidation::Expired);
    }

    #[test]
    fn test_validate_tampered_zone() {
        let secret = test_secret();
        let token = EnrollmentToken::create(
            "test.ztlp",
            "127.0.0.1:23096",
            &[],
            None,
            0,
            u64::MAX,
            &secret,
        );

        let mut bytes = token.serialize();
        // Tamper with a byte in the zone name
        bytes[4] = b'X';
        let tampered = EnrollmentToken::deserialize(&bytes).expect("should parse");
        assert_eq!(tampered.validate(&secret), TokenValidation::InvalidMac);
    }

    #[test]
    fn test_multiple_relay_addrs() {
        let secret = test_secret();
        let relays = vec![
            "10.0.0.1:23095".to_string(),
            "10.0.0.2:23095".to_string(),
            "10.0.0.3:23095".to_string(),
        ];
        let token = EnrollmentToken::create(
            "mesh.acme.ztlp",
            "10.0.0.1:23096",
            &relays,
            None,
            100,
            u64::MAX,
            &secret,
        );

        let bytes = token.serialize();
        let parsed = EnrollmentToken::deserialize(&bytes).expect("should parse");
        assert_eq!(parsed.relay_addrs.len(), 3);
        assert_eq!(parsed.relay_addrs, relays);
        assert_eq!(parsed.validate(&secret), TokenValidation::Valid);
    }

    #[test]
    fn test_hmac_blake2s_deterministic() {
        let key = [0x42u8; 32];
        let data = b"hello world";
        let mac1 = hmac_blake2s(&key, data);
        let mac2 = hmac_blake2s(&key, data);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_blake2s_different_keys() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let data = b"hello world";
        let mac1 = hmac_blake2s(&key1, data);
        let mac2 = hmac_blake2s(&key2, data);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_parse_duration_secs() {
        assert_eq!(parse_duration_secs("24h").ok(), Some(86400));
        assert_eq!(parse_duration_secs("7d").ok(), Some(604800));
        assert_eq!(parse_duration_secs("30m").ok(), Some(1800));
        assert_eq!(parse_duration_secs("3600s").ok(), Some(3600));
        assert_eq!(parse_duration_secs("3600").ok(), Some(3600));
        assert!(parse_duration_secs("").is_err());
        assert!(parse_duration_secs("abc").is_err());
    }

    #[test]
    fn test_generate_enrollment_secret() {
        let s1 = generate_enrollment_secret();
        let s2 = generate_enrollment_secret();
        assert_ne!(s1, s2); // extremely unlikely to collide
        assert_eq!(s1.len(), 32);
    }

    #[test]
    fn test_deserialize_truncated() {
        assert!(EnrollmentToken::deserialize(&[]).is_err());
        assert!(EnrollmentToken::deserialize(&[0x01]).is_err());
        assert!(EnrollmentToken::deserialize(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn test_deserialize_wrong_version() {
        let mut data = vec![0x02, 0x00]; // version 2
        data.extend_from_slice(&[0x00, 0x04]); // zone len
        data.extend_from_slice(b"test");
        let err = EnrollmentToken::deserialize(&data).expect_err("should fail on bad version");
        assert!(err.contains("unsupported version"));
    }

    #[test]
    fn test_expires_in_human() {
        let secret = test_secret();

        // Never expires
        let token = EnrollmentToken::create("t.ztlp", "1:1", &[], None, 0, 0, &secret);
        assert_eq!(token.expires_in_human(), "never");

        // Already expired
        let token = EnrollmentToken::create("t.ztlp", "1:1", &[], None, 0, 1, &secret);
        assert_eq!(token.expires_in_human(), "expired");

        // Far future (should show days)
        let far_future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() + 86400 * 30)
            .unwrap_or(0);
        let token = EnrollmentToken::create("t.ztlp", "1:1", &[], None, 0, far_future, &secret);
        assert!(token.expires_in_human().ends_with('d'));
    }

    #[test]
    fn test_from_query_param_uri() {
        let uri = "ztlp://enroll/?zone=techrockstars.ztlp&ns=52.39.59.34:23096&relay=54.188.93.13:23095&token=8935f613470affc4&expires=1773728471";
        let token = EnrollmentToken::from_base64url(uri).expect("should parse query-param URI");
        assert_eq!(token.zone, "techrockstars.ztlp");
        assert_eq!(token.ns_addr, "52.39.59.34:23096");
        assert_eq!(token.relay_addrs, vec!["54.188.93.13:23095"]);
        assert_eq!(token.expires_at, 1773728471);
        assert_eq!(token.max_uses, 1);
        assert_eq!(token.version, TOKEN_VERSION);
    }

    #[test]
    fn test_from_query_param_uri_multiple_relays() {
        let uri = "ztlp://enroll/?zone=test.ztlp&ns=10.0.0.1:23096&relay=10.0.0.2:23095&relay=10.0.0.3:23095&token=abcd1234&expires=9999999999";
        let token = EnrollmentToken::from_base64url(uri).expect("should parse multi-relay URI");
        assert_eq!(token.relay_addrs.len(), 2);
    }

    #[test]
    fn test_from_query_param_uri_with_gateway() {
        let uri = "ztlp://enroll/?zone=test.ztlp&ns=10.0.0.1:23096&relay=10.0.0.2:23095&gateway=10.0.0.4:23098&token=abcd&expires=9999999999";
        let token = EnrollmentToken::from_base64url(uri).expect("should parse with gateway");
        assert_eq!(token.gateway_addr, Some("10.0.0.4:23098".to_string()));
    }

    #[test]
    fn test_from_query_param_uri_missing_zone() {
        let uri = "ztlp://enroll/?ns=10.0.0.1:23096&token=abcd&expires=9999999999";
        assert!(EnrollmentToken::from_base64url(uri).is_err());
    }

    #[test]
    fn test_from_query_param_uri_missing_token() {
        let uri = "ztlp://enroll/?zone=test.ztlp&ns=10.0.0.1:23096&expires=9999999999";
        assert!(EnrollmentToken::from_base64url(uri).is_err());
    }

    #[test]
    fn test_binary_format_still_works() {
        // Ensure base64url binary format is not broken by query-param addition
        let secret = test_secret();
        let relays = vec!["10.0.0.2:23095".to_string()];
        let original = EnrollmentToken::create(
            "test.ztlp",
            "10.0.0.1:23096",
            &relays,
            None,
            1,
            9999999999,
            &secret,
        );
        let b64 = original.to_base64url();
        let parsed = EnrollmentToken::from_base64url(&b64).expect("binary round-trip");
        assert_eq!(parsed.zone, "test.ztlp");
        assert_eq!(parsed.ns_addr, "10.0.0.1:23096");
    }

    #[test]
    fn test_uri_format_still_works() {
        // ztlp://enroll/<base64> format
        let secret = test_secret();
        let relays = vec!["10.0.0.2:23095".to_string()];
        let original = EnrollmentToken::create(
            "test.ztlp",
            "10.0.0.1:23096",
            &relays,
            None,
            1,
            9999999999,
            &secret,
        );
        let uri = original.to_uri();
        assert!(uri.starts_with("ztlp://enroll/"));
        let parsed = EnrollmentToken::from_base64url(&uri).expect("URI round-trip");
        assert_eq!(parsed.zone, "test.ztlp");
    }

    // ── v0.30.10: signed query-param URIs (&nonce= &mac=) ──────────────
    //
    // Launch issues `ztlp://enroll/?…&nonce=<hex>&mac=<hex>` URIs when
    // ZTLP_ENROLLMENT_SECRET is configured. The CLI MUST parse these new
    // params into the EnrollmentToken struct so NS can verify the MAC via
    // its existing HMAC-BLAKE2s code path.
    //
    // Backward compat: when the params are ABSENT, behaviour falls back
    // to zero nonce + zero MAC (current legacy path).

    #[test]
    fn test_from_query_param_uri_parses_mac_and_nonce_when_present() {
        // URI with signed-form trailing params. The MAC value is irrelevant
        // for parsing — we just need the hex to round-trip through into
        // the EnrollmentToken.mac field.
        let uri = "ztlp://enroll/?zone=signed.example.ztlp\
                   &ns=192.0.2.10:23096\
                   &token=deadbeef\
                   &expires=1893456000\
                   &nonce=00112233445566778899aabbccddeeff\
                   &mac=f320ecd5c86cd29835b106e9b82d371b3c09650baf13bcb1e0f61b5b0af907a1";

        let parsed = EnrollmentToken::from_base64url(uri).expect("signed URI parses");

        assert_eq!(parsed.zone, "signed.example.ztlp");
        assert_eq!(parsed.ns_addr, "192.0.2.10:23096");

        // Nonce filled from &nonce=, NOT zeros
        let expected_nonce: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        assert_eq!(
            parsed.nonce, expected_nonce,
            "nonce must be parsed from &nonce= hex"
        );

        // MAC filled from &mac=, NOT zeros
        let mac_hex = parsed
            .mac
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        assert_eq!(
            mac_hex, "f320ecd5c86cd29835b106e9b82d371b3c09650baf13bcb1e0f61b5b0af907a1",
            "mac must be parsed from &mac= hex"
        );
    }

    #[test]
    fn test_from_query_param_uri_zeros_when_absent() {
        // Legacy URI: no &nonce= or &mac= → struct has zeroed fields,
        // backward-compatible with NS running REGISTRATION_AUTH=false.
        let uri = "ztlp://enroll/?zone=legacy.ztlp\
                   &ns=192.0.2.10:23096\
                   &token=abc\
                   &expires=1893456000";

        let parsed = EnrollmentToken::from_base64url(uri).expect("legacy URI parses");
        assert_eq!(parsed.nonce, [0u8; 16]);
        assert_eq!(parsed.mac, [0u8; 32]);
    }

    #[test]
    fn test_signed_query_param_token_validates_against_secret() {
        // End-to-end: build a token via Launch's canonical serialization,
        // compute the HMAC, embed it in a URI, parse it back, validate it.
        // This is the golden path that NS will execute on every signed
        // enrollment request.
        let secret: [u8; 32] = [0xAA; 32];

        // Build the canonical bytes matching Launch's Python serialization.
        // Exactly the same shape as the golden vector in
        // ns/test/ztlp_ns/enrollment_test.exs and
        // ztlp.net/tests/test_launch_app.py.
        let zone = "golden.example.ztlp";
        let ns_addr = "192.0.2.10:23096";
        let relay = "192.0.2.20:23095";
        let gateway = "192.0.2.30:23097";
        let nonce: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expires_at: u64 = 1_893_456_000;

        let mut buf = Vec::new();
        buf.push(0x01u8); // version
        buf.push(0x01u8); // flags (gateway present)
        buf.extend_from_slice(&(zone.len() as u16).to_be_bytes());
        buf.extend_from_slice(zone.as_bytes());
        buf.extend_from_slice(&(ns_addr.len() as u16).to_be_bytes());
        buf.extend_from_slice(ns_addr.as_bytes());
        buf.push(1u8); // relay_count
        buf.extend_from_slice(&(relay.len() as u16).to_be_bytes());
        buf.extend_from_slice(relay.as_bytes());
        buf.extend_from_slice(&(gateway.len() as u16).to_be_bytes());
        buf.extend_from_slice(gateway.as_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // max_uses
        buf.extend_from_slice(&expires_at.to_be_bytes());
        buf.extend_from_slice(&nonce);

        let mac = hmac_blake2s(&secret, &buf);
        let mac_hex = mac.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        // Build the URI Launch would produce.
        let uri = format!(
            "ztlp://enroll/?zone={}&ns={}&token=abc&expires={}\
             &relay={}&gateway={}&nonce={}&mac={}",
            zone,
            ns_addr,
            expires_at,
            relay,
            gateway,
            nonce
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            mac_hex
        );

        let parsed = EnrollmentToken::from_base64url(&uri).expect("signed URI parses");
        // Per the validate() implementation: serialize_without_mac() over
        // the parsed struct, HMAC-BLAKE2s with the secret, compare to the
        // mac field. This is the same path NS runs.
        let result = parsed.validate(&secret);
        assert!(
            matches!(result, TokenValidation::Valid),
            "signed token should validate against the secret, got {:?}",
            result
        );
    }

    #[test]
    fn test_signed_query_param_token_rejects_wrong_secret() {
        // Same URI as above, but validate against a different secret —
        // must reject with InvalidMac.
        let signing_secret: [u8; 32] = [0xAA; 32];
        let wrong_secret: [u8; 32] = [0xBB; 32];

        let zone = "wrong-secret.ztlp";
        let ns_addr = "192.0.2.10:23096";
        let nonce: [u8; 16] = [0xAA; 16];
        let expires_at: u64 = 1_893_456_000;

        let mut buf = Vec::new();
        buf.push(0x01u8);
        buf.push(0x00u8); // no gateway
        buf.extend_from_slice(&(zone.len() as u16).to_be_bytes());
        buf.extend_from_slice(zone.as_bytes());
        buf.extend_from_slice(&(ns_addr.len() as u16).to_be_bytes());
        buf.extend_from_slice(ns_addr.as_bytes());
        buf.push(0u8); // no relays
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&expires_at.to_be_bytes());
        buf.extend_from_slice(&nonce);

        let mac = hmac_blake2s(&signing_secret, &buf);
        let mac_hex = mac.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let uri = format!(
            "ztlp://enroll/?zone={}&ns={}&token=abc&expires={}\
             &nonce={}&mac={}",
            zone,
            ns_addr,
            expires_at,
            nonce
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            mac_hex
        );

        let parsed = EnrollmentToken::from_base64url(&uri).expect("URI parses");
        assert!(
            matches!(parsed.validate(&wrong_secret), TokenValidation::InvalidMac),
            "token signed with secret A must NOT validate under secret B"
        );
    }
}
