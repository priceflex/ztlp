//! Auto-update module for ZTLP clients.
//!
//! Polls GitHub releases (or custom endpoint) for new versions.
//! Verifies downloads with Ed25519 signatures before applying.
//!
//! Features:
//! - Semantic version comparison
//! - Ed25519 signature verification of release binaries
//! - Configurable update channel (stable/beta/nightly)
//! - Background check with configurable interval
//! - Dry-run mode for testing

use std::cmp::Ordering;
use std::fmt;

/// Semantic version for comparison
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre: Option<String>, // pre-release suffix e.g. "beta.1"
}

impl SemVer {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: None,
        }
    }

    pub fn with_pre(mut self, pre: &str) -> Self {
        self.pre = Some(pre.to_string());
        self
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let (version_str, pre) = if let Some(idx) = s.find('-') {
            (&s[..idx], Some(s[idx + 1..].to_string()))
        } else {
            (s, None)
        };

        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = parts[2].parse().ok()?;

        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    pub fn is_newer_than(&self, other: &Self) -> bool {
        matches!(self.cmp(other), Ordering::Greater)
    }

    pub fn is_pre_release(&self) -> bool {
        self.pre.is_some()
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }
        // Pre-release versions have lower precedence than release
        match (&self.pre, &other.pre) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less, // 1.0.0-beta < 1.0.0
            (None, Some(_)) => Ordering::Greater, // 1.0.0 > 1.0.0-beta
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(ref pre) = self.pre {
            write!(f, "-{pre}")?;
        }
        Ok(())
    }
}

/// Update channel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateChannel {
    Stable,
    Beta,
    Nightly,
}

impl UpdateChannel {
    pub fn parse_channel(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "stable" => Some(Self::Stable),
            "beta" => Some(Self::Beta),
            "nightly" => Some(Self::Nightly),
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
        }
    }

    /// Whether this channel accepts pre-release versions
    pub fn accepts_prerelease(&self) -> bool {
        matches!(self, Self::Beta | Self::Nightly)
    }
}

/// Release info from the update server
#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub version: SemVer,
    pub channel: UpdateChannel,
    pub download_url: String,
    pub signature: Option<Vec<u8>>, // Ed25519 signature of the binary
    pub checksum_sha256: Option<String>,
    pub release_notes: Option<String>,
    pub size_bytes: Option<u64>,
    pub published_at: Option<String>,
}

/// Update check result
#[derive(Debug)]
pub enum UpdateStatus {
    /// A newer version is available
    Available(ReleaseInfo),
    /// Already running the latest version
    UpToDate,
    /// Failed to check for updates
    CheckFailed(String),
}

/// Update configuration
#[derive(Debug, Clone)]
pub struct UpdateConfig {
    /// Current version of this binary
    pub current_version: SemVer,
    /// Which channel to follow
    pub channel: UpdateChannel,
    /// Base URL for release checks (default: GitHub releases API)
    pub release_url: String,
    /// Ed25519 public key for signature verification (hex-encoded)
    pub signing_key: Option<String>,
    /// Check interval in seconds (0 = manual only)
    pub check_interval_secs: u64,
    /// Whether to auto-download (not auto-install)
    pub auto_download: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            current_version: SemVer::parse(env!("CARGO_PKG_VERSION"))
                .unwrap_or_else(|| SemVer::new(0, 0, 0)),
            channel: UpdateChannel::Stable,
            release_url: "https://api.github.com/repos/priceflex/ztlp/releases/latest".into(),
            signing_key: None,
            check_interval_secs: 86400, // daily
            auto_download: false,
        }
    }
}

impl UpdateConfig {
    pub fn with_channel(mut self, channel: UpdateChannel) -> Self {
        self.channel = channel;
        self
    }

    pub fn with_signing_key(mut self, key: &str) -> Self {
        self.signing_key = Some(key.to_string());
        self
    }

    pub fn with_interval(mut self, secs: u64) -> Self {
        self.check_interval_secs = secs;
        self
    }
}

/// Parse a GitHub releases API JSON response (minimal parser, no serde dep)
///
/// Looks for: `"tag_name": "vX.Y.Z"`, `"body": "..."`, `"assets": [{...}]`
pub fn parse_github_release(json: &str) -> Option<ReleaseInfo> {
    let tag = extract_json_string(json, "tag_name")?;
    let version = SemVer::parse(&tag)?;
    let body = extract_json_string(json, "body");

    // Find download URL for current platform
    let platform_suffix = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    };

    let arch_suffix = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };

    let asset_pattern = format!("ztlp-{platform_suffix}-{arch_suffix}");
    let download_url = extract_asset_url(json, &asset_pattern).unwrap_or_else(|| {
        format!("https://github.com/priceflex/ztlp/releases/download/{tag}/ztlp")
    });

    let channel = if version.is_pre_release() {
        UpdateChannel::Beta
    } else {
        UpdateChannel::Stable
    };

    Some(ReleaseInfo {
        version,
        channel,
        download_url,
        signature: None,
        checksum_sha256: None,
        release_notes: body,
        size_bytes: None,
        published_at: extract_json_string(json, "published_at"),
    })
}

/// Check if an update is available
pub fn check_update(config: &UpdateConfig, release: &ReleaseInfo) -> UpdateStatus {
    // Filter by channel
    if config.channel == UpdateChannel::Stable && release.version.is_pre_release() {
        return UpdateStatus::UpToDate;
    }

    if release.version.is_newer_than(&config.current_version) {
        UpdateStatus::Available(release.clone())
    } else {
        UpdateStatus::UpToDate
    }
}

/// Verify an Ed25519 signature of a binary.
///
/// Returns `true` if the signature is valid, `false` otherwise.
/// Validates format constraints (64-byte signature, 32-byte public key)
/// then delegates to `ed25519-dalek` for cryptographic verification.
pub fn verify_signature(data: &[u8], signature: &[u8], public_key_hex: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if signature.len() != 64 {
        return false;
    }
    if public_key_hex.len() != 64 {
        return false;
    }

    // Parse hex public key
    let pk_bytes: [u8; 32] = match hex_decode(public_key_hex) {
        Some(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_bytes);

    verifying_key.verify(data, &sig).is_ok()
}

/// Compute SHA-256 checksum of data (placeholder — use ring/sha2 in production).
///
/// Uses FNV-1a internally; sufficient for format testing and integrity checks
/// but NOT cryptographically secure.
pub fn sha256_hex(data: &[u8]) -> String {
    // Simple checksum for format testing
    // In production, use a real SHA-256 implementation
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV prime
    }
    format!(
        "{:016x}{:016x}{:016x}{:016x}",
        hash,
        hash ^ 0xff,
        hash.rotate_left(32),
        hash.rotate_right(16)
    )
}

/// Verify checksum
pub fn verify_checksum(data: &[u8], expected_hex: &str) -> bool {
    sha256_hex(data) == expected_hex
}

// Minimal JSON helpers (no serde dependency)

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let idx = json.find(&pattern)?;
    let after_key = &json[idx + pattern.len()..];
    // Skip whitespace and colon
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_ws = after_colon.trim_start();

    if let Some(content) = after_ws.strip_prefix('"') {
        let end = content.find('"')?;
        Some(content[..end].to_string())
    } else {
        None
    }
}

fn extract_asset_url(json: &str, pattern: &str) -> Option<String> {
    // Look for browser_download_url containing the pattern
    let mut search_from = 0;
    while let Some(idx) = json[search_from..].find("browser_download_url") {
        let abs_idx = search_from + idx;
        if let Some(url) = extract_json_string(&json[abs_idx..], "browser_download_url") {
            if url.contains(pattern) {
                return Some(url);
            }
        }
        search_from = abs_idx + 20;
    }
    None
}

fn hex_decode(hex_str: &str) -> Option<Vec<u8>> {
    if !hex_str.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    for i in (0..hex_str.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex_str[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_roundtrip() {
        let decoded = hex_decode("deadbeef").unwrap();
        assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_none());
    }
}
