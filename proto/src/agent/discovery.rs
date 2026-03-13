//! DNS TXT-based ZTLP zone discovery.
//!
//! Companies publish `_ztlp` TXT records in public DNS to enable automatic
//! discovery of their ZTLP zones:
//!
//! ```dns
//! _ztlp.internal.techrockstars.com  IN TXT  "v=ztlp1 zone=techrockstars.ztlp ns=ns.techrockstars.com:23096"
//! ```
//!
//! When the agent encounters an unknown domain (not in `dns.zones` or
//! `dns.domain_map`), it queries public DNS for `_ztlp.<domain>` TXT records.
//! If found, the agent learns the ZTLP zone and NS server, caches the mapping,
//! and resolves the name through ZTLP-NS.
//!
//! ## TXT record format
//!
//! ```text
//! v=ztlp1 zone=<ztlp-zone> ns=<ns-host>:<ns-port> [strip=<domain-suffix>]
//! ```
//!
//! - `v=ztlp1` — version tag (required)
//! - `zone=<zone>` — ZTLP zone name (required)
//! - `ns=<host>:<port>` — NS server address (required)
//! - `strip=<suffix>` — domain suffix to strip before prepending to zone (optional)
//!
//! If `strip` is omitted, the entire queried domain suffix is stripped
//! (the `_ztlp.` prefix domain).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::debug;

use super::dns::{encode_dns_name, forward_to_upstream};

// ─── TXT record parsing ────────────────────────────────────────────────────

/// Parsed ZTLP TXT discovery record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZtlpTxtRecord {
    /// Version (must be "ztlp1").
    pub version: String,
    /// ZTLP zone name.
    pub zone: String,
    /// NS server address.
    pub ns_server: String,
    /// Domain suffix to strip (if specified).
    pub strip: Option<String>,
}

/// Parse a `_ztlp` TXT record value.
///
/// Format: `v=ztlp1 zone=<zone> ns=<host>:<port> [strip=<suffix>]`
///
/// Returns `None` if the record is not a valid ZTLP TXT record.
pub fn parse_ztlp_txt(txt: &str) -> Option<ZtlpTxtRecord> {
    let mut version = None;
    let mut zone = None;
    let mut ns_server = None;
    let mut strip = None;

    for part in txt.split_whitespace() {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "v" => version = Some(value.to_string()),
                "zone" => zone = Some(value.to_string()),
                "ns" => ns_server = Some(value.to_string()),
                "strip" => strip = Some(value.to_string()),
                _ => {} // Ignore unknown keys for forward compatibility
            }
        }
    }

    let version = version?;
    if version != "ztlp1" {
        debug!("unknown ZTLP TXT version: {}", version);
        return None;
    }

    Some(ZtlpTxtRecord {
        version,
        zone: zone?,
        ns_server: ns_server?,
        strip,
    })
}

// ─── Discovery cache ────────────────────────────────────────────────────────

/// Cached discovery result.
#[derive(Debug, Clone)]
pub struct CachedDiscovery {
    /// The parsed TXT record.
    pub record: ZtlpTxtRecord,
    /// When this was discovered.
    pub discovered_at: Instant,
    /// TTL for the cache entry.
    pub ttl: Duration,
}

impl CachedDiscovery {
    /// Check if this cache entry has expired.
    pub fn is_expired(&self) -> bool {
        Instant::now().duration_since(self.discovered_at) >= self.ttl
    }
}

/// Discovery cache — maps domain suffixes to ZTLP TXT records.
pub struct DiscoveryCache {
    /// Cached discoveries keyed by the domain suffix they were queried for.
    entries: HashMap<String, CachedDiscovery>,
    /// Negative cache — domains we've already queried with no result.
    negative_cache: HashMap<String, Instant>,
    /// TTL for positive cache entries (default: 1 hour).
    positive_ttl: Duration,
    /// TTL for negative cache entries (default: 15 minutes).
    negative_ttl: Duration,
    /// Maximum cache size.
    max_entries: usize,
}

impl DiscoveryCache {
    /// Create a new discovery cache with default settings.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            negative_cache: HashMap::new(),
            positive_ttl: Duration::from_secs(3600),     // 1 hour
            negative_ttl: Duration::from_secs(900),      // 15 min
            max_entries: 256,
        }
    }

    /// Create with custom TTLs.
    pub fn with_ttls(positive_ttl: Duration, negative_ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            negative_cache: HashMap::new(),
            positive_ttl,
            negative_ttl,
            max_entries,
        }
    }

    /// Look up a cached discovery for a domain.
    pub fn get(&self, domain: &str) -> Option<&CachedDiscovery> {
        let entry = self.entries.get(domain)?;
        if entry.is_expired() {
            None
        } else {
            Some(entry)
        }
    }

    /// Check if a domain is in the negative cache (already queried, no result).
    pub fn is_negative_cached(&self, domain: &str) -> bool {
        if let Some(cached_at) = self.negative_cache.get(domain) {
            Instant::now().duration_since(*cached_at) < self.negative_ttl
        } else {
            false
        }
    }

    /// Insert a positive discovery result.
    pub fn insert(&mut self, domain: &str, record: ZtlpTxtRecord) {
        // Evict expired entries if at capacity
        if self.entries.len() >= self.max_entries {
            self.gc();
        }

        self.entries.insert(
            domain.to_string(),
            CachedDiscovery {
                record,
                discovered_at: Instant::now(),
                ttl: self.positive_ttl,
            },
        );
        // Remove from negative cache if present
        self.negative_cache.remove(domain);

        debug!("discovery cached: {}", domain);
    }

    /// Insert a negative cache entry (domain has no _ztlp TXT record).
    pub fn insert_negative(&mut self, domain: &str) {
        self.negative_cache
            .insert(domain.to_string(), Instant::now());
    }

    /// Remove expired entries from both caches.
    pub fn gc(&mut self) -> usize {
        let before = self.entries.len() + self.negative_cache.len();

        self.entries.retain(|_, v| !v.is_expired());

        let neg_ttl = self.negative_ttl;
        self.negative_cache.retain(|_, cached_at| {
            Instant::now().duration_since(*cached_at) < neg_ttl
        });

        let after = self.entries.len() + self.negative_cache.len();
        before - after
    }

    /// Number of positive cache entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Number of negative cache entries.
    pub fn negative_len(&self) -> usize {
        self.negative_cache.len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── Domain suffix extraction ───────────────────────────────────────────────

/// Extract the domain suffix to query for `_ztlp` TXT records.
///
/// For `server1.internal.techrockstars.com`, we try:
/// 1. `_ztlp.internal.techrockstars.com`
/// 2. `_ztlp.techrockstars.com`
///
/// Returns a list of candidate `_ztlp` query names, most specific first.
pub fn discovery_candidates(hostname: &str) -> Vec<String> {
    let hostname = hostname.to_lowercase();
    let parts: Vec<&str> = hostname.split('.').collect();

    let mut candidates = Vec::new();

    // Start from second label (skip the hostname itself)
    // e.g., for "server1.internal.techrockstars.com":
    //   → _ztlp.internal.techrockstars.com
    //   → _ztlp.techrockstars.com
    // Stop before the TLD (need at least 2 labels after _ztlp)
    for i in 1..parts.len().saturating_sub(1) {
        let suffix: String = parts[i..].join(".");
        if suffix.contains('.') {
            // Need at least domain.tld
            candidates.push(format!("_ztlp.{}", suffix));
        }
    }

    candidates
}

/// Given a hostname and a discovered TXT record, compute the ZTLP name.
///
/// For hostname "server1.internal.techrockstars.com" with:
///   zone="techrockstars.ztlp", strip="internal.techrockstars.com"
/// Result: "server1.techrockstars.ztlp"
///
/// Without strip (strip the queried suffix):
///   Queried "_ztlp.internal.techrockstars.com"
///   Strip "internal.techrockstars.com"
///   Result: "server1.techrockstars.ztlp"
pub fn compute_ztlp_name(
    hostname: &str,
    queried_domain: &str,
    record: &ZtlpTxtRecord,
) -> Option<String> {
    let hostname = hostname.to_lowercase();

    // Determine what to strip
    let strip_suffix = record
        .strip
        .as_deref()
        .or_else(|| queried_domain.strip_prefix("_ztlp."))
        .unwrap_or("");

    if strip_suffix.is_empty() {
        return None;
    }

    let strip_lower = strip_suffix.to_lowercase();

    // Strip the suffix from the hostname
    let remaining = if hostname.ends_with(&strip_lower) {
        let prefix = &hostname[..hostname.len() - strip_lower.len()];
        prefix.trim_end_matches('.')
    } else {
        return None;
    };

    if remaining.is_empty() {
        // Hostname IS the domain (e.g., "internal.techrockstars.com")
        // Map to the zone root
        Some(record.zone.clone())
    } else {
        Some(format!("{}.{}", remaining, record.zone))
    }
}

// ─── DNS TXT query ──────────────────────────────────────────────────────────

/// DNS query type: TXT record.
const QTYPE_TXT: u16 = 16;
/// DNS query class: IN.
const QCLASS_IN: u16 = 1;

/// Query public DNS for a TXT record and parse any ZTLP TXT entries.
///
/// This sends a UDP DNS query to the upstream resolver and parses
/// the TXT records from the response.
pub async fn query_ztlp_txt(
    name: &str,
    upstream_dns: &str,
) -> Result<Option<ZtlpTxtRecord>, Box<dyn std::error::Error + Send + Sync>> {
    // Build a TXT query
    let id: u16 = (Instant::now().elapsed().as_nanos() & 0xFFFF) as u16;
    let query = build_txt_query(name, id);

    let response = forward_to_upstream(&query, upstream_dns).await?;

    // Parse TXT records from response
    let txt_values = parse_txt_response(&response)?;

    for txt in &txt_values {
        if let Some(record) = parse_ztlp_txt(txt) {
            return Ok(Some(record));
        }
    }

    Ok(None)
}

/// Build a DNS TXT query.
fn build_txt_query(name: &str, id: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
    query.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT
    query.extend_from_slice(&0u16.to_be_bytes());      // ANCOUNT
    query.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT
    query.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT
    query.extend_from_slice(&encode_dns_name(name));
    query.extend_from_slice(&QTYPE_TXT.to_be_bytes());
    query.extend_from_slice(&QCLASS_IN.to_be_bytes());
    query
}

/// Parse TXT record values from a DNS response.
///
/// Returns a list of TXT string values from the answer section.
fn parse_txt_response(
    response: &[u8],
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    if response.len() < 12 {
        return Err("response too short".into());
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return Ok(Vec::new());
    }

    // Skip header (12 bytes) and question section
    let mut pos = 12;
    // Skip question
    pos = skip_dns_name(response, pos)?;
    pos += 4; // QTYPE + QCLASS

    let mut txt_values = Vec::new();

    // Parse answer records
    for _ in 0..ancount {
        if pos >= response.len() {
            break;
        }

        // Skip name (might be a pointer)
        pos = skip_dns_name(response, pos)?;

        if pos + 10 > response.len() {
            break;
        }

        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let _rclass = u16::from_be_bytes([response[pos + 2], response[pos + 3]]);
        let _ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;

        if rtype == QTYPE_TXT && rdlength > 0 && pos + rdlength <= response.len() {
            // TXT records contain one or more <length><string> segments
            let mut txt_pos = pos;
            let txt_end = pos + rdlength;
            let mut full_text = String::new();

            while txt_pos < txt_end {
                let seg_len = response[txt_pos] as usize;
                txt_pos += 1;
                if txt_pos + seg_len > txt_end {
                    break;
                }
                if let Ok(s) = std::str::from_utf8(&response[txt_pos..txt_pos + seg_len]) {
                    full_text.push_str(s);
                }
                txt_pos += seg_len;
            }

            if !full_text.is_empty() {
                txt_values.push(full_text);
            }
        }

        pos += rdlength;
    }

    Ok(txt_values)
}

/// Skip a DNS name at the given position (handles label encoding + compression pointers).
fn skip_dns_name(data: &[u8], mut pos: usize) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    loop {
        if pos >= data.len() {
            return Err("name extends past data".into());
        }
        let len = data[pos] as usize;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes
            return Ok(pos + 2);
        }
        pos += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ztlp_txt_valid() {
        let txt = "v=ztlp1 zone=techrockstars.ztlp ns=ns.techrockstars.com:23096";
        let record = parse_ztlp_txt(txt).unwrap();
        assert_eq!(record.version, "ztlp1");
        assert_eq!(record.zone, "techrockstars.ztlp");
        assert_eq!(record.ns_server, "ns.techrockstars.com:23096");
        assert!(record.strip.is_none());
    }

    #[test]
    fn test_parse_ztlp_txt_with_strip() {
        let txt = "v=ztlp1 zone=acme.techrockstars.ztlp ns=10.0.0.1:23096 strip=internal.acmecorp.com";
        let record = parse_ztlp_txt(txt).unwrap();
        assert_eq!(record.zone, "acme.techrockstars.ztlp");
        assert_eq!(record.strip, Some("internal.acmecorp.com".to_string()));
    }

    #[test]
    fn test_parse_ztlp_txt_wrong_version() {
        let txt = "v=ztlp2 zone=test.ztlp ns=1.2.3.4:23096";
        assert!(parse_ztlp_txt(txt).is_none());
    }

    #[test]
    fn test_parse_ztlp_txt_missing_fields() {
        assert!(parse_ztlp_txt("v=ztlp1 zone=test.ztlp").is_none()); // missing ns
        assert!(parse_ztlp_txt("v=ztlp1 ns=1.2.3.4:23096").is_none()); // missing zone
        assert!(parse_ztlp_txt("zone=test.ztlp ns=1.2.3.4:23096").is_none()); // missing version
    }

    #[test]
    fn test_parse_ztlp_txt_not_ztlp() {
        assert!(parse_ztlp_txt("google-site-verification=abc123").is_none());
        assert!(parse_ztlp_txt("").is_none());
    }

    #[test]
    fn test_parse_ztlp_txt_unknown_keys_ignored() {
        let txt = "v=ztlp1 zone=test.ztlp ns=1.2.3.4:23096 future_key=value";
        let record = parse_ztlp_txt(txt).unwrap();
        assert_eq!(record.zone, "test.ztlp");
    }

    #[test]
    fn test_discovery_candidates() {
        let candidates = discovery_candidates("server1.internal.techrockstars.com");
        assert_eq!(
            candidates,
            vec![
                "_ztlp.internal.techrockstars.com",
                "_ztlp.techrockstars.com",
            ]
        );
    }

    #[test]
    fn test_discovery_candidates_short_name() {
        let candidates = discovery_candidates("mail.example.com");
        assert_eq!(candidates, vec!["_ztlp.example.com"]);
    }

    #[test]
    fn test_discovery_candidates_too_short() {
        let candidates = discovery_candidates("example.com");
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_discovery_candidates_single_label() {
        let candidates = discovery_candidates("localhost");
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_compute_ztlp_name_with_strip() {
        let record = ZtlpTxtRecord {
            version: "ztlp1".to_string(),
            zone: "techrockstars.ztlp".to_string(),
            ns_server: "ns.techrockstars.com:23096".to_string(),
            strip: Some("internal.techrockstars.com".to_string()),
        };

        let name = compute_ztlp_name(
            "server1.internal.techrockstars.com",
            "_ztlp.internal.techrockstars.com",
            &record,
        );
        assert_eq!(name, Some("server1.techrockstars.ztlp".to_string()));
    }

    #[test]
    fn test_compute_ztlp_name_auto_strip() {
        let record = ZtlpTxtRecord {
            version: "ztlp1".to_string(),
            zone: "acme.techrockstars.ztlp".to_string(),
            ns_server: "10.0.0.1:23096".to_string(),
            strip: None,
        };

        let name = compute_ztlp_name(
            "fileserver.internal.acmecorp.com",
            "_ztlp.internal.acmecorp.com",
            &record,
        );
        assert_eq!(name, Some("fileserver.acme.techrockstars.ztlp".to_string()));
    }

    #[test]
    fn test_compute_ztlp_name_no_match() {
        let record = ZtlpTxtRecord {
            version: "ztlp1".to_string(),
            zone: "test.ztlp".to_string(),
            ns_server: "1.2.3.4:23096".to_string(),
            strip: Some("wrong.domain.com".to_string()),
        };

        let name = compute_ztlp_name(
            "server1.other.domain.com",
            "_ztlp.other.domain.com",
            &record,
        );
        assert!(name.is_none());
    }

    #[test]
    fn test_compute_ztlp_name_bare_domain() {
        let record = ZtlpTxtRecord {
            version: "ztlp1".to_string(),
            zone: "test.ztlp".to_string(),
            ns_server: "1.2.3.4:23096".to_string(),
            strip: Some("example.com".to_string()),
        };

        let name = compute_ztlp_name("example.com", "_ztlp.example.com", &record);
        assert_eq!(name, Some("test.ztlp".to_string()));
    }

    // ── Cache tests ─────────────────────────────────────────────────────

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = DiscoveryCache::new();
        let record = ZtlpTxtRecord {
            version: "ztlp1".to_string(),
            zone: "test.ztlp".to_string(),
            ns_server: "1.2.3.4:23096".to_string(),
            strip: None,
        };

        cache.insert("example.com", record.clone());
        assert_eq!(cache.len(), 1);

        let cached = cache.get("example.com").unwrap();
        assert_eq!(cached.record.zone, "test.ztlp");
    }

    #[test]
    fn test_cache_negative() {
        let mut cache = DiscoveryCache::new();
        assert!(!cache.is_negative_cached("nope.com"));

        cache.insert_negative("nope.com");
        assert!(cache.is_negative_cached("nope.com"));
    }

    #[test]
    fn test_cache_gc() {
        let mut cache = DiscoveryCache::with_ttls(
            Duration::from_millis(1),  // Very short positive TTL
            Duration::from_millis(1),  // Very short negative TTL
            256,
        );

        let record = ZtlpTxtRecord {
            version: "ztlp1".to_string(),
            zone: "test.ztlp".to_string(),
            ns_server: "1.2.3.4:23096".to_string(),
            strip: None,
        };

        cache.insert("test.com", record);
        cache.insert_negative("nope.com");

        std::thread::sleep(Duration::from_millis(5));
        let freed = cache.gc();
        assert!(freed >= 1);
    }

    #[test]
    fn test_cache_miss() {
        let cache = DiscoveryCache::new();
        assert!(cache.get("nonexistent.com").is_none());
    }
}
