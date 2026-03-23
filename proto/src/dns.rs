//! Minimal DNS server for ZTLP VIP resolution.
//!
//! Listens on a loopback address (e.g., `127.0.55.53:53`) and resolves
//! `*.ztlp` domain queries to VIP addresses from the service registry.
//!
//! DNS wire format (minimal implementation):
//! - Supports A record queries only
//! - Returns NXDOMAIN for unknown services
//! - Ignores all other query types gracefully

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Maximum DNS UDP packet size per RFC 1035 §2.3.4.
/// UDP DNS messages are limited to 512 bytes. Responses larger than this
/// must use TCP (not supported in this minimal implementation).
const DNS_MAX_PACKET: usize = 512;

/// Maximum length of a single DNS label (63 bytes per RFC 1035 §2.3.4).
const DNS_MAX_LABEL_LEN: usize = 63;

/// Maximum total length of a DNS name (253 characters per RFC 1035 §2.3.4).
const DNS_MAX_NAME_LEN: usize = 253;

/// DNS header flags
const DNS_FLAG_QR: u16 = 0x8000; // Response
const DNS_FLAG_AA: u16 = 0x0400; // Authoritative
const DNS_FLAG_RCODE_NXDOMAIN: u16 = 0x0003; // Name error

/// DNS record types
const DNS_TYPE_A: u16 = 1;
/// DNS class IN
const DNS_CLASS_IN: u16 = 1;

/// TTL for DNS responses (seconds).
const DNS_TTL: u32 = 60;

/// Shared VIP registry for DNS lookups.
pub type VipRegistry = Arc<RwLock<HashMap<String, Ipv4Addr>>>;

/// The ZTLP DNS resolver.
pub struct ZtlpDns {
    /// VIP name → IP mappings.
    registry: VipRegistry,
    /// Stop flag.
    stop_flag: Arc<AtomicBool>,
    /// Listener task handle.
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl ZtlpDns {
    /// Create a new DNS resolver with the given registry.
    pub fn new(registry: VipRegistry) -> Self {
        Self {
            registry,
            stop_flag: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    /// Start the DNS server on the given address.
    pub async fn start(&mut self, listen_addr: SocketAddr) -> Result<(), String> {
        let socket = UdpSocket::bind(listen_addr)
            .await
            .map_err(|e| format!("DNS bind {} failed: {}", listen_addr, e))?;

        let registry = self.registry.clone();
        let stop = self.stop_flag.clone();

        self.stop_flag.store(false, Ordering::SeqCst);

        let handle = tokio::spawn(async move {
            dns_server_loop(socket, registry, stop).await;
        });

        self.handle = Some(handle);
        tracing::info!("ZTLP DNS server listening on {}", listen_addr);
        Ok(())
    }

    /// Stop the DNS server.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Main DNS server loop.
async fn dns_server_loop(socket: UdpSocket, registry: VipRegistry, stop: Arc<AtomicBool>) {
    let mut buf = vec![0u8; DNS_MAX_PACKET];

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        let recv_result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            socket.recv_from(&mut buf),
        )
        .await;

        let (len, src) = match recv_result {
            Ok(Ok((len, src))) => (len, src),
            Ok(Err(e)) => {
                tracing::warn!("DNS recv error: {}", e);
                continue;
            }
            Err(_) => continue, // Timeout, check stop flag
        };

        if len < 12 {
            continue; // Too short to be a DNS packet
        }

        // SECURITY: Reject queries larger than 512 bytes per RFC 1035 §4.2.1.
        // UDP DNS messages must not exceed 512 bytes.
        if len > DNS_MAX_PACKET {
            tracing::warn!(
                "DNS: rejecting oversized query ({} bytes) from {}",
                len,
                src
            );
            continue;
        }

        let query = &buf[..len];
        match handle_dns_query(query, &registry).await {
            Some(response) => {
                if let Err(e) = socket.send_to(&response, src).await {
                    tracing::warn!("DNS send error to {}: {}", src, e);
                }
            }
            None => {
                tracing::debug!("DNS: ignoring malformed query from {}", src);
            }
        }
    }
}

/// Parse a DNS query and produce a response.
///
/// Returns `None` if the query is malformed.
async fn handle_dns_query(query: &[u8], registry: &VipRegistry) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    // Parse header
    let id = u16::from_be_bytes([query[0], query[1]]);
    let _flags = u16::from_be_bytes([query[2], query[3]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);

    if qdcount == 0 {
        return None;
    }

    // Parse the first question
    let (qname, offset) = parse_dns_name(query, 12)?;
    if offset + 4 > query.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
    let qclass = u16::from_be_bytes([query[offset + 2], query[offset + 3]]);

    // Only handle A record queries for IN class
    if qtype != DNS_TYPE_A || qclass != DNS_CLASS_IN {
        return Some(build_dns_response(
            id,
            &query[12..offset + 4],
            DNS_FLAG_RCODE_NXDOMAIN,
            None,
        ));
    }

    // Extract service name from qname: expect `<service>.<zone>.ztlp`
    // or just `<service>.ztlp`
    let service_name = extract_service_name(&qname)?;

    // Look up in registry
    let reg = registry.read().await;
    let ip = reg.get(&service_name).copied();
    drop(reg);

    match ip {
        Some(addr) => Some(build_dns_response(
            id,
            &query[12..offset + 4],
            0, // No error
            Some(addr),
        )),
        None => Some(build_dns_response(
            id,
            &query[12..offset + 4],
            DNS_FLAG_RCODE_NXDOMAIN,
            None,
        )),
    }
}

/// Extract the service name from a ZTLP domain name.
///
/// Supports patterns:
/// - `<service>.ztlp` → service
/// - `<service>.<zone>.ztlp` → service
fn extract_service_name(qname: &str) -> Option<String> {
    let lower = qname.to_ascii_lowercase();

    // Must end with .ztlp or be exactly something.ztlp
    if !lower.ends_with(".ztlp") {
        return None;
    }

    // Strip the `.ztlp` suffix
    let without_tld = &lower[..lower.len() - 5]; // Remove ".ztlp"

    // Get the first label (the service name)
    let service = if let Some(dot_pos) = without_tld.find('.') {
        &without_tld[..dot_pos]
    } else {
        without_tld
    };

    if service.is_empty() {
        return None;
    }

    Some(service.to_string())
}

/// Parse a DNS name from wire format.
///
/// Returns (name_string, next_offset).
///
/// SECURITY: Validates label length (max 63 bytes) and total name length
/// (max 253 bytes) per RFC 1035 §2.3.4 to prevent buffer over-reads and
/// excessively long name allocations from malicious queries.
fn parse_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumps = 0;
    let mut return_pos: Option<usize> = None;
    let mut total_len: usize = 0;

    loop {
        if pos >= data.len() || jumps > 10 {
            return None; // Prevent infinite loops
        }

        let len = data[pos] as usize;

        if len == 0 {
            if return_pos.is_none() {
                return_pos = Some(pos + 1);
            }
            break;
        }

        // Check for DNS compression pointer
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            if return_pos.is_none() {
                return_pos = Some(pos + 2);
            }
            let pointer = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            pos = pointer;
            jumps += 1;
            continue;
        }

        // SECURITY: Reject labels longer than 63 bytes per RFC 1035 §2.3.4.
        // A label length > 63 that isn't a compression pointer (0xC0) is invalid.
        if len > DNS_MAX_LABEL_LEN {
            return None;
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&data[pos..pos + len]).to_string();

        // SECURITY: Track total name length and reject names > 253 bytes.
        // Total includes label lengths + dots between labels.
        total_len += len;
        if !labels.is_empty() {
            total_len += 1; // dot separator
        }
        if total_len > DNS_MAX_NAME_LEN {
            return None;
        }

        labels.push(label);
        pos += len;
    }

    let name = labels.join(".");
    Some((name, return_pos?))
}

/// Build a DNS response packet.
///
/// SECURITY: The response is truncated to DNS_MAX_PACKET (512 bytes) per
/// RFC 1035 §2.3.4. If the question section is too large for an answer to
/// fit, the answer is omitted and NXDOMAIN is returned instead.
fn build_dns_response(
    id: u16,
    question_section: &[u8],
    rcode: u16,
    answer_ip: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(DNS_MAX_PACKET);

    // Calculate if the answer will fit within 512 bytes.
    // Header (12) + question + answer_record (2+2+2+4+2+4 = 16 bytes).
    let header_size = 12;
    let answer_size: usize = if answer_ip.is_some() { 16 } else { 0 };
    let total_size = header_size + question_section.len() + answer_size;

    // SECURITY: If the response would exceed 512 bytes, omit the answer.
    // This prevents generating oversized UDP DNS responses.
    let (effective_answer, effective_rcode, effective_ancount) = if total_size > DNS_MAX_PACKET {
        (None, DNS_FLAG_RCODE_NXDOMAIN, 0u16)
    } else {
        (
            answer_ip,
            rcode,
            if answer_ip.is_some() { 1u16 } else { 0u16 },
        )
    };

    // Header
    response.extend_from_slice(&id.to_be_bytes()); // Transaction ID

    let flags = DNS_FLAG_QR | DNS_FLAG_AA | effective_rcode;
    response.extend_from_slice(&flags.to_be_bytes()); // Flags

    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1

    response.extend_from_slice(&effective_ancount.to_be_bytes()); // ANCOUNT

    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section (echo back) — truncate if it alone exceeds limit
    let max_question_len = DNS_MAX_PACKET.saturating_sub(header_size);
    let question_to_write = if question_section.len() > max_question_len {
        &question_section[..max_question_len]
    } else {
        question_section
    };
    response.extend_from_slice(question_to_write);

    // Answer section (if we have an IP and it fits)
    if let Some(ip) = effective_answer {
        // Name pointer to the question name (offset 12)
        response.extend_from_slice(&[0xC0, 0x0C]);

        // Type A
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        // Class IN
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        // TTL
        response.extend_from_slice(&DNS_TTL.to_be_bytes());
        // RDLENGTH (4 bytes for IPv4)
        response.extend_from_slice(&4u16.to_be_bytes());
        // RDATA (IPv4 address)
        response.extend_from_slice(&ip.octets());
    }

    // Final safety truncation — should never trigger with correct logic above
    response.truncate(DNS_MAX_PACKET);

    response
}

/// Encode a domain name to DNS wire format.
pub fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0); // Root label
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_service_name_simple() {
        assert_eq!(extract_service_name("beta.ztlp"), Some("beta".to_string()));
    }

    #[test]
    fn test_extract_service_name_with_zone() {
        assert_eq!(
            extract_service_name("beta.techrockstars.ztlp"),
            Some("beta".to_string())
        );
    }

    #[test]
    fn test_extract_service_name_case_insensitive() {
        assert_eq!(
            extract_service_name("Beta.TechRockstars.ZTLP"),
            Some("beta".to_string())
        );
    }

    #[test]
    fn test_extract_service_name_not_ztlp() {
        assert_eq!(extract_service_name("beta.example.com"), None);
    }

    #[test]
    fn test_extract_service_name_empty() {
        assert_eq!(extract_service_name(".ztlp"), None);
    }

    #[test]
    fn test_parse_dns_name() {
        let data = encode_dns_name("beta.techrockstars.ztlp");
        // Prepend 12 bytes of fake header
        let mut packet = vec![0u8; 12];
        packet.extend_from_slice(&data);
        let (name, offset) = parse_dns_name(&packet, 12).expect("should parse");
        assert_eq!(name, "beta.techrockstars.ztlp");
        assert_eq!(offset, 12 + data.len());
    }

    #[test]
    fn test_parse_dns_name_single_label() {
        let data = encode_dns_name("ztlp");
        let mut packet = vec![0u8; 12];
        packet.extend_from_slice(&data);
        let (name, _) = parse_dns_name(&packet, 12).expect("should parse");
        assert_eq!(name, "ztlp");
    }

    #[test]
    fn test_encode_dns_name() {
        let encoded = encode_dns_name("beta.ztlp");
        assert_eq!(
            encoded,
            vec![4, b'b', b'e', b't', b'a', 4, b'z', b't', b'l', b'p', 0]
        );
    }

    #[test]
    fn test_build_dns_response_with_answer() {
        let question = encode_dns_name("beta.ztlp");
        let mut question_section = question.clone();
        question_section.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        question_section.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let response = build_dns_response(
            0x1234,
            &question_section,
            0,
            Some(Ipv4Addr::new(127, 0, 55, 1)),
        );

        // Check header
        assert_eq!(response[0], 0x12); // ID high
        assert_eq!(response[1], 0x34); // ID low
                                       // Check QR + AA flags
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_ne!(flags & DNS_FLAG_QR, 0);
        assert_ne!(flags & DNS_FLAG_AA, 0);
        // ANCOUNT = 1
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
    }

    #[test]
    fn test_build_dns_response_nxdomain() {
        let question = encode_dns_name("unknown.ztlp");
        let mut question_section = question.clone();
        question_section.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        question_section.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let response = build_dns_response(0x5678, &question_section, DNS_FLAG_RCODE_NXDOMAIN, None);

        // Check RCODE = NXDOMAIN
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x000F, 3); // NXDOMAIN
                                       // ANCOUNT = 0
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[tokio::test]
    async fn test_handle_dns_query_found() {
        let registry: VipRegistry = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut reg = registry.write().await;
            reg.insert("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1));
        }

        // Build a minimal DNS query for beta.techrockstars.ztlp
        let query = build_test_query(0x1234, "beta.techrockstars.ztlp");
        let response = handle_dns_query(&query, &registry).await;

        assert!(response.is_some());
        let resp = response.expect("should have response");
        // ANCOUNT should be 1
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
    }

    #[tokio::test]
    async fn test_handle_dns_query_not_found() {
        let registry: VipRegistry = Arc::new(RwLock::new(HashMap::new()));

        let query = build_test_query(0x5678, "unknown.ztlp");
        let response = handle_dns_query(&query, &registry).await;

        assert!(response.is_some());
        let resp = response.expect("should have response");
        // Check NXDOMAIN
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x000F, 3);
    }

    #[tokio::test]
    async fn test_handle_dns_query_too_short() {
        let registry: VipRegistry = Arc::new(RwLock::new(HashMap::new()));
        let response = handle_dns_query(&[0u8; 5], &registry).await;
        assert!(response.is_none());
    }

    /// Build a minimal DNS query packet for testing.
    fn build_test_query(id: u16, name: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        // Header
        packet.extend_from_slice(&id.to_be_bytes()); // ID
        packet.extend_from_slice(&0u16.to_be_bytes()); // Flags (standard query)
        packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question
        packet.extend_from_slice(&encode_dns_name(name));
        packet.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        packet
    }

    #[test]
    fn test_vip_registry_shared() {
        let registry: VipRegistry = Arc::new(RwLock::new(HashMap::new()));
        let dns = ZtlpDns::new(registry.clone());
        // Should be the same Arc
        assert!(Arc::ptr_eq(&dns.registry, &registry));
    }

    #[test]
    fn test_dns_stop_without_start() {
        let registry: VipRegistry = Arc::new(RwLock::new(HashMap::new()));
        let mut dns = ZtlpDns::new(registry);
        dns.stop(); // Should not panic
    }

    // ── Security audit tests ────────────────────────────────────────────

    /// SECURITY: Verify that DNS labels longer than 63 bytes are rejected.
    /// RFC 1035 §2.3.4 limits each label to 63 octets.
    #[test]
    fn test_parse_dns_name_rejects_overlength_label() {
        let mut packet = vec![0u8; 12]; // fake header

        // Build a label with 64 bytes (exceeds 63-byte limit)
        let label_len: u8 = 64;
        packet.push(label_len);
        packet.extend_from_slice(&vec![b'a'; 64]);
        packet.push(0); // root

        let result = parse_dns_name(&packet, 12);
        assert!(result.is_none(), "should reject label > 63 bytes");
    }

    /// SECURITY: Verify that labels at exactly 63 bytes are accepted.
    #[test]
    fn test_parse_dns_name_accepts_max_label() {
        let mut packet = vec![0u8; 12]; // fake header

        // Build a label with exactly 63 bytes (the maximum)
        let label_len: u8 = 63;
        packet.push(label_len);
        packet.extend_from_slice(&vec![b'a'; 63]);
        // Add .ztlp suffix
        packet.push(4);
        packet.extend_from_slice(b"ztlp");
        packet.push(0); // root

        let result = parse_dns_name(&packet, 12);
        assert!(result.is_some(), "should accept label of exactly 63 bytes");
        let (name, _) = result.unwrap();
        assert_eq!(name.len(), 63 + 1 + 4); // 63 a's + dot + "ztlp"
    }

    /// SECURITY: Verify that DNS names longer than 253 bytes total are rejected.
    /// RFC 1035 §2.3.4 limits the total name to 253 octets.
    #[test]
    fn test_parse_dns_name_rejects_overlength_total() {
        let mut packet = vec![0u8; 12]; // fake header

        // Build many 10-byte labels to exceed 253 bytes total.
        // Each label contributes 10 chars + 1 dot = 11 chars to the name.
        // 24 labels × 11 = 264 characters > 253.
        for _ in 0..24 {
            packet.push(10); // label length
            packet.extend_from_slice(b"abcdefghij"); // 10-byte label
        }
        packet.push(0); // root

        let result = parse_dns_name(&packet, 12);
        assert!(result.is_none(), "should reject name > 253 bytes total");
    }

    /// SECURITY: Verify that DNS responses never exceed 512 bytes.
    /// RFC 1035 §4.2.1 limits UDP DNS messages to 512 bytes.
    #[test]
    fn test_build_dns_response_max_size() {
        // Build an oversized question section
        let mut question = Vec::new();
        // Create a very long name that takes up most of the 512-byte budget
        for _ in 0..40 {
            question.push(10);
            question.extend_from_slice(b"abcdefghij");
        }
        question.push(0); // root
        question.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        question.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let response = build_dns_response(0x1234, &question, 0, Some(Ipv4Addr::new(127, 0, 55, 1)));

        assert!(
            response.len() <= DNS_MAX_PACKET,
            "response ({} bytes) must not exceed {} bytes",
            response.len(),
            DNS_MAX_PACKET,
        );
    }

    /// SECURITY: Verify that normal responses are well within 512 bytes.
    #[test]
    fn test_build_dns_response_normal_size() {
        let question = encode_dns_name("beta.ztlp");
        let mut question_section = question;
        question_section.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        question_section.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let response = build_dns_response(
            0x1234,
            &question_section,
            0,
            Some(Ipv4Addr::new(127, 0, 55, 1)),
        );

        assert!(response.len() <= DNS_MAX_PACKET);
        // Normal response should be quite small
        assert!(response.len() < 100, "normal response should be compact");
    }

    /// SECURITY: Verify that compression pointer loops don't cause infinite loops.
    #[test]
    fn test_parse_dns_name_compression_loop() {
        let mut packet = vec![0u8; 12]; // fake header
                                        // Create a compression pointer that points to itself (offset 12)
        packet.push(0xC0); // compression marker
        packet.push(12); // points back to offset 12 — infinite loop!

        let result = parse_dns_name(&packet, 12);
        // Should return None after hitting the jump limit (10), not loop forever
        assert!(result.is_none(), "should reject compression pointer loops");
    }

    /// SECURITY: Verify that truncated compression pointers are rejected.
    #[test]
    fn test_parse_dns_name_truncated_compression() {
        let mut packet = vec![0u8; 12]; // fake header
                                        // Compression pointer with missing second byte
        packet.push(0xC0);
        // No second byte — packet ends here

        let result = parse_dns_name(&packet, 12);
        assert!(
            result.is_none(),
            "should reject truncated compression pointer"
        );
    }
}
