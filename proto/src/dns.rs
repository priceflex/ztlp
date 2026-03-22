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

/// Maximum DNS UDP packet size.
const DNS_MAX_PACKET: usize = 512;

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
async fn dns_server_loop(
    socket: UdpSocket,
    registry: VipRegistry,
    stop: Arc<AtomicBool>,
) {
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
fn parse_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumps = 0;
    let mut return_pos: Option<usize> = None;

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

        pos += 1;
        if pos + len > data.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
        labels.push(label);
        pos += len;
    }

    let name = labels.join(".");
    Some((name, return_pos?))
}

/// Build a DNS response packet.
fn build_dns_response(
    id: u16,
    question_section: &[u8],
    rcode: u16,
    answer_ip: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(DNS_MAX_PACKET);

    // Header
    response.extend_from_slice(&id.to_be_bytes()); // Transaction ID

    let flags = DNS_FLAG_QR | DNS_FLAG_AA | rcode;
    response.extend_from_slice(&flags.to_be_bytes()); // Flags

    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1

    let ancount: u16 = if answer_ip.is_some() { 1 } else { 0 };
    response.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT

    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section (echo back)
    response.extend_from_slice(question_section);

    // Answer section (if we have an IP)
    if let Some(ip) = answer_ip {
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
        assert_eq!(
            extract_service_name("beta.ztlp"),
            Some("beta".to_string())
        );
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
        assert_eq!(encoded, vec![4, b'b', b'e', b't', b'a', 4, b'z', b't', b'l', b'p', 0]);
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

        let response = build_dns_response(
            0x5678,
            &question_section,
            DNS_FLAG_RCODE_NXDOMAIN,
            None,
        );

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
}
