//! Lightweight DNS resolver for the ZTLP agent.
//!
//! Listens on UDP (default `127.0.0.53:5353`) and handles:
//! - `*.ztlp` queries → ZTLP-NS resolution → virtual IP from pool
//! - Custom domain queries (via domain_map) → ZTLP-NS → virtual IP
//! - Everything else → forward to upstream DNS
//!
//! Implements enough of RFC 1035 to satisfy standard DNS clients (dig, nslookup,
//! SSH, curl, etc.) — specifically A record queries and responses.
//!
//! ## Wire format (RFC 1035 minimal subset)
//!
//! ```text
//! DNS Header (12 bytes):
//!   ID (2) | Flags (2) | QDCOUNT (2) | ANCOUNT (2) | NSCOUNT (2) | ARCOUNT (2)
//!
//! Question:
//!   QNAME (variable, label-encoded) | QTYPE (2) | QCLASS (2)
//!
//! Answer (A record):
//!   NAME (pointer 0xC00C) | TYPE=1 (2) | CLASS=1 (2) | TTL (4) | RDLENGTH=4 (2) | RDATA (4)
//! ```

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::domain_map::DomainMapper;
use super::proxy;
use super::vip_pool::VipPool;

// ─── DNS constants ──────────────────────────────────────────────────────────

/// DNS header size.
const DNS_HEADER_SIZE: usize = 12;

/// DNS query type: A record (IPv4 address).
const QTYPE_A: u16 = 1;
/// DNS query type: AAAA record (IPv6 address).
const QTYPE_AAAA: u16 = 28;
/// DNS query class: IN (Internet).
const QCLASS_IN: u16 = 1;

/// DNS response flags:
/// QR=1 (response), Opcode=0 (standard query), AA=1, TC=0, RD=1, RA=1, RCODE=0.
const FLAGS_RESPONSE_OK: u16 = 0x8580;
/// QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=3 (NXDOMAIN).
const FLAGS_RESPONSE_NXDOMAIN: u16 = 0x8583;
/// QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=2 (SERVFAIL).
const FLAGS_RESPONSE_SERVFAIL: u16 = 0x8582;

/// Default TTL for ZTLP DNS responses (5 minutes).
const DEFAULT_TTL: u32 = 300;

/// Maximum DNS message size for UDP.
const MAX_DNS_MSG: usize = 512;

// ─── Shared state ───────────────────────────────────────────────────────────

/// Shared agent state accessible by the DNS resolver.
pub struct DnsResolverState {
    /// Virtual IP pool.
    pub vip_pool: VipPool,
    /// Domain mapper.
    pub domain_mapper: DomainMapper,
    /// NS server address.
    pub ns_server: String,
    /// Upstream DNS server for non-ZTLP queries.
    pub upstream_dns: String,
}

// ─── DNS resolver server ────────────────────────────────────────────────────

/// Parse a "host:port" listen address into (host, port), defaulting the port
/// to 5353 if the string has no `:port` suffix (defensive — `config.rs`
/// always supplies one, but this keeps `bind_dns_socket_with_fallback`
/// robust to a bare-host caller too).
fn split_host_port(listen_addr: &str) -> (String, u16) {
    match listen_addr.rsplit_once(':') {
        Some((host, port_str)) => match port_str.parse::<u16>() {
            Ok(port) => (host.to_string(), port),
            Err(_) => (listen_addr.to_string(), 5353),
        },
        None => (listen_addr.to_string(), 5353),
    }
}

/// Ensure the dedicated ZTLP loopback alias `127.0.0.53` exists on the
/// Windows loopback adapter (a no-op when it's already present — which is
/// the default on stock Windows 10/11). The NRPT fix needs the resolver on
/// `127.0.0.53:53`; a bare `127.0.0.1/8` loopback only has `127.0.0.1`
/// unless an alias is added. Requires elevation (matches the NRPT rule
/// write, which also requires Administrator).
///
/// Failure is non-fatal: the bind step that follows is the real gate, and
/// the NRPT step then fails loudly with a clear error if the alias is
/// still missing.
#[cfg(target_os = "windows")]
pub fn ensure_loopback_alias_127_0_0_53() {
    use std::process::Command;
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"Get-NetIPConfiguration -Loopback | Where-Object { $_.IPv4Address -notcontains 127.0.0.53 } | ForEach-Object { New-NetIPAddress -InterfaceIndex $_.InterfaceIndex -IPAddress 127.0.0.53 -PrefixLength 32 -PrefixOrigin Dhcp -SuffixOrigin Dhcp -AddressFamily IPv4 }"#,
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            debug!("ensured loopback alias 127.0.0.53 present");
        }
        Ok(o) => {
            warn!(
                "could not ensure loopback alias 127.0.0.53 (exit {}): {}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stderr)
            );
        }
        Err(e) => {
            warn!("could not invoke PowerShell for loopback alias check: {e}");
        }
    }
}

/// Real bug found live on Windows (2026-08-30): the configured DNS listen
/// port (`5353`, standard mDNS) is frequently ALREADY occupied system-wide —
/// Windows' own mDNS responder service (svchost) and even Chrome itself both
/// bind it — so `UdpSocket::bind` on the configured address fails with
/// `WSAEACCES`/`os error 10013` (confirmed via a raw .NET UdpClient bind
/// probe on a real Windows box: `Get-NetUDPEndpoint -LocalPort 5353` showed
/// BOTH svchost and chrome already owning it). On Linux/macOS this port is
/// typically free, so the bug was invisible until tested on real Windows
/// hardware. The old code had no fallback at all — a bind failure killed the
/// whole automatic DNS-capture flow with a Linux-oriented error message
/// ("port 53 requires root") that didn't even describe the real problem.
///
/// Fix: try the configured port first (unchanged behavior when it's free —
/// the common case on Linux/macOS), then fall back to a small set of
/// alternate high ports before giving up. Returns the bound socket AND the
/// actual `SocketAddr` it ended up on, so callers (Windows NRPT/DNS-routing
/// setup) can be told the REAL port instead of assuming the configured one.
pub async fn bind_dns_socket_with_fallback(
    listen_addr: &str,
) -> Result<(UdpSocket, SocketAddr), std::io::Error> {
    let (host, primary_port) = split_host_port(listen_addr);

    // Fallback ports tried in order after the configured one. 15353/25353
    // are unassigned by IANA and unlikely to collide with anything else a
    // desktop OS or browser claims by default (unlike 5353/mDNS).
    //
    // Windows gets EXTRA candidates up front: NRPT (the Windows NRPT rule
    // installer) can only route a namespace to an IP with an implicit
    // port 53, so on Windows the resolver's end goal is port 53 on the
    // dedicated loopback alias 127.0.0.53 (see
    // `dns_setup_windows::plan_windows_nrpt_listen`). If the configured
    // high port is taken (common: svchost mDNS + Chrome both hold 5353),
    // falling back to port 53 on the alias FIRST means NRPT can point at
    // `127.0.0.53` and the rule actually works. A real bug found live
    // (2026-08-30, DESKTOP-CBSQDNE): NRPT given `127.0.0.53:15353`
    // silently stored an EMPTY NameServers list and Chrome got
    // DNS_PROBE_FINISHED_NXDOMAIN — the high-port fallback "worked" but
    // the rule pointed at nothing NRPT can express.
    #[cfg(target_os = "windows")]
    let mut candidates: Vec<u16> = {
        // Ensure the alias exists before attempting the port-53 bind.
        ensure_loopback_alias_127_0_0_53();
        let mut c = Vec::new();
        if primary_port == 53 {
            c.push(53);
        } else if primary_port != 53 {
            // Port 53 on the alias first (the NRPT-compatible address),
            // then the configured high port as a last resort.
            c.push(53);
            c.push(primary_port);
        }
        for fallback in [15353u16, 25353u16] {
            if !c.contains(&fallback) {
                c.push(fallback);
            }
        }
        c
    };
    #[cfg(not(target_os = "windows"))]
    let mut candidates: Vec<u16> = {
        let mut c = vec![primary_port];
        for fallback in [15353u16, 25353u16] {
            if fallback != primary_port {
                c.push(fallback);
            }
        }
        c
    };

    let mut last_err: Option<std::io::Error> = None;
    for port in candidates {
        let addr = format!("{}:{}", host, port);
        match UdpSocket::bind(&addr).await {
            Ok(socket) => {
                let bound_addr = socket.local_addr()?;
                if port != primary_port {
                    warn!(
                        "DNS resolver: configured port {} unavailable, fell back to {}",
                        primary_port, port
                    );
                }
                return Ok((socket, bound_addr));
            }
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrInUse, "no candidate port available")
    }))
}

/// Run the DNS resolver on the given address.
///
/// This is a long-running task that processes DNS queries in a loop.
/// It should be spawned as a tokio task.
pub async fn run_dns_resolver(
    listen_addr: &str,
    state: Arc<Mutex<DnsResolverState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (socket, bound_addr) = bind_dns_socket_with_fallback(listen_addr)
        .await
        .map_err(|e| {
            format!(
                "failed to bind DNS resolver on {} or any fallback port: {} \
                 (hint: on Linux, port 53 requires root — use 5353 or configure \
                 systemd-resolved; on Windows, port 5353 is often already used by \
                 the OS mDNS responder or a browser — this should have fallen back \
                 automatically, so a failure here means even the fallback ports are \
                 taken)",
                listen_addr, e
            )
        })?;

    info!("DNS resolver listening on {}", bound_addr);
    run_dns_resolver_on_socket(socket, state).await
}

/// Same as [`run_dns_resolver`] but takes an already-bound socket.
///
/// Split out so callers that need to know the REAL listening address before
/// the resolver loop starts (e.g. `run_daemon`, which must publish the
/// actual bound port into `AgentState.dns_listen` for the control API and
/// for Windows NRPT/DNS-routing setup — both of which are wrong if they
/// assume the *configured* port when a fallback silently kicked in) can
/// bind up front via [`bind_dns_socket_with_fallback`], read
/// `socket.local_addr()`, and only then hand the socket off to this loop.
pub async fn run_dns_resolver_on_socket(
    socket: UdpSocket,
    state: Arc<Mutex<DnsResolverState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; MAX_DNS_MSG];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(e) => {
                warn!("DNS recv error: {}", e);
                continue;
            }
        };

        let query_data = buf[..len].to_vec();
        let socket_ref = &socket;
        let state_ref = state.clone();

        // Process inline (DNS must be fast — don't spawn a task per query)
        let response = process_dns_query(&query_data, &state_ref).await;

        match response {
            Ok(resp_data) => {
                if let Err(e) = socket_ref.send_to(&resp_data, src).await {
                    debug!("DNS send error to {}: {}", src, e);
                }
            }
            Err(e) => {
                debug!("DNS query processing error from {}: {}", src, e);
                // Send SERVFAIL response
                if let Ok(servfail) = build_error_response(&query_data, FLAGS_RESPONSE_SERVFAIL) {
                    let _ = socket_ref.send_to(&servfail, src).await;
                }
            }
        }
    }
}

/// Process a single DNS query and return the response bytes.
async fn process_dns_query(
    query: &[u8],
    state: &Mutex<DnsResolverState>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if query.len() < DNS_HEADER_SIZE {
        return Err("query too short".into());
    }

    // Parse header
    let _id = u16::from_be_bytes([query[0], query[1]]);
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);

    // Only handle standard queries (QR=0, Opcode=0)
    if flags & 0x8000 != 0 {
        return Err("not a query (QR=1)".into());
    }
    if (flags >> 11) & 0xF != 0 {
        return Err("non-standard opcode".into());
    }
    if qdcount == 0 {
        return Err("no questions".into());
    }

    // Parse the first question
    let (qname, qtype, _qclass, _question_end) = parse_question(&query[DNS_HEADER_SIZE..])?;
    let qname_lower = qname.to_lowercase();

    debug!("DNS query: {} type={} from question", qname_lower, qtype);

    // Only handle A queries for ZTLP names
    if qtype != QTYPE_A && qtype != QTYPE_AAAA {
        // Forward non-A/AAAA queries upstream
        let st = state.lock().await;
        let upstream = st.upstream_dns.clone();
        drop(st);
        return forward_to_upstream(query, &upstream).await;
    }

    // Check if this is a ZTLP name or custom domain
    let st = state.lock().await;
    let ztlp_name = st.domain_mapper.to_ztlp_name(&qname_lower);
    let ns_server = st.ns_server.clone();
    let upstream = st.upstream_dns.clone();
    drop(st);

    let ztlp_name = match ztlp_name {
        Some(name) => name,
        None => {
            // Not a ZTLP name — forward upstream
            return forward_to_upstream(query, &upstream).await;
        }
    };

    // AAAA for ZTLP names → empty response (no IPv6 VIPs)
    if qtype == QTYPE_AAAA {
        return build_empty_response(query);
    }

    // Resolve via ZTLP-NS and allocate a VIP
    debug!("DNS: resolving {} via ZTLP-NS ({})", ztlp_name, ns_server);

    match proxy::ns_resolve(&ztlp_name, &ns_server).await {
        Ok(resolution) => {
            let mut st = state.lock().await;
            let ttl = Duration::from_secs(DEFAULT_TTL as u64);
            if let Some(ip) = st.vip_pool.allocate(&ztlp_name, Some(ttl)) {
                // Store the resolved peer address AND NodeID.
                //
                // The NodeID matters for the automatic tunnel dialer's
                // CLIENT_ROUTE frame — a shared relay's fallback-by-
                // NodeID lookup requires the PEER's NodeID (not the
                // client's own), and without caching it here alongside
                // peer_addr, `run_tcp_proxy` (which reads cached
                // `VipEntry.peer_node_id`, not a fresh NS lookup) always
                // saw `None` even after `ns_resolve` itself was fixed to
                // return a real NodeID — found live 2026-08-30.
                if let Some(entry) = st.vip_pool.lookup_name_mut(&ztlp_name) {
                    entry.peer_addr = Some(resolution.addr);
                    entry.peer_node_id = resolution.node_id;
                }
                drop(st);

                debug!("DNS: {} → {} (VIP {})", qname_lower, ztlp_name, ip);
                build_a_response(query, ip, DEFAULT_TTL)
            } else {
                drop(st);
                warn!("DNS: VIP pool exhausted for {}", ztlp_name);
                build_error_response(query, FLAGS_RESPONSE_SERVFAIL)
            }
        }
        Err(e) => {
            debug!("DNS: NS resolution failed for {}: {}", ztlp_name, e);
            build_error_response(query, FLAGS_RESPONSE_NXDOMAIN)
        }
    }
}

// ─── DNS message construction ───────────────────────────────────────────────

/// Build a DNS response with a single A record.
fn build_a_response(
    query: &[u8],
    ip: Ipv4Addr,
    ttl: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if query.len() < DNS_HEADER_SIZE {
        return Err("query too short for response".into());
    }

    let id = u16::from_be_bytes([query[0], query[1]]);

    // Find the end of the question section
    let (_, _, _, question_len) = parse_question(&query[DNS_HEADER_SIZE..])?;
    let question_bytes = &query[DNS_HEADER_SIZE..DNS_HEADER_SIZE + question_len];

    let mut resp = Vec::with_capacity(DNS_HEADER_SIZE + question_len + 16);

    // Header
    resp.extend_from_slice(&id.to_be_bytes()); // ID
    resp.extend_from_slice(&FLAGS_RESPONSE_OK.to_be_bytes()); // Flags
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // Question section (echo back)
    resp.extend_from_slice(question_bytes);

    // Answer: A record
    resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to question
    resp.extend_from_slice(&QTYPE_A.to_be_bytes()); // TYPE = A
    resp.extend_from_slice(&QCLASS_IN.to_be_bytes()); // CLASS = IN
    resp.extend_from_slice(&ttl.to_be_bytes()); // TTL
    resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
    resp.extend_from_slice(&ip.octets()); // RDATA = IPv4 address

    Ok(resp)
}

/// Build an empty response (no answer records) — used for AAAA queries on VIPs.
fn build_empty_response(query: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if query.len() < DNS_HEADER_SIZE {
        return Err("query too short".into());
    }

    let id = u16::from_be_bytes([query[0], query[1]]);
    let (_, _, _, question_len) = parse_question(&query[DNS_HEADER_SIZE..])?;
    let question_bytes = &query[DNS_HEADER_SIZE..DNS_HEADER_SIZE + question_len];

    let mut resp = Vec::with_capacity(DNS_HEADER_SIZE + question_len);
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&FLAGS_RESPONSE_OK.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    resp.extend_from_slice(question_bytes);

    Ok(resp)
}

/// Build a DNS error response (NXDOMAIN, SERVFAIL, etc.)
fn build_error_response(
    query: &[u8],
    flags: u16,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if query.len() < DNS_HEADER_SIZE {
        return Err("query too short".into());
    }

    let id = u16::from_be_bytes([query[0], query[1]]);

    // Try to include the question section for well-formed responses
    let question_bytes = if query.len() > DNS_HEADER_SIZE {
        match parse_question(&query[DNS_HEADER_SIZE..]) {
            Ok((_, _, _, len)) => Some(&query[DNS_HEADER_SIZE..DNS_HEADER_SIZE + len]),
            Err(_) => None,
        }
    } else {
        None
    };

    let qdcount: u16 = if question_bytes.is_some() { 1 } else { 0 };

    let mut resp = Vec::with_capacity(DNS_HEADER_SIZE + question_bytes.map_or(0, |b| b.len()));
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&qdcount.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    if let Some(qb) = question_bytes {
        resp.extend_from_slice(qb);
    }

    Ok(resp)
}

// ─── DNS message parsing ────────────────────────────────────────────────────

/// Parse a DNS question section.
///
/// Returns (name, qtype, qclass, bytes_consumed).
fn parse_question(
    data: &[u8],
) -> Result<(String, u16, u16, usize), Box<dyn std::error::Error + Send + Sync>> {
    let (name, name_end) = parse_dns_name(data)?;

    if data.len() < name_end + 4 {
        return Err("question truncated after name".into());
    }

    let qtype = u16::from_be_bytes([data[name_end], data[name_end + 1]]);
    let qclass = u16::from_be_bytes([data[name_end + 2], data[name_end + 3]]);

    Ok((name, qtype, qclass, name_end + 4))
}

/// Parse a DNS label-encoded name.
///
/// Returns (decoded_name, bytes_consumed).
fn parse_dns_name(
    data: &[u8],
) -> Result<(String, usize), Box<dyn std::error::Error + Send + Sync>> {
    let mut labels = Vec::new();
    let mut pos = 0;

    loop {
        if pos >= data.len() {
            return Err("name extends past end of data".into());
        }

        let label_len = data[pos] as usize;

        if label_len == 0 {
            pos += 1; // skip the null terminator
            break;
        }

        // Check for compression pointer (top 2 bits = 11)
        if label_len & 0xC0 == 0xC0 {
            // We don't follow pointers in queries — shouldn't happen
            // but skip 2 bytes
            pos += 2;
            break;
        }

        if label_len > 63 {
            return Err(format!("label too long: {} bytes", label_len).into());
        }

        pos += 1;
        if pos + label_len > data.len() {
            return Err("label extends past end of data".into());
        }

        let label = std::str::from_utf8(&data[pos..pos + label_len])
            .map_err(|_| "invalid UTF-8 in DNS label")?;
        labels.push(label.to_string());
        pos += label_len;
    }

    Ok((labels.join("."), pos))
}

/// Encode a hostname as DNS label-encoded wire format.
pub fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0); // null terminator
    encoded
}

/// Build a DNS A query for upstream forwarding.
#[allow(dead_code)]
fn build_dns_query(name: &str, id: u16) -> Vec<u8> {
    let mut query = Vec::new();

    // Header
    query.extend_from_slice(&id.to_be_bytes()); // ID
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
    query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question
    query.extend_from_slice(&encode_dns_name(name));
    query.extend_from_slice(&QTYPE_A.to_be_bytes());
    query.extend_from_slice(&QCLASS_IN.to_be_bytes());

    query
}

/// Forward a DNS query to the upstream resolver and return the response.
///
/// Validates that the response:
/// 1. Arrives from the upstream address we sent the query to (prevents UDP spoofing)
/// 2. Contains the same Transaction ID as the query (prevents response confusion)
///
/// Mismatched responses are silently discarded and the socket continues waiting.
pub async fn forward_to_upstream(
    query: &[u8],
    upstream: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let upstream_addr: SocketAddr = upstream
        .parse()
        .map_err(|e| format!("invalid upstream DNS '{}': {}", upstream, e))?;

    // Extract our query's Transaction ID for response validation
    let query_id = if query.len() >= 2 {
        u16::from_be_bytes([query[0], query[1]])
    } else {
        return Err("query too short to contain Transaction ID".into());
    };

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(query, upstream_addr).await?;

    let mut buf = vec![0u8; 4096];
    let result: Result<Result<Vec<u8>, std::io::Error>, tokio::time::error::Elapsed> =
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let (len, src) = sock.recv_from(&mut buf).await?;
                // Must come from the upstream we sent the query to
                if src != upstream_addr {
                    debug!(
                        "upstream DNS: dropped response from {} (expected {})",
                        src, upstream_addr
                    );
                    continue;
                }
                // Response Transaction ID must match our query
                if len >= 2 {
                    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
                    if resp_id == query_id {
                        return Ok(buf[..len].to_vec());
                    }
                    debug!(
                        "upstream DNS: dropped response with ID {resp_id} (expected {query_id})"
                    );
                    continue;
                }
                // Response too short to be valid DNS — discard
                debug!("upstream DNS: dropped response too short ({len} bytes)");
            }
        })
        .await;

    match result {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => Err(format!("upstream DNS error: {}", e).into()),
        Err(_) => Err("upstream DNS timeout".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── bind_dns_socket_with_fallback / split_host_port (2026-08-30) ──────
    //
    // Real bug found live on Windows: port 5353 (the configured DNS listen
    // port) is frequently already occupied system-wide by Windows' own mDNS
    // responder service AND by Chrome — confirmed via `Get-NetUDPEndpoint
    // -LocalPort 5353` on a real Windows box showing both svchost and
    // chrome.exe already bound. The old code had zero fallback, so the
    // entire automatic DNS-capture flow died with a Linux-oriented "port 53
    // requires root" message that didn't even match the real problem.

    #[test]
    fn split_host_port_parses_host_and_port() {
        assert_eq!(
            split_host_port("127.0.0.53:5353"),
            ("127.0.0.53".to_string(), 5353)
        );
    }

    #[test]
    fn split_host_port_defaults_port_when_missing() {
        assert_eq!(
            split_host_port("127.0.0.53"),
            ("127.0.0.53".to_string(), 5353)
        );
    }

    #[tokio::test]
    async fn bind_dns_socket_with_fallback_uses_configured_port_when_free() {
        // Use port 0 (OS picks a free ephemeral port) as the "configured"
        // port to avoid any real port-collision flakiness in CI — this
        // still exercises the "primary port succeeds" path since port 0
        // always succeeds immediately (no fallback needed).
        let (_, bound_addr) = bind_dns_socket_with_fallback("127.0.0.1:0").await.unwrap();
        assert_eq!(bound_addr.ip().to_string(), "127.0.0.1");
        assert_ne!(bound_addr.port(), 0, "OS must have assigned a real port");
    }

    #[tokio::test]
    async fn bind_dns_socket_with_fallback_falls_back_when_primary_port_taken() {
        // Occupy an arbitrary high port first (simulating "something else
        // already has 5353"), then verify bind_dns_socket_with_fallback
        // configured to use THAT exact port still succeeds by falling
        // through to one of its hardcoded fallback candidates (15353/25353)
        // instead of failing outright.
        let blocker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let taken_port = blocker.local_addr().unwrap().port();

        let (_, bound_addr) = bind_dns_socket_with_fallback(&format!("127.0.0.1:{}", taken_port))
            .await
            .unwrap();

        assert_ne!(
            bound_addr.port(),
            taken_port,
            "must NOT report success on the already-taken port"
        );
        assert!(
            bound_addr.port() == 15353 || bound_addr.port() == 25353,
            "must fall back to one of the documented fallback ports, got {}",
            bound_addr.port()
        );
        drop(blocker);
    }

    #[test]
    fn test_encode_dns_name() {
        let encoded = encode_dns_name("server.corp.ztlp");
        assert_eq!(
            encoded,
            vec![
                6, b's', b'e', b'r', b'v', b'e', b'r', 4, b'c', b'o', b'r', b'p', 4, b'z', b't',
                b'l', b'p', 0, // null terminator
            ]
        );
    }

    #[test]
    fn test_encode_dns_name_single_label() {
        let encoded = encode_dns_name("localhost");
        assert_eq!(
            encoded,
            vec![9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0]
        );
    }

    #[test]
    fn test_parse_dns_name() {
        let wire = vec![
            6, b's', b'e', b'r', b'v', b'e', b'r', 4, b'c', b'o', b'r', b'p', 4, b'z', b't', b'l',
            b'p', 0,
        ];
        let (name, consumed) = parse_dns_name(&wire).unwrap();
        assert_eq!(name, "server.corp.ztlp");
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn test_parse_question() {
        // Build a question: server.corp.ztlp A IN
        let mut question = encode_dns_name("server.corp.ztlp");
        question.extend_from_slice(&QTYPE_A.to_be_bytes());
        question.extend_from_slice(&QCLASS_IN.to_be_bytes());

        let (name, qtype, qclass, consumed) = parse_question(&question).unwrap();
        assert_eq!(name, "server.corp.ztlp");
        assert_eq!(qtype, QTYPE_A);
        assert_eq!(qclass, QCLASS_IN);
        assert_eq!(consumed, question.len());
    }

    #[test]
    fn test_build_a_response() {
        // Build a fake query
        let mut query = vec![0x12, 0x34]; // ID
        query.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags
        query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        query.extend_from_slice(&encode_dns_name("test.ztlp"));
        query.extend_from_slice(&QTYPE_A.to_be_bytes());
        query.extend_from_slice(&QCLASS_IN.to_be_bytes());

        let ip = Ipv4Addr::new(127, 100, 0, 1);
        let resp = build_a_response(&query, ip, 300).unwrap();

        // Check response header
        assert_eq!(resp[0], 0x12); // ID preserved
        assert_eq!(resp[1], 0x34);

        // ANCOUNT = 1
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert_eq!(ancount, 1);

        // Find the answer section (after header + question)
        // The answer should end with the IP address bytes
        let len = resp.len();
        assert_eq!(resp[len - 4], 127);
        assert_eq!(resp[len - 3], 100);
        assert_eq!(resp[len - 2], 0);
        assert_eq!(resp[len - 1], 1);
    }

    #[test]
    fn test_build_error_response_nxdomain() {
        let mut query = vec![0xAB, 0xCD]; // ID
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&encode_dns_name("nope.ztlp"));
        query.extend_from_slice(&QTYPE_A.to_be_bytes());
        query.extend_from_slice(&QCLASS_IN.to_be_bytes());

        let resp = build_error_response(&query, FLAGS_RESPONSE_NXDOMAIN).unwrap();

        // Check ID preserved
        assert_eq!(resp[0], 0xAB);
        assert_eq!(resp[1], 0xCD);

        // Check RCODE = 3 (NXDOMAIN)
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0xF, 3);

        // ANCOUNT = 0
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert_eq!(ancount, 0);
    }

    #[test]
    fn test_build_empty_response() {
        let mut query = vec![0x00, 0x01];
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&encode_dns_name("test.ztlp"));
        query.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
        query.extend_from_slice(&QCLASS_IN.to_be_bytes());

        let resp = build_empty_response(&query).unwrap();

        // ANCOUNT = 0
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert_eq!(ancount, 0);

        // RCODE = 0 (no error)
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0xF, 0);
    }

    #[test]
    fn test_roundtrip_name_encoding() {
        let names = vec![
            "a.ztlp",
            "server.corp.ztlp",
            "deep.nested.sub.domain.ztlp",
            "x.internal.techrockstars.com",
        ];

        for name in names {
            let encoded = encode_dns_name(name);
            let (decoded, consumed) = parse_dns_name(&encoded).unwrap();
            assert_eq!(decoded, name, "roundtrip failed for '{}'", name);
            assert_eq!(consumed, encoded.len());
        }
    }
}
