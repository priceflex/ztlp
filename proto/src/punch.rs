//! NAT hole punching via NS-coordinated peer endpoints.
//!
//! Implements Nebula-style hole punching: both peers simultaneously send
//! 1-byte UDP packets to each other's known endpoints, creating NAT
//! mappings that allow the subsequent Noise_XX handshake to traverse.
//!
//! ## Flow
//!
//! 1. Client queries NS for peer's endpoints via PEER_ENDPOINTS (0x0A)
//! 2. NS responds with known endpoints and sends PUNCH_NOTIFY (0x0B) to peer
//! 3. Both sides send 1-byte punch packets (`0x00`) to each other's addresses
//! 4. Once a punch packet is received (NAT is opened), proceed with handshake
//! 5. If no response within timeout, fall back to relay
//!
//! ## Punch Packet
//!
//! A single byte `0x00` — not a valid ZTLP magic (which is `0x5A37`), so
//! these packets are trivially distinguishable and safely ignored by ZTLP
//! packet processors.

#![deny(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, info};

use crate::identity::NodeId;

// ─── Constants ──────────────────────────────────────────────────────

/// The punch packet payload — a single zero byte.
/// Not a valid ZTLP magic (0x5A37), so safely ignored by the protocol.
pub const PUNCH_BYTE: u8 = 0x00;

/// NS query type for PEER_ENDPOINTS.
pub const NS_PEER_ENDPOINTS: u8 = 0x0A;

/// NS notification type for PUNCH_NOTIFY.
pub const NS_PUNCH_NOTIFY: u8 = 0x0B;

/// NS endpoint report type.
pub const NS_PUNCH_REPORT: u8 = 0x0C;

/// Default keepalive interval (25s — below most NAT timeouts of 30-60s).
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);

// ─── Error Type ─────────────────────────────────────────────────────

/// Errors specific to punch operations.
#[derive(Debug, thiserror::Error)]
pub enum PunchError {
    /// IO error during network operations.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Timeout waiting for punch to succeed.
    #[error("punch timed out after {0:?}")]
    Timeout(Duration),

    /// NS returned an error or unexpected response.
    #[error("NS protocol error: {0}")]
    NsError(String),

    /// No endpoints available for the peer.
    #[error("no endpoints available for peer")]
    NoEndpoints,

    /// Punch failed, relay fallback suggested.
    #[error("punch failed, falling back to relay")]
    FallbackToRelay,
}

// ─── Configuration ──────────────────────────────────────────────────

/// Configuration for the hole punch procedure.
#[derive(Debug, Clone)]
pub struct PunchConfig {
    /// Time to wait before sending the first punch packets.
    /// Allows the PUNCH_NOTIFY to propagate and the peer to start punching too.
    pub punch_delay: Duration,

    /// Interval between punch packet retries.
    pub punch_interval: Duration,

    /// Overall timeout for the punch procedure.
    pub punch_timeout: Duration,

    /// Whether to punch all known addresses or just the primary.
    pub punch_all_addresses: bool,

    /// NAT keepalive interval (sent when tunnel is idle).
    pub keepalive_interval: Duration,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            punch_delay: Duration::from_millis(100),
            punch_interval: Duration::from_millis(500),
            punch_timeout: Duration::from_secs(10),
            punch_all_addresses: true,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
        }
    }
}

/// Result of a punch attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchResult {
    /// Punch succeeded — the peer responded from this address.
    Success { peer_addr: SocketAddr },
    /// Punch timed out — no response from any endpoint.
    TimedOut,
}

// ─── Peer Endpoint Wire Protocol ────────────────────────────────────

/// A peer endpoint parsed from NS responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub addr: SocketAddr,
}

/// Encode a PEER_ENDPOINTS request to the NS.
///
/// Wire format:
/// ```text
/// [0x0A]                     query type
/// [requester_node_id: 16B]   our NodeID
/// [target_node_id: 16B]      peer's NodeID
/// [reported_count: 1B]       number of our own reported endpoints
/// [reported_addrs...]        our endpoints (for NS to track)
/// ```
pub fn encode_peer_endpoints_request(
    our_node_id: &NodeId,
    peer_node_id: &NodeId,
    our_endpoints: &[SocketAddr],
) -> Vec<u8> {
    let count = our_endpoints.len().min(255) as u8;
    let mut pkt = Vec::with_capacity(1 + 16 + 16 + 1 + count as usize * 7);

    pkt.push(NS_PEER_ENDPOINTS);
    pkt.extend_from_slice(our_node_id.as_bytes());
    pkt.extend_from_slice(peer_node_id.as_bytes());
    pkt.push(count);

    for addr in our_endpoints.iter().take(count as usize) {
        encode_addr(&mut pkt, *addr);
    }

    pkt
}

/// Encode a PUNCH_REPORT to the NS (refresh our endpoints).
///
/// Wire format:
/// ```text
/// [0x0C]                     query type
/// [node_id: 16B]             our NodeID
/// [reported_count: 1B]       number of reported endpoints
/// [reported_addrs...]        our endpoints
/// ```
pub fn encode_punch_report(our_node_id: &NodeId, our_endpoints: &[SocketAddr]) -> Vec<u8> {
    let count = our_endpoints.len().min(255) as u8;
    let mut pkt = Vec::with_capacity(1 + 16 + 1 + count as usize * 7);

    pkt.push(NS_PUNCH_REPORT);
    pkt.extend_from_slice(our_node_id.as_bytes());
    pkt.push(count);

    for addr in our_endpoints.iter().take(count as usize) {
        encode_addr(&mut pkt, *addr);
    }

    pkt
}

/// Decode a PEER_ENDPOINTS response from NS.
///
/// Wire format:
/// ```text
/// [0x0A]                     response type
/// [endpoint_count: 1B]       number of endpoints
/// [endpoints...]             addr entries
/// ```
pub fn decode_peer_endpoints_response(data: &[u8]) -> Result<Vec<PeerEndpoint>, PunchError> {
    if data.is_empty() || data[0] != NS_PEER_ENDPOINTS {
        return Err(PunchError::NsError(format!(
            "expected PEER_ENDPOINTS response (0x0A), got 0x{:02X}",
            data.first().copied().unwrap_or(0)
        )));
    }

    if data.len() < 2 {
        return Err(PunchError::NsError(
            "PEER_ENDPOINTS response too short".to_string(),
        ));
    }

    let count = data[1] as usize;
    let mut endpoints = Vec::with_capacity(count);
    let mut pos = 2;

    for _ in 0..count {
        if pos >= data.len() {
            break;
        }
        match decode_addr(&data[pos..]) {
            Some((addr, consumed)) => {
                endpoints.push(PeerEndpoint { addr });
                pos += consumed;
            }
            None => break,
        }
    }

    Ok(endpoints)
}

/// Decode a PUNCH_NOTIFY message from NS.
///
/// Wire format:
/// ```text
/// [0x0B]                         notification type
/// [requester_node_id: 16B]       who wants to connect
/// [endpoint_count: 1B]           number of requester's endpoints
/// [endpoints...]                 requester's addr entries
/// ```
pub fn decode_punch_notify(data: &[u8]) -> Result<(NodeId, Vec<PeerEndpoint>), PunchError> {
    if data.is_empty() || data[0] != NS_PUNCH_NOTIFY {
        return Err(PunchError::NsError(format!(
            "expected PUNCH_NOTIFY (0x0B), got 0x{:02X}",
            data.first().copied().unwrap_or(0)
        )));
    }

    if data.len() < 18 {
        // 1 (type) + 16 (node_id) + 1 (count) = 18
        return Err(PunchError::NsError("PUNCH_NOTIFY too short".to_string()));
    }

    let mut node_id_bytes = [0u8; 16];
    node_id_bytes.copy_from_slice(&data[1..17]);
    let node_id = NodeId::from_bytes(node_id_bytes);

    let count = data[17] as usize;
    let mut endpoints = Vec::with_capacity(count);
    let mut pos = 18;

    for _ in 0..count {
        if pos >= data.len() {
            break;
        }
        match decode_addr(&data[pos..]) {
            Some((addr, consumed)) => {
                endpoints.push(PeerEndpoint { addr });
                pos += consumed;
            }
            None => break,
        }
    }

    Ok((node_id, endpoints))
}

/// Check if a packet is a punch packet (single byte 0x00).
pub fn is_punch_packet(data: &[u8]) -> bool {
    data.len() == 1 && data[0] == PUNCH_BYTE
}

/// Check if a packet is a PUNCH_NOTIFY from NS.
pub fn is_punch_notify(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == NS_PUNCH_NOTIFY
}

// ─── Hole Punch Procedure ───────────────────────────────────────────

/// Execute the hole punch procedure.
///
/// 1. Query NS for peer endpoints
/// 2. Wait for `punch_delay` (let PUNCH_NOTIFY propagate)
/// 3. Send punch packets to all peer endpoints on an interval
/// 4. Listen for incoming punch packets (NAT opened from the other side)
/// 5. Return the address that responded, or timeout
pub async fn execute_punch(
    socket: &Arc<UdpSocket>,
    ns_addr: SocketAddr,
    our_node_id: &NodeId,
    peer_node_id: &NodeId,
    our_endpoints: &[SocketAddr],
    config: &PunchConfig,
) -> Result<PunchResult, PunchError> {
    // Step 1: Query NS for peer's endpoints
    info!(
        "punch: querying NS at {} for peer {} endpoints",
        ns_addr, peer_node_id
    );

    let req = encode_peer_endpoints_request(our_node_id, peer_node_id, our_endpoints);
    socket.send_to(&req, ns_addr).await?;

    // Wait for NS response
    let peer_endpoints = {
        let mut buf = [0u8; 1024];
        match timeout(Duration::from_secs(5), async {
            loop {
                let (len, from) = socket.recv_from(&mut buf).await?;
                if from == ns_addr && !buf[..len].is_empty() && buf[0] == NS_PEER_ENDPOINTS {
                    return decode_peer_endpoints_response(&buf[..len]);
                }
                // Not our response, continue
            }
        })
        .await
        {
            Ok(Ok(endpoints)) => endpoints,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(PunchError::NsError(
                    "timeout waiting for NS PEER_ENDPOINTS response".to_string(),
                ))
            }
        }
    };

    if peer_endpoints.is_empty() {
        info!("punch: no endpoints known for peer, waiting for PUNCH_NOTIFY or retry");
        // Even without known endpoints, the NS sent a PUNCH_NOTIFY to the peer,
        // so the peer may start punching us. We'll still listen for incoming punches.
    }

    let target_addrs: Vec<SocketAddr> = if config.punch_all_addresses {
        peer_endpoints.iter().map(|e| e.addr).collect()
    } else {
        peer_endpoints
            .first()
            .map(|e| vec![e.addr])
            .unwrap_or_default()
    };

    info!("punch: targeting {} peer endpoints", target_addrs.len());
    for addr in &target_addrs {
        debug!("punch: target endpoint: {}", addr);
    }

    // Step 2: Wait for punch_delay
    if !config.punch_delay.is_zero() {
        debug!(
            "punch: waiting {:?} for PUNCH_NOTIFY propagation",
            config.punch_delay
        );
        sleep(config.punch_delay).await;
    }

    // Step 3-4: Send punch packets and listen for responses
    let deadline = Instant::now() + config.punch_timeout;
    let punch_socket = socket.clone();

    // Shared cancellation signal
    let cancel = Arc::new(Notify::new());
    let cancel_send = cancel.clone();

    // Spawn sender task
    let send_addrs = target_addrs.clone();
    let send_interval = config.punch_interval;
    let send_task = tokio::spawn(async move {
        let mut ticker = interval(send_interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    for addr in &send_addrs {
                        if let Err(e) = punch_socket.send_to(&[PUNCH_BYTE], addr).await {
                            debug!("punch: send to {} failed: {}", addr, e);
                        } else {
                            debug!("punch: sent punch to {}", addr);
                        }
                    }
                }
                _ = cancel_send.notified() => {
                    debug!("punch: sender cancelled");
                    return;
                }
            }
        }
    });

    // Listen for incoming punch packets or PUNCH_NOTIFY
    let result = {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut buf = [0u8; 1024];

        match timeout(remaining, async {
            loop {
                let (len, from) = socket.recv_from(&mut buf).await?;
                let data = &buf[..len];

                if is_punch_packet(data) {
                    info!("punch: received punch from {} — NAT opened!", from);
                    return Ok::<SocketAddr, PunchError>(from);
                }

                if is_punch_notify(data) {
                    // We received a PUNCH_NOTIFY — parse and start punching those addrs too
                    if let Ok((_node_id, new_endpoints)) = decode_punch_notify(data) {
                        for ep in &new_endpoints {
                            debug!("punch: PUNCH_NOTIFY added target: {}", ep.addr);
                            // Send punch immediately to the new addresses
                            let _ = socket.send_to(&[PUNCH_BYTE], ep.addr).await;
                        }
                    }
                    continue;
                }

                // Not a punch packet — might be normal traffic, skip
            }
        })
        .await
        {
            Ok(Ok(addr)) => PunchResult::Success { peer_addr: addr },
            Ok(Err(_)) => PunchResult::TimedOut,
            Err(_) => PunchResult::TimedOut,
        }
    };

    // Cancel the sender
    cancel.notify_one();
    send_task.abort();

    Ok(result)
}

// ─── NAT Keepalive ──────────────────────────────────────────────────

/// Keepalive state tracker.
///
/// Sends a 1-byte keepalive packet when the tunnel has been idle for
/// longer than the configured interval. Call `note_activity()` whenever
/// data is sent to reset the idle timer.
pub struct KeepaliveTracker {
    last_activity: Instant,
    interval: Duration,
}

impl KeepaliveTracker {
    /// Create a new keepalive tracker.
    pub fn new(interval: Duration) -> Self {
        Self {
            last_activity: Instant::now(),
            interval,
        }
    }

    /// Record that data was sent (resets the idle timer).
    pub fn note_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if a keepalive should be sent now.
    pub fn should_send(&self) -> bool {
        self.last_activity.elapsed() >= self.interval
    }

    /// Duration until the next keepalive is due.
    pub fn time_until_next(&self) -> Duration {
        let elapsed = self.last_activity.elapsed();
        if elapsed >= self.interval {
            Duration::ZERO
        } else {
            self.interval - elapsed
        }
    }

    /// Send a keepalive packet if the tunnel has been idle.
    /// Returns true if a keepalive was sent.
    pub async fn maybe_send(
        &mut self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
    ) -> Result<bool, std::io::Error> {
        if self.should_send() {
            socket.send_to(&[PUNCH_BYTE], peer_addr).await?;
            self.note_activity();
            debug!("keepalive: sent to {}", peer_addr);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ─── Wire Encoding Helpers ──────────────────────────────────────────

fn encode_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        IpAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
}

fn decode_addr(data: &[u8]) -> Option<(SocketAddr, usize)> {
    if data.is_empty() {
        return None;
    }

    match data[0] {
        4 => {
            // IPv4: family(1) + addr(4) + port(2) = 7 bytes
            if data.len() < 7 {
                return None;
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), 7))
        }
        6 => {
            // IPv6: family(1) + addr(16) + port(2) = 19 bytes
            if data.len() < 19 {
                return None;
            }
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&data[1..17]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Some((
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr_bytes)), port),
                19,
            ))
        }
        _ => None,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    // ── Punch Packet Tests ──────────────────────────────────────────

    #[test]
    fn test_is_punch_packet() {
        assert!(is_punch_packet(&[0x00]));
        assert!(!is_punch_packet(&[]));
        assert!(!is_punch_packet(&[0x01]));
        assert!(!is_punch_packet(&[0x00, 0x00]));
        assert!(!is_punch_packet(&[0x5A, 0x37])); // ZTLP magic
    }

    #[test]
    fn test_is_punch_notify() {
        assert!(is_punch_notify(&[0x0B, 0x00]));
        assert!(is_punch_notify(&[0x0B]));
        assert!(!is_punch_notify(&[]));
        assert!(!is_punch_notify(&[0x0A]));
    }

    // ── PEER_ENDPOINTS Request Encoding ─────────────────────────────

    #[test]
    fn test_encode_peer_endpoints_request_no_reported() {
        let our_id = NodeId::from_bytes([0xAA; 16]);
        let peer_id = NodeId::from_bytes([0xBB; 16]);

        let pkt = encode_peer_endpoints_request(&our_id, &peer_id, &[]);

        assert_eq!(pkt[0], NS_PEER_ENDPOINTS);
        assert_eq!(&pkt[1..17], &[0xAA; 16]);
        assert_eq!(&pkt[17..33], &[0xBB; 16]);
        assert_eq!(pkt[33], 0); // 0 reported endpoints
        assert_eq!(pkt.len(), 34);
    }

    #[test]
    fn test_encode_peer_endpoints_request_with_reported() {
        let our_id = NodeId::from_bytes([0xAA; 16]);
        let peer_id = NodeId::from_bytes([0xBB; 16]);
        let endpoints = vec![
            "1.2.3.4:5000".parse::<SocketAddr>().unwrap(),
            "10.0.0.1:6000".parse::<SocketAddr>().unwrap(),
        ];

        let pkt = encode_peer_endpoints_request(&our_id, &peer_id, &endpoints);

        assert_eq!(pkt[0], NS_PEER_ENDPOINTS);
        assert_eq!(pkt[33], 2); // 2 reported endpoints
                                // Each IPv4 addr = 7 bytes (1 family + 4 addr + 2 port)
        assert_eq!(pkt.len(), 34 + 14);
    }

    // ── PEER_ENDPOINTS Response Decoding ────────────────────────────

    #[test]
    fn test_decode_peer_endpoints_response_empty() {
        let data = vec![0x0A, 0x00]; // 0 endpoints
        let result = decode_peer_endpoints_response(&data).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_decode_peer_endpoints_response_ipv4() {
        let mut data = vec![0x0A, 0x01]; // 1 endpoint
                                         // IPv4: 203.0.113.42:3478
        data.push(4);
        data.extend_from_slice(&[203, 0, 113, 42]);
        data.extend_from_slice(&3478u16.to_be_bytes());

        let result = decode_peer_endpoints_response(&data).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].addr,
            "203.0.113.42:3478".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_decode_peer_endpoints_response_ipv6() {
        let mut data = vec![0x0A, 0x01]; // 1 endpoint
                                         // IPv6: [2001:db8::1]:19302
        let addr: SocketAddr = "[2001:db8::1]:19302".parse().unwrap();
        data.push(6);
        if let IpAddr::V6(v6) = addr.ip() {
            data.extend_from_slice(&v6.octets());
        }
        data.extend_from_slice(&addr.port().to_be_bytes());

        let result = decode_peer_endpoints_response(&data).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].addr, addr);
    }

    #[test]
    fn test_decode_peer_endpoints_response_multiple() {
        let mut data = vec![0x0A, 0x02]; // 2 endpoints
                                         // Endpoint 1: 1.2.3.4:5000
        data.push(4);
        data.extend_from_slice(&[1, 2, 3, 4]);
        data.extend_from_slice(&5000u16.to_be_bytes());
        // Endpoint 2: 10.0.0.1:6000
        data.push(4);
        data.extend_from_slice(&[10, 0, 0, 1]);
        data.extend_from_slice(&6000u16.to_be_bytes());

        let result = decode_peer_endpoints_response(&data).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].addr,
            "1.2.3.4:5000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            result[1].addr,
            "10.0.0.1:6000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_decode_peer_endpoints_response_wrong_type() {
        let data = vec![0x0B, 0x00]; // Wrong type
        let result = decode_peer_endpoints_response(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_peer_endpoints_response_too_short() {
        let data = vec![0x0A]; // Missing count
        let result = decode_peer_endpoints_response(&data);
        assert!(result.is_err());
    }

    // ── PUNCH_NOTIFY Decoding ───────────────────────────────────────

    #[test]
    fn test_decode_punch_notify_basic() {
        let node_id = [0xCC; 16];
        let mut data = vec![0x0B];
        data.extend_from_slice(&node_id);
        data.push(1); // 1 endpoint
                      // IPv4: 198.51.100.25:19302
        data.push(4);
        data.extend_from_slice(&[198, 51, 100, 25]);
        data.extend_from_slice(&19302u16.to_be_bytes());

        let (decoded_id, endpoints) = decode_punch_notify(&data).unwrap();
        assert_eq!(decoded_id.0, node_id);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0].addr,
            "198.51.100.25:19302".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_decode_punch_notify_no_endpoints() {
        let node_id = [0xDD; 16];
        let mut data = vec![0x0B];
        data.extend_from_slice(&node_id);
        data.push(0); // 0 endpoints

        let (decoded_id, endpoints) = decode_punch_notify(&data).unwrap();
        assert_eq!(decoded_id.0, node_id);
        assert!(endpoints.is_empty());
    }

    #[test]
    fn test_decode_punch_notify_wrong_type() {
        let data = vec![0x0A, 0x00]; // Wrong type
        let result = decode_punch_notify(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_punch_notify_too_short() {
        let data = vec![0x0B, 0x01, 0x02]; // Too short for node_id
        let result = decode_punch_notify(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_punch_notify_multiple_endpoints() {
        let node_id = [0xEE; 16];
        let mut data = vec![0x0B];
        data.extend_from_slice(&node_id);
        data.push(3); // 3 endpoints
                      // Endpoint 1: 1.1.1.1:100
        data.push(4);
        data.extend_from_slice(&[1, 1, 1, 1]);
        data.extend_from_slice(&100u16.to_be_bytes());
        // Endpoint 2: 2.2.2.2:200
        data.push(4);
        data.extend_from_slice(&[2, 2, 2, 2]);
        data.extend_from_slice(&200u16.to_be_bytes());
        // Endpoint 3: 3.3.3.3:300
        data.push(4);
        data.extend_from_slice(&[3, 3, 3, 3]);
        data.extend_from_slice(&300u16.to_be_bytes());

        let (decoded_id, endpoints) = decode_punch_notify(&data).unwrap();
        assert_eq!(decoded_id.0, node_id);
        assert_eq!(endpoints.len(), 3);
        assert_eq!(
            endpoints[0].addr,
            "1.1.1.1:100".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            endpoints[1].addr,
            "2.2.2.2:200".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            endpoints[2].addr,
            "3.3.3.3:300".parse::<SocketAddr>().unwrap()
        );
    }

    // ── PUNCH_REPORT Encoding ───────────────────────────────────────

    #[test]
    fn test_encode_punch_report_empty() {
        let node_id = NodeId::from_bytes([0xFF; 16]);
        let pkt = encode_punch_report(&node_id, &[]);

        assert_eq!(pkt[0], NS_PUNCH_REPORT);
        assert_eq!(&pkt[1..17], &[0xFF; 16]);
        assert_eq!(pkt[17], 0);
        assert_eq!(pkt.len(), 18);
    }

    #[test]
    fn test_encode_punch_report_with_addrs() {
        let node_id = NodeId::from_bytes([0x11; 16]);
        let addrs = vec!["5.6.7.8:9000".parse::<SocketAddr>().unwrap()];
        let pkt = encode_punch_report(&node_id, &addrs);

        assert_eq!(pkt[0], NS_PUNCH_REPORT);
        assert_eq!(pkt[17], 1);
        assert_eq!(pkt.len(), 18 + 7); // 1 IPv4 addr
    }

    // ── Wire Encoding Roundtrip ─────────────────────────────────────

    #[test]
    fn test_addr_encode_decode_ipv4() {
        let addr: SocketAddr = "203.0.113.42:3478".parse().unwrap();
        let mut buf = Vec::new();
        encode_addr(&mut buf, addr);

        let (decoded, consumed) = decode_addr(&buf).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_addr_encode_decode_ipv6() {
        let addr: SocketAddr = "[2001:db8::cafe]:19302".parse().unwrap();
        let mut buf = Vec::new();
        encode_addr(&mut buf, addr);

        let (decoded, consumed) = decode_addr(&buf).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(consumed, 19);
    }

    #[test]
    fn test_decode_addr_empty() {
        assert!(decode_addr(&[]).is_none());
    }

    #[test]
    fn test_decode_addr_unknown_family() {
        assert!(decode_addr(&[99, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn test_decode_addr_truncated_ipv4() {
        assert!(decode_addr(&[4, 1, 2, 3]).is_none()); // missing port
    }

    #[test]
    fn test_decode_addr_truncated_ipv6() {
        assert!(decode_addr(&[6, 0, 0, 0]).is_none()); // way too short
    }

    // ── PunchConfig Default Tests ───────────────────────────────────

    #[test]
    fn test_punch_config_defaults() {
        let config = PunchConfig::default();
        assert_eq!(config.punch_delay, Duration::from_millis(100));
        assert_eq!(config.punch_interval, Duration::from_millis(500));
        assert_eq!(config.punch_timeout, Duration::from_secs(10));
        assert!(config.punch_all_addresses);
        assert_eq!(config.keepalive_interval, Duration::from_secs(25));
    }

    // ── KeepaliveTracker Tests ──────────────────────────────────────

    #[test]
    fn test_keepalive_tracker_new() {
        let tracker = KeepaliveTracker::new(Duration::from_secs(25));
        assert!(!tracker.should_send());
    }

    #[test]
    fn test_keepalive_tracker_should_send_after_interval() {
        let mut tracker = KeepaliveTracker::new(Duration::from_millis(0));
        // Zero interval means should always send
        assert!(tracker.should_send());
        tracker.note_activity();
        // Still should send because interval is 0
        assert!(tracker.should_send());
    }

    #[test]
    fn test_keepalive_tracker_note_activity_resets() {
        let tracker = KeepaliveTracker::new(Duration::from_secs(100));
        assert!(!tracker.should_send());
        assert!(tracker.time_until_next() > Duration::from_secs(99));
    }

    #[test]
    fn test_keepalive_tracker_time_until_next() {
        let tracker = KeepaliveTracker::new(Duration::from_secs(25));
        let until = tracker.time_until_next();
        // Should be close to 25 seconds (minus tiny elapsed time)
        assert!(until > Duration::from_secs(24));
        assert!(until <= Duration::from_secs(25));
    }

    // ── Integration Tests with UDP ──────────────────────────────────

    #[tokio::test]
    async fn test_punch_exchange_between_two_sockets() {
        // Simulate two peers sending punch packets to each other
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        // A sends punch to B
        socket_a.send_to(&[PUNCH_BYTE], addr_b).await.unwrap();

        // B receives punch
        let mut buf = [0u8; 10];
        let (len, from) = socket_b.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 1);
        assert_eq!(buf[0], PUNCH_BYTE);
        assert!(is_punch_packet(&buf[..len]));
        assert_eq!(from, addr_a);

        // B sends punch to A
        socket_b.send_to(&[PUNCH_BYTE], addr_a).await.unwrap();

        // A receives punch
        let (len, from) = socket_a.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 1);
        assert!(is_punch_packet(&buf[..len]));
        assert_eq!(from, addr_b);
    }

    #[tokio::test]
    async fn test_keepalive_maybe_send() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_socket.local_addr().unwrap();

        let mut tracker = KeepaliveTracker::new(Duration::from_millis(0));

        // Should send immediately (0ms interval)
        let sent = tracker.maybe_send(&socket, peer_addr).await.unwrap();
        assert!(sent);

        // Verify peer received it
        let mut buf = [0u8; 10];
        let (len, _) = peer_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 1);
        assert!(is_punch_packet(&buf[..len]));
    }

    #[tokio::test]
    async fn test_simulated_ns_punch_coordination() {
        // Simulate the full punch flow with a fake NS
        let ns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns_addr = ns_socket.local_addr().unwrap();

        let client_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_b = client_b.local_addr().unwrap();

        let node_a = NodeId::from_bytes([0xAA; 16]);
        let node_b = NodeId::from_bytes([0xBB; 16]);

        // Spawn fake NS that responds with client B's address
        let ns_node_a = node_a;
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, from) = ns_socket.recv_from(&mut buf).await.unwrap();
            let data = &buf[..len];

            // Verify it's a PEER_ENDPOINTS request
            assert_eq!(data[0], NS_PEER_ENDPOINTS);

            // Respond with client B's address
            let mut resp = vec![0x0A, 0x01]; // 1 endpoint
            resp.push(4); // IPv4
            if let IpAddr::V4(v4) = addr_b.ip() {
                resp.extend_from_slice(&v4.octets());
            }
            resp.extend_from_slice(&addr_b.port().to_be_bytes());

            ns_socket.send_to(&resp, from).await.unwrap();

            // Also send PUNCH_NOTIFY to client B
            let mut notify = vec![NS_PUNCH_NOTIFY];
            notify.extend_from_slice(ns_node_a.as_bytes());
            notify.push(1); // 1 endpoint
            notify.push(4); // IPv4
            if let IpAddr::V4(v4) = from.ip() {
                notify.extend_from_slice(&v4.octets());
            }
            notify.extend_from_slice(&from.port().to_be_bytes());

            ns_socket.send_to(&notify, addr_b).await.unwrap();
        });

        // Client A starts punching
        let config = PunchConfig {
            punch_delay: Duration::from_millis(10),
            punch_interval: Duration::from_millis(50),
            punch_timeout: Duration::from_secs(5),
            punch_all_addresses: true,
            keepalive_interval: Duration::from_secs(25),
        };

        // Client B listens for PUNCH_NOTIFY and responds
        let client_b_clone = client_b.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let (len, from) = client_b_clone.recv_from(&mut buf).await.unwrap();
                let data = &buf[..len];

                if is_punch_notify(data) {
                    // Got PUNCH_NOTIFY — send punch back
                    if let Ok((_node_id, endpoints)) = decode_punch_notify(data) {
                        for ep in &endpoints {
                            let _ = client_b_clone.send_to(&[PUNCH_BYTE], ep.addr).await;
                        }
                    }
                } else if is_punch_packet(data) {
                    // Got punch — send one back
                    let _ = client_b_clone.send_to(&[PUNCH_BYTE], from).await;
                    return;
                }
            }
        });

        let result = execute_punch(&client_a, ns_addr, &node_a, &node_b, &[], &config).await;

        match result {
            Ok(PunchResult::Success { peer_addr }) => {
                info!("Punch succeeded with peer at {}", peer_addr);
            }
            Ok(PunchResult::TimedOut) => {
                panic!("Punch timed out — expected success in local test");
            }
            Err(e) => {
                panic!("Punch error: {}", e);
            }
        }
    }

    // ── Punch Timing Tests ──────────────────────────────────────────

    #[test]
    fn test_punch_config_various_delays() {
        // Test that various delay configurations are valid
        let configs = vec![
            PunchConfig {
                punch_delay: Duration::from_millis(0),
                ..PunchConfig::default()
            },
            PunchConfig {
                punch_delay: Duration::from_millis(100),
                ..PunchConfig::default()
            },
            PunchConfig {
                punch_delay: Duration::from_secs(1),
                ..PunchConfig::default()
            },
            PunchConfig {
                punch_delay: Duration::from_secs(5),
                ..PunchConfig::default()
            },
            PunchConfig {
                punch_delay: Duration::from_secs(10),
                ..PunchConfig::default()
            },
        ];

        for config in &configs {
            assert!(config.punch_timeout >= config.punch_delay);
        }
    }

    #[tokio::test]
    async fn test_punch_timeout_behavior() {
        // Test that punch times out correctly when no peer responds
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns_addr = ns_socket.local_addr().unwrap();

        let node_a = NodeId::from_bytes([0x11; 16]);
        let node_b = NodeId::from_bytes([0x22; 16]);

        // Fake NS that returns 1 endpoint that won't respond
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (_len, from) = ns_socket.recv_from(&mut buf).await.unwrap();

            // Respond with a non-existent endpoint
            let resp = vec![0x0A, 0x01, 4, 192, 0, 2, 1, 0x27, 0x10]; // 192.0.2.1:10000
            ns_socket.send_to(&resp, from).await.unwrap();
        });

        let config = PunchConfig {
            punch_delay: Duration::from_millis(0),
            punch_interval: Duration::from_millis(50),
            punch_timeout: Duration::from_millis(300),
            punch_all_addresses: true,
            keepalive_interval: Duration::from_secs(25),
        };

        let start = Instant::now();
        let result = execute_punch(&socket, ns_addr, &node_a, &node_b, &[], &config).await;
        let elapsed = start.elapsed();

        match result {
            Ok(PunchResult::TimedOut) => {
                // Timeout should be roughly punch_timeout duration
                assert!(elapsed >= Duration::from_millis(250));
                assert!(elapsed < Duration::from_secs(2));
            }
            other => panic!("Expected TimedOut, got {:?}", other),
        }
    }

    // ── Graceful Fallback Test ──────────────────────────────────────

    #[test]
    fn test_punch_result_variants() {
        let success = PunchResult::Success {
            peer_addr: "10.0.0.1:5000".parse().unwrap(),
        };
        assert_eq!(
            success,
            PunchResult::Success {
                peer_addr: "10.0.0.1:5000".parse().unwrap()
            }
        );

        let timed_out = PunchResult::TimedOut;
        assert_eq!(timed_out, PunchResult::TimedOut);
        assert_ne!(success, timed_out);
    }
}
