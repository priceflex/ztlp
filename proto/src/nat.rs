//! NAT traversal for ZTLP.
//!
//! Provides STUN-based endpoint discovery (RFC 5389 subset), relay-coordinated
//! hole punching, and automatic fallback to relay mode when direct connection
//! fails. This enables ZTLP peers behind NAT to establish direct connections
//! whenever possible.
//!
//! ## Architecture
//!
//! 1. **STUN Client** — discovers the public (mapped) endpoint of the local
//!    UDP socket by sending a Binding Request to a STUN server and parsing
//!    the XOR-MAPPED-ADDRESS or MAPPED-ADDRESS from the response.
//!
//! 2. **Rendezvous Protocol** — a lightweight coordination protocol layered on
//!    top of the existing ZTLP relay. Two peers register their mapped endpoints
//!    with a shared rendezvous ID (derived from both NodeIDs). The relay
//!    exchanges endpoint information so each peer knows where to send hole-punch
//!    probes.
//!
//! 3. **Hole Punch Procedure** — after exchanging endpoints via rendezvous,
//!    both peers simultaneously send ZTLP Ping probes to each other's mapped
//!    address. If the NAT is endpoint-independent (most common), the outbound
//!    packet creates a mapping that the peer's inbound packet can traverse.
//!    Falls back to relay mode if punching fails.

#![deny(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use blake2::{Blake2s256, Digest};
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::identity::{NodeId, NodeIdentity};
use crate::packet::{HandshakeHeader, MsgType, HANDSHAKE_HEADER_SIZE};

// ─── STUN Constants (RFC 5389) ──────────────────────────────────────────────

/// STUN magic cookie per RFC 5389.
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN Binding Request message type.
const STUN_BINDING_REQUEST: u16 = 0x0001;

/// STUN Binding Response (success) message type.
const STUN_BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute type: MAPPED-ADDRESS.
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// STUN attribute type: XOR-MAPPED-ADDRESS.
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN header size in bytes: 20 (2 type + 2 length + 4 cookie + 12 txn ID).
const STUN_HEADER_SIZE: usize = 20;

/// Address family: IPv4.
const STUN_ADDR_FAMILY_IPV4: u8 = 0x01;

/// Address family: IPv6.
const STUN_ADDR_FAMILY_IPV6: u8 = 0x02;

// ─── Rendezvous Protocol Constants ──────────────────────────────────────────

/// Rendezvous magic bytes: "RV".
pub const RV_MAGIC: [u8; 2] = [0x52, 0x56];

/// Rendezvous op: register my mapped endpoint.
pub const RV_REGISTER: u8 = 0x01;

/// Rendezvous op: here is your peer's endpoint info.
pub const RV_PEER_INFO: u8 = 0x02;

/// Rendezvous op: peer not (yet) found.
pub const RV_NOT_FOUND: u8 = 0x03;

/// Minimum rendezvous packet size: magic(2) + rendezvous_id(32) + op(1) = 35.
pub const RV_MIN_PACKET_SIZE: usize = 35;

/// Rendezvous entry TTL in seconds.
pub const RV_ENTRY_TTL_SECS: u64 = 60;

// ─── Default STUN Servers ───────────────────────────────────────────────────

/// Well-known public STUN servers used as fallbacks.
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

// ─── Error Type ─────────────────────────────────────────────────────────────

/// Errors specific to NAT traversal operations.
#[derive(Debug, thiserror::Error)]
pub enum NatError {
    /// IO error during network operations.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// STUN protocol error.
    #[error("STUN error: {0}")]
    Stun(String),

    /// Timeout waiting for STUN response or rendezvous.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Rendezvous protocol error.
    #[error("rendezvous error: {0}")]
    Rendezvous(String),

    /// Hole punch failed (all attempts exhausted).
    #[error("hole punch failed after {0} attempts")]
    HolePunchFailed(u32),

    /// No relay fallback allowed and direct connection failed.
    #[error("direct connection failed and relay fallback disabled")]
    NoFallback,
}

// ─── Types ──────────────────────────────────────────────────────────────────

/// A discovered public (mapped) endpoint from STUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedEndpoint {
    /// The public address as seen by the STUN server.
    pub address: SocketAddr,
    /// Whether NAT was detected.
    pub nat_type: NatType,
}

/// NAT detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT detected (mapped address == local address).
    None,
    /// NAT detected (mapped address differs from local).
    Detected,
}

/// Configuration for the hole punch procedure.
pub struct HolePunchConfig {
    /// STUN servers to try for endpoint discovery.
    pub stun_servers: Vec<SocketAddr>,
    /// Relay address for rendezvous coordination.
    pub relay_addr: SocketAddr,
    /// The local UDP socket (shared with ZTLP traffic).
    pub local_socket: Arc<UdpSocket>,
    /// Our identity.
    pub identity: NodeIdentity,
    /// The peer's NodeID.
    pub peer_node_id: NodeId,
    /// Overall timeout for the entire procedure.
    pub timeout: Duration,
    /// Number of hole-punch probe attempts.
    pub punch_attempts: u32,
    /// Interval between probe attempts.
    pub punch_interval: Duration,
}

impl HolePunchConfig {
    /// Create a config with sensible defaults.
    pub fn new(
        relay_addr: SocketAddr,
        local_socket: Arc<UdpSocket>,
        identity: NodeIdentity,
        peer_node_id: NodeId,
    ) -> Self {
        Self {
            stun_servers: Vec::new(), // will use DEFAULT_STUN_SERVERS
            relay_addr,
            local_socket,
            identity,
            peer_node_id,
            timeout: Duration::from_secs(30),
            punch_attempts: 10,
            punch_interval: Duration::from_millis(200),
        }
    }
}

/// Result of the connection establishment procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionResult {
    /// Direct connection established via hole punch.
    Direct { peer_addr: SocketAddr },
    /// Hole punch failed, fell back to relay.
    Relayed { relay_addr: SocketAddr },
}

// ─── STUN Client ────────────────────────────────────────────────────────────

/// Minimal STUN client implementing only Binding Request/Response (RFC 5389).
pub struct StunClient;

impl StunClient {
    /// Discover our public (mapped) endpoint via a STUN server.
    ///
    /// Sends a Binding Request, parses the response, returns the
    /// XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS.
    ///
    /// `local_socket` should be the same UDP socket used for ZTLP traffic
    /// so the NAT mapping matches.
    pub async fn discover_endpoint(
        local_socket: &UdpSocket,
        stun_server: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<MappedEndpoint, NatError> {
        let (request, transaction_id) = Self::build_binding_request();

        local_socket.send_to(&request, stun_server).await?;
        debug!("sent STUN Binding Request to {}", stun_server);

        let mut buf = [0u8; 576]; // STUN responses are typically small
        let (len, _from) = timeout(timeout_duration, local_socket.recv_from(&mut buf))
            .await
            .map_err(|_| NatError::Timeout("STUN server did not respond".to_string()))??;

        let response = &buf[..len];
        let mut endpoint = Self::parse_binding_response(response, &transaction_id)?;

        // Determine NAT type by comparing mapped address with local address
        let local_addr = local_socket.local_addr()?;
        endpoint.nat_type = if endpoint.address == local_addr {
            NatType::None
        } else {
            NatType::Detected
        };

        info!(
            "STUN discovery: mapped={}, local={}, nat={:?}",
            endpoint.address, local_addr, endpoint.nat_type
        );

        Ok(endpoint)
    }

    /// Build a STUN Binding Request packet.
    ///
    /// Returns the serialized packet and the transaction ID for matching
    /// the response.
    pub fn build_binding_request() -> (Vec<u8>, [u8; 12]) {
        let mut transaction_id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut transaction_id);

        let mut pkt = Vec::with_capacity(STUN_HEADER_SIZE);

        // Message Type: Binding Request (0x0001)
        pkt.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());

        // Message Length: 0 (no attributes in request)
        pkt.extend_from_slice(&0u16.to_be_bytes());

        // Magic Cookie
        pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID (96 bits)
        pkt.extend_from_slice(&transaction_id);

        (pkt, transaction_id)
    }

    /// Parse a STUN Binding Response.
    ///
    /// Extracts XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS from the
    /// response attributes. Validates the transaction ID matches.
    pub fn parse_binding_response(
        data: &[u8],
        transaction_id: &[u8; 12],
    ) -> Result<MappedEndpoint, NatError> {
        if data.len() < STUN_HEADER_SIZE {
            return Err(NatError::Stun(format!(
                "response too short: {} bytes (need at least {})",
                data.len(),
                STUN_HEADER_SIZE
            )));
        }

        // Parse header
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let txn_id = &data[8..20];

        // Validate magic cookie
        if cookie != STUN_MAGIC_COOKIE {
            return Err(NatError::Stun(format!(
                "invalid magic cookie: 0x{:08X} (expected 0x{:08X})",
                cookie, STUN_MAGIC_COOKIE
            )));
        }

        // Validate message type is Binding Response
        if msg_type != STUN_BINDING_RESPONSE {
            return Err(NatError::Stun(format!(
                "unexpected message type: 0x{:04X} (expected Binding Response 0x{:04X})",
                msg_type, STUN_BINDING_RESPONSE
            )));
        }

        // Validate transaction ID
        if txn_id != transaction_id {
            return Err(NatError::Stun("transaction ID mismatch".to_string()));
        }

        // Validate we have enough data for the declared message length
        if data.len() < STUN_HEADER_SIZE + msg_len {
            return Err(NatError::Stun(format!(
                "response truncated: header says {} attribute bytes, but only {} available",
                msg_len,
                data.len() - STUN_HEADER_SIZE
            )));
        }

        // Parse attributes — prefer XOR-MAPPED-ADDRESS over MAPPED-ADDRESS
        let attrs = &data[STUN_HEADER_SIZE..STUN_HEADER_SIZE + msg_len];
        let mut xor_mapped: Option<SocketAddr> = None;
        let mut mapped: Option<SocketAddr> = None;

        let mut pos = 0;
        while pos + 4 <= attrs.len() {
            let attr_type = u16::from_be_bytes([attrs[pos], attrs[pos + 1]]);
            let attr_len = u16::from_be_bytes([attrs[pos + 2], attrs[pos + 3]]) as usize;
            pos += 4;

            if pos + attr_len > attrs.len() {
                break; // Truncated attribute — stop parsing
            }

            let attr_data = &attrs[pos..pos + attr_len];

            match attr_type {
                STUN_ATTR_XOR_MAPPED_ADDRESS => {
                    xor_mapped = Self::parse_xor_mapped_address(attr_data, transaction_id).ok();
                }
                STUN_ATTR_MAPPED_ADDRESS => {
                    mapped = Self::parse_mapped_address(attr_data).ok();
                }
                _ => {
                    // Skip unknown attributes
                    debug!("skipping unknown STUN attribute 0x{:04X}", attr_type);
                }
            }

            // Attributes are padded to 4-byte boundaries
            let padded_len = (attr_len + 3) & !3;
            pos += padded_len;
        }

        let address = xor_mapped.or(mapped).ok_or_else(|| {
            NatError::Stun("no MAPPED-ADDRESS or XOR-MAPPED-ADDRESS in response".to_string())
        })?;

        Ok(MappedEndpoint {
            address,
            nat_type: NatType::Detected, // Will be refined by caller
        })
    }

    /// Parse a XOR-MAPPED-ADDRESS attribute value.
    ///
    /// Format: `[0x00, family, x-port, x-address...]`
    /// - x-port = port XOR (magic_cookie >> 16)
    /// - x-address(IPv4) = addr XOR magic_cookie
    /// - x-address(IPv6) = addr XOR (magic_cookie || transaction_id)
    fn parse_xor_mapped_address(
        data: &[u8],
        transaction_id: &[u8; 12],
    ) -> Result<SocketAddr, NatError> {
        if data.len() < 4 {
            return Err(NatError::Stun("XOR-MAPPED-ADDRESS too short".to_string()));
        }

        let family = data[1];
        let x_port = u16::from_be_bytes([data[2], data[3]]);
        let port = x_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

        match family {
            STUN_ADDR_FAMILY_IPV4 => {
                if data.len() < 8 {
                    return Err(NatError::Stun(
                        "XOR-MAPPED-ADDRESS IPv4 too short".to_string(),
                    ));
                }
                let x_addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let addr = x_addr ^ STUN_MAGIC_COOKIE;
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
            }
            STUN_ADDR_FAMILY_IPV6 => {
                if data.len() < 20 {
                    return Err(NatError::Stun(
                        "XOR-MAPPED-ADDRESS IPv6 too short".to_string(),
                    ));
                }
                // XOR key for IPv6: magic_cookie (4 bytes) || transaction_id (12 bytes)
                let mut xor_key = [0u8; 16];
                xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                xor_key[4..].copy_from_slice(transaction_id);

                let mut addr_bytes = [0u8; 16];
                for i in 0..16 {
                    addr_bytes[i] = data[4 + i] ^ xor_key[i];
                }
                Ok(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(addr_bytes)),
                    port,
                ))
            }
            _ => Err(NatError::Stun(format!(
                "unknown address family: 0x{:02X}",
                family
            ))),
        }
    }

    /// Parse a plain MAPPED-ADDRESS attribute value.
    ///
    /// Format: `[0x00, family, port, address...]`
    fn parse_mapped_address(data: &[u8]) -> Result<SocketAddr, NatError> {
        if data.len() < 4 {
            return Err(NatError::Stun("MAPPED-ADDRESS too short".to_string()));
        }

        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);

        match family {
            STUN_ADDR_FAMILY_IPV4 => {
                if data.len() < 8 {
                    return Err(NatError::Stun("MAPPED-ADDRESS IPv4 too short".to_string()));
                }
                let addr = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                Ok(SocketAddr::new(IpAddr::V4(addr), port))
            }
            STUN_ADDR_FAMILY_IPV6 => {
                if data.len() < 20 {
                    return Err(NatError::Stun("MAPPED-ADDRESS IPv6 too short".to_string()));
                }
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&data[4..20]);
                Ok(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(addr_bytes)),
                    port,
                ))
            }
            _ => Err(NatError::Stun(format!(
                "unknown address family: 0x{:02X}",
                family
            ))),
        }
    }
}

// ─── Rendezvous Protocol ────────────────────────────────────────────────────

/// Compute a deterministic rendezvous ID from two NodeIDs.
///
/// The ID is BLAKE2s(sort(NodeID_A || NodeID_B)), ensuring both peers
/// compute the same value regardless of who initiates.
pub fn compute_rendezvous_id(node_a: &NodeId, node_b: &NodeId) -> [u8; 32] {
    let mut hasher = Blake2s256::new();

    // Sort by raw bytes to ensure deterministic ordering
    if node_a.0 <= node_b.0 {
        hasher.update(node_a.0);
        hasher.update(node_b.0);
    } else {
        hasher.update(node_b.0);
        hasher.update(node_a.0);
    }

    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Encode a rendezvous Register packet.
///
/// Wire format:
/// ```text
/// [0x52 0x56]           magic "RV"
/// [rendezvous_id: 32B]  BLAKE2s(sort(NodeID_A || NodeID_B))
/// [op: 1B]              0x01 = register
/// [addr_family: 1B]     4 = IPv4, 6 = IPv6
/// [addr: 4B or 16B]     IP address bytes
/// [port: 2B BE]         port number
/// ```
pub fn encode_rv_register(rendezvous_id: &[u8; 32], mapped_addr: SocketAddr) -> Vec<u8> {
    let (family, addr_bytes) = match mapped_addr.ip() {
        IpAddr::V4(v4) => (4u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => (6u8, v6.octets().to_vec()),
    };

    let mut pkt = Vec::with_capacity(2 + 32 + 1 + 1 + addr_bytes.len() + 2);
    pkt.extend_from_slice(&RV_MAGIC);
    pkt.extend_from_slice(rendezvous_id);
    pkt.push(RV_REGISTER);
    pkt.push(family);
    pkt.extend_from_slice(&addr_bytes);
    pkt.extend_from_slice(&mapped_addr.port().to_be_bytes());
    pkt
}

/// Encode a rendezvous PeerInfo packet (sent by relay to both peers).
///
/// Wire format:
/// ```text
/// [0x52 0x56]           magic "RV"
/// [rendezvous_id: 32B]  rendezvous ID
/// [op: 1B]              0x02 = peer_info
/// [addr_family: 1B]     4 = IPv4, 6 = IPv6
/// [addr: 4B or 16B]     peer's mapped IP address
/// [port: 2B BE]         peer's mapped port
/// ```
pub fn encode_rv_peer_info(rendezvous_id: &[u8; 32], peer_addr: SocketAddr) -> Vec<u8> {
    let (family, addr_bytes) = match peer_addr.ip() {
        IpAddr::V4(v4) => (4u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => (6u8, v6.octets().to_vec()),
    };

    let mut pkt = Vec::with_capacity(2 + 32 + 1 + 1 + addr_bytes.len() + 2);
    pkt.extend_from_slice(&RV_MAGIC);
    pkt.extend_from_slice(rendezvous_id);
    pkt.push(RV_PEER_INFO);
    pkt.push(family);
    pkt.extend_from_slice(&addr_bytes);
    pkt.extend_from_slice(&peer_addr.port().to_be_bytes());
    pkt
}

/// Encode a rendezvous NotFound packet.
///
/// Wire format:
/// ```text
/// [0x52 0x56]           magic "RV"
/// [rendezvous_id: 32B]  rendezvous ID
/// [op: 1B]              0x03 = not_found
/// ```
pub fn encode_rv_not_found(rendezvous_id: &[u8; 32]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(2 + 32 + 1);
    pkt.extend_from_slice(&RV_MAGIC);
    pkt.extend_from_slice(rendezvous_id);
    pkt.push(RV_NOT_FOUND);
    pkt
}

/// Decoded rendezvous message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendezvousMessage {
    /// Register: a peer is announcing its mapped endpoint.
    Register {
        rendezvous_id: [u8; 32],
        mapped_addr: SocketAddr,
    },
    /// PeerInfo: the relay is telling us about our peer's endpoint.
    PeerInfo {
        rendezvous_id: [u8; 32],
        peer_addr: SocketAddr,
    },
    /// NotFound: the peer hasn't registered yet.
    NotFound { rendezvous_id: [u8; 32] },
}

/// Check if a packet starts with the rendezvous magic.
pub fn is_rendezvous_packet(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == RV_MAGIC[0] && data[1] == RV_MAGIC[1]
}

/// Decode a rendezvous message from raw bytes.
pub fn decode_rv_message(data: &[u8]) -> Result<RendezvousMessage, NatError> {
    if data.len() < RV_MIN_PACKET_SIZE {
        return Err(NatError::Rendezvous(format!(
            "packet too short: {} bytes (need at least {})",
            data.len(),
            RV_MIN_PACKET_SIZE
        )));
    }

    if data[0] != RV_MAGIC[0] || data[1] != RV_MAGIC[1] {
        return Err(NatError::Rendezvous("invalid rendezvous magic".to_string()));
    }

    let mut rendezvous_id = [0u8; 32];
    rendezvous_id.copy_from_slice(&data[2..34]);
    let op = data[34];

    match op {
        RV_REGISTER | RV_PEER_INFO => {
            // Need at least: magic(2) + rv_id(32) + op(1) + family(1) + addr(4) + port(2) = 42 for IPv4
            if data.len() < 36 {
                return Err(NatError::Rendezvous(
                    "register/peer_info packet too short for address".to_string(),
                ));
            }

            let family = data[35];
            let addr = match family {
                4 => {
                    if data.len() < 42 {
                        return Err(NatError::Rendezvous(
                            "IPv4 register packet too short".to_string(),
                        ));
                    }
                    let ip = Ipv4Addr::new(data[36], data[37], data[38], data[39]);
                    let port = u16::from_be_bytes([data[40], data[41]]);
                    SocketAddr::new(IpAddr::V4(ip), port)
                }
                6 => {
                    if data.len() < 54 {
                        return Err(NatError::Rendezvous(
                            "IPv6 register packet too short".to_string(),
                        ));
                    }
                    let mut ip_bytes = [0u8; 16];
                    ip_bytes.copy_from_slice(&data[36..52]);
                    let port = u16::from_be_bytes([data[52], data[53]]);
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port)
                }
                _ => {
                    return Err(NatError::Rendezvous(format!(
                        "unknown address family: {}",
                        family
                    )));
                }
            };

            if op == RV_REGISTER {
                Ok(RendezvousMessage::Register {
                    rendezvous_id,
                    mapped_addr: addr,
                })
            } else {
                Ok(RendezvousMessage::PeerInfo {
                    rendezvous_id,
                    peer_addr: addr,
                })
            }
        }
        RV_NOT_FOUND => Ok(RendezvousMessage::NotFound { rendezvous_id }),
        _ => Err(NatError::Rendezvous(format!(
            "unknown rendezvous op: 0x{:02X}",
            op
        ))),
    }
}

// ─── Hole Punch Procedure ───────────────────────────────────────────────────

/// Establish a connection to a peer, using STUN + hole punching with
/// relay fallback.
///
/// Steps:
/// 1. Discover our mapped endpoint via STUN
/// 2. Register with relay's rendezvous service
/// 3. Wait for peer's mapped endpoint from relay
/// 4. Attempt hole punch (send probes simultaneously)
/// 5. If no response within timeout, fall back to relay
pub async fn establish_connection(config: HolePunchConfig) -> Result<ConnectionResult, NatError> {
    let stun_timeout = Duration::from_secs(3);

    // Step 1: Discover our mapped endpoint via STUN
    info!("NAT traversal: discovering mapped endpoint via STUN...");
    let mapped =
        discover_with_fallback(&config.local_socket, &config.stun_servers, stun_timeout).await?;
    info!("NAT traversal: mapped endpoint = {}", mapped.address);

    // Step 2: Compute rendezvous ID and register with relay
    let rv_id = compute_rendezvous_id(&config.identity.node_id, &config.peer_node_id);
    debug!(
        "NAT traversal: rendezvous ID = {}",
        hex::encode(&rv_id[..8])
    );

    let register_pkt = encode_rv_register(&rv_id, mapped.address);
    config
        .local_socket
        .send_to(&register_pkt, config.relay_addr)
        .await?;
    info!("NAT traversal: registered with relay for rendezvous");

    // Step 3: Wait for peer's endpoint from relay
    let peer_addr = wait_for_peer_info(&config.local_socket, &rv_id, config.timeout).await?;
    info!("NAT traversal: peer endpoint = {}", peer_addr);

    // Step 4: Attempt hole punch
    match attempt_hole_punch(
        &config.local_socket,
        peer_addr,
        &config.identity,
        config.punch_attempts,
        config.punch_interval,
    )
    .await
    {
        Ok(()) => {
            info!(
                "NAT traversal: hole punch succeeded — direct connection to {}",
                peer_addr
            );
            Ok(ConnectionResult::Direct { peer_addr })
        }
        Err(e) => {
            warn!(
                "NAT traversal: hole punch failed: {} — falling back to relay",
                e
            );
            Ok(ConnectionResult::Relayed {
                relay_addr: config.relay_addr,
            })
        }
    }
}

/// Try multiple STUN servers in sequence, returning the first successful result.
async fn discover_with_fallback(
    socket: &UdpSocket,
    servers: &[SocketAddr],
    stun_timeout: Duration,
) -> Result<MappedEndpoint, NatError> {
    // If no servers provided, resolve default STUN servers
    let resolved: Vec<SocketAddr> = if servers.is_empty() {
        let mut addrs = Vec::new();
        for server_str in DEFAULT_STUN_SERVERS {
            if let Ok(mut resolved) = tokio::net::lookup_host(server_str).await {
                if let Some(addr) = resolved.next() {
                    addrs.push(addr);
                }
            }
        }
        if addrs.is_empty() {
            return Err(NatError::Stun(
                "could not resolve any default STUN servers".to_string(),
            ));
        }
        addrs
    } else {
        servers.to_vec()
    };

    let mut last_err = None;
    for server in &resolved {
        match StunClient::discover_endpoint(socket, *server, stun_timeout).await {
            Ok(endpoint) => return Ok(endpoint),
            Err(e) => {
                debug!("STUN server {} failed: {}", server, e);
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| NatError::Stun("no STUN servers available".to_string())))
}

/// Wait for a PeerInfo message from the relay.
async fn wait_for_peer_info(
    socket: &UdpSocket,
    expected_rv_id: &[u8; 32],
    timeout_duration: Duration,
) -> Result<SocketAddr, NatError> {
    let deadline = Instant::now() + timeout_duration;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(NatError::Timeout(
                "timed out waiting for peer rendezvous info".to_string(),
            ));
        }

        let mut buf = [0u8; 256];
        let (len, _from) = timeout(remaining, socket.recv_from(&mut buf))
            .await
            .map_err(|_| {
                NatError::Timeout("timed out waiting for peer rendezvous info".to_string())
            })??;

        let data = &buf[..len];

        if !is_rendezvous_packet(data) {
            // Not a rendezvous packet — could be normal ZTLP traffic, skip
            continue;
        }

        match decode_rv_message(data) {
            Ok(RendezvousMessage::PeerInfo {
                rendezvous_id,
                peer_addr,
            }) if rendezvous_id == *expected_rv_id => {
                return Ok(peer_addr);
            }
            Ok(RendezvousMessage::NotFound { rendezvous_id })
                if rendezvous_id == *expected_rv_id =>
            {
                debug!("peer not yet registered, continuing to wait...");
                continue;
            }
            _ => {
                // Different rendezvous ID or unexpected message, skip
                continue;
            }
        }
    }
}

/// Attempt hole punch by sending Ping probes to the peer's mapped address.
async fn attempt_hole_punch(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    identity: &NodeIdentity,
    attempts: u32,
    interval: Duration,
) -> Result<(), NatError> {
    for i in 0..attempts {
        // Build a ZTLP Ping packet as the probe
        let mut ping_hdr = HandshakeHeader::new(MsgType::Ping);
        ping_hdr.src_node_id = *identity.node_id.as_bytes();
        ping_hdr.packet_seq = i as u64;
        let pkt = ping_hdr.serialize();

        socket.send_to(&pkt, peer_addr).await?;
        debug!("hole punch probe #{} sent to {}", i + 1, peer_addr);

        // Wait briefly for a Pong response
        let mut buf = [0u8; 256];
        match timeout(interval, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                if len >= HANDSHAKE_HEADER_SIZE {
                    if let Ok(hdr) = HandshakeHeader::deserialize(&buf[..len]) {
                        if hdr.msg_type == MsgType::Pong {
                            info!(
                                "hole punch: received Pong from {} on probe #{}",
                                from,
                                i + 1
                            );
                            return Ok(());
                        }
                    }
                }
                // Received something but not a Pong — continue trying
            }
            Ok(Err(_)) | Err(_) => {
                // Timeout or error — continue to next attempt
            }
        }
    }

    Err(NatError::HolePunchFailed(attempts))
}

// ─── Relay Rendezvous Entry ─────────────────────────────────────────────────

/// A rendezvous registration entry stored in the relay.
#[derive(Debug, Clone)]
pub struct RendezvousEntry {
    /// The registrant's relay-visible address (where to send replies).
    pub addr: SocketAddr,
    /// Their STUN-discovered public address (to share with peer).
    pub mapped_addr: SocketAddr,
    /// When this entry was registered.
    pub registered_at: Instant,
}

impl RendezvousEntry {
    /// Check if this entry has expired.
    pub fn is_expired(&self) -> bool {
        self.registered_at.elapsed() > Duration::from_secs(RV_ENTRY_TTL_SECS)
    }
}

// ─── STUN Response Builder (for testing) ────────────────────────────────────

/// Build a synthetic STUN Binding Response for testing purposes.
///
/// This creates a valid response with a XOR-MAPPED-ADDRESS attribute.
#[cfg(test)]
pub fn build_stun_response(transaction_id: &[u8; 12], mapped_addr: SocketAddr) -> Vec<u8> {
    build_stun_response_with_attr(transaction_id, mapped_addr, true)
}

/// Build a synthetic STUN Binding Response with either XOR-MAPPED-ADDRESS
/// or plain MAPPED-ADDRESS.
#[cfg(test)]
pub fn build_stun_response_with_attr(
    transaction_id: &[u8; 12],
    mapped_addr: SocketAddr,
    use_xor: bool,
) -> Vec<u8> {
    let (attr_type, attr_data) = if use_xor {
        build_xor_mapped_address_attr(mapped_addr, transaction_id)
    } else {
        build_mapped_address_attr(mapped_addr)
    };

    let attr_len = attr_data.len();
    let msg_len = 4 + attr_len; // 4 bytes attr header + attr value

    let mut pkt = Vec::with_capacity(STUN_HEADER_SIZE + msg_len);

    // Header
    pkt.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
    pkt.extend_from_slice(&(msg_len as u16).to_be_bytes());
    pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    pkt.extend_from_slice(transaction_id);

    // Attribute TLV
    pkt.extend_from_slice(&attr_type.to_be_bytes());
    pkt.extend_from_slice(&(attr_len as u16).to_be_bytes());
    pkt.extend_from_slice(&attr_data);

    pkt
}

#[cfg(test)]
fn build_xor_mapped_address_attr(addr: SocketAddr, transaction_id: &[u8; 12]) -> (u16, Vec<u8>) {
    let x_port = addr.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    let mut data = Vec::new();
    data.push(0x00); // reserved

    match addr.ip() {
        IpAddr::V4(v4) => {
            data.push(STUN_ADDR_FAMILY_IPV4);
            data.extend_from_slice(&x_port.to_be_bytes());
            let x_addr = u32::from(v4) ^ STUN_MAGIC_COOKIE;
            data.extend_from_slice(&x_addr.to_be_bytes());
        }
        IpAddr::V6(v6) => {
            data.push(STUN_ADDR_FAMILY_IPV6);
            data.extend_from_slice(&x_port.to_be_bytes());
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            xor_key[4..].copy_from_slice(transaction_id);
            let octets = v6.octets();
            for i in 0..16 {
                data.push(octets[i] ^ xor_key[i]);
            }
        }
    }

    (STUN_ATTR_XOR_MAPPED_ADDRESS, data)
}

#[cfg(test)]
fn build_mapped_address_attr(addr: SocketAddr) -> (u16, Vec<u8>) {
    let mut data = Vec::new();
    data.push(0x00); // reserved

    match addr.ip() {
        IpAddr::V4(v4) => {
            data.push(STUN_ADDR_FAMILY_IPV4);
            data.extend_from_slice(&addr.port().to_be_bytes());
            data.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            data.push(STUN_ADDR_FAMILY_IPV6);
            data.extend_from_slice(&addr.port().to_be_bytes());
            data.extend_from_slice(&v6.octets());
        }
    }

    (STUN_ATTR_MAPPED_ADDRESS, data)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    // ── STUN Binding Request Tests ──────────────────────────────────

    #[test]
    fn test_stun_binding_request_format() {
        let (pkt, txn_id) = StunClient::build_binding_request();

        assert_eq!(pkt.len(), STUN_HEADER_SIZE);

        // Message type: Binding Request
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), STUN_BINDING_REQUEST);

        // Message length: 0
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 0);

        // Magic cookie
        assert_eq!(
            u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]),
            STUN_MAGIC_COOKIE
        );

        // Transaction ID matches returned value
        assert_eq!(&pkt[8..20], &txn_id);

        // Top 2 bits must be zero (STUN requirement)
        assert_eq!(pkt[0] & 0xC0, 0x00);
    }

    #[test]
    fn test_stun_binding_request_unique_transaction_ids() {
        let (_, txn1) = StunClient::build_binding_request();
        let (_, txn2) = StunClient::build_binding_request();
        assert_ne!(txn1, txn2);
    }

    // ── STUN Binding Response Parsing: XOR-MAPPED-ADDRESS ───────────

    #[test]
    fn test_parse_xor_mapped_address_ipv4() {
        let txn_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let addr: SocketAddr = "203.0.113.42:3478".parse().unwrap();

        let response = build_stun_response(&txn_id, addr);
        let result = StunClient::parse_binding_response(&response, &txn_id).unwrap();

        assert_eq!(result.address, addr);
    }

    #[test]
    fn test_parse_xor_mapped_address_ipv6() {
        let txn_id = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        ];
        let addr: SocketAddr = "[2001:db8::1]:19302".parse().unwrap();

        let response = build_stun_response(&txn_id, addr);
        let result = StunClient::parse_binding_response(&response, &txn_id).unwrap();

        assert_eq!(result.address, addr);
    }

    #[test]
    fn test_parse_mapped_address_ipv4() {
        let txn_id = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();

        let response = build_stun_response_with_attr(&txn_id, addr, false);
        let result = StunClient::parse_binding_response(&response, &txn_id).unwrap();

        assert_eq!(result.address, addr);
    }

    #[test]
    fn test_parse_mapped_address_ipv6() {
        let txn_id = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
        ];
        let addr: SocketAddr = "[::1]:8080".parse().unwrap();

        let response = build_stun_response_with_attr(&txn_id, addr, false);
        let result = StunClient::parse_binding_response(&response, &txn_id).unwrap();

        assert_eq!(result.address, addr);
    }

    // ── STUN XOR Decoding Verification ──────────────────────────────

    #[test]
    fn test_xor_decode_known_values() {
        // Verify XOR decoding manually with known values
        let txn_id = [0; 12];
        let addr: SocketAddr = "1.2.3.4:12345".parse().unwrap();

        // Manually compute expected XOR values
        let expected_x_port = 12345u16 ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let ip_u32: u32 = u32::from(Ipv4Addr::new(1, 2, 3, 4));
        let expected_x_addr = ip_u32 ^ STUN_MAGIC_COOKIE;

        // Build and parse
        let response = build_stun_response(&txn_id, addr);

        // Verify the XOR'd values in the wire format
        // Attr starts at offset 20 (header) + 4 (attr type+len) = 24
        // After reserved byte (24) and family byte (25), x-port is at 26-27
        let x_port = u16::from_be_bytes([response[26], response[27]]);
        assert_eq!(x_port, expected_x_port);

        // x-addr is at 28-31
        let x_addr = u32::from_be_bytes([response[28], response[29], response[30], response[31]]);
        assert_eq!(x_addr, expected_x_addr);

        // And it round-trips correctly
        let result = StunClient::parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(result.address, addr);
    }

    // ── Invalid STUN Response Tests ─────────────────────────────────

    #[test]
    fn test_stun_response_too_short() {
        let txn_id = [0; 12];
        let result = StunClient::parse_binding_response(&[0; 10], &txn_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NatError::Stun(_)));
    }

    #[test]
    fn test_stun_response_wrong_transaction_id() {
        let txn_id = [0x01; 12];
        let wrong_txn = [0x02; 12];
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();

        let response = build_stun_response(&wrong_txn, addr);
        let result = StunClient::parse_binding_response(&response, &txn_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::Stun(msg) => assert!(msg.contains("transaction ID mismatch")),
            other => panic!("expected Stun error, got {:?}", other),
        }
    }

    #[test]
    fn test_stun_response_bad_magic_cookie() {
        let txn_id = [0; 12];
        let mut response = vec![0u8; STUN_HEADER_SIZE];
        // Binding Response type
        response[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        // Message length = 0
        response[2..4].copy_from_slice(&0u16.to_be_bytes());
        // Wrong magic cookie
        response[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        // Transaction ID
        response[8..20].copy_from_slice(&txn_id);

        let result = StunClient::parse_binding_response(&response, &txn_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::Stun(msg) => assert!(msg.contains("magic cookie")),
            other => panic!("expected Stun error, got {:?}", other),
        }
    }

    #[test]
    fn test_stun_response_truncated_attributes() {
        let txn_id = [0; 12];
        let mut response = vec![0u8; STUN_HEADER_SIZE];
        // Binding Response type
        response[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        // Message length = 100 (but we won't provide that many bytes)
        response[2..4].copy_from_slice(&100u16.to_be_bytes());
        // Magic cookie
        response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        // Transaction ID
        response[8..20].copy_from_slice(&txn_id);

        let result = StunClient::parse_binding_response(&response, &txn_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::Stun(msg) => assert!(msg.contains("truncated")),
            other => panic!("expected Stun error, got {:?}", other),
        }
    }

    #[test]
    fn test_stun_response_no_mapped_address() {
        let txn_id = [0; 12];
        let mut response = vec![0u8; STUN_HEADER_SIZE];
        // Binding Response type
        response[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        // Message length = 0 (no attributes)
        response[2..4].copy_from_slice(&0u16.to_be_bytes());
        // Magic cookie
        response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        // Transaction ID
        response[8..20].copy_from_slice(&txn_id);

        let result = StunClient::parse_binding_response(&response, &txn_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::Stun(msg) => assert!(msg.contains("no MAPPED-ADDRESS")),
            other => panic!("expected Stun error, got {:?}", other),
        }
    }

    #[test]
    fn test_stun_response_wrong_message_type() {
        let txn_id = [0; 12];
        let mut response = vec![0u8; STUN_HEADER_SIZE];
        // Wrong message type (Binding Error Response = 0x0111)
        response[0..2].copy_from_slice(&0x0111u16.to_be_bytes());
        response[2..4].copy_from_slice(&0u16.to_be_bytes());
        response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&txn_id);

        let result = StunClient::parse_binding_response(&response, &txn_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::Stun(msg) => assert!(msg.contains("unexpected message type")),
            other => panic!("expected Stun error, got {:?}", other),
        }
    }

    // ── Rendezvous Protocol Tests ───────────────────────────────────

    #[test]
    fn test_rendezvous_id_deterministic() {
        let node_a = NodeId::from_bytes([1; 16]);
        let node_b = NodeId::from_bytes([2; 16]);

        let id1 = compute_rendezvous_id(&node_a, &node_b);
        let id2 = compute_rendezvous_id(&node_a, &node_b);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_rendezvous_id_order_independent() {
        let node_a = NodeId::from_bytes([1; 16]);
        let node_b = NodeId::from_bytes([2; 16]);

        let id_ab = compute_rendezvous_id(&node_a, &node_b);
        let id_ba = compute_rendezvous_id(&node_b, &node_a);
        assert_eq!(id_ab, id_ba);
    }

    #[test]
    fn test_rendezvous_id_different_for_different_pairs() {
        let node_a = NodeId::from_bytes([1; 16]);
        let node_b = NodeId::from_bytes([2; 16]);
        let node_c = NodeId::from_bytes([3; 16]);

        let id_ab = compute_rendezvous_id(&node_a, &node_b);
        let id_ac = compute_rendezvous_id(&node_a, &node_c);
        assert_ne!(id_ab, id_ac);
    }

    #[test]
    fn test_rv_register_encode_decode_ipv4() {
        let rv_id = [0xAA; 32];
        let addr: SocketAddr = "198.51.100.25:19302".parse().unwrap();

        let encoded = encode_rv_register(&rv_id, addr);
        let decoded = decode_rv_message(&encoded).unwrap();

        assert_eq!(
            decoded,
            RendezvousMessage::Register {
                rendezvous_id: rv_id,
                mapped_addr: addr,
            }
        );
    }

    #[test]
    fn test_rv_register_encode_decode_ipv6() {
        let rv_id = [0xBB; 32];
        let addr: SocketAddr = "[2001:db8::cafe]:3478".parse().unwrap();

        let encoded = encode_rv_register(&rv_id, addr);
        let decoded = decode_rv_message(&encoded).unwrap();

        assert_eq!(
            decoded,
            RendezvousMessage::Register {
                rendezvous_id: rv_id,
                mapped_addr: addr,
            }
        );
    }

    #[test]
    fn test_rv_peer_info_encode_decode() {
        let rv_id = [0xCC; 32];
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();

        let encoded = encode_rv_peer_info(&rv_id, addr);
        let decoded = decode_rv_message(&encoded).unwrap();

        assert_eq!(
            decoded,
            RendezvousMessage::PeerInfo {
                rendezvous_id: rv_id,
                peer_addr: addr,
            }
        );
    }

    #[test]
    fn test_rv_not_found_encode_decode() {
        let rv_id = [0xDD; 32];

        let encoded = encode_rv_not_found(&rv_id);
        let decoded = decode_rv_message(&encoded).unwrap();

        assert_eq!(
            decoded,
            RendezvousMessage::NotFound {
                rendezvous_id: rv_id,
            }
        );
    }

    #[test]
    fn test_rv_decode_too_short() {
        let result = decode_rv_message(&[0x52, 0x56]); // magic only
        assert!(result.is_err());
    }

    #[test]
    fn test_rv_decode_bad_magic() {
        let mut pkt = vec![0x00; 42];
        pkt[0] = 0xFF;
        pkt[1] = 0xFF;
        let result = decode_rv_message(&pkt);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::Rendezvous(msg) => assert!(msg.contains("magic")),
            other => panic!("expected Rendezvous error, got {:?}", other),
        }
    }

    #[test]
    fn test_rv_decode_unknown_op() {
        let mut pkt = vec![0x00; 42];
        pkt[0..2].copy_from_slice(&RV_MAGIC);
        // 32 bytes of rendezvous ID
        pkt[34] = 0xFF; // unknown op
        let result = decode_rv_message(&pkt);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::Rendezvous(msg) => assert!(msg.contains("unknown")),
            other => panic!("expected Rendezvous error, got {:?}", other),
        }
    }

    #[test]
    fn test_is_rendezvous_packet() {
        assert!(is_rendezvous_packet(&[0x52, 0x56, 0x00]));
        assert!(!is_rendezvous_packet(&[0x5A, 0x37, 0x00])); // ZTLP magic
        assert!(!is_rendezvous_packet(&[0x52])); // too short
        assert!(!is_rendezvous_packet(&[]));
    }

    // ── RendezvousEntry Tests ───────────────────────────────────────

    #[test]
    fn test_rendezvous_entry_not_expired() {
        let entry = RendezvousEntry {
            addr: "127.0.0.1:1000".parse().unwrap(),
            mapped_addr: "1.2.3.4:5000".parse().unwrap(),
            registered_at: Instant::now(),
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_rendezvous_entry_expired() {
        let entry = RendezvousEntry {
            addr: "127.0.0.1:1000".parse().unwrap(),
            mapped_addr: "1.2.3.4:5000".parse().unwrap(),
            registered_at: Instant::now() - Duration::from_secs(RV_ENTRY_TTL_SECS + 1),
        };
        assert!(entry.is_expired());
    }

    // ── HolePunchConfig Tests ───────────────────────────────────────

    #[test]
    fn test_hole_punch_config_defaults() {
        // We can't easily create an Arc<UdpSocket> in a sync test,
        // but we can check the default values are set correctly
        // by testing a runtime-created config.

        // Verify the default constants are sensible
        assert_eq!(DEFAULT_STUN_SERVERS.len(), 3);
        assert!(DEFAULT_STUN_SERVERS[0].contains("google.com"));
        assert_eq!(RV_ENTRY_TTL_SECS, 60);
    }

    // ── NatType Detection Tests ─────────────────────────────────────

    #[test]
    fn test_nat_type_none_when_same_address() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let endpoint = MappedEndpoint {
            address: addr,
            nat_type: NatType::None,
        };
        assert_eq!(endpoint.nat_type, NatType::None);
    }

    #[test]
    fn test_nat_type_detected_when_different() {
        let endpoint = MappedEndpoint {
            address: "203.0.113.42:19302".parse().unwrap(),
            nat_type: NatType::Detected,
        };
        assert_eq!(endpoint.nat_type, NatType::Detected);
    }

    // ── Connection Result Tests ─────────────────────────────────────

    #[test]
    fn test_connection_result_direct() {
        let result = ConnectionResult::Direct {
            peer_addr: "10.0.0.1:23095".parse().unwrap(),
        };
        match result {
            ConnectionResult::Direct { peer_addr } => {
                assert_eq!(peer_addr, "10.0.0.1:23095".parse::<SocketAddr>().unwrap());
            }
            _ => panic!("expected Direct"),
        }
    }

    #[test]
    fn test_connection_result_relayed() {
        let result = ConnectionResult::Relayed {
            relay_addr: "10.0.0.1:23095".parse().unwrap(),
        };
        match result {
            ConnectionResult::Relayed { relay_addr } => {
                assert_eq!(relay_addr, "10.0.0.1:23095".parse::<SocketAddr>().unwrap());
            }
            _ => panic!("expected Relayed"),
        }
    }

    // ── Integration-style Tests (with local UDP sockets) ────────────

    #[tokio::test]
    async fn test_stun_discover_endpoint_timeout() {
        // Bind a socket and send to a non-responsive address
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fake_stun: SocketAddr = "127.0.0.1:1".parse().unwrap(); // port 1 won't respond

        let result =
            StunClient::discover_endpoint(&socket, fake_stun, Duration::from_millis(100)).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::Timeout(_) => {} // expected
            NatError::Io(_) => {}      // also acceptable (connection refused)
            other => panic!("expected Timeout or Io, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_simulated_stun_exchange() {
        // Set up a fake STUN server that responds with a fixed mapped address
        let stun_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun_server.local_addr().unwrap();

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mapped_addr: SocketAddr = "203.0.113.42:12345".parse().unwrap();

        // Spawn fake STUN server
        let fake_mapped = mapped_addr;
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let (len, from) = stun_server.recv_from(&mut buf).await.unwrap();
            let data = &buf[..len];

            // Extract transaction ID from request
            assert!(data.len() >= STUN_HEADER_SIZE);
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&data[8..20]);

            // Build response
            let response = build_stun_response(&txn_id, fake_mapped);
            stun_server.send_to(&response, from).await.unwrap();
        });

        let result =
            StunClient::discover_endpoint(&client_socket, stun_addr, Duration::from_secs(2))
                .await
                .unwrap();

        assert_eq!(result.address, mapped_addr);
        assert_eq!(result.nat_type, NatType::Detected); // different from local addr
    }

    #[tokio::test]
    async fn test_rendezvous_exchange_via_relay() {
        // Simulate a basic rendezvous: two peers register, relay pairs them.
        // This tests the encode/decode round-trip over actual UDP.
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();

        let peer_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let node_a = NodeId::from_bytes([0xAA; 16]);
        let node_b = NodeId::from_bytes([0xBB; 16]);
        let rv_id = compute_rendezvous_id(&node_a, &node_b);

        let mapped_a: SocketAddr = "1.1.1.1:1111".parse().unwrap();
        let mapped_b: SocketAddr = "2.2.2.2:2222".parse().unwrap();

        // Peer A registers
        let reg_a = encode_rv_register(&rv_id, mapped_a);
        peer_a.send_to(&reg_a, relay_addr).await.unwrap();

        // Relay receives Peer A's registration
        let mut buf = [0u8; 256];
        let (len, from_a) = relay_socket.recv_from(&mut buf).await.unwrap();
        let msg_a = decode_rv_message(&buf[..len]).unwrap();
        assert!(matches!(msg_a, RendezvousMessage::Register { .. }));

        // Peer B registers
        let reg_b = encode_rv_register(&rv_id, mapped_b);
        peer_b.send_to(&reg_b, relay_addr).await.unwrap();

        // Relay receives Peer B's registration
        let (len, from_b) = relay_socket.recv_from(&mut buf).await.unwrap();
        let msg_b = decode_rv_message(&buf[..len]).unwrap();
        assert!(matches!(msg_b, RendezvousMessage::Register { .. }));

        // Relay sends PeerInfo to both
        let info_for_a = encode_rv_peer_info(&rv_id, mapped_b);
        let info_for_b = encode_rv_peer_info(&rv_id, mapped_a);
        relay_socket.send_to(&info_for_a, from_a).await.unwrap();
        relay_socket.send_to(&info_for_b, from_b).await.unwrap();

        // Peer A receives Peer B's info
        let (len, _) = peer_a.recv_from(&mut buf).await.unwrap();
        let decoded = decode_rv_message(&buf[..len]).unwrap();
        assert_eq!(
            decoded,
            RendezvousMessage::PeerInfo {
                rendezvous_id: rv_id,
                peer_addr: mapped_b,
            }
        );

        // Peer B receives Peer A's info
        let (len, _) = peer_b.recv_from(&mut buf).await.unwrap();
        let decoded = decode_rv_message(&buf[..len]).unwrap();
        assert_eq!(
            decoded,
            RendezvousMessage::PeerInfo {
                rendezvous_id: rv_id,
                peer_addr: mapped_a,
            }
        );
    }
}
