//! Packet router for iOS utun (TUN) interface.
//!
//! Provides a userspace TCP/IP handler that processes raw IPv4 packets from
//! the iOS tunnel interface (`NEPacketTunnelProvider`). Maps destination IPs
//! in a virtual subnet (e.g., `10.122.0.0/16`) to ZTLP service names and
//! creates multiplexed streams to the gateway.
//!
//! ## Architecture
//!
//! ```text
//! App → kernel routes 10.122.0.0/16 → utun → readPackets() → Swift
//!   → ztlp_router_write_packet() → PacketRouter parses IP/TCP
//!   → creates ZTLP mux stream → gateway → backend
//!
//! ← gateway response → PacketRouter constructs IP/TCP response
//!   → ztlp_router_read_packet() → Swift → writePackets()
//!   → utun → kernel → App
//! ```
//!
//! ## Service Map
//!
//! Each VIP address in the tunnel subnet maps to a ZTLP service name:
//! - `10.122.0.1` → "vault"
//! - `10.122.0.2` → "http"
//!
//! Apps connect to service VIPs using standard ports (80, 443, 22).

#![deny(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::Instant;

// ── Constants ───────────────────────────────────────────────────────────

/// TCP protocol number in IPv4 header.
const IPPROTO_TCP: u8 = 6;

/// Fixed TCP window size advertised to clients.
const TCP_WINDOW_SIZE: u16 = 65535;

/// Maximum Segment Size — accounts for ZTLP overhead within 1400 MTU.
const TCP_MSS: u16 = 1360;

/// Flow inactivity timeout in seconds.
const FLOW_TIMEOUT_SECS: u64 = 120;

/// Maximum packets in outbound queue. Bounds memory for iOS NE (15MB limit).
/// 256 packets × ~1400 bytes = ~350KB.
const OUTBOUND_MAX_PACKETS: usize = 256;

/// Default tunnel subnet: 10.122.0.0/16.
const DEFAULT_SUBNET: Ipv4Addr = Ipv4Addr::new(10, 122, 0, 0);
const DEFAULT_PREFIX_LEN: u32 = 16;

/// Minimum IPv4 header length (20 bytes, no options).
const IPV4_MIN_HEADER_LEN: usize = 20;

/// Minimum TCP header length (20 bytes, no options).
const TCP_MIN_HEADER_LEN: usize = 20;

// ── TCP Flags ───────────────────────────────────────────────────────────

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

// ── IPv4 Header ─────────────────────────────────────────────────────────

/// Parsed IPv4 header.
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    /// Internet Header Length in 32-bit words (typically 5 = 20 bytes).
    pub ihl: u8,
    /// Total packet length including header and payload.
    pub total_length: u16,
    /// Identification field.
    pub identification: u16,
    /// Time to live.
    pub ttl: u8,
    /// Protocol (6 = TCP).
    pub protocol: u8,
    /// Source IP address.
    pub src_ip: Ipv4Addr,
    /// Destination IP address.
    pub dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    /// Header length in bytes.
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }
}

/// Parse an IPv4 header from a raw packet.
///
/// Returns `None` if the packet is too short or not IPv4.
pub fn parse_ipv4(packet: &[u8]) -> Option<Ipv4Header> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    let ihl = packet[0] & 0x0F;
    if ihl < 5 {
        return None;
    }

    let header_len = (ihl as usize) * 4;
    if packet.len() < header_len {
        return None;
    }

    let total_length = u16::from_be_bytes([packet[2], packet[3]]);
    let identification = u16::from_be_bytes([packet[4], packet[5]]);
    let ttl = packet[8];
    let protocol = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    Some(Ipv4Header {
        ihl,
        total_length,
        identification,
        ttl,
        protocol,
        src_ip,
        dst_ip,
    })
}

// ── TCP Header ──────────────────────────────────────────────────────────

/// Parsed TCP header.
#[derive(Debug, Clone)]
pub struct TcpHeader {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgment number.
    pub ack: u32,
    /// Data offset in 32-bit words (header length / 4).
    pub data_offset: u8,
    /// TCP flags (SYN, ACK, FIN, RST, PSH).
    pub flags: u8,
    /// Window size.
    pub window: u16,
}

impl TcpHeader {
    /// TCP header length in bytes.
    pub fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }

    /// Check if SYN flag is set.
    pub fn is_syn(&self) -> bool {
        self.flags & TCP_SYN != 0
    }

    /// Check if ACK flag is set.
    pub fn is_ack(&self) -> bool {
        self.flags & TCP_ACK != 0
    }

    /// Check if FIN flag is set.
    pub fn is_fin(&self) -> bool {
        self.flags & TCP_FIN != 0
    }

    /// Check if RST flag is set.
    pub fn is_rst(&self) -> bool {
        self.flags & TCP_RST != 0
    }

    /// Check if PSH flag is set.
    pub fn is_psh(&self) -> bool {
        self.flags & TCP_PSH != 0
    }
}

/// Parse a TCP header from the IPv4 payload.
///
/// Returns `None` if the payload is too short.
pub fn parse_tcp(payload: &[u8]) -> Option<TcpHeader> {
    if payload.len() < TCP_MIN_HEADER_LEN {
        return None;
    }

    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ack = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let data_offset = payload[12] >> 4;

    if data_offset < 5 {
        return None;
    }

    let header_len = (data_offset as usize) * 4;
    if payload.len() < header_len {
        return None;
    }

    let flags = payload[13];
    let window = u16::from_be_bytes([payload[14], payload[15]]);

    Some(TcpHeader {
        src_port,
        dst_port,
        seq,
        ack,
        data_offset,
        flags,
        window,
    })
}

// ── Checksum Helpers ────────────────────────────────────────────────────

/// Compute the standard IPv4 header checksum (ones-complement sum).
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        // Include all bytes — caller zeroes checksum field when computing,
        // or passes filled checksum when verifying (result will be 0).
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    // If odd number of bytes, pad with zero
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Compute TCP checksum with pseudo-header.
pub fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    let tcp_len = tcp_segment.len() as u16;

    let mut sum: u32 = 0;

    // Pseudo-header
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += IPPROTO_TCP as u32;
    sum += tcp_len as u32;

    // TCP segment — include all bytes including checksum field.
    // When computing: caller passes segment with checksum zeroed → result is the checksum.
    // When verifying: caller passes segment with checksum filled → result is 0.
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }

    // Fold
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

// ── Packet Construction ─────────────────────────────────────────────────

/// Build a TCP segment (header + payload) with flags and options.
#[allow(clippy::too_many_arguments)]
fn build_tcp_segment(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    include_mss: bool,
) -> Vec<u8> {
    // Calculate header length: 20 base + optional MSS (4 bytes)
    let options_len = if include_mss { 4 } else { 0 };
    let header_len = TCP_MIN_HEADER_LEN + options_len;
    let data_offset = (header_len / 4) as u8;

    let mut segment = Vec::with_capacity(header_len + payload.len());

    // Source port
    segment.extend_from_slice(&src_port.to_be_bytes());
    // Destination port
    segment.extend_from_slice(&dst_port.to_be_bytes());
    // Sequence number
    segment.extend_from_slice(&seq.to_be_bytes());
    // Acknowledgment number
    segment.extend_from_slice(&ack.to_be_bytes());
    // Data offset (4 bits) + reserved (4 bits)
    segment.push(data_offset << 4);
    // Flags
    segment.push(flags);
    // Window
    segment.extend_from_slice(&window.to_be_bytes());
    // Checksum placeholder
    segment.extend_from_slice(&[0u8; 2]);
    // Urgent pointer
    segment.extend_from_slice(&[0u8; 2]);

    // MSS option: kind=2, length=4, MSS value
    if include_mss {
        segment.push(2); // MSS option kind
        segment.push(4); // Option length
        segment.extend_from_slice(&TCP_MSS.to_be_bytes());
    }

    // Payload
    segment.extend_from_slice(payload);

    segment
}

/// Build a complete IPv4/TCP packet with correct checksums.
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    include_mss: bool,
) -> Vec<u8> {
    // Build TCP segment first (need its length for IP header)
    let mut tcp_segment = build_tcp_segment(
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload,
        include_mss,
    );

    // Compute TCP checksum and fill it in
    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &tcp_segment);
    tcp_segment[16] = (tcp_cksum >> 8) as u8;
    tcp_segment[17] = (tcp_cksum & 0xFF) as u8;

    // Build IPv4 header (20 bytes, no options)
    let total_length = (IPV4_MIN_HEADER_LEN + tcp_segment.len()) as u16;
    let mut ip_header = Vec::with_capacity(IPV4_MIN_HEADER_LEN);

    // Version (4) + IHL (5)
    ip_header.push(0x45);
    // DSCP + ECN
    ip_header.push(0x00);
    // Total length
    ip_header.extend_from_slice(&total_length.to_be_bytes());
    // Identification (use 0, OS doesn't care for utun)
    ip_header.extend_from_slice(&[0x00, 0x00]);
    // Flags (DF) + Fragment offset
    ip_header.extend_from_slice(&[0x40, 0x00]);
    // TTL
    ip_header.push(64);
    // Protocol (TCP)
    ip_header.push(IPPROTO_TCP);
    // Header checksum placeholder
    ip_header.extend_from_slice(&[0x00, 0x00]);
    // Source IP
    ip_header.extend_from_slice(&src_ip.octets());
    // Destination IP
    ip_header.extend_from_slice(&dst_ip.octets());

    // Compute and fill in IP checksum
    let ip_cksum = ipv4_checksum(&ip_header);
    ip_header[10] = (ip_cksum >> 8) as u8;
    ip_header[11] = (ip_cksum & 0xFF) as u8;

    // Combine
    let mut packet = ip_header;
    packet.extend_from_slice(&tcp_segment);
    packet
}

// ── Service Map ─────────────────────────────────────────────────────────

/// Maps VIP addresses to ZTLP service names.
#[derive(Debug, Clone)]
pub struct ServiceMap {
    services: HashMap<Ipv4Addr, String>,
}

impl ServiceMap {
    /// Create an empty service map.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Register a VIP → service name mapping.
    pub fn add(&mut self, vip: Ipv4Addr, service_name: String) {
        self.services.insert(vip, service_name);
    }

    /// Look up the service name for a VIP address.
    pub fn lookup(&self, vip: &Ipv4Addr) -> Option<&str> {
        self.services.get(vip).map(|s| s.as_str())
    }

    /// Number of registered services.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Whether the service map is empty.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }
}

impl Default for ServiceMap {
    fn default() -> Self {
        Self::new()
    }
}

// ── TCP State Machine ───────────────────────────────────────────────────

/// TCP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// SYN received, SYN-ACK sent, waiting for ACK.
    SynReceived,
    /// Three-way handshake complete, data can flow.
    Established,
    /// We sent FIN, waiting for ACK.
    FinWait1,
    /// Our FIN was ACKed, waiting for remote FIN.
    FinWait2,
    /// Remote sent FIN, we need to send FIN.
    CloseWait,
    /// We sent FIN in response to remote FIN, waiting for ACK.
    LastAck,
    /// Connection fully closed.
    Closed,
}

/// A 4-tuple identifying a TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

/// Per-connection TCP flow state.
#[derive(Debug)]
pub struct TcpFlow {
    /// Current TCP state.
    pub state: TcpState,
    /// Last seen sequence number from the client.
    pub client_seq: u32,
    /// Our (server) sequence number.
    pub server_seq: u32,
    /// Last ACK number received from the client.
    pub client_ack: u32,
    /// ZTLP service name for this flow.
    pub service_name: String,
    /// ZTLP mux stream ID.
    pub stream_id: u32,
    /// Advertised receive window.
    pub recv_window: u16,
    /// Data from gateway waiting to be sent as TCP packets.
    pub send_buf: VecDeque<u8>,
    /// Last activity timestamp for timeout detection.
    pub last_activity: Instant,
    /// The flow key for constructing response packets.
    pub flow_key: FlowKey,
}

// ── Router Actions ──────────────────────────────────────────────────────

/// Actions the packet router returns to the caller (FFI layer).
/// These describe what ZTLP operations to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterAction {
    /// Open a new ZTLP mux stream for this service.
    OpenStream {
        stream_id: u32,
        service_name: String,
    },
    /// Send data on an existing stream.
    SendData { stream_id: u32, data: Vec<u8> },
    /// Close a stream.
    CloseStream { stream_id: u32 },
}

// ── Packet Router ───────────────────────────────────────────────────────

/// Userspace TCP/IP packet router for iOS utun interface.
///
/// Processes raw IPv4 packets, manages TCP connection state, and bridges
/// TCP flows to ZTLP multiplexed streams.
pub struct PacketRouter {
    /// VIP address → service name mapping.
    service_map: ServiceMap,
    /// Active TCP flows indexed by 4-tuple.
    flows: HashMap<FlowKey, TcpFlow>,
    /// Reverse lookup: stream_id → FlowKey.
    stream_to_flow: HashMap<u32, FlowKey>,
    /// Outbound packet queue (responses to inject back into utun).
    /// Capped at OUTBOUND_MAX_PACKETS to bound memory in iOS NE (15MB limit).
    outbound: VecDeque<Vec<u8>>,
    /// The tunnel interface's own IP address (e.g., the utun source IP).
    #[allow(dead_code)]
    tunnel_addr: Ipv4Addr,
    /// The tunnel subnet (network, prefix_len).
    tunnel_subnet: (Ipv4Addr, u32),
    /// Counter for allocating ZTLP mux stream IDs.
    next_stream_id: u32,
}

impl PacketRouter {
    /// Create a new packet router with the given tunnel address.
    ///
    /// The tunnel address is the IP assigned to the utun interface
    /// (e.g., `10.122.0.100`). The subnet defaults to `10.122.0.0/16`.
    pub fn new(tunnel_addr: Ipv4Addr) -> Self {
        Self {
            service_map: ServiceMap::new(),
            flows: HashMap::new(),
            stream_to_flow: HashMap::new(),
            outbound: VecDeque::new(),
            tunnel_addr,
            tunnel_subnet: (DEFAULT_SUBNET, DEFAULT_PREFIX_LEN),
            next_stream_id: 1, // Start at 1 (0 = legacy/unused)
        }
    }

    /// Register a service: VIP address → service name.
    pub fn add_service(&mut self, vip: Ipv4Addr, service_name: String) {
        self.service_map.add(vip, service_name);
    }

    /// Check if a destination IP is in our tunnel subnet.
    fn is_in_subnet(&self, ip: Ipv4Addr) -> bool {
        let (network, prefix_len) = self.tunnel_subnet;
        let net_u32 = u32::from(network);
        let ip_u32 = u32::from(ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        (ip_u32 & mask) == (net_u32 & mask)
    }

    /// Allocate a new stream ID.
    fn alloc_stream_id(&mut self) -> u32 {
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        if self.next_stream_id == 0 {
            self.next_stream_id = 1;
        }
        id
    }

    /// Generate a pseudo-random initial sequence number.
    fn generate_isn() -> u32 {
        // Use a simple hash of current time for ISN. In production this
        // could use a proper PRNG, but for a tunnel interface this is fine.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let seed = now.as_nanos() as u32;
        // Mix bits
        seed.wrapping_mul(2654435761) // Knuth's multiplicative hash
    }

    /// Process an inbound IP packet from the utun interface.
    ///
    /// Parses IPv4/TCP headers, manages TCP state, and returns ZTLP actions
    /// to perform (open streams, send data, close streams).
    ///
    /// Response packets (SYN-ACK, ACK, data, FIN) are queued in the outbound
    /// buffer and can be retrieved with `drain_outbound()`.
    pub fn process_inbound(&mut self, packet: &[u8]) -> Vec<RouterAction> {
        let mut actions = Vec::new();

        // Parse IPv4 header
        let ip_hdr = match parse_ipv4(packet) {
            Some(h) => h,
            None => return actions,
        };

        // Only handle TCP
        if ip_hdr.protocol != IPPROTO_TCP {
            return actions;
        }

        // Check if destination is in our subnet
        if !self.is_in_subnet(ip_hdr.dst_ip) {
            return actions;
        }

        // Extract TCP header from IP payload
        let ip_payload_offset = ip_hdr.header_len();
        if packet.len() < ip_payload_offset {
            return actions;
        }
        let ip_payload = &packet[ip_payload_offset..];

        let tcp_hdr = match parse_tcp(ip_payload) {
            Some(h) => h,
            None => return actions,
        };

        let flow_key = FlowKey {
            src_ip: ip_hdr.src_ip,
            src_port: tcp_hdr.src_port,
            dst_ip: ip_hdr.dst_ip,
            dst_port: tcp_hdr.dst_port,
        };

        // Extract TCP payload
        let tcp_payload_offset = tcp_hdr.header_len();
        let tcp_payload = if ip_payload.len() > tcp_payload_offset {
            &ip_payload[tcp_payload_offset..]
        } else {
            &[]
        };

        // Handle RST — clean up flow immediately
        if tcp_hdr.is_rst() {
            if let Some(flow) = self.flows.remove(&flow_key) {
                self.stream_to_flow.remove(&flow.stream_id);
                actions.push(RouterAction::CloseStream {
                    stream_id: flow.stream_id,
                });
            }
            return actions;
        }

        // Handle SYN (new connection)
        if tcp_hdr.is_syn() && !tcp_hdr.is_ack() {
            return self.handle_syn(&flow_key, &ip_hdr, &tcp_hdr);
        }

        // Look up existing flow
        if let Some(flow) = self.flows.get_mut(&flow_key) {
            flow.last_activity = Instant::now();

            match flow.state {
                TcpState::SynReceived => {
                    // Expecting ACK to complete handshake
                    if tcp_hdr.is_ack() {
                        flow.state = TcpState::Established;
                        flow.client_ack = tcp_hdr.ack;

                        // If there's data piggybacked on the ACK
                        if !tcp_payload.is_empty() {
                            flow.client_seq = tcp_hdr.seq.wrapping_add(tcp_payload.len() as u32);
                            actions.push(RouterAction::SendData {
                                stream_id: flow.stream_id,
                                data: tcp_payload.to_vec(),
                            });
                            // ACK the data
                            queue_ack(flow, &mut self.outbound);
                        }
                    }
                }

                TcpState::Established => {
                    // Handle data
                    if !tcp_payload.is_empty() {
                        flow.client_seq = tcp_hdr.seq.wrapping_add(tcp_payload.len() as u32);
                        actions.push(RouterAction::SendData {
                            stream_id: flow.stream_id,
                            data: tcp_payload.to_vec(),
                        });
                        // ACK the data
                        queue_ack(flow, &mut self.outbound);
                    }

                    // Handle FIN from client
                    if tcp_hdr.is_fin() {
                        flow.client_seq = tcp_hdr.seq.wrapping_add(
                            tcp_payload.len() as u32 + 1, // FIN consumes 1 seq
                        );
                        flow.state = TcpState::CloseWait;
                        // ACK the FIN
                        queue_ack(flow, &mut self.outbound);
                        // Close the ZTLP stream
                        actions.push(RouterAction::CloseStream {
                            stream_id: flow.stream_id,
                        });
                        // Send our own FIN
                        queue_fin(flow, &mut self.outbound);
                        flow.state = TcpState::LastAck;
                    }
                }

                TcpState::FinWait1 => {
                    if tcp_hdr.is_ack() && tcp_hdr.is_fin() {
                        // Simultaneous close
                        flow.client_seq = tcp_hdr.seq.wrapping_add(1);
                        queue_ack(flow, &mut self.outbound);
                        flow.state = TcpState::Closed;
                    } else if tcp_hdr.is_ack() {
                        flow.state = TcpState::FinWait2;
                    } else if tcp_hdr.is_fin() {
                        flow.client_seq = tcp_hdr.seq.wrapping_add(1);
                        queue_ack(flow, &mut self.outbound);
                        flow.state = TcpState::Closed;
                    }
                }

                TcpState::FinWait2 => {
                    if tcp_hdr.is_fin() {
                        flow.client_seq = tcp_hdr.seq.wrapping_add(1);
                        queue_ack(flow, &mut self.outbound);
                        flow.state = TcpState::Closed;
                    }
                }

                TcpState::LastAck => {
                    if tcp_hdr.is_ack() {
                        flow.state = TcpState::Closed;
                    }
                }

                TcpState::CloseWait | TcpState::Closed => {
                    // Ignore packets in terminal states
                }
            }
        } else if tcp_hdr.is_ack() && !tcp_hdr.is_syn() {
            // ACK for unknown flow — send RST
            queue_rst(
                ip_hdr.dst_ip,
                ip_hdr.src_ip,
                tcp_hdr.dst_port,
                tcp_hdr.src_port,
                tcp_hdr.ack,
                0,
                &mut self.outbound,
            );
        }

        // Clean up closed flows
        self.cleanup_closed_flows();

        actions
    }

    /// Handle a SYN packet (new TCP connection attempt).
    fn handle_syn(
        &mut self,
        flow_key: &FlowKey,
        ip_hdr: &Ipv4Header,
        tcp_hdr: &TcpHeader,
    ) -> Vec<RouterAction> {
        let mut actions = Vec::new();

        // Look up service for this VIP
        let service_name = match self.service_map.lookup(&ip_hdr.dst_ip) {
            Some(name) => name.to_string(),
            None => {
                // No service registered for this IP — send RST
                queue_rst(
                    ip_hdr.dst_ip,
                    ip_hdr.src_ip,
                    tcp_hdr.dst_port,
                    tcp_hdr.src_port,
                    0,
                    tcp_hdr.seq.wrapping_add(1),
                    &mut self.outbound,
                );
                return actions;
            }
        };

        // Remove stale flow for this 4-tuple if exists
        if let Some(old_flow) = self.flows.remove(flow_key) {
            self.stream_to_flow.remove(&old_flow.stream_id);
            actions.push(RouterAction::CloseStream {
                stream_id: old_flow.stream_id,
            });
        }

        // Allocate stream ID
        let stream_id = self.alloc_stream_id();

        // Generate ISN for our side
        let server_isn = Self::generate_isn();

        // Create flow
        let flow = TcpFlow {
            state: TcpState::SynReceived,
            client_seq: tcp_hdr.seq.wrapping_add(1), // SYN consumes 1 seq
            server_seq: server_isn.wrapping_add(1),  // After SYN-ACK
            client_ack: 0,
            service_name: service_name.clone(),
            stream_id,
            recv_window: TCP_WINDOW_SIZE,
            send_buf: VecDeque::new(),
            last_activity: Instant::now(),
            flow_key: *flow_key,
        };

        // Send SYN-ACK
        let syn_ack = build_ipv4_tcp(
            ip_hdr.dst_ip,     // src = service VIP
            ip_hdr.src_ip,     // dst = client
            tcp_hdr.dst_port,  // src port = service port
            tcp_hdr.src_port,  // dst port = client port
            server_isn,        // seq = our ISN
            flow.client_seq,   // ack = client_seq (syn+1)
            TCP_SYN | TCP_ACK, // flags
            TCP_WINDOW_SIZE,   // window
            &[],               // no payload
            true,              // include MSS option
        );
        self.outbound.push_back(syn_ack);

        // Store flow
        self.flows.insert(*flow_key, flow);
        self.stream_to_flow.insert(stream_id, *flow_key);

        // Return action to open ZTLP stream
        actions.push(RouterAction::OpenStream {
            stream_id,
            service_name,
        });

        actions
    }

    /// Process data received from the gateway for a specific stream.
    ///
    /// Constructs TCP data packets and queues them in the outbound buffer.
    pub fn process_gateway_data(&mut self, stream_id: u32, data: &[u8]) {
        let flow_key = match self.stream_to_flow.get(&stream_id) {
            Some(k) => *k,
            None => return,
        };

        let flow = match self.flows.get_mut(&flow_key) {
            Some(f) => f,
            None => return,
        };

        if flow.state != TcpState::Established && flow.state != TcpState::CloseWait {
            return;
        }

        flow.last_activity = Instant::now();

        // Send data in MSS-sized chunks
        let mut offset = 0;
        while offset < data.len() {
            let chunk_end = std::cmp::min(offset + TCP_MSS as usize, data.len());
            let chunk = &data[offset..chunk_end];

            let flags = if chunk_end == data.len() {
                TCP_PSH | TCP_ACK // Push on last segment
            } else {
                TCP_ACK
            };

            let pkt = build_ipv4_tcp(
                flow.flow_key.dst_ip,
                flow.flow_key.src_ip,
                flow.flow_key.dst_port,
                flow.flow_key.src_port,
                flow.server_seq,
                flow.client_seq,
                flags,
                TCP_WINDOW_SIZE,
                chunk,
                false,
            );

            flow.server_seq = flow.server_seq.wrapping_add(chunk.len() as u32);
            // Cap outbound queue to prevent unbounded memory growth in iOS NE
            if self.outbound.len() >= OUTBOUND_MAX_PACKETS {
                self.outbound.pop_front();
            }
            self.outbound.push_back(pkt);
            offset = chunk_end;
        }
    }

    /// Process gateway stream close.
    ///
    /// Sends a FIN to the client and transitions the flow state.
    pub fn process_gateway_close(&mut self, stream_id: u32) {
        let flow_key = match self.stream_to_flow.get(&stream_id) {
            Some(k) => *k,
            None => return,
        };

        let flow = match self.flows.get_mut(&flow_key) {
            Some(f) => f,
            None => return,
        };

        match flow.state {
            TcpState::Established => {
                queue_fin(flow, &mut self.outbound);
                flow.state = TcpState::FinWait1;
            }
            TcpState::CloseWait => {
                queue_fin(flow, &mut self.outbound);
                flow.state = TcpState::LastAck;
            }
            _ => {
                // Already closing or closed
            }
        }
    }

    /// Drain the outbound packet queue.
    ///
    /// Returns all queued IPv4 packets to inject back into the utun interface.
    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.outbound.drain(..).collect()
    }

    /// Pop a single outbound packet (FIFO). Returns None if empty.
    /// Used by the FFI layer to feed packets one at a time to Swift.
    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    /// Clean up flows in the Closed state and timed-out flows.
    fn cleanup_closed_flows(&mut self) {
        let now = Instant::now();
        let to_remove: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, flow)| {
                flow.state == TcpState::Closed
                    || now.duration_since(flow.last_activity).as_secs() > FLOW_TIMEOUT_SECS
            })
            .map(|(key, _)| *key)
            .collect();

        for key in to_remove {
            if let Some(flow) = self.flows.remove(&key) {
                self.stream_to_flow.remove(&flow.stream_id);
            }
        }
    }

    /// Explicitly clean up timed-out flows.
    ///
    /// Returns stream IDs of flows that were cleaned up (caller should close
    /// the corresponding ZTLP streams).
    pub fn cleanup_stale_flows(&mut self) -> Vec<u32> {
        let now = Instant::now();
        let stale: Vec<(FlowKey, u32)> = self
            .flows
            .iter()
            .filter(|(_, flow)| {
                now.duration_since(flow.last_activity).as_secs() > FLOW_TIMEOUT_SECS
            })
            .map(|(key, flow)| (*key, flow.stream_id))
            .collect();

        let mut stream_ids = Vec::new();
        for (key, stream_id) in stale {
            self.flows.remove(&key);
            self.stream_to_flow.remove(&stream_id);
            stream_ids.push(stream_id);
        }
        stream_ids
    }

    /// Number of active flows.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Get the service map (for inspection/testing).
    pub fn service_map(&self) -> &ServiceMap {
        &self.service_map
    }
}

// ── Free functions for packet construction (avoids borrow conflicts) ────

/// Queue an ACK packet for the given flow.
fn queue_ack(flow: &TcpFlow, outbound: &mut VecDeque<Vec<u8>>) {
    let pkt = build_ipv4_tcp(
        flow.flow_key.dst_ip,
        flow.flow_key.src_ip,
        flow.flow_key.dst_port,
        flow.flow_key.src_port,
        flow.server_seq,
        flow.client_seq,
        TCP_ACK,
        TCP_WINDOW_SIZE,
        &[],
        false,
    );
    outbound.push_back(pkt);
}

/// Queue a FIN+ACK packet and advance the server sequence number.
fn queue_fin(flow: &mut TcpFlow, outbound: &mut VecDeque<Vec<u8>>) {
    let pkt = build_ipv4_tcp(
        flow.flow_key.dst_ip,
        flow.flow_key.src_ip,
        flow.flow_key.dst_port,
        flow.flow_key.src_port,
        flow.server_seq,
        flow.client_seq,
        TCP_FIN | TCP_ACK,
        TCP_WINDOW_SIZE,
        &[],
        false,
    );
    flow.server_seq = flow.server_seq.wrapping_add(1); // FIN consumes 1 seq
    outbound.push_back(pkt);
}

/// Queue a RST packet.
fn queue_rst(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    outbound: &mut VecDeque<Vec<u8>>,
) {
    let flags = if ack != 0 { TCP_RST | TCP_ACK } else { TCP_RST };
    let pkt = build_ipv4_tcp(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        0, // window = 0 for RST
        &[],
        false,
    );
    outbound.push_back(pkt);
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IPv4 Parsing Tests ──────────────────────────────────────────

    #[test]
    fn test_parse_ipv4_valid() {
        // Minimal valid IPv4 header (20 bytes)
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // version=4, ihl=5
        pkt[2] = 0x00;
        pkt[3] = 40; // total_length=40
        pkt[8] = 64; // ttl
        pkt[9] = 6; // protocol=TCP
        pkt[12] = 10;
        pkt[13] = 0;
        pkt[14] = 0;
        pkt[15] = 1; // src=10.0.0.1
        pkt[16] = 10;
        pkt[17] = 122;
        pkt[18] = 0;
        pkt[19] = 2; // dst=10.122.0.2

        let hdr = parse_ipv4(&pkt).expect("should parse");
        assert_eq!(hdr.ihl, 5);
        assert_eq!(hdr.total_length, 40);
        assert_eq!(hdr.ttl, 64);
        assert_eq!(hdr.protocol, 6);
        assert_eq!(hdr.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(hdr.dst_ip, Ipv4Addr::new(10, 122, 0, 2));
        assert_eq!(hdr.header_len(), 20);
    }

    #[test]
    fn test_parse_ipv4_too_short() {
        assert!(parse_ipv4(&[0u8; 19]).is_none());
        assert!(parse_ipv4(&[]).is_none());
    }

    #[test]
    fn test_parse_ipv4_wrong_version() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x65; // version=6
        assert!(parse_ipv4(&pkt).is_none());
    }

    #[test]
    fn test_parse_ipv4_ihl_too_small() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x43; // version=4, ihl=3 (invalid, min is 5)
        assert!(parse_ipv4(&pkt).is_none());
    }

    #[test]
    fn test_parse_ipv4_with_options() {
        // IHL=6 means 24 bytes header
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x46; // version=4, ihl=6
        pkt[2] = 0x00;
        pkt[3] = 44;
        pkt[9] = 6;
        pkt[12] = 192;
        pkt[13] = 168;
        pkt[14] = 1;
        pkt[15] = 1;
        pkt[16] = 10;
        pkt[17] = 122;
        pkt[18] = 0;
        pkt[19] = 1;

        let hdr = parse_ipv4(&pkt).expect("should parse with options");
        assert_eq!(hdr.ihl, 6);
        assert_eq!(hdr.header_len(), 24);
    }

    // ── TCP Parsing Tests ───────────────────────────────────────────

    #[test]
    fn test_parse_tcp_valid() {
        let mut seg = vec![0u8; 20];
        seg[0] = 0x1F;
        seg[1] = 0x90; // src_port=8080
        seg[2] = 0x00;
        seg[3] = 0x50; // dst_port=80
        seg[4..8].copy_from_slice(&100u32.to_be_bytes()); // seq=100
        seg[8..12].copy_from_slice(&200u32.to_be_bytes()); // ack=200
        seg[12] = 0x50; // data_offset=5 (20 bytes)
        seg[13] = TCP_SYN | TCP_ACK; // flags
        seg[14] = 0xFF;
        seg[15] = 0xFF; // window=65535

        let hdr = parse_tcp(&seg).expect("should parse");
        assert_eq!(hdr.src_port, 8080);
        assert_eq!(hdr.dst_port, 80);
        assert_eq!(hdr.seq, 100);
        assert_eq!(hdr.ack, 200);
        assert_eq!(hdr.data_offset, 5);
        assert!(hdr.is_syn());
        assert!(hdr.is_ack());
        assert!(!hdr.is_fin());
        assert!(!hdr.is_rst());
        assert_eq!(hdr.window, 65535);
        assert_eq!(hdr.header_len(), 20);
    }

    #[test]
    fn test_parse_tcp_too_short() {
        assert!(parse_tcp(&[0u8; 19]).is_none());
        assert!(parse_tcp(&[]).is_none());
    }

    #[test]
    fn test_parse_tcp_data_offset_too_small() {
        let mut seg = vec![0u8; 20];
        seg[12] = 0x30; // data_offset=3 (invalid, min is 5)
        assert!(parse_tcp(&seg).is_none());
    }

    #[test]
    fn test_parse_tcp_flags() {
        let mut seg = vec![0u8; 20];
        seg[12] = 0x50; // data_offset=5

        seg[13] = TCP_FIN;
        let hdr = parse_tcp(&seg).unwrap();
        assert!(hdr.is_fin());
        assert!(!hdr.is_syn());

        seg[13] = TCP_RST;
        let hdr = parse_tcp(&seg).unwrap();
        assert!(hdr.is_rst());

        seg[13] = TCP_PSH | TCP_ACK;
        let hdr = parse_tcp(&seg).unwrap();
        assert!(hdr.is_psh());
        assert!(hdr.is_ack());
    }

    // ── Checksum Tests ──────────────────────────────────────────────

    #[test]
    fn test_ipv4_checksum() {
        // Example from RFC 1071 / real packet
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[2] = 0x00;
        header[3] = 0x28; // total_length=40
        header[4] = 0xAB;
        header[5] = 0xCD; // identification
        header[6] = 0x40;
        header[7] = 0x00; // flags=DF
        header[8] = 0x40; // ttl=64
        header[9] = 0x06; // protocol=TCP
                          // checksum bytes 10-11 will be skipped
        header[12] = 0x0A;
        header[13] = 0x00;
        header[14] = 0x00;
        header[15] = 0x01; // src=10.0.0.1
        header[16] = 0x0A;
        header[17] = 0x7A;
        header[18] = 0x00;
        header[19] = 0x02; // dst=10.122.0.2

        let cksum = ipv4_checksum(&header);
        // Verify by computing checksum over header with checksum set
        header[10] = (cksum >> 8) as u8;
        header[11] = (cksum & 0xFF) as u8;

        // Full header with checksum should verify to 0
        let mut verify_sum: u32 = 0;
        for i in (0..20).step_by(2) {
            verify_sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        }
        while verify_sum >> 16 != 0 {
            verify_sum = (verify_sum & 0xFFFF) + (verify_sum >> 16);
        }
        assert_eq!(!verify_sum as u16, 0, "checksum should verify to zero");
    }

    #[test]
    fn test_tcp_checksum_round_trip() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 122, 0, 2);

        // Build a TCP SYN packet
        let pkt = build_ipv4_tcp(src_ip, dst_ip, 8080, 80, 1000, 0, TCP_SYN, 65535, &[], true);

        // Parse it back
        let ip_hdr = parse_ipv4(&pkt).unwrap();
        let tcp_data = &pkt[ip_hdr.header_len()..];

        // Verify TCP checksum by including checksum field in sum
        let cksum = verify_tcp_checksum(src_ip, dst_ip, tcp_data);
        assert_eq!(
            cksum, 0,
            "TCP checksum should verify to 0 for correct packet"
        );
    }

    #[test]
    fn test_tcp_checksum_with_data() {
        let src_ip = Ipv4Addr::new(10, 122, 0, 2);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 1);
        let payload = b"GET / HTTP/1.1\r\n\r\n";

        let pkt = build_ipv4_tcp(
            src_ip,
            dst_ip,
            80,
            8080,
            5000,
            1001,
            TCP_PSH | TCP_ACK,
            65535,
            payload,
            false,
        );

        let ip_hdr = parse_ipv4(&pkt).unwrap();
        let tcp_data = &pkt[ip_hdr.header_len()..];
        let cksum = verify_tcp_checksum(src_ip, dst_ip, tcp_data);
        assert_eq!(cksum, 0);
    }

    /// Verify a TCP checksum by summing the entire segment including the
    /// checksum field. Returns 0 if the checksum is correct.
    fn verify_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
        let src = src_ip.octets();
        let dst = dst_ip.octets();
        let tcp_len = tcp_segment.len() as u16;

        let mut sum: u32 = 0;

        // Pseudo-header
        sum += u16::from_be_bytes([src[0], src[1]]) as u32;
        sum += u16::from_be_bytes([src[2], src[3]]) as u32;
        sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
        sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
        sum += IPPROTO_TCP as u32;
        sum += tcp_len as u32;

        // TCP segment (including checksum field)
        let mut i = 0;
        while i + 1 < tcp_segment.len() {
            sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
            i += 2;
        }
        if i < tcp_segment.len() {
            sum += (tcp_segment[i] as u32) << 8;
        }

        // Fold
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    // ── Packet Construction Tests ───────────────────────────────────

    #[test]
    fn test_build_ipv4_tcp_syn_ack_with_mss() {
        let pkt = build_ipv4_tcp(
            Ipv4Addr::new(10, 122, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            80,
            12345,
            5000,
            1001,
            TCP_SYN | TCP_ACK,
            65535,
            &[],
            true, // include MSS
        );

        // IPv4 header: 20 bytes, TCP header: 24 bytes (20 + 4 MSS option)
        assert_eq!(pkt.len(), 44);

        let ip_hdr = parse_ipv4(&pkt).unwrap();
        assert_eq!(ip_hdr.protocol, 6);
        assert_eq!(ip_hdr.src_ip, Ipv4Addr::new(10, 122, 0, 2));
        assert_eq!(ip_hdr.dst_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip_hdr.total_length, 44);

        let tcp_data = &pkt[20..];
        let tcp_hdr = parse_tcp(tcp_data).unwrap();
        assert_eq!(tcp_hdr.src_port, 80);
        assert_eq!(tcp_hdr.dst_port, 12345);
        assert_eq!(tcp_hdr.seq, 5000);
        assert_eq!(tcp_hdr.ack, 1001);
        assert!(tcp_hdr.is_syn());
        assert!(tcp_hdr.is_ack());
        assert_eq!(tcp_hdr.data_offset, 6); // 24 bytes / 4

        // Check MSS option
        assert_eq!(tcp_data[20], 2); // MSS kind
        assert_eq!(tcp_data[21], 4); // MSS length
        let mss = u16::from_be_bytes([tcp_data[22], tcp_data[23]]);
        assert_eq!(mss, TCP_MSS);
    }

    #[test]
    fn test_build_ipv4_tcp_data_packet() {
        let payload = b"Hello, World!";
        let pkt = build_ipv4_tcp(
            Ipv4Addr::new(10, 122, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            80,
            12345,
            5001,
            1001,
            TCP_PSH | TCP_ACK,
            65535,
            payload,
            false,
        );

        // 20 (IP) + 20 (TCP) + 13 (payload) = 53
        assert_eq!(pkt.len(), 53);

        let ip_hdr = parse_ipv4(&pkt).unwrap();
        assert_eq!(ip_hdr.total_length, 53);

        let tcp_data = &pkt[20..];
        let tcp_hdr = parse_tcp(tcp_data).unwrap();
        assert!(tcp_hdr.is_psh());
        assert!(tcp_hdr.is_ack());
        assert_eq!(tcp_hdr.data_offset, 5);

        // Extract payload
        let extracted_payload = &tcp_data[20..];
        assert_eq!(extracted_payload, payload);
    }

    // ── Service Map Tests ───────────────────────────────────────────

    #[test]
    fn test_service_map_add_lookup() {
        let mut smap = ServiceMap::new();
        assert!(smap.is_empty());

        smap.add(Ipv4Addr::new(10, 122, 0, 1), "vault".to_string());
        smap.add(Ipv4Addr::new(10, 122, 0, 2), "http".to_string());

        assert_eq!(smap.len(), 2);
        assert_eq!(smap.lookup(&Ipv4Addr::new(10, 122, 0, 1)), Some("vault"));
        assert_eq!(smap.lookup(&Ipv4Addr::new(10, 122, 0, 2)), Some("http"));
        assert_eq!(smap.lookup(&Ipv4Addr::new(10, 122, 0, 3)), None);
    }

    #[test]
    fn test_service_map_overwrite() {
        let mut smap = ServiceMap::new();
        smap.add(Ipv4Addr::new(10, 122, 0, 1), "old".to_string());
        smap.add(Ipv4Addr::new(10, 122, 0, 1), "new".to_string());
        assert_eq!(smap.lookup(&Ipv4Addr::new(10, 122, 0, 1)), Some("new"));
        assert_eq!(smap.len(), 1);
    }

    // ── PacketRouter Tests ──────────────────────────────────────────

    fn make_router() -> PacketRouter {
        let mut router = PacketRouter::new(Ipv4Addr::new(10, 122, 0, 100));
        router.add_service(Ipv4Addr::new(10, 122, 0, 1), "vault".to_string());
        router.add_service(Ipv4Addr::new(10, 122, 0, 2), "http".to_string());
        router
    }

    /// Build a raw IPv4/TCP SYN packet.
    fn make_syn_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Vec<u8> {
        build_ipv4_tcp(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            0,
            TCP_SYN,
            65535,
            &[],
            true,
        )
    }

    /// Build a raw IPv4/TCP ACK packet.
    fn make_ack_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        build_ipv4_tcp(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            TCP_ACK,
            65535,
            &[],
            false,
        )
    }

    /// Build a raw IPv4/TCP data packet.
    fn make_data_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        build_ipv4_tcp(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            TCP_PSH | TCP_ACK,
            65535,
            payload,
            false,
        )
    }

    /// Build a raw IPv4/TCP FIN+ACK packet.
    fn make_fin_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        build_ipv4_tcp(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            TCP_FIN | TCP_ACK,
            65535,
            &[],
            false,
        )
    }

    /// Build a raw IPv4/TCP RST packet.
    fn make_rst_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Vec<u8> {
        build_ipv4_tcp(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            0,
            TCP_RST,
            0,
            &[],
            false,
        )
    }

    #[test]
    fn test_router_new() {
        let router = PacketRouter::new(Ipv4Addr::new(10, 122, 0, 100));
        assert_eq!(router.flow_count(), 0);
        assert!(router.service_map().is_empty());
    }

    #[test]
    fn test_router_add_service() {
        let router = make_router();
        assert_eq!(router.service_map().len(), 2);
        assert_eq!(
            router.service_map().lookup(&Ipv4Addr::new(10, 122, 0, 1)),
            Some("vault")
        );
    }

    #[test]
    fn test_router_syn_creates_flow() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        let actions = router.process_inbound(&syn);

        // Should open a stream
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            RouterAction::OpenStream {
                stream_id,
                service_name,
            } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(service_name, "http");
            }
            other => panic!("expected OpenStream, got {:?}", other),
        }

        // Should have one flow
        assert_eq!(router.flow_count(), 1);

        // Should have a SYN-ACK in outbound
        let outbound = router.drain_outbound();
        assert_eq!(outbound.len(), 1);

        // Parse SYN-ACK
        let syn_ack = &outbound[0];
        let ip_hdr = parse_ipv4(syn_ack).unwrap();
        assert_eq!(ip_hdr.src_ip, service_ip);
        assert_eq!(ip_hdr.dst_ip, client_ip);

        let tcp_data = &syn_ack[ip_hdr.header_len()..];
        let tcp_hdr = parse_tcp(tcp_data).unwrap();
        assert!(tcp_hdr.is_syn());
        assert!(tcp_hdr.is_ack());
        assert_eq!(tcp_hdr.src_port, 80);
        assert_eq!(tcp_hdr.dst_port, 54321);
        assert_eq!(tcp_hdr.ack, 1001); // client_seq + 1
    }

    #[test]
    fn test_router_syn_unknown_service() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let unknown_ip = Ipv4Addr::new(10, 122, 0, 99); // Not registered

        let syn = make_syn_packet(client_ip, unknown_ip, 54321, 80, 1000);
        let actions = router.process_inbound(&syn);

        // No stream opened
        assert!(actions.is_empty());
        assert_eq!(router.flow_count(), 0);

        // Should have a RST in outbound
        let outbound = router.drain_outbound();
        assert_eq!(outbound.len(), 1);
        let rst = &outbound[0];
        let tcp_data = &rst[20..];
        let tcp_hdr = parse_tcp(tcp_data).unwrap();
        assert!(tcp_hdr.is_rst());
    }

    #[test]
    fn test_router_three_way_handshake() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        // Step 1: SYN
        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        let actions = router.process_inbound(&syn);
        assert_eq!(actions.len(), 1);

        // Get the server ISN from SYN-ACK
        let outbound = router.drain_outbound();
        let syn_ack = &outbound[0];
        let tcp_data = &syn_ack[20..];
        let syn_ack_hdr = parse_tcp(tcp_data).unwrap();
        let server_isn = syn_ack_hdr.seq;

        // Step 2: ACK
        let ack = make_ack_packet(
            client_ip,
            service_ip,
            54321,
            80,
            1001,
            server_isn + 1, // ACK the SYN-ACK
        );
        let actions = router.process_inbound(&ack);
        // No actions needed for bare ACK
        assert!(actions.is_empty());

        // Flow should be Established now
        assert_eq!(router.flow_count(), 1);
    }

    #[test]
    fn test_router_data_forwarding() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        // Handshake
        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        router.process_inbound(&syn);
        let outbound = router.drain_outbound();
        let syn_ack_hdr = parse_tcp(&outbound[0][20..]).unwrap();
        let server_isn = syn_ack_hdr.seq;

        let ack = make_ack_packet(client_ip, service_ip, 54321, 80, 1001, server_isn + 1);
        router.process_inbound(&ack);
        router.drain_outbound();

        // Send data
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let data_pkt =
            make_data_packet(client_ip, service_ip, 54321, 80, 1001, server_isn + 1, data);
        let actions = router.process_inbound(&data_pkt);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            RouterAction::SendData { stream_id, data: d } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(d.as_slice(), data.as_slice());
            }
            other => panic!("expected SendData, got {:?}", other),
        }

        // Should have ACK in outbound
        let outbound = router.drain_outbound();
        assert_eq!(outbound.len(), 1);
        let ack_pkt = &outbound[0];
        let tcp_hdr = parse_tcp(&ack_pkt[20..]).unwrap();
        assert!(tcp_hdr.is_ack());
        assert_eq!(tcp_hdr.ack, 1001 + data.len() as u32);
    }

    #[test]
    fn test_router_gateway_data_response() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        // Handshake
        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        router.process_inbound(&syn);
        let outbound = router.drain_outbound();
        let syn_ack_hdr = parse_tcp(&outbound[0][20..]).unwrap();
        let server_isn = syn_ack_hdr.seq;

        let ack = make_ack_packet(client_ip, service_ip, 54321, 80, 1001, server_isn + 1);
        router.process_inbound(&ack);
        router.drain_outbound();

        // Gateway sends response data
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
        router.process_gateway_data(1, response);

        let outbound = router.drain_outbound();
        assert!(!outbound.is_empty());

        // Verify response packet
        let resp_pkt = &outbound[0];
        let ip_hdr = parse_ipv4(resp_pkt).unwrap();
        assert_eq!(ip_hdr.src_ip, service_ip);
        assert_eq!(ip_hdr.dst_ip, client_ip);

        let tcp_data = &resp_pkt[20..];
        let tcp_hdr = parse_tcp(tcp_data).unwrap();
        assert_eq!(tcp_hdr.src_port, 80);
        assert_eq!(tcp_hdr.dst_port, 54321);
        assert!(tcp_hdr.is_ack());

        // Extract payload
        let payload_offset = tcp_hdr.header_len();
        let payload = &tcp_data[payload_offset..];
        assert_eq!(payload, response);
    }

    #[test]
    fn test_router_fin_handling() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        // Handshake
        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        router.process_inbound(&syn);
        let outbound = router.drain_outbound();
        let syn_ack_hdr = parse_tcp(&outbound[0][20..]).unwrap();
        let server_isn = syn_ack_hdr.seq;

        let ack = make_ack_packet(client_ip, service_ip, 54321, 80, 1001, server_isn + 1);
        router.process_inbound(&ack);
        router.drain_outbound();

        // Client sends FIN
        let fin = make_fin_packet(client_ip, service_ip, 54321, 80, 1001, server_isn + 1);
        let actions = router.process_inbound(&fin);

        // Should close the ZTLP stream
        assert!(actions
            .iter()
            .any(|a| matches!(a, RouterAction::CloseStream { stream_id: 1 })));

        // Should have ACK + FIN in outbound
        let outbound = router.drain_outbound();
        assert!(outbound.len() >= 1);

        // At least one should have FIN flag
        let has_fin = outbound.iter().any(|pkt| {
            let tcp_hdr = parse_tcp(&pkt[20..]).unwrap();
            tcp_hdr.is_fin()
        });
        assert!(has_fin, "should send FIN");
    }

    #[test]
    fn test_router_rst_handling() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        // Handshake
        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        router.process_inbound(&syn);
        router.drain_outbound();

        assert_eq!(router.flow_count(), 1);

        // Client sends RST
        let rst = make_rst_packet(client_ip, service_ip, 54321, 80, 1001);
        let actions = router.process_inbound(&rst);

        // Should close the ZTLP stream
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            RouterAction::CloseStream { stream_id: 1 }
        ));

        // Flow should be removed
        assert_eq!(router.flow_count(), 0);
    }

    #[test]
    fn test_router_gateway_close() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        // Full handshake
        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        router.process_inbound(&syn);
        let outbound = router.drain_outbound();
        let syn_ack_hdr = parse_tcp(&outbound[0][20..]).unwrap();
        let server_isn = syn_ack_hdr.seq;

        let ack = make_ack_packet(client_ip, service_ip, 54321, 80, 1001, server_isn + 1);
        router.process_inbound(&ack);
        router.drain_outbound();

        // Gateway closes the stream
        router.process_gateway_close(1);

        // Should have FIN in outbound
        let outbound = router.drain_outbound();
        assert!(!outbound.is_empty());
        let tcp_hdr = parse_tcp(&outbound[0][20..]).unwrap();
        assert!(tcp_hdr.is_fin());
    }

    #[test]
    fn test_router_stale_flow_cleanup() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        // Create a flow
        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        router.process_inbound(&syn);
        router.drain_outbound();

        assert_eq!(router.flow_count(), 1);

        // Manually set flow's last_activity to the past
        let flow_key = FlowKey {
            src_ip: client_ip,
            src_port: 54321,
            dst_ip: service_ip,
            dst_port: 80,
        };
        if let Some(flow) = router.flows.get_mut(&flow_key) {
            flow.last_activity =
                Instant::now() - std::time::Duration::from_secs(FLOW_TIMEOUT_SECS + 10);
        }

        let stale = router.cleanup_stale_flows();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], 1);
        assert_eq!(router.flow_count(), 0);
    }

    #[test]
    fn test_router_multiple_flows() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service1 = Ipv4Addr::new(10, 122, 0, 1);
        let service2 = Ipv4Addr::new(10, 122, 0, 2);

        // SYN to vault
        let syn1 = make_syn_packet(client_ip, service1, 54321, 443, 1000);
        let actions1 = router.process_inbound(&syn1);
        assert_eq!(actions1.len(), 1);
        match &actions1[0] {
            RouterAction::OpenStream {
                stream_id,
                service_name,
            } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(service_name, "vault");
            }
            _ => panic!("expected OpenStream"),
        }

        // SYN to http
        let syn2 = make_syn_packet(client_ip, service2, 54322, 80, 2000);
        let actions2 = router.process_inbound(&syn2);
        assert_eq!(actions2.len(), 1);
        match &actions2[0] {
            RouterAction::OpenStream {
                stream_id,
                service_name,
            } => {
                assert_eq!(*stream_id, 2);
                assert_eq!(service_name, "http");
            }
            _ => panic!("expected OpenStream"),
        }

        assert_eq!(router.flow_count(), 2);
    }

    #[test]
    fn test_router_non_tcp_ignored() {
        let mut router = make_router();

        // Build a UDP-like packet (protocol=17)
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[3] = 40;
        pkt[9] = 17; // UDP
        pkt[12] = 10;
        pkt[13] = 122;
        pkt[14] = 0;
        pkt[15] = 100;
        pkt[16] = 10;
        pkt[17] = 122;
        pkt[18] = 0;
        pkt[19] = 2;

        let actions = router.process_inbound(&pkt);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_router_out_of_subnet_ignored() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let outside_ip = Ipv4Addr::new(192, 168, 1, 1); // Not in 10.122.0.0/16

        let syn = make_syn_packet(client_ip, outside_ip, 54321, 80, 1000);
        let actions = router.process_inbound(&syn);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_router_ack_for_unknown_flow_sends_rst() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        // Send ACK without prior SYN
        let ack = make_ack_packet(client_ip, service_ip, 54321, 80, 1000, 5000);
        let actions = router.process_inbound(&ack);
        assert!(actions.is_empty());

        // Should RST
        let outbound = router.drain_outbound();
        assert_eq!(outbound.len(), 1);
        let tcp_hdr = parse_tcp(&outbound[0][20..]).unwrap();
        assert!(tcp_hdr.is_rst());
    }

    #[test]
    fn test_router_drain_outbound_clears() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        router.process_inbound(&syn);

        let first = router.drain_outbound();
        assert!(!first.is_empty());

        // Second drain should be empty
        let second = router.drain_outbound();
        assert!(second.is_empty());
    }

    #[test]
    fn test_router_gateway_data_chunking() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        // Handshake
        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        router.process_inbound(&syn);
        let outbound = router.drain_outbound();
        let syn_ack_hdr = parse_tcp(&outbound[0][20..]).unwrap();
        let server_isn = syn_ack_hdr.seq;

        let ack = make_ack_packet(client_ip, service_ip, 54321, 80, 1001, server_isn + 1);
        router.process_inbound(&ack);
        router.drain_outbound();

        // Send data larger than MSS
        let big_data = vec![0x42u8; TCP_MSS as usize + 500];
        router.process_gateway_data(1, &big_data);

        let outbound = router.drain_outbound();
        // Should be split into 2 packets (1360 + 500)
        assert_eq!(outbound.len(), 2);

        let first_tcp = parse_tcp(&outbound[0][20..]).unwrap();
        let first_payload_len = outbound[0].len() - 20 - first_tcp.header_len();
        assert_eq!(first_payload_len, TCP_MSS as usize);

        let second_tcp = parse_tcp(&outbound[1][20..]).unwrap();
        let second_payload_len = outbound[1].len() - 20 - second_tcp.header_len();
        assert_eq!(second_payload_len, 500);

        // Last segment should have PSH flag
        assert!(second_tcp.is_psh());
    }

    #[test]
    fn test_is_in_subnet() {
        let router = PacketRouter::new(Ipv4Addr::new(10, 122, 0, 100));

        assert!(router.is_in_subnet(Ipv4Addr::new(10, 122, 0, 1)));
        assert!(router.is_in_subnet(Ipv4Addr::new(10, 122, 255, 255)));
        assert!(router.is_in_subnet(Ipv4Addr::new(10, 122, 0, 0)));
        assert!(!router.is_in_subnet(Ipv4Addr::new(10, 123, 0, 1)));
        assert!(!router.is_in_subnet(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_syn_retransmit_reuses_flow() {
        let mut router = make_router();
        let client_ip = Ipv4Addr::new(10, 122, 0, 100);
        let service_ip = Ipv4Addr::new(10, 122, 0, 2);

        // First SYN
        let syn = make_syn_packet(client_ip, service_ip, 54321, 80, 1000);
        let actions1 = router.process_inbound(&syn);
        assert_eq!(actions1.len(), 1);
        router.drain_outbound();

        // Same SYN again (retransmit)
        let actions2 = router.process_inbound(&syn);
        // Should close old stream and open new one
        assert!(actions2.len() >= 1);
        assert_eq!(router.flow_count(), 1);
    }
}
