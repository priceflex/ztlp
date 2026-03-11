//! TCP ↔ ZTLP tunnel bridge.
//!
//! Provides bidirectional forwarding between a local TCP connection and an
//! encrypted ZTLP session over UDP. This enables tunneling of arbitrary TCP
//! services (SSH, RDP, HTTP, databases, etc.) through ZTLP's identity-first
//! encrypted transport.
//!
//! Two modes of operation:
//!
//! - **Server-side (`--forward`):** After accepting a ZTLP session, connects
//!   to a local TCP service and bridges traffic bidirectionally.
//!
//! - **Client-side (`--local-forward`):** Opens a local TCP listener, performs
//!   a ZTLP handshake with the remote peer, and bridges incoming TCP
//!   connections through the encrypted ZTLP tunnel.
//!
//! The bridge uses length-prefixed framing within ZTLP data packets to
//! preserve TCP message boundaries across the UDP transport.

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::packet::{DataHeader, SessionId, DATA_HEADER_SIZE};
use crate::pipeline::{compute_header_auth_tag, AdmissionResult, Pipeline};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use std::collections::HashMap;

/// Maximum service name length (must fit in 16-byte DstSvcID field).
pub const MAX_SERVICE_NAME_LEN: usize = 16;

/// The default service name used when no name is specified.
pub const DEFAULT_SERVICE: &str = "_default";

/// Maximum TCP read buffer size per chunk.
/// Larger buffers reduce syscall overhead and improve throughput
/// for bulk transfers (SCP, file copies).
const TCP_READ_BUF: usize = 65536;

/// Maximum UDP payload (minus ZTLP header + AEAD overhead).
/// ZTLP data header is 42 bytes, Poly1305 tag is 16 bytes, so
/// max plaintext per packet ≈ 65535 - 42 - 16 = 65477.
/// We use a conservative 16KB to avoid IP fragmentation on most MTUs.
const MAX_PLAINTEXT_PER_PACKET: usize = 16384;

/// Send-side flow control: maximum number of unacknowledged packets
/// before the TCP→ZTLP direction yields to let the receiver catch up.
/// This provides basic backpressure to prevent UDP send buffer overflows
/// during sustained high-throughput transfers.
const SEND_WINDOW: u64 = 256;

/// Yield delay (microseconds) when the send window is exhausted.
/// Gives the receiver time to drain its buffer.
const BACKPRESSURE_DELAY_US: u64 = 100;

/// Run the bidirectional TCP ↔ ZTLP bridge.
///
/// Reads from the TCP stream, encrypts and sends as ZTLP data packets.
/// Receives ZTLP data packets, decrypts and writes to the TCP stream.
/// Returns when either side closes or an unrecoverable error occurs.
pub async fn run_bridge(
    tcp_stream: TcpStream,
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut tcp_reader, mut tcp_writer) = tcp_stream.into_split();

    let udp_send = udp_socket.clone();
    let udp_recv = udp_socket;
    let pipeline_send = pipeline.clone();
    let pipeline_recv = pipeline;
    let sid_send = session_id;
    let sid_recv = session_id;

    // TCP → ZTLP direction
    let tcp_to_ztlp = async move {
        let mut buf = vec![0u8; TCP_READ_BUF];

        // Extract the send key upfront to avoid holding the mutex in the hot loop.
        // The send key is established during the handshake and doesn't change.
        let (send_key, initial_seq) = {
            let mut pl = pipeline_send.lock().await;
            let session = pl.get_session_mut(&sid_send)
                .ok_or("session not found")?;
            (session.send_key, session.next_send_seq())
        };

        let cipher = ChaCha20Poly1305::new((&send_key).into());
        let mut current_seq = initial_seq;
        let mut packets_in_flight: u64 = 0;

        loop {
            let n = match tcp_reader.read(&mut buf).await {
                Ok(0) => {
                    info!("TCP connection closed (read EOF)");
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
                Ok(n) => n,
                Err(e) => {
                    warn!("TCP read error: {}", e);
                    return Err(e.into());
                }
            };

            let data = &buf[..n];
            debug!("TCP → ZTLP: {} bytes", n);

            for chunk in data.chunks(MAX_PLAINTEXT_PER_PACKET) {
                // Basic backpressure: yield periodically to let the receiver
                // drain its buffer and prevent UDP send buffer overflows
                if packets_in_flight >= SEND_WINDOW {
                    tokio::time::sleep(tokio::time::Duration::from_micros(BACKPRESSURE_DELAY_US)).await;
                    packets_in_flight = 0;
                }

                // Get next sequence number from the session (must lock briefly)
                let seq = {
                    let mut pl = pipeline_send.lock().await;
                    let session = pl.get_session_mut(&sid_send)
                        .ok_or("session not found")?;
                    session.next_send_seq()
                };
                current_seq = seq;

                // Encrypt
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..12].copy_from_slice(&seq.to_be_bytes());
                let nonce = Nonce::from_slice(&nonce_bytes);
                let encrypted = cipher.encrypt(nonce, chunk)
                    .map_err(|e| format!("encryption error: {}", e))?;

                // Build data header
                let mut header = DataHeader::new(sid_send, seq);
                let aad = header.aad_bytes();
                header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);

                // Serialize and send
                let mut packet = header.serialize();
                packet.extend_from_slice(&encrypted);
                udp_send.send_to(&packet, peer_addr).await?;
                packets_in_flight += 1;
                debug!("ZTLP sent: {} bytes (seq {})", packet.len(), seq);
            }
        }


    };

    // ZTLP → TCP direction
    let ztlp_to_tcp = async move {
        let mut buf = vec![0u8; 65535];

        // Extract recv key upfront — it doesn't change after handshake
        let recv_key = {
            let pl = pipeline_recv.lock().await;
            let session = pl.get_session(&sid_recv)
                .ok_or("session not found for recv key extraction")?;
            session.recv_key
        };
        let cipher = ChaCha20Poly1305::new((&recv_key).into());

        // Use BufWriter for TCP to batch small writes and reduce syscalls
        let mut tcp_writer = tokio::io::BufWriter::with_capacity(65536, tcp_writer);

        let mut bytes_since_flush: usize = 0;

        loop {
            let (n, _addr) = match udp_recv.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("UDP recv error: {}", e);
                    return Err::<(), Box<dyn std::error::Error>>(e.into());
                }
            };

            let data = &buf[..n];

            // Run through pipeline (brief lock)
            {
                let pl = pipeline_recv.lock().await;
                let result = pl.process(data);
                if !matches!(result, AdmissionResult::Pass) {
                    debug!("packet dropped by pipeline");
                    continue;
                }
            }

            // Parse data header
            if n < DATA_HEADER_SIZE {
                debug!("packet too short for data header");
                continue;
            }
            let header = match DataHeader::deserialize(data) {
                Ok(h) => h,
                Err(_) => {
                    debug!("failed to parse data header");
                    continue;
                }
            };

            // Verify session ID matches
            if header.session_id != sid_recv {
                debug!("wrong session ID, ignoring");
                continue;
            }

            // Decrypt
            let encrypted_payload = &data[DATA_HEADER_SIZE..];
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..12].copy_from_slice(&header.packet_seq.to_be_bytes());
            let nonce = Nonce::from_slice(&nonce_bytes);

            let plaintext = match cipher.decrypt(nonce, encrypted_payload) {
                Ok(pt) => pt,
                Err(e) => {
                    warn!("decryption failed (seq {}): {}", header.packet_seq, e);
                    continue;
                }
            };

            debug!("ZTLP → TCP: {} bytes (seq {})", plaintext.len(), header.packet_seq);

            if let Err(e) = tcp_writer.write_all(&plaintext).await {
                warn!("TCP write error: {}", e);
                return Err(e.into());
            }

            bytes_since_flush += plaintext.len();

            // Flush periodically rather than every packet — reduces syscalls
            // Flush when we've buffered 32KB+ or when the packet is small
            // (indicates end of a burst)
            if bytes_since_flush >= 32768 || plaintext.len() < MAX_PLAINTEXT_PER_PACKET {
                if let Err(e) = tcp_writer.flush().await {
                    warn!("TCP flush error: {}", e);
                    return Err(e.into());
                }
                bytes_since_flush = 0;
            }
        }
    };

    // Run both directions concurrently, stop when either ends
    tokio::select! {
        result = tcp_to_ztlp => {
            match result {
                Ok(()) => info!("tunnel closed (TCP side)"),
                Err(e) => warn!("tunnel error (TCP→ZTLP): {}", e),
            }
        }
        result = ztlp_to_tcp => {
            match result {
                Ok(()) => info!("tunnel closed (ZTLP side)"),
                Err(e) => warn!("tunnel error (ZTLP→TCP): {}", e),
            }
        }
    }

    info!("tunnel bridge terminated for session {}", session_id);
    Ok(())
}

/// A registry of named services mapped to backend TCP addresses.
///
/// Built from `--forward` flags on the listener:
/// - `--forward ssh:127.0.0.1:22` → named service "ssh"
/// - `--forward 127.0.0.1:22` → unnamed default service
/// - Multiple `--forward` flags → multi-service listener
#[derive(Debug, Clone)]
pub struct ServiceRegistry {
    pub services: HashMap<String, SocketAddr>,
}

impl ServiceRegistry {
    /// Build a service registry from a list of `--forward` arguments.
    ///
    /// Each argument is either:
    /// - `NAME:HOST:PORT` — a named service
    /// - `HOST:PORT` — the default (unnamed) service
    pub fn from_forward_args(args: &[String]) -> Result<Self, String> {
        let mut services = HashMap::new();

        for arg in args {
            let (name, addr) = parse_forward_arg(arg)?;
            if services.contains_key(&name) {
                return Err(format!("duplicate service name '{}'", name));
            }
            services.insert(name, addr);
        }

        Ok(Self { services })
    }

    /// Look up a service by the DstSvcID bytes from the handshake header.
    ///
    /// If the DstSvcID is all zeros, returns the default service.
    /// Otherwise, trims trailing zeros and looks up by name.
    pub fn resolve(&self, dst_svc_id: &[u8; 16]) -> Option<(&str, SocketAddr)> {
        let name = if dst_svc_id == &[0u8; 16] {
            DEFAULT_SERVICE.to_string()
        } else {
            // Trim trailing null bytes to get the service name
            let end = dst_svc_id.iter().rposition(|&b| b != 0)
                .map(|i| i + 1)
                .unwrap_or(0);
            String::from_utf8_lossy(&dst_svc_id[..end]).to_string()
        };

        self.services.get(&name).map(|addr| {
            let key = self.services.keys().find(|k| *k == &name).unwrap();
            (key.as_str(), *addr)
        })
    }

    /// Check if this registry has any services.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Number of registered services.
    pub fn len(&self) -> usize {
        self.services.len()
    }
}

/// Encode a service name into a 16-byte DstSvcID field.
///
/// Pads with zeros if shorter than 16 bytes.
/// Returns an error if the name is too long.
pub fn encode_service_name(name: &str) -> Result<[u8; 16], String> {
    let bytes = name.as_bytes();
    if bytes.len() > MAX_SERVICE_NAME_LEN {
        return Err(format!(
            "service name '{}' too long ({} bytes, max {})",
            name, bytes.len(), MAX_SERVICE_NAME_LEN
        ));
    }
    let mut buf = [0u8; 16];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(buf)
}

/// Parse a single `--forward` argument.
///
/// Formats:
/// - `NAME:HOST:PORT` → (name, address)
/// - `HOST:PORT` → (DEFAULT_SERVICE, address)
fn parse_forward_arg(s: &str) -> Result<(String, SocketAddr), String> {
    // Try to parse as a plain address first (HOST:PORT)
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok((DEFAULT_SERVICE.to_string(), addr));
    }

    // Try NAME:HOST:PORT — split on first ':'
    let first_colon = s.find(':')
        .ok_or_else(|| format!("invalid --forward argument '{}'. Expected NAME:HOST:PORT or HOST:PORT", s))?;

    let name = &s[..first_colon];
    let addr_str = &s[first_colon + 1..];

    // Validate the name
    if name.is_empty() {
        return Err(format!("empty service name in '{}'", s));
    }
    if name.len() > MAX_SERVICE_NAME_LEN {
        return Err(format!(
            "service name '{}' too long ({} bytes, max {})",
            name, name.len(), MAX_SERVICE_NAME_LEN
        ));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(format!(
            "service name '{}' contains invalid characters (use a-z, 0-9, -, _)",
            name
        ));
    }

    let addr: SocketAddr = addr_str.parse()
        .map_err(|e| format!("invalid address '{}' in '{}': {}", addr_str, s, e))?;

    Ok((name.to_string(), addr))
}

/// Parse a forward target string like "127.0.0.1:22" into a SocketAddr.
pub fn parse_forward_target(s: &str) -> Result<SocketAddr, String> {
    s.parse::<SocketAddr>()
        .map_err(|e| format!("invalid forward target '{}': {}", s, e))
}

/// Parse a local-forward string like "2222:127.0.0.1:22" into (local_port, remote_addr).
pub fn parse_local_forward(s: &str) -> Result<(u16, String), String> {
    // Format: local_port:remote_host:remote_port
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "invalid local-forward format '{}'. Expected: LOCAL_PORT:REMOTE_HOST:REMOTE_PORT",
            s
        ));
    }

    let local_port: u16 = parts[0].parse()
        .map_err(|_| format!("invalid local port '{}' in '{}'", parts[0], s))?;

    let remote = parts[1].to_string();

    // Validate the remote part looks like host:port
    if !remote.contains(':') {
        return Err(format!(
            "invalid remote address '{}'. Expected HOST:PORT",
            remote
        ));
    }

    Ok((local_port, remote))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_forward_target() {
        let addr = parse_forward_target("127.0.0.1:22").unwrap();
        assert_eq!(addr.port(), 22);
        assert_eq!(addr.ip().to_string(), "127.0.0.1");

        let addr = parse_forward_target("0.0.0.0:3389").unwrap();
        assert_eq!(addr.port(), 3389);

        assert!(parse_forward_target("not-an-addr").is_err());
        assert!(parse_forward_target("127.0.0.1").is_err());
    }

    #[test]
    fn test_parse_local_forward() {
        let (port, remote) = parse_local_forward("2222:127.0.0.1:22").unwrap();
        assert_eq!(port, 2222);
        assert_eq!(remote, "127.0.0.1:22");

        let (port, remote) = parse_local_forward("3389:10.0.0.5:3389").unwrap();
        assert_eq!(port, 3389);
        assert_eq!(remote, "10.0.0.5:3389");

        assert!(parse_local_forward("invalid").is_err());
        assert!(parse_local_forward("abc:127.0.0.1:22").is_err());
        assert!(parse_local_forward("2222:noport").is_err());
    }

    #[test]
    fn test_parse_local_forward_ipv6() {
        let (port, remote) = parse_local_forward("8080:[::1]:443").unwrap();
        assert_eq!(port, 8080);
        assert_eq!(remote, "[::1]:443");
    }

    // --- Service registry tests ---

    #[test]
    fn test_parse_forward_arg_unnamed() {
        let (name, addr) = parse_forward_arg("127.0.0.1:22").unwrap();
        assert_eq!(name, DEFAULT_SERVICE);
        assert_eq!(addr.port(), 22);
    }

    #[test]
    fn test_parse_forward_arg_named() {
        let (name, addr) = parse_forward_arg("ssh:127.0.0.1:22").unwrap();
        assert_eq!(name, "ssh");
        assert_eq!(addr.port(), 22);

        let (name, addr) = parse_forward_arg("rdp:10.0.0.1:3389").unwrap();
        assert_eq!(name, "rdp");
        assert_eq!(addr.port(), 3389);
    }

    #[test]
    fn test_parse_forward_arg_invalid() {
        assert!(parse_forward_arg("").is_err());
        assert!(parse_forward_arg("noport").is_err());
        assert!(parse_forward_arg(":127.0.0.1:22").is_err()); // empty name
    }

    #[test]
    fn test_parse_forward_arg_name_too_long() {
        let long_name = "a".repeat(17);
        let arg = format!("{}:127.0.0.1:22", long_name);
        assert!(parse_forward_arg(&arg).is_err());
    }

    #[test]
    fn test_parse_forward_arg_name_invalid_chars() {
        assert!(parse_forward_arg("my service:127.0.0.1:22").is_err()); // space
        assert!(parse_forward_arg("my.svc:127.0.0.1:22").is_err()); // dot
    }

    #[test]
    fn test_service_registry_single_default() {
        let reg = ServiceRegistry::from_forward_args(&[
            "127.0.0.1:22".to_string(),
        ]).unwrap();
        assert_eq!(reg.len(), 1);
        assert!(reg.services.contains_key(DEFAULT_SERVICE));
    }

    #[test]
    fn test_service_registry_multi() {
        let reg = ServiceRegistry::from_forward_args(&[
            "ssh:127.0.0.1:22".to_string(),
            "rdp:127.0.0.1:3389".to_string(),
            "db:127.0.0.1:5432".to_string(),
        ]).unwrap();
        assert_eq!(reg.len(), 3);
        assert_eq!(reg.services["ssh"].port(), 22);
        assert_eq!(reg.services["rdp"].port(), 3389);
        assert_eq!(reg.services["db"].port(), 5432);
    }

    #[test]
    fn test_service_registry_duplicate_rejected() {
        let result = ServiceRegistry::from_forward_args(&[
            "ssh:127.0.0.1:22".to_string(),
            "ssh:127.0.0.1:2222".to_string(),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_zero_dst_svc_id() {
        let reg = ServiceRegistry::from_forward_args(&[
            "127.0.0.1:22".to_string(), // default
        ]).unwrap();
        let zeros = [0u8; 16];
        let (name, addr) = reg.resolve(&zeros).unwrap();
        assert_eq!(name, DEFAULT_SERVICE);
        assert_eq!(addr.port(), 22);
    }

    #[test]
    fn test_resolve_named_service() {
        let reg = ServiceRegistry::from_forward_args(&[
            "ssh:127.0.0.1:22".to_string(),
            "rdp:127.0.0.1:3389".to_string(),
        ]).unwrap();

        let mut svc_id = [0u8; 16];
        svc_id[..3].copy_from_slice(b"ssh");
        let (name, addr) = reg.resolve(&svc_id).unwrap();
        assert_eq!(name, "ssh");
        assert_eq!(addr.port(), 22);

        let mut svc_id2 = [0u8; 16];
        svc_id2[..3].copy_from_slice(b"rdp");
        let (name, addr) = reg.resolve(&svc_id2).unwrap();
        assert_eq!(name, "rdp");
        assert_eq!(addr.port(), 3389);
    }

    #[test]
    fn test_resolve_unknown_service() {
        let reg = ServiceRegistry::from_forward_args(&[
            "ssh:127.0.0.1:22".to_string(),
        ]).unwrap();

        let mut svc_id = [0u8; 16];
        svc_id[..5].copy_from_slice(b"mysql");
        assert!(reg.resolve(&svc_id).is_none());
    }

    #[test]
    fn test_encode_service_name() {
        let buf = encode_service_name("ssh").unwrap();
        assert_eq!(&buf[..3], b"ssh");
        assert_eq!(&buf[3..], &[0u8; 13]);

        let buf = encode_service_name("rdp").unwrap();
        assert_eq!(&buf[..3], b"rdp");

        // Exactly 16 bytes
        let name16 = "a".repeat(16);
        let buf = encode_service_name(&name16).unwrap();
        assert_eq!(&buf, name16.as_bytes());

        // Too long
        let name17 = "a".repeat(17);
        assert!(encode_service_name(&name17).is_err());
    }
}
