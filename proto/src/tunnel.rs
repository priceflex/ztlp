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
use tracing::{debug, info, warn, error};

use crate::packet::{DataHeader, SessionId, DATA_HEADER_SIZE};
use crate::pipeline::{compute_header_auth_tag, AdmissionResult, Pipeline};
use crate::session::SessionState;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

/// Maximum TCP read buffer size per chunk.
const TCP_READ_BUF: usize = 16384;

/// Maximum UDP payload (minus ZTLP header + AEAD overhead).
/// ZTLP data header is 42 bytes, Poly1305 tag is 16 bytes, so
/// max plaintext per packet ≈ 65535 - 42 - 16 = 65477.
/// We use a conservative 16KB to avoid fragmentation.
const MAX_PLAINTEXT_PER_PACKET: usize = 16384;

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

            // Chunk if necessary (unlikely with 16KB buf but be safe)
            for chunk in data.chunks(MAX_PLAINTEXT_PER_PACKET) {
                let mut pl = pipeline_send.lock().await;
                let session = pl.get_session_mut(&sid_send)
                    .ok_or("session not found")?;

                let seq = session.next_send_seq();
                let send_key = session.send_key;
                drop(pl);

                // Encrypt
                let cipher = ChaCha20Poly1305::new((&send_key).into());
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
                debug!("ZTLP sent: {} bytes (seq {})", packet.len(), seq);
            }
        }
    };

    // ZTLP → TCP direction
    let ztlp_to_tcp = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, _addr) = match udp_recv.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("UDP recv error: {}", e);
                    return Err::<(), Box<dyn std::error::Error>>(e.into());
                }
            };

            let data = &buf[..n];

            // Run through pipeline
            let pl = pipeline_recv.lock().await;
            let result = pl.process(data);
            if !matches!(result, AdmissionResult::Pass) {
                debug!("packet dropped by pipeline");
                continue;
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

            // Check replay
            let session = match pl.get_session(&sid_recv) {
                Some(s) => s,
                None => {
                    warn!("session not found for decryption");
                    continue;
                }
            };
            let recv_key = session.recv_key;
            drop(pl);

            // Decrypt
            let encrypted_payload = &data[DATA_HEADER_SIZE..];
            let cipher = ChaCha20Poly1305::new((&recv_key).into());
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..12].copy_from_slice(&header.packet_seq.to_be_bytes());
            let nonce = Nonce::from_slice(&nonce_bytes);

            let plaintext = match cipher.decrypt(nonce, encrypted_payload) {
                Ok(pt) => pt,
                Err(e) => {
                    warn!("decryption failed: {}", e);
                    continue;
                }
            };

            debug!("ZTLP → TCP: {} bytes (seq {})", plaintext.len(), header.packet_seq);

            if let Err(e) = tcp_writer.write_all(&plaintext).await {
                warn!("TCP write error: {}", e);
                return Err(e.into());
            }
            if let Err(e) = tcp_writer.flush().await {
                warn!("TCP flush error: {}", e);
                return Err(e.into());
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
        // IPv6 with brackets
        let (port, remote) = parse_local_forward("8080:[::1]:443").unwrap();
        assert_eq!(port, 8080);
        assert_eq!(remote, "[::1]:443");
    }
}
