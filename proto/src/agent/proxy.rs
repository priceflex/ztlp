//! SSH ProxyCommand — stdin/stdout ↔ ZTLP tunnel.
//!
//! Implements `ztlp proxy <hostname> <port>` for use as an SSH ProxyCommand.
//! Resolves the ZTLP name (via NS or custom domain mapping), establishes a
//! Noise_XX tunnel to the target peer, requests TCP forwarding to the given
//! port, and bidirectionally pipes stdin/stdout through the encrypted tunnel.
//!
//! ## Usage
//!
//! ```bash
//! # Direct use:
//! ztlp proxy fileserver.techrockstars.ztlp 22
//!
//! # In ~/.ssh/config:
//! Host *.ztlp
//!     ProxyCommand ztlp proxy %h %p
//!
//! Host *.internal.techrockstars.com
//!     ProxyCommand ztlp proxy %h %p
//! ```
//!
//! ## How it works
//!
//! 1. Load identity from `~/.ztlp/identity.json`
//! 2. Resolve hostname → ZTLP name (native or via domain_map)
//! 3. Query ZTLP-NS for the target's SVC record (IP:port + NodeID)
//! 4. Perform Noise_XX handshake with the target peer
//! 5. Send a service request for the target TCP port
//! 6. Pipe stdin → ZTLP tunnel → peer → TCP service
//! 7. Pipe TCP service → peer → ZTLP tunnel → stdout
//! 8. Exit when either side closes

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::debug;

use crate::handshake::HandshakeContext;
use crate::identity::{NodeId, NodeIdentity};
use crate::packet::{
    DataHeader, HandshakeHeader, MsgType, SessionId, DATA_HEADER_SIZE, HANDSHAKE_HEADER_SIZE,
};
use crate::pipeline::{compute_header_auth_tag, Pipeline};
use crate::reject::RejectFrame;
use crate::transport::TransportNode;
use crate::tunnel;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use super::config::{AgentConfig, StaticProxyTargetConfig};
use super::domain_map::DomainMapper;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Handshake timeout.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Short post-handshake window to surface server-side REJECT frames.
const REJECT_POLL_TIMEOUT: Duration = Duration::from_millis(500);

/// NS query timeout.
const NS_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum read buffer for stdin.
const STDIN_READ_BUF: usize = 65536;

/// Maximum plaintext per ZTLP data packet — kept identical to the gateway's
/// `tunnel::MAX_PLAINTEXT_PER_PACKET` so the on-wire UDP packet stays under
/// the ~1500-byte Ethernet MTU after ZTLP/UDP/IP overhead. A larger value
/// here causes UDP fragmentation, and most consumer NATs (and Windows
/// Defender Firewall in particular) silently drop fragmented inbound UDP,
/// which manifests as SSH KEXINIT hanging immediately after the banner.
const MAX_PLAINTEXT_PER_PACKET: usize = tunnel::MAX_PLAINTEXT_PER_PACKET;

/// Frame type bytes (must match tunnel.rs).
const FRAME_DATA: u8 = 0x00;
const FRAME_ACK: u8 = 0x01;
const FRAME_FIN: u8 = 0x02;
const FRAME_NACK: u8 = 0x03;

/// ACK send interval.
const ACK_INTERVAL: Duration = Duration::from_millis(50);

/// Maximum out-of-order packets to buffer before NACK.
const MAX_REORDER_BUFFER: usize = 512;

// ─── NS Resolution ──────────────────────────────────────────────────────────

/// Result of resolving a ZTLP name via NS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsResolution {
    /// The resolved peer endpoint address.
    pub addr: SocketAddr,
    /// The peer's NodeID (if found in KEY record).
    pub node_id: Option<NodeId>,
    /// The ZTLP-NS name that was queried.
    pub ztlp_name: String,
}

/// Query ZTLP-NS for a name, returning the SVC endpoint and optional NodeID.
pub async fn ns_resolve(
    ztlp_name: &str,
    ns_server: &str,
) -> Result<NsResolution, Box<dyn std::error::Error + Send + Sync>> {
    let addr = ns_query_addr(ztlp_name, ns_server)
        .await?
        .ok_or_else(|| format!("no SVC address found for '{}'", ztlp_name))?;

    let node_id = ns_query_node_id(ztlp_name, ns_server).await?;

    Ok(NsResolution {
        addr,
        node_id,
        ztlp_name: ztlp_name.to_string(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProxyTargetResolution {
    Static(NsResolution),
    NsLookup { ztlp_name: String },
}

fn resolve_proxy_target_from_config(
    config: &AgentConfig,
    hostname: &str,
) -> Result<ProxyTargetResolution, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(target) = config.proxy_targets.get(hostname) {
        return Ok(ProxyTargetResolution::Static(static_proxy_resolution(
            hostname, target,
        )?));
    }

    let mapper = DomainMapper::new(&config.dns.domain_map);
    let ztlp_name = mapper.to_ztlp_name(hostname).ok_or_else(|| {
        format!(
            "hostname '{}' is not a native .ztlp name and does not match dns.domain_map",
            hostname
        )
    })?;

    Ok(ProxyTargetResolution::NsLookup { ztlp_name })
}

fn static_proxy_resolution(
    hostname: &str,
    target: &StaticProxyTargetConfig,
) -> Result<NsResolution, Box<dyn std::error::Error + Send + Sync>> {
    let addr = target.addr.parse().map_err(|e| {
        format!(
            "invalid static proxy target addr '{}' for '{}': {}",
            target.addr, hostname, e
        )
    })?;

    Ok(NsResolution {
        addr,
        node_id: target.node_id,
        ztlp_name: target
            .ztlp_name
            .clone()
            .unwrap_or_else(|| hostname.to_lowercase()),
    })
}

async fn ns_query_addr(
    ztlp_name: &str,
    ns_server: &str,
) -> Result<Option<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(data) = ns_query_raw(ztlp_name, ns_server, 2).await? {
        match parse_svc_response(&data) {
            Ok(addr) => return Ok(Some(addr)),
            Err(e) => eprintln!("DEBUG: parse_svc_response failed for type 2: {}", e),
        }
    }

    if let Some(data) = ns_query_raw(ztlp_name, ns_server, 1).await? {
        if let Some(addr_str) = cbor_extract_string(&data, "address") {
            let addr = addr_str
                .parse()
                .map_err(|e| format!("invalid address in KEY record '{}': {}", addr_str, e))?;
            return Ok(Some(addr));
        }
    }

    Ok(None)
}

async fn ns_query_node_id(
    ztlp_name: &str,
    ns_server: &str,
) -> Result<Option<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(data) = ns_query_raw(ztlp_name, ns_server, 1).await? else {
        return Ok(None);
    };

    match parse_key_node_id(&data) {
        Ok(node_id) => Ok(Some(node_id)),
        Err(_) => Ok(None),
    }
}

async fn ns_query_raw(
    name: &str,
    ns_server: &str,
    record_type: u8,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let ns_addr: SocketAddr = ns_server
        .parse()
        .map_err(|e| format!("invalid NS server address '{}': {}", ns_server, e))?;
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let mut query = Vec::with_capacity(4 + name_bytes.len());
    query.push(0x01);
    query.extend_from_slice(&name_len.to_be_bytes());
    query.extend_from_slice(name_bytes);
    query.push(record_type);

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&query, ns_addr).await?;
    let mut buf = vec![0u8; 65535];
    match timeout(NS_QUERY_TIMEOUT, sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            let data = &buf[..len];

            if data.is_empty() || data[0] != 0x02 {
                return Ok(None);
            }

            let record = if data.len() > 5 && data[1] == 0x01 {
                &data[2..]
            } else {
                &data[1..]
            };

            if record.len() < 4 {
                return Ok(None);
            }
            let name_len = u16::from_be_bytes([record[1], record[2]]) as usize;
            if record.len() < 3 + name_len + 4 {
                return Ok(None);
            }
            let offset = 3 + name_len;
            let data_len = u32::from_be_bytes([
                record[offset],
                record[offset + 1],
                record[offset + 2],
                record[offset + 3],
            ]) as usize;
            if record.len() < offset + 4 + data_len {
                return Ok(None);
            }

            let data_start = offset + 4;
            Ok(Some(record[data_start..data_start + data_len].to_vec()))
        }
        _ => Ok(None),
    }
}

/// Parse a SVC record response to extract the endpoint address.
fn parse_svc_response(data: &[u8]) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    let address_str =
        cbor_extract_string(data, "address").ok_or("SVC record missing address")?;

    address_str
        .parse()
        .map_err(|e| format!("invalid address in SVC record '{}': {}", address_str, e).into())
}

fn resolved_peer_addr(resolution: &NsResolution) -> SocketAddr {
    resolution.addr
}

fn decode_reject_payload(plaintext: &[u8]) -> Option<String> {
    if !RejectFrame::is_reject(plaintext) {
        return None;
    }

    RejectFrame::decode(plaintext)
        .map(|reject| format!("access denied: {} ({})", reject.message, reject.reason))
}

async fn poll_for_post_handshake_reject(
    node: &TransportNode,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let reject_deadline = tokio::time::sleep(REJECT_POLL_TIMEOUT);
    tokio::pin!(reject_deadline);

    loop {
        tokio::select! {
            _ = &mut reject_deadline => return Ok(()),
            result = node.recv_data() => {
                match result {
                    Ok(Some((plaintext, _from))) => {
                        if let Some(err) = decode_reject_payload(&plaintext) {
                            return Err(err.into());
                        }
                        // Non-reject data — ignore during this window.
                    }
                    Ok(None) => {}
                    Err(_) => return Ok(()),
                }
            }
        }
    }
}

/// Parse a KEY record response to extract the NodeID.
fn parse_key_node_id(data: &[u8]) -> Result<NodeId, Box<dyn std::error::Error + Send + Sync>> {
    let record = parse_ns_record(data).ok_or("invalid NS response (parse failed)")?;
    if record.status != NsResponseStatus::Found {
        return Err("NS response: record not found or revoked".into());
    }

    let nid_hex =
        cbor_extract_string(&record.data, "node_id").ok_or("KEY record missing 'node_id'")?;

    if nid_hex.len() != 32 {
        return Err(format!("invalid NodeID hex length: {}", nid_hex.len()).into());
    }

    let bytes = hex::decode(&nid_hex)?;
    if bytes.len() != 16 {
        return Err("NodeID must be 16 bytes".into());
    }

    let mut nid = [0u8; 16];
    nid.copy_from_slice(&bytes);
    Ok(NodeId::from_bytes(nid))
}

// Delegate CBOR parsing to the shared ns_cbor module (also available in ios-sync builds).
use crate::ns_cbor::{cbor_extract_string, parse_ns_record, NsResponseStatus};

// ─── Proxy Command ──────────────────────────────────────────────────────────

/// Run the proxy command: resolve hostname, establish tunnel, pipe stdin/stdout.
///
/// This is designed for use as an SSH ProxyCommand. All diagnostic output
/// goes to stderr; only tunnel data goes through stdin/stdout.
///
/// # Arguments
///
/// * `hostname` — ZTLP name or custom domain (e.g., `fileserver.techrockstars.ztlp`
///   or `fileserver.internal.techrockstars.com`)
/// * `port` — TCP port on the remote peer (e.g., 22 for SSH)
/// * `identity_path` — Optional path to identity file (default: `~/.ztlp/identity.json`)
/// * `ns_server` — Optional NS server address override
/// * `relay_addr` — Optional relay server address (host:port). When set, handshake
///   packets are sent to the relay instead of directly to the peer, enabling
///   connectivity to peers behind NAT.
pub async fn run_proxy(
    hostname: &str,
    port: u16,
    identity_path: Option<&str>,
    ns_server_override: Option<&str>,
    relay_addr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── Load config + identity ──────────────────────────────────────────
    let config = AgentConfig::load();

    let identity_file = if let Some(p) = identity_path {
        std::path::PathBuf::from(p)
    } else {
        config.identity_path()
    };

    let identity = NodeIdentity::load(&identity_file).map_err(|e| {
        format!(
            "failed to load identity from {}: {}\n\
             Hint: run `ztlp setup` to create an identity, or use --key <path>",
            identity_file.display(),
            e
        )
    })?;

    eprintln!(
        "[ztlp proxy] identity: {} ({})",
        identity.node_id,
        identity_file.display()
    );
    // ── Resolve Hostname ────────────────────────────────────────────────
    let resolution = match resolve_proxy_target_from_config(&config, hostname)? {
        ProxyTargetResolution::Static(resolution) => resolution,
        ProxyTargetResolution::NsLookup { ztlp_name } => {
            let ns_server = ns_server_override.unwrap_or_else(|| config.ns_server());
            ns_resolve(&ztlp_name, ns_server).await?
        }
    };

    eprintln!(
        "[ztlp proxy] resolved {} → {} (NodeID: {})",
        resolution.ztlp_name,
        resolution.addr,
        resolution
            .node_id
            .map(|n| format!("{}", n))
            .unwrap_or_else(|| "unknown".to_string())
    );

    // ── Establish ZTLP tunnel ───────────────────────────────────────────
    let node = TransportNode::bind(&config.tunnel.bind).await?;

    let peer_addr = resolved_peer_addr(&resolution);

    // ── Determine send address (relay or direct) ────────────────────────
    let send_addr = if let Some(relay) = relay_addr {
        let relay_sock: std::net::SocketAddr = relay
            .parse()
            .map_err(|e| format!("invalid relay address '{}': {}", relay, e))?;
        eprintln!("[ztlp proxy] relay: {} (target: {})", relay, peer_addr);
        relay_sock
    } else {
        peer_addr
    };

    let session_id = SessionId::generate();
    let mut ctx = HandshakeContext::new_initiator(&identity)?;

    eprintln!(
        "[ztlp proxy] handshake → {}:{}{}",
        peer_addr,
        port,
        if relay_addr.is_some() {
            " [via relay]"
        } else {
            ""
        }
    );
    let dst_svc_hash = crate::tunnel::encode_service_name(&resolution.ztlp_name)?;

    // Message 1: HELLO
    let msg1 = ctx.write_message(&[])?;
    let mut hello_hdr = HandshakeHeader::new(MsgType::Hello);
    hello_hdr.session_id = session_id;
    hello_hdr.src_node_id = *identity.node_id.as_bytes();
    hello_hdr.payload_len = msg1.len() as u16;
    hello_hdr.dst_svc_hash = dst_svc_hash;
    let mut pkt1 = hello_hdr.serialize();
    pkt1.extend_from_slice(&msg1);
    node.send_raw(&pkt1, send_addr).await?;

    // Message 2: receive HELLO_ACK (with retransmit)
    let mut retry_delay = std::time::Duration::from_millis(500);
    let mut retries = 0;

    let (recv2, _from2) = loop {
        match timeout(retry_delay, node.recv_raw()).await {
            Ok(Ok((data, addr))) => {
                if data.len() >= HANDSHAKE_HEADER_SIZE {
                    if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                        if hdr.msg_type == MsgType::HelloAck && hdr.session_id == session_id {
                            break (data, addr);
                        }
                    }
                }
                continue;
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                retries += 1;
                if retries > 5 {
                    return Err(
                        "handshake timeout waiting for HELLO_ACK (max retries reached)".into(),
                    );
                }
                node.send_raw(&pkt1, send_addr).await?;
                retry_delay = (retry_delay * 2).min(std::time::Duration::from_millis(2000));
            }
        }
    };

    if recv2.len() < HANDSHAKE_HEADER_SIZE {
        return Err("received packet too short for handshake header".into());
    }
    let recv2_header = HandshakeHeader::deserialize(&recv2)?;
    if recv2_header.msg_type != MsgType::HelloAck {
        return Err(format!("expected HELLO_ACK, got {:?}", recv2_header.msg_type).into());
    }

    let noise_payload2 = &recv2[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload2)?;

    // Message 3: final confirmation
    let msg3 = ctx.write_message(&[])?;
    let mut final_hdr = HandshakeHeader::new(MsgType::Data);
    final_hdr.session_id = session_id;
    final_hdr.src_node_id = *identity.node_id.as_bytes();
    final_hdr.payload_len = msg3.len() as u16;
    let mut pkt3 = final_hdr.serialize();
    pkt3.extend_from_slice(&msg3);
    node.send_raw(&pkt3, send_addr).await?;

    // Finalize handshake
    if !ctx.is_finished() {
        return Err("handshake did not complete".into());
    }

    let peer_node_id = NodeId::from_bytes(recv2_header.src_node_id);
    let (_transport, session) = ctx.finalize(peer_node_id, session_id)?;

    // Extract crypto keys before moving session into pipeline
    let send_key_bytes = session.send_key;
    let recv_key_bytes = session.recv_key;

    // Register session in pipeline
    {
        let mut pipeline = node.pipeline.lock().await;
        pipeline.register_session(session);
    }

    eprintln!(
        "[ztlp proxy] tunnel established → {} (session {})",
        peer_addr, session_id
    );

    poll_for_post_handshake_reject(&node).await?;

    // ── Bidirectional pipe: stdin/stdout ↔ ZTLP tunnel ─────────────────
    // Note: When a relay is configured, send_addr != peer_addr and the
    // relay forwards our encrypted packets to the peer. The peer's
    // responses come back directly to our UDP socket (via NAT punch-
    // through from the handshake), so the recv path still works.
    run_stdio_bridge(
        node.socket.clone(),
        node.pipeline.clone(),
        session_id,
        send_addr,
        &send_key_bytes,
        &recv_key_bytes,
    )
    .await
}

/// Bidirectional bridge between stdin/stdout and a ZTLP tunnel.
///
/// This is the core of the proxy command. It runs two tasks concurrently:
/// - stdin → encrypt → UDP send (to peer via ZTLP)
/// - UDP recv → decrypt → stdout (from peer via ZTLP)
///
/// The function returns when either side closes (stdin EOF or FIN from peer).
async fn run_stdio_bridge(
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    send_key: &[u8],
    recv_key: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let udp_send = udp_socket.clone();
    let udp_recv = udp_socket;
    let pipeline_send = pipeline.clone();
    let pipeline_recv = pipeline;

    // Each task gets its own cipher instance from the raw key bytes
    let send_key_owned = send_key.to_vec();
    let recv_key_owned = recv_key.to_vec();

    // Shared state for sequence tracking
    let send_seq = Arc::new(AtomicU64::new(0));
    let recv_delivered_seq = Arc::new(AtomicU64::new(0));

    // ── Task 1: stdin → ZTLP tunnel ────────────────────────────────────
    let stdin_task = {
        let udp = udp_send;
        let pl = pipeline_send;
        let seq = send_seq.clone();

        let send_cipher = ChaCha20Poly1305::new_from_slice(&send_key_owned)
            .map_err(|e| format!("invalid send key: {}", e))?;

        tokio::spawn(async move {
            let mut stdin = io::stdin();
            let mut buf = vec![0u8; STDIN_READ_BUF];

            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(0) => {
                        // EOF on stdin — send FIN frame
                        debug!("stdin EOF, sending FIN");
                        let data_seq = seq.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = send_frame(
                            &udp,
                            &pl,
                            &send_cipher,
                            session_id,
                            peer_addr,
                            FRAME_FIN,
                            data_seq,
                            &[],
                        )
                        .await
                        {
                            debug!("failed to send FIN: {}", e);
                        }
                        return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                    }
                    Ok(n) => n,
                    Err(e) => {
                        debug!("stdin read error: {}", e);
                        return Err(e.into());
                    }
                };

                // Split into packets if needed
                let data = &buf[..n];
                let mut offset = 0;
                while offset < data.len() {
                    let chunk_end = (offset + MAX_PLAINTEXT_PER_PACKET).min(data.len());
                    let chunk = &data[offset..chunk_end];
                    let data_seq = seq.fetch_add(1, Ordering::Relaxed);

                    send_frame(
                        &udp,
                        &pl,
                        &send_cipher,
                        session_id,
                        peer_addr,
                        FRAME_DATA,
                        data_seq,
                        chunk,
                    )
                    .await?;

                    offset = chunk_end;
                }
            }
        })
    };

    // ── Task 2: ZTLP tunnel → stdout ───────────────────────────────────
    let recv_task = {
        let udp = udp_recv;
        let _pl = pipeline_recv;
        let delivered = recv_delivered_seq.clone();

        let recv_cipher = ChaCha20Poly1305::new_from_slice(&recv_key_owned)
            .map_err(|e| format!("invalid recv key: {}", e))?;

        tokio::spawn(async move {
            let mut stdout = io::stdout();
            let mut reorder_buf: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
            let mut expected_seq: u64 = 0;
            let mut last_ack_time = Instant::now();
            let mut recv_buf = vec![0u8; 65535];

            loop {
                // Receive with timeout to periodically send ACKs
                let recv_result = timeout(ACK_INTERVAL, udp.recv_from(&mut recv_buf)).await;

                match recv_result {
                    Ok(Ok((len, _from))) => {
                        let pkt = &recv_buf[..len];

                        // Must be at least a data header
                        if len < DATA_HEADER_SIZE {
                            continue;
                        }

                        // Parse ZTLP data header
                        let header = match DataHeader::deserialize(pkt) {
                            Ok(h) => h,
                            Err(_) => continue,
                        };

                        // Check session ID
                        if header.session_id != session_id {
                            continue;
                        }

                        // Decrypt payload
                        let ciphertext = &pkt[DATA_HEADER_SIZE..];
                        let mut nonce_bytes = [0u8; 12];
                        // NOTE: nonce uses little-endian to match the rest of the codebase
                        // (tunnel.rs, ztlp-cli.rs multi-session listener, ffi.rs, transport.rs).
                        // An earlier version used to_be_bytes() here which made every packet
                        // past packet_seq=0 fail decryption (BE and LE only collide on 0).
                        // Symptom: SSH banner exchange works (seq=0) but KEXINIT response is
                        // silently dropped (seq=2), and SSH times out with "banner timed out".
                        nonce_bytes[4..].copy_from_slice(&header.packet_seq.to_le_bytes());
                        let nonce = Nonce::from_slice(&nonce_bytes);

                        let plaintext = match recv_cipher.decrypt(nonce, ciphertext) {
                            Ok(pt) => pt,
                            Err(_) => {
                                debug!("decryption failed for seq {}", header.packet_seq);
                                continue;
                            }
                        };

                        if plaintext.is_empty() {
                            continue;
                        }

                        let frame_type = plaintext[0];
                        let frame_data = &plaintext[1..];

                        match frame_type {
                            FRAME_DATA => {
                                if frame_data.len() < 8 {
                                    continue;
                                }
                                let data_seq = u64::from_be_bytes(
                                    frame_data[..8].try_into().unwrap_or([0; 8]),
                                );
                                let payload = &frame_data[8..];

                                if data_seq == expected_seq {
                                    // In-order delivery
                                    if let Err(e) = stdout.write_all(payload).await {
                                        debug!("stdout write error: {}", e);
                                        return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(
                                            (),
                                        );
                                    }
                                    if let Err(e) = stdout.flush().await {
                                        debug!("stdout flush error: {}", e);
                                        return Ok(());
                                    }
                                    expected_seq += 1;

                                    // Deliver any buffered in-order packets
                                    while let Some(data) = reorder_buf.remove(&expected_seq) {
                                        if let Err(e) = stdout.write_all(&data).await {
                                            debug!("stdout write error: {}", e);
                                            return Ok(());
                                        }
                                        expected_seq += 1;
                                    }
                                    if let Err(e) = stdout.flush().await {
                                        debug!("stdout flush error: {}", e);
                                        return Ok(());
                                    }

                                    delivered
                                        .store(expected_seq.saturating_sub(1), Ordering::Relaxed);
                                } else if data_seq > expected_seq {
                                    // Out-of-order: buffer it
                                    if reorder_buf.len() < MAX_REORDER_BUFFER {
                                        reorder_buf.insert(data_seq, payload.to_vec());
                                    }
                                }
                                // data_seq < expected_seq → duplicate, drop
                            }
                            FRAME_FIN => {
                                debug!("received FIN from peer");
                                // Flush any remaining buffered data
                                let _ = stdout.flush().await;
                                return Ok(());
                            }
                            FRAME_ACK => {
                                // Peer acknowledging our data — we don't need
                                // to track this for the proxy (no retransmission
                                // in the simple proxy; the tunnel's reliability
                                // layer handles it)
                            }
                            FRAME_NACK => {
                                // Peer requesting retransmission — not implemented
                                // in simple proxy mode (handled by tunnel layer)
                            }
                            _ => {
                                debug!("unknown frame type: 0x{:02x}", frame_type);
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("UDP recv error: {}", e);
                        return Err(e.into());
                    }
                    Err(_) => {
                        // Timeout — send periodic ACK
                    }
                }

                // Send periodic ACK
                if last_ack_time.elapsed() >= ACK_INTERVAL && expected_seq > 0 {
                    let _ack_seq = expected_seq.saturating_sub(1);
                    // We need a send cipher clone for ACKs... but we only have recv_cipher here.
                    // ACKs go through the send path. We'll handle this differently —
                    // the recv task will signal the send task to emit ACKs.
                    // For the simple proxy, we skip ACKs from the recv side since
                    // the tunnel peer handles reliability.
                    last_ack_time = Instant::now();
                }
            }
        })
    };

    // Wait for either task to complete
    tokio::select! {
        result = stdin_task => {
            match result {
                Ok(Ok(())) => {
                    debug!("stdin task completed normally");
                    // Give recv task a moment to flush
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(Err(e)) => {
                    debug!("stdin task error: {}", e);
                }
                Err(e) => {
                    debug!("stdin task panicked: {}", e);
                }
            }
        }
        result = recv_task => {
            match result {
                Ok(Ok(())) => {
                    debug!("recv task completed normally (peer closed)");
                }
                Ok(Err(e)) => {
                    debug!("recv task error: {}", e);
                }
                Err(e) => {
                    debug!("recv task panicked: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Build the AAD bytes used when authenticating an outbound ZTLP data header.
///
/// The verifier (Pipeline::layer3_auth_check) authenticates the non-contiguous
/// tag-free header bytes via DataHeader::aad_bytes(). Producers MUST use the
/// same construction or every packet will be rejected as auth_tag_invalid.
fn data_frame_aad(header: &DataHeader) -> Vec<u8> {
    // AAD must be the non-contiguous tag-free header bytes — use the canonical
    // DataHeader::aad_bytes() helper so producer and verifier agree.
    header.aad_bytes()
}

/// Encrypt and send a framed data packet through the ZTLP tunnel.
#[allow(clippy::too_many_arguments)]
async fn send_frame(
    udp: &UdpSocket,
    pipeline: &Mutex<Pipeline>,
    cipher: &ChaCha20Poly1305,
    session_id: SessionId,
    peer_addr: SocketAddr,
    frame_type: u8,
    data_seq: u64,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Build plaintext: [frame_type: 1] [data_seq: 8 BE] [payload]
    let mut plaintext = Vec::with_capacity(1 + 8 + payload.len());
    plaintext.push(frame_type);
    plaintext.extend_from_slice(&data_seq.to_be_bytes());
    plaintext.extend_from_slice(payload);

    // Get packet_seq from session state
    let (packet_seq, send_key) = {
        let mut pl = pipeline.lock().await;
        let session = pl
            .get_session_mut(&session_id)
            .ok_or("session not found in pipeline")?;
        let seq = session.next_send_seq();
        (seq, session.send_key)
    };

    // Encrypt
    let mut nonce_bytes = [0u8; 12];
    // NOTE: nonce uses little-endian to match the rest of the codebase (gateway side).
    // Using to_be_bytes() here caused every proxy→gateway data packet past packet_seq=0
    // to fail decryption on the gateway side (see decryption-side note above).
    nonce_bytes[4..].copy_from_slice(&packet_seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("encryption failed: {}", e))?;

    // Build ZTLP data header
    let mut header = DataHeader::new(session_id, packet_seq);
    header.payload_len = ciphertext.len() as u16;

    // Compute auth tag using the session's send key.
    let aad = data_frame_aad(&header);
    header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);

    let mut pkt = header.serialize();
    pkt.extend_from_slice(&ciphertext);

    udp.send_to(&pkt, peer_addr).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::config::{AgentConfig, StaticProxyTargetConfig};
    use crate::reject::{RejectFrame, RejectReason};

    #[test]
    fn test_cbor_extract_string() {
        // Build a simple CBOR map: {"address": "10.0.0.1:23095"}
        let mut cbor = Vec::new();
        // Map with 1 entry: 0xA1
        cbor.push(0xA1);
        // Key: "address" (7 bytes): 0x67 + "address"
        cbor.push(0x67);
        cbor.extend_from_slice(b"address");
        // Value: "10.0.0.1:23095" (14 bytes): 0x6E + value
        cbor.push(0x6E);
        cbor.extend_from_slice(b"10.0.0.1:23095");

        assert_eq!(
            cbor_extract_string(&cbor, "address"),
            Some("10.0.0.1:23095".to_string())
        );
        assert_eq!(cbor_extract_string(&cbor, "missing"), None);
    }

    #[test]
    fn test_cbor_extract_string_multi_field() {
        // CBOR map: {"node_id": "abcd1234...", "zone": "test.ztlp"}
        let mut cbor = Vec::new();
        cbor.push(0xA2); // map with 2 entries

        // "node_id" (7 bytes)
        cbor.push(0x67);
        cbor.extend_from_slice(b"node_id");
        // 32-char hex string
        cbor.push(0x78);
        cbor.push(32); // length in next byte
        cbor.extend_from_slice(b"abcdef0123456789abcdef0123456789");

        // "zone" (4 bytes)
        cbor.push(0x64);
        cbor.extend_from_slice(b"zone");
        // "test.ztlp" (9 bytes)
        cbor.push(0x69);
        cbor.extend_from_slice(b"test.ztlp");

        assert_eq!(
            cbor_extract_string(&cbor, "node_id"),
            Some("abcdef0123456789abcdef0123456789".to_string())
        );
        assert_eq!(
            cbor_extract_string(&cbor, "zone"),
            Some("test.ztlp".to_string())
        );
    }

    #[test]
    fn test_cbor_extract_empty() {
        assert_eq!(cbor_extract_string(&[], "key"), None);
    }

    #[test]
    fn test_cbor_extract_not_a_map() {
        // A text string instead of a map
        let cbor = vec![0x65, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(cbor_extract_string(&cbor, "key"), None);
    }

    fn ns_found_response(record_type: u8, name: &str, cbor_data: &[u8]) -> Vec<u8> {
        let mut resp = vec![0x02, record_type];
        resp.extend_from_slice(&(name.len() as u16).to_be_bytes());
        resp.extend_from_slice(name.as_bytes());
        resp.extend_from_slice(&(cbor_data.len() as u32).to_be_bytes());
        resp.extend_from_slice(cbor_data);
        resp
    }

    #[test]
    fn test_parse_svc_response_extracts_address_field() {
        let mut cbor = Vec::new();
        cbor.push(0xA1);
        cbor.push(0x67);
        cbor.extend_from_slice(b"address");
        cbor.push(0x6E);
        cbor.extend_from_slice(b"10.0.0.1:23095");

        let response = ns_found_response(0x02, "test.techrockstars.ztlp", &cbor);
        let addr = parse_svc_response(&response).unwrap();

        assert_eq!(addr, "10.0.0.1:23095".parse().unwrap());
    }

    #[test]
    fn test_parse_svc_response_errors_when_address_missing() {
        let mut cbor = Vec::new();
        cbor.push(0xA1);
        cbor.push(0x64);
        cbor.extend_from_slice(b"zone");
        cbor.push(0x69);
        cbor.extend_from_slice(b"test.ztlp");

        let response = ns_found_response(0x02, "test.techrockstars.ztlp", &cbor);
        let err = parse_svc_response(&response).unwrap_err().to_string();

        assert!(err.contains("missing address"), "unexpected error: {err}");
    }

    #[test]
    fn test_resolved_peer_addr_uses_resolution_addr() {
        let resolution = NsResolution {
            addr: "10.0.0.99:22000".parse().unwrap(),
            node_id: None,
            ztlp_name: "test.techrockstars.ztlp".to_string(),
        };

        assert_eq!(resolved_peer_addr(&resolution), resolution.addr);
    }

    #[test]
    fn test_resolve_prefers_static_proxy_target() {
        let mut cfg = AgentConfig::default();
        cfg.proxy_targets.insert(
            "windows-relay.internal.techrockstars.com".to_string(),
            StaticProxyTargetConfig {
                ztlp_name: Some("windows.techrockstars.ztlp".to_string()),
                addr: "10.170.3.111:23095".to_string(),
                node_id: Some(NodeId::from_bytes(
                    hex::decode("b88397923c2518ca6aa400eb79a18c7b")
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )),
            },
        );
        cfg.dns.domain_map.insert(
            "internal.techrockstars.com".to_string(),
            "techrockstars.ztlp".to_string(),
        );

        let resolution =
            resolve_proxy_target_from_config(&cfg, "windows-relay.internal.techrockstars.com")
                .unwrap();

        assert_eq!(
            resolution,
            ProxyTargetResolution::Static(NsResolution {
                addr: "10.170.3.111:23095".parse().unwrap(),
                node_id: Some(NodeId::from_bytes(
                    hex::decode("b88397923c2518ca6aa400eb79a18c7b")
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )),
                ztlp_name: "windows.techrockstars.ztlp".to_string(),
            })
        );
    }

    #[test]
    fn test_resolve_falls_back_to_domain_map_when_no_static_target() {
        let mut cfg = AgentConfig::default();
        cfg.dns.domain_map.insert(
            "internal.techrockstars.com".to_string(),
            "techrockstars.ztlp".to_string(),
        );

        let resolution =
            resolve_proxy_target_from_config(&cfg, "db.internal.techrockstars.com").unwrap();

        assert_eq!(
            resolution,
            ProxyTargetResolution::NsLookup {
                ztlp_name: "db.techrockstars.ztlp".to_string()
            }
        );
    }

    #[test]
    fn test_resolve_native_ztlp_name_uses_ns_lookup() {
        let cfg = AgentConfig::default();

        let resolution =
            resolve_proxy_target_from_config(&cfg, "server.techrockstars.ztlp").unwrap();

        assert_eq!(
            resolution,
            ProxyTargetResolution::NsLookup {
                ztlp_name: "server.techrockstars.ztlp".to_string()
            }
        );
    }

    #[test]
    fn test_decode_reject_payload_surfaces_message_and_reason() {
        let payload =
            RejectFrame::new(RejectReason::ServiceUnavailable, "ssh service disabled").encode();

        let err = decode_reject_payload(&payload).expect("reject should decode");

        assert_eq!(
            err,
            "access denied: ssh service disabled (requested service not available)"
        );
    }

    #[test]
    fn test_decode_reject_payload_rejects_non_reject_frames() {
        assert_eq!(decode_reject_payload(&[FRAME_DATA, 0x00]), None);
    }

    #[test]
    fn test_decode_reject_payload_rejects_malformed_reject_frames() {
        assert_eq!(decode_reject_payload(&[crate::reject::FRAME_REJECT]), None);
    }

    /// Regression test for the AAD-construction bug in `send_frame`.
    ///
    /// The data-header HeaderAuthTag is computed by the producer with one AAD
    /// definition and verified by `Pipeline::layer3_auth_check` with another.
    /// The verifier uses `DataHeader::aad_bytes()` (non-contiguous, 30 bytes,
    /// tag region excluded). The producer in `send_frame` MUST use the same
    /// construction or every data frame is rejected as `auth_tag_invalid`.
    ///
    /// This test pins the producer-side AAD (via `data_frame_aad`) to match
    /// the canonical `DataHeader::aad_bytes()`. It will FAIL while the helper
    /// returns the broken full-serialized-header AAD and PASS after the fix.
    #[test]
    fn test_send_frame_aad_matches_verifier_aad() {
        // Build a DataHeader exactly the way send_frame does.
        let session_id = SessionId([0x11; 12]);
        let packet_seq: u64 = 42;
        let mut header = DataHeader::new(session_id, packet_seq);
        header.payload_len = 128;

        let producer_aad = data_frame_aad(&header);
        let verifier_aad = header.aad_bytes();

        assert_eq!(
            producer_aad, verifier_aad,
            "send_frame's AAD must match DataHeader::aad_bytes() used by \
             Pipeline::layer3_auth_check; otherwise every data packet is \
             rejected as auth_tag_invalid"
        );

        // And the resulting tags must match under the same key.
        let send_key = [0u8; 32];
        let producer_tag = compute_header_auth_tag(&send_key, &producer_aad);
        let verifier_tag = compute_header_auth_tag(&send_key, &verifier_aad);
        assert_eq!(
            producer_tag, verifier_tag,
            "producer and verifier must compute identical auth tags"
        );
    }
}
