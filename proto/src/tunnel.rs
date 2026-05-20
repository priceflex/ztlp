//! TCP ↔ ZTLP tunnel bridge with reliable ordered delivery.
//!
//! Provides bidirectional forwarding between a local TCP connection and an
//! encrypted ZTLP session over UDP. This enables tunneling of arbitrary TCP
//! services (SSH, RDP, HTTP, databases, etc.) through ZTLP's identity-first
//! encrypted transport.
//!
//! ## Reliability Layer
//!
//! UDP does not guarantee ordering or delivery. Since TCP is an ordered byte
//! stream, writing decrypted UDP packets to TCP in arrival order corrupts the
//! stream (SSH/SCP will detect this and reset the connection). This module
//! implements a lightweight reliability protocol on top of ZTLP data packets:
//!
//! - **Reassembly buffer:** Out-of-order packets are buffered and delivered
//!   to TCP in sequence-number order. Duplicates and stale packets are dropped.
//!
//! - **ACK mechanism:** The receiver periodically sends ACK frames back
//!   through the ZTLP session, reporting the highest contiguous sequence
//!   number that has been delivered to TCP.
//!
//! - **Sender flow control:** The sender tracks ACKs and limits the number
//!   of in-flight (unacknowledged) packets to a configurable window size.
//!   When the window is exhausted, the sender waits for ACKs.
//!
//! - **Congestion control:** AIMD-style congestion control with slow start
//!   and congestion avoidance phases. RTT is estimated via EWMA from ACK
//!   round-trips, with RTO computed as srtt + 4*rttvar.
//!
//! - **Retransmission:** The sender keeps a bounded retransmit buffer of
//!   sent packets. The receiver detects gaps and sends NACK frames listing
//!   missing sequence numbers. The sender re-encrypts and retransmits them.
//!
//! - **Graceful shutdown:** TCP EOF is signaled via a FIN frame so the
//!   remote side can flush buffered data and close cleanly.
//!
//! ### Frame format
//!
//! Each ZTLP data packet's plaintext is prefixed with a 1-byte frame type.
//! DATA and FIN frames carry an embedded `data_seq` (8-byte BE) that is
//! independent of the ZTLP packet header's `packet_seq`. The `packet_seq`
//! provides nonce uniqueness; `data_seq` provides reassembly ordering.
//! ACK/NACK frames reference `data_seq` values, NOT `packet_seq`.
//!
//! | Type | Byte | Payload |
//! |------|------|---------|
//! | DATA  | 0x00 | 8-byte BE data_seq + raw TCP bytes |
//! | ACK   | 0x01 | 8-byte BE data_seq: highest delivered data_seq |
//! | FIN   | 0x02 | 8-byte BE data_seq |
//! | NACK  | 0x03 | 2-byte BE count + N × 8-byte BE missing data_seqs |
//! | SACK  | 0x05 | 8-byte cumulative_ack + 2-byte count + N × (start, end) ranges |
//! | RESET | 0x04 | (empty) — signals new TCP stream, resets data_seq |
//!
//! Two modes of operation:
//!
//! - **Server-side (`--forward`):** After accepting a ZTLP session, connects
//!   to a local TCP service and bridges traffic bidirectionally.
//!
//! - **Client-side (`--local-forward`):** Opens a local TCP listener, performs
//!   a ZTLP handshake with the remote peer, and bridges incoming TCP
//!   connections through the encrypted ZTLP tunnel.

#![deny(clippy::unwrap_used)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::packet::{DataHeader, SessionId, DATA_HEADER_SIZE};
use crate::pipeline::{compute_header_auth_tag, AdmissionResult, Pipeline};
use crate::stats::TunnelStats;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Maximum service name length (must fit in 16-byte DstSvcID field).
pub const MAX_SERVICE_NAME_LEN: usize = 16;

/// The default service name used when no name is specified.
pub const DEFAULT_SERVICE: &str = "_default";

/// Maximum TCP read buffer size per chunk.
/// Larger buffers reduce syscall overhead and improve throughput
/// for bulk transfers (SCP, file copies).
const TCP_READ_BUF: usize = 131072;

/// Default maximum number of packets to send in a single sub-batch.
/// The actual value is determined at runtime based on the detected
/// UDP receive buffer size. This constant serves as the fallback when
/// system detection is unavailable.
///
/// At ~16KB per packet, 64 packets ≈ 1MB per burst.
#[allow(dead_code)]
/// Maximum packets per sendmmsg batch.
/// iOS: 16 to limit memory pressure. Desktop: 64 for throughput.
#[cfg(target_os = "ios")]
const MAX_SUB_BATCH: usize = 16;
#[cfg(not(target_os = "ios"))]
const MAX_SUB_BATCH: usize = 64;

/// Maximum UDP payload (minus ZTLP header + AEAD overhead).
/// ZTLP data header is 46 bytes, Poly1305 tag is 16 bytes, so
/// max plaintext per packet ≈ 65535 - 46 - 16 = 65473.
/// We use 16KB to stay well within IP fragmentation limits.
/// On 1500-byte MTU networks, ~16KB payloads fragment into ~11 pieces
/// which is manageable. Larger payloads suffer exponentially worse
/// fragment loss rates under any packet loss.
/// Subtract 9 bytes for the frame type prefix (1) + data_seq (8).
/// Maximum plaintext payload per ZTLP packet (TCP data only, before framing).
/// iOS: 1200B to fit in 1280-byte IPv6 min MTU (cellular-friendly).
/// Desktop: 1200B to match — this is an MTU constraint, not a memory one.
/// NOTE: This value MUST match the gateway's @max_payload_bytes (1140 + framing).
/// Currently we cap generic tunnel data at 1200 bytes per packet.
pub const MAX_PLAINTEXT_PER_PACKET: usize = 1200;

// ─── Frame types ────────────────────────────────────────────────────────────

/// Frame type byte: DATA frame containing TCP payload bytes.
const FRAME_DATA: u8 = 0x00;

/// Frame type byte: ACK frame containing 8-byte big-endian delivered seq.
const FRAME_ACK: u8 = 0x01;

/// Frame type byte: FIN frame signaling TCP EOF / stream complete.
const FRAME_FIN: u8 = 0x02;

/// Frame type byte: NACK frame listing missing sequence numbers.
/// Payload: [count: u16 BE] [seq1: u64 BE] [seq2: u64 BE] ...
const FRAME_NACK: u8 = 0x03;

/// Stream reset: signals the start of a new TCP connection within the same
/// ZTLP session. The receiver resets its reassembly state (`expected_seq` = 0)
/// and opens a new backend TCP connection. The RESET frame has no payload
/// beyond the frame type byte itself.
const FRAME_RESET: u8 = 0x04;

/// Frame type byte: SACK frame with cumulative ACK + received ranges.
/// Payload: [cumulative_ack: u64 BE] [count: u16 BE] [(start: u64 BE, end: u64 BE) × count]
const FRAME_SACK: u8 = 0x05;

/// Frame type byte: REJECT frame — server denying access after handshake.
/// Payload: [reason_code: 1B] [message: UTF-8 remaining bytes]
const FRAME_REJECT: u8 = 0x08;

/// Frame type byte: RTT_PING frame for dedicated RTT measurement.
/// Payload: [ping_id: u32 BE] [timestamp_us: u64 BE]
/// Sent periodically by the sender to obtain clean RTT samples even during
/// heavy retransmission (when Karn's algorithm filters all data-packet RTTs).
/// Never retransmitted — if lost, the next probe covers it.
const FRAME_RTT_PING: u8 = 0x06;

/// Frame type byte: RTT_PONG frame — response to RTT_PING.
/// Payload: [ping_id: u32 BE] [echo_timestamp_us: u64 BE] [receiver_delay_us: u32 BE]
/// The receiver echoes the ping_id and original timestamp, plus the time it
/// spent processing (receiver_delay_us) so the sender can subtract it.
const FRAME_RTT_PONG: u8 = 0x07;

/// Frame type byte: CORRUPTION_NACK frame — receiver detected AEAD decrypt
/// failure (bit-flip, not congestion). Same wire format as NACK. Sender
/// retransmits but does NOT reduce cwnd.
const FRAME_CORRUPTION_NACK: u8 = 0x09;

/// Frame type byte: STREAM_RESET — VIP mux protocol.
///
/// Sent by the client instead of FRAME_CLOSE + FRAME_OPEN when it wants to
/// reuse the same stream for a new HTTP request. The gateway can then reuse
/// the same backend TCP connection, avoiding a full TCP teardown/setup cycle.
///
/// Wire format: `[0x0B | stream_id(4 BE)]`
///
/// This is a mux-layer frame (like FRAME_OPEN/FRAME_CLOSE in `vip.rs`),
/// not a tunnel reliability frame. It travels inside the encrypted tunnel
/// payload alongside mux DATA/OPEN/CLOSE frames.
///
/// Gateway-side handling is added separately.
pub const FRAME_STREAM_RESET: u8 = 0x0B;

/// PLPMTUD probe request — sent with padding to test larger MTU sizes.
/// Wire format: `[0x0C | probe_size(2 BE) | probe_seq(2 BE) | padding...]`
pub const FRAME_PMTU_PROBE: u8 = 0x0C;

/// PLPMTUD probe acknowledgment.
/// Wire format: `[0x0D | probe_size(2 BE) | probe_seq(2 BE)]`
pub const FRAME_PMTU_PROBE_ACK: u8 = 0x0D;

/// Outcome of a bridge run, distinguishing normal close from a stream reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeOutcome {
    /// The TCP stream closed normally (FIN from both sides).
    Closed,
    /// A RESET frame was received — the remote side is starting a new TCP
    /// stream on the same ZTLP session. The caller should open a new backend
    /// TCP connection and start a fresh bridge.
    ResetReceived,
}

/// Result from `wait_for_reset_buffered`: indicates whether a RESET was
/// received, plus any data packets captured during the wait that must be
/// fed into the next bridge's receiver.
#[derive(Debug)]
pub struct ResetWaitResult {
    /// Whether a RESET frame was received.
    pub reset_received: bool,
    /// Raw encrypted UDP packets received after the RESET (or during the
    /// wait) that belong to the next bridge cycle. These must be processed
    /// by the new bridge to avoid data loss.
    pub buffered_packets: Vec<Vec<u8>>,
}

// ─── Dumb-pipe constants ────────────────────────────────────────────────────
//
// Nebula-pivot R3: the reliability layer (reassembly buffer, retransmit
// buffer, ACK/NACK/SACK frames, congestion control, stall detection) was
// removed. The tunnel is now a dumb encrypted pipe: encrypt-and-sendto on TX,
// decrypt-and-deliver on RX with replay-bitmap admission, no acknowledgements.

/// Keepalive interval — send a heartbeat ping if idle this long.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

// ─── HTTP header injection (passwordless admin auth) ────────────────────────
//
// When configured, the listener rewrites the FIRST decrypted HTTP request of
// each TCP bridge to inject signed X-ZTLP-* identity headers. Subsequent bytes
// on the same TCP connection flow through untouched. The signature is computed
// over the canonical (lowercased, sorted, "\n"-joined) form of the three
// injected headers and verified upstream by the Ruby/Elixir HeaderVerifier.

/// Configuration for HTTP identity-header injection on tunnel bridges.
///
/// Built once per listener startup and shared (immutably) across all bridges.
/// The `admin_pubkey_to_email` map keys are the lowercased hex of the peer's
/// Noise static public key (from `HandshakeContext::remote_static_hex()`).
#[derive(Clone, Default)]
pub struct HttpInjectionConfig {
    pub enabled: bool,
    pub hmac_secret: String,
    pub admin_pubkey_to_email: std::collections::HashMap<String, String>,
}

impl HttpInjectionConfig {
    /// Look up the admin email for a peer's Noise static-key hex, normalising
    /// case so callers don't have to.
    pub fn lookup_email(&self, peer_pubkey_hex: &str) -> Option<&str> {
        if !self.enabled {
            return None;
        }
        let lc = peer_pubkey_hex.to_lowercase();
        self.admin_pubkey_to_email.get(&lc).map(|s| s.as_str())
    }
}

/// Per-bridge state for tracking whether the first HTTP request has been
/// rewritten. Once `done` is true, all subsequent plaintext is forwarded
/// untouched.
///
/// `pending_buffer` accumulates plaintext bytes from the decrypted stream
/// across multiple frames until the first HTTP request is fully parseable
/// (header section ends with `\r\n\r\n`). This is required because a single
/// HTTP request can arrive split across several decrypted chunks — TCP
/// segmentation, MTU constraints on the underlying UDP carrier, or the
/// browser sending headers in multiple writes. The buffer is bounded to
/// MAX_HTTP_INJECT_BUFFER to prevent unbounded growth on non-HTTP traffic
/// or pathological clients.
struct HttpInjectionState {
    config: Arc<HttpInjectionConfig>,
    peer_email: String,
    done: bool,
    pending_buffer: Vec<u8>,
}

/// Cap on how much plaintext we'll accumulate while waiting for the first
/// HTTP request's header section to complete. 64 KiB is far above any
/// realistic HTTP/1.1 request-line + headers (rarely exceed 8 KiB even
/// with large cookies); going over the cap means the stream is almost
/// certainly not HTTP and we should drop the connection rather than buffer
/// forever.
const MAX_HTTP_INJECT_BUFFER: usize = 64 * 1024;

/// Format `SystemTime::now()` as a UTC ISO-8601 / RFC-3339 second-precision
/// timestamp (e.g. `2026-05-20T12:34:56Z`). Used as the value for the injected
/// `X-ZTLP-Timestamp` header; the Ruby/Elixir verifier parses this exact form.
fn iso8601_utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil time conversion (Howard Hinnant's algorithm, public domain).
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as u32;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    // Shift epoch so that day 0 == 0000-03-01 (March 1).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, minute, second
    )
}

// ─── Lazy Connect ───────────────────────────────────────────────────────────

/// Send a REJECT frame to a peer over an established ZTLP session.
///
/// This encrypts the reject frame as a DATA packet and sends it to the peer.
/// Used by the server after handshake when policy denies the client.
pub async fn send_reject(
    udp_socket: &tokio::net::UdpSocket,
    pipeline: &Mutex<Pipeline>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    reject_frame: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // Extract send key from session
    let send_key = {
        let pl = pipeline.lock().await;
        let session = pl.get_session(&session_id).ok_or("session not found")?;
        session.send_key
    };
    let cipher = ChaCha20Poly1305::new((&send_key).into());

    // Use packet_seq = 0 for the reject packet
    let packet_seq: u64 = 0;

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&packet_seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, reject_frame)
        .map_err(|e| format!("AEAD encrypt failed: {}", e))?;

    let mut header = DataHeader::new(session_id, packet_seq);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);
    header.payload_len = ciphertext.len() as u16;

    let mut packet = header.serialize();
    packet.extend_from_slice(&ciphertext);

    udp_socket.send_to(&packet, peer_addr).await?;

    Ok(())
}

/// Wait for the first valid ZTLP data packet on a session before connecting to
/// the backend service. Implements "lazy connect" for the listener side.
pub async fn wait_for_first_data(
    udp_socket: &tokio::net::UdpSocket,
    pipeline: &Mutex<Pipeline>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    timeout_duration: Duration,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now() + timeout_duration;
    let mut buffered_packets: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; 65535];

    loop {
        let recv_result = tokio::time::timeout_at(deadline, udp_socket.recv_from(&mut buf)).await;
        match recv_result {
            Err(_) => {
                return Err("timeout waiting for first data from client".into());
            }
            Ok(Err(e)) => {
                return Err(format!("recv error while waiting for first data: {}", e).into());
            }
            Ok(Ok((len, addr))) => {
                if addr != peer_addr {
                    continue;
                }

                let data = buf[..len].to_vec();

                {
                    let pl = pipeline.lock().await;
                    let result = pl.process(&data);
                    if !matches!(result, AdmissionResult::Pass) {
                        continue;
                    }
                }

                if data.len() < DATA_HEADER_SIZE {
                    continue;
                }
                let header = match DataHeader::deserialize(&data) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                if header.session_id != session_id {
                    continue;
                }

                buffered_packets.push(data);

                // Brief grace window to capture burst.
                let grace_deadline = tokio::time::Instant::now() + Duration::from_millis(50);
                loop {
                    let grace_result =
                        tokio::time::timeout_at(grace_deadline, udp_socket.recv_from(&mut buf))
                            .await;
                    match grace_result {
                        Err(_) => break,
                        Ok(Err(_)) => break,
                        Ok(Ok((glen, gaddr))) => {
                            if gaddr == peer_addr && glen >= DATA_HEADER_SIZE {
                                buffered_packets.push(buf[..glen].to_vec());
                            }
                        }
                    }
                }
                return Ok(buffered_packets);
            }
        }
    }
}

/// Like [`wait_for_first_data`] but reads from an mpsc channel.
pub async fn wait_for_first_data_channeled(
    rx: &mut tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
    recv_socket: &tokio::net::UdpSocket,
    recv_target: std::net::SocketAddr,
    pipeline: &Mutex<Pipeline>,
    session_id: SessionId,
    timeout_duration: Duration,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now() + timeout_duration;
    let mut buffered_packets: Vec<Vec<u8>> = Vec::new();

    loop {
        let recv_result = tokio::time::timeout_at(deadline, rx.recv()).await;
        match recv_result {
            Err(_) => {
                return Err("timeout waiting for first data from client (channeled)".into());
            }
            Ok(None) => {
                return Err("channel closed while waiting for first data".into());
            }
            Ok(Some((data, _addr))) => {
                {
                    let pl = pipeline.lock().await;
                    let result = pl.process(&data);
                    if !matches!(result, AdmissionResult::Pass) {
                        continue;
                    }
                }

                if data.len() < DATA_HEADER_SIZE {
                    continue;
                }
                let header = match DataHeader::deserialize(&data) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                if header.session_id != session_id {
                    continue;
                }

                let _ = recv_socket.send_to(&data, recv_target).await;
                buffered_packets.push(data);

                let grace_deadline = tokio::time::Instant::now() + Duration::from_millis(50);
                loop {
                    let grace_result = tokio::time::timeout_at(grace_deadline, rx.recv()).await;
                    match grace_result {
                        Err(_) => break,
                        Ok(None) => break,
                        Ok(Some((gdata, _gaddr))) => {
                            if gdata.len() >= DATA_HEADER_SIZE {
                                let _ = recv_socket.send_to(&gdata, recv_target).await;
                                buffered_packets.push(gdata);
                            }
                        }
                    }
                }
                return Ok(buffered_packets);
            }
        }
    }
}

// ─── Bridge ─────────────────────────────────────────────────────────────────
//
// Nebula-pivot R3 (strategy B rewrite): dumb encrypted pipe.
//
//   TCP→UDP: read → encrypt → sendto (fire-and-forget, no retransmit buffer)
//   UDP→TCP: recv_from → admission/replay check → decrypt → write_all
//
// No ACKs, no NACKs, no SACK, no cwnd, no stall detection. The upper layer
// (TCP between user and the tunnel endpoints) already provides end-to-end
// reliability; loss recovery is the end systems' job, Nebula-style.

/// Run a bidirectional TCP ↔ ZTLP bridge (dumb encrypted pipe).
pub async fn run_bridge(
    tcp_stream: TcpStream,
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>> {
    run_bridge_inner(
        tcp_stream,
        udp_socket,
        None,
        pipeline,
        session_id,
        peer_addr,
        false,
        Vec::new(),
        None,
    )
    .await
}

/// Like [`run_bridge`] but sends a RESET frame first to signal a new TCP stream.
pub async fn run_bridge_with_reset(
    tcp_stream: TcpStream,
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>> {
    run_bridge_inner(
        tcp_stream,
        udp_socket,
        None,
        pipeline,
        session_id,
        peer_addr,
        true,
        Vec::new(),
        None,
    )
    .await
}

/// Like [`run_bridge`] but accepts pre-fetched packets from a prior
/// `wait_for_first_data` call.
pub async fn run_bridge_with_buffered(
    tcp_stream: TcpStream,
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    buffered_packets: Vec<Vec<u8>>,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>> {
    run_bridge_inner(
        tcp_stream,
        udp_socket,
        None,
        pipeline,
        session_id,
        peer_addr,
        false,
        buffered_packets,
        None,
    )
    .await
}

/// Like [`run_bridge_with_buffered`] but uses a dedicated receive socket.
pub async fn run_bridge_demuxed(
    tcp_stream: TcpStream,
    udp_send_socket: Arc<UdpSocket>,
    udp_recv_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    buffered_packets: Vec<Vec<u8>>,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>> {
    run_bridge_inner(
        tcp_stream,
        udp_send_socket,
        Some(udp_recv_socket),
        pipeline,
        session_id,
        peer_addr,
        false,
        buffered_packets,
        None,
    )
    .await
}

/// Like [`run_bridge_demuxed`] but additionally rewrites the FIRST HTTP
/// request on the inbound (UDP→TCP) side to inject signed `X-ZTLP-*` admin
/// identity headers when the peer's Noise static key matches an admin entry.
///
/// `peer_pubkey_hex` is the lowercase hex of the responder-observed Noise
/// remote static key (`HandshakeContext::remote_static_hex()`). If it does
/// not appear in `config.admin_pubkey_to_email`, no rewrite happens and bytes
/// pass through verbatim (so the upstream app can fall back to its normal
/// login flow).
#[allow(clippy::too_many_arguments)]
pub async fn run_bridge_demuxed_with_http_injection(
    tcp_stream: TcpStream,
    udp_send_socket: Arc<UdpSocket>,
    udp_recv_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    buffered_packets: Vec<Vec<u8>>,
    http_injection_config: Arc<HttpInjectionConfig>,
    peer_pubkey_hex: Option<String>,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>> {
    let injection_state = match peer_pubkey_hex
        .as_deref()
        .and_then(|hex| http_injection_config.lookup_email(hex).map(str::to_owned))
    {
        Some(email) => {
            info!(
                "http injection ENABLED for session {} peer_pubkey={} as admin {}",
                session_id,
                peer_pubkey_hex.as_deref().unwrap_or("?"),
                email
            );
            Some(HttpInjectionState {
                config: http_injection_config,
                peer_email: email,
                done: false,
                pending_buffer: Vec::new(),
            })
        }
        None => None,
    };

    run_bridge_inner(
        tcp_stream,
        udp_send_socket,
        Some(udp_recv_socket),
        pipeline,
        session_id,
        peer_addr,
        false,
        buffered_packets,
        injection_state,
    )
    .await
}

/// Like [`run_bridge`] but accepts any `AsyncRead + AsyncWrite` stream.
pub async fn run_bridge_io<S>(
    stream: S,
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    run_bridge_inner(
        stream,
        udp_socket,
        None,
        pipeline,
        session_id,
        peer_addr,
        false,
        Vec::new(),
        None,
    )
    .await
}

/// Encrypt a plaintext frame and send as a ZTLP data packet.
/// Fire-and-forget; returns the packet_seq used on success.
async fn encrypt_and_send(
    pipeline: &Mutex<Pipeline>,
    send_key: &[u8; 32],
    cipher: &ChaCha20Poly1305,
    session_id: SessionId,
    udp: &UdpSocket,
    peer_addr: SocketAddr,
    plaintext: &[u8],
) -> Result<u64, Box<dyn std::error::Error>> {
    let packet_seq = {
        let mut pl = pipeline.lock().await;
        let session = pl.get_session_mut(&session_id).ok_or("session not found")?;
        session.next_send_seq()
    };
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&packet_seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("AEAD encrypt failed: {}", e))?;
    let mut header = DataHeader::new(session_id, packet_seq);
    header.payload_len = encrypted.len() as u16;
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(send_key, &aad);
    let mut packet = header.serialize();
    packet.extend_from_slice(&encrypted);
    udp.send_to(&packet, peer_addr).await?;
    Ok(packet_seq)
}

#[allow(clippy::too_many_arguments)]
async fn run_bridge_inner<S>(
    tcp_stream: S,
    udp_socket: Arc<UdpSocket>,
    udp_recv_override: Option<Arc<UdpSocket>>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    send_initial_reset: bool,
    prefetched_packets: Vec<Vec<u8>>,
    mut http_injection: Option<HttpInjectionState>,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    info!(
        "run_bridge (nebula dumb-pipe): starting for session {} peer={} local_udp={:?}",
        session_id,
        peer_addr,
        udp_socket.local_addr()
    );

    // Pre-extract AEAD keys once.
    let (send_key, recv_key) = {
        let pl = pipeline.lock().await;
        let session = pl.get_session(&session_id).ok_or("session not found")?;
        (session.send_key, session.recv_key)
    };
    let send_cipher = ChaCha20Poly1305::new((&send_key).into());
    let recv_cipher = ChaCha20Poly1305::new((&recv_key).into());

    // Optional initial RESET to signal a new TCP stream on a reused session.
    if send_initial_reset {
        info!(
            "sending RESET frame for new TCP stream on session {}",
            session_id
        );
        let reset_frame = [FRAME_RESET];
        if let Err(e) = encrypt_and_send(
            &pipeline,
            &send_key,
            &send_cipher,
            session_id,
            &udp_socket,
            peer_addr,
            &reset_frame,
        )
        .await
        {
            warn!("failed to send initial RESET: {}", e);
        }
    }

    let (mut tcp_reader, mut tcp_writer) = tokio::io::split(tcp_stream);

    let udp_send = udp_socket.clone();
    let udp_recv = udp_recv_override
        .as_ref()
        .map(Arc::clone)
        .unwrap_or_else(|| udp_socket.clone());
    // When a dedicated per-session recv socket is supplied (multi-session
    // listener mode), the listener's demuxer is responsible for delivering
    // only this session's packets, and it does so via a loopback UDP socket
    // pair whose `from` address will *not* match `peer_addr`. In that mode,
    // skip the per-packet peer_addr filter — otherwise every client→server
    // data packet is silently dropped and the local TCP backend never sees
    // any inbound bytes (the gateway just sits idle until SSH times out).
    let enforce_peer_filter = udp_recv_override.is_none();

    // Monotonic data_seq for the DATA frame's in-band counter. The receiver
    // no longer reassembles on it, but we keep the field so gateways and
    // older tools that still parse it don't break.
    let mut data_seq: u64 = 0;

    // Stats (dropped-to-stub for now; TODO(nebula-pivot-R5): wire real stats).
    let tunnel_stats = Arc::new(TunnelStats::new());
    let _ = tunnel_stats;

    // Flag set when a RESET frame arrives.
    let mut reset_received = false;
    // Flag set when we see a FIN frame from the peer (remote closed its TCP side).
    let mut peer_fin = false;
    // Flag set when our local TCP reader hits EOF.
    let mut local_eof = false;
    let mut local_fin_sent = false;

    let mut recv_window = crate::ReceiveWindow::default();

    let mut tcp_buf = vec![0u8; TCP_READ_BUF];
    let mut udp_buf = vec![0u8; 65535];
    let mut prefetched_iter = prefetched_packets.into_iter();

    let mut keepalive_tick = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick.
    keepalive_tick.tick().await;

    // Set by handle_incoming_packet if the HTTP injector fails on the first
    // request — we then MUST drop the connection rather than forward
    // unsigned bytes upstream (security model).
    let mut injection_failed = false;

    loop {
        // Drain prefetched packets first (from wait_for_first_data).
        if let Some(pkt) = prefetched_iter.next() {
            if let Err(e) = handle_incoming_packet(
                &pkt,
                &pipeline,
                &recv_cipher,
                session_id,
                &mut tcp_writer,
                &mut reset_received,
                &mut peer_fin,
                &mut recv_window,
                http_injection.as_mut(),
                &mut injection_failed,
            )
            .await
            {
                debug!("prefetched packet handling error: {}", e);
            }
            if injection_failed {
                warn!(
                    "http injection failed on session {} — dropping connection",
                    session_id
                );
                break;
            }
            if reset_received {
                break;
            }
            continue;
        }

        tokio::select! {
            // ─── TCP → UDP: encrypt and fire-and-forget ──────────────
            read_result = tcp_reader.read(&mut tcp_buf), if !local_eof => {
                match read_result {
                    Ok(0) => {
                        local_eof = true;
                        if !local_fin_sent {
                            let mut fin_frame = Vec::with_capacity(9);
                            fin_frame.push(FRAME_FIN);
                            fin_frame.extend_from_slice(&data_seq.to_be_bytes());
                            data_seq = data_seq.wrapping_add(1);
                            if let Err(e) = encrypt_and_send(
                                &pipeline, &send_key, &send_cipher,
                                session_id, &udp_send, peer_addr, &fin_frame,
                            ).await {
                                debug!("FIN send error: {}", e);
                            }
                            local_fin_sent = true;
                        }
                        if peer_fin {
                            break;
                        }
                    }
                    Ok(n) => {
                        // Chunk into <= MAX_PLAINTEXT_PER_PACKET frames.
                        let mut off = 0;
                        while off < n {
                            let chunk_end = (off + MAX_PLAINTEXT_PER_PACKET).min(n);
                            let chunk = &tcp_buf[off..chunk_end];
                            let mut frame = Vec::with_capacity(1 + 8 + chunk.len());
                            frame.push(FRAME_DATA);
                            frame.extend_from_slice(&data_seq.to_be_bytes());
                            frame.extend_from_slice(chunk);
                            data_seq = data_seq.wrapping_add(1);
                            if let Err(e) = encrypt_and_send(
                                &pipeline, &send_key, &send_cipher,
                                session_id, &udp_send, peer_addr, &frame,
                            ).await {
                                debug!("data send error: {}", e);
                            }
                            off = chunk_end;
                        }
                    }
                    Err(e) => {
                        debug!("tcp read error: {}", e);
                        local_eof = true;
                    }
                }
            }

            // ─── UDP → TCP: admission/replay → decrypt → write ──────
            udp_result = udp_recv.recv_from(&mut udp_buf) => {
                match udp_result {
                    Ok((len, from)) => {
                        if enforce_peer_filter && from != peer_addr {
                            continue;
                        }
                        let pkt = &udp_buf[..len];
                        if let Err(e) = handle_incoming_packet(
                            pkt,
                            &pipeline,
                            &recv_cipher,
                            session_id,
                            &mut tcp_writer,
                            &mut reset_received,
                            &mut peer_fin,
                            &mut recv_window,
                            http_injection.as_mut(),
                            &mut injection_failed,
                        ).await {
                            debug!("incoming packet error: {}", e);
                        }
                        if injection_failed {
                            warn!(
                                "http injection failed on session {} — dropping connection",
                                session_id
                            );
                            break;
                        }
                        if reset_received {
                            break;
                        }
                        if peer_fin && local_eof {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("udp recv error: {}", e);
                        break;
                    }
                }
            }

            // ─── Keepalive: idle heartbeat (RTT ping, not reliability) ─
            _ = keepalive_tick.tick() => {
                // Send a minimal RTT_PING to keep NAT bindings alive and
                // exercise the path. Never retransmitted.
                let ping_id: u32 = 0;
                let ts_us: u64 = 0;
                let mut ping_frame = Vec::with_capacity(1 + 4 + 8);
                ping_frame.push(FRAME_RTT_PING);
                ping_frame.extend_from_slice(&ping_id.to_be_bytes());
                ping_frame.extend_from_slice(&ts_us.to_be_bytes());
                let _ = encrypt_and_send(
                    &pipeline, &send_key, &send_cipher,
                    session_id, &udp_send, peer_addr, &ping_frame,
                ).await;
            }
        }
    }

    let _ = tcp_writer.shutdown().await;
    info!("tunnel bridge terminated for session {}", session_id);
    if reset_received {
        Ok(BridgeOutcome::ResetReceived)
    } else {
        Ok(BridgeOutcome::Closed)
    }
}

/// Decrypt an incoming UDP packet and write any resulting TCP bytes.
/// Sets flags on RESET / FIN. Replay/admission is done by Pipeline::process.
///
/// When `http_injection` is `Some` and `done == false`, the FIRST contiguous
/// payload delivered out of the reassembly window is rewritten by
/// `http_injector::inject_headers` before being written to TCP. If the
/// injector returns Err (partial request, malformed HTTP, etc.) the
/// `injection_failed` flag is set and the caller drops the connection.
#[allow(clippy::too_many_arguments)]
async fn handle_incoming_packet<W>(
    pkt: &[u8],
    pipeline: &Mutex<Pipeline>,
    recv_cipher: &ChaCha20Poly1305,
    session_id: SessionId,
    tcp_writer: &mut W,
    reset_received: &mut bool,
    peer_fin: &mut bool,
    recv_window: &mut crate::ReceiveWindow,
    mut http_injection: Option<&mut HttpInjectionState>,
    injection_failed: &mut bool,
) -> Result<(), Box<dyn std::error::Error>>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    // Admission: magic + session + replay bitmap + auth tag.
    {
        let pl = pipeline.lock().await;
        if !matches!(pl.process(pkt), AdmissionResult::Pass) {
            return Ok(());
        }
    }
    if pkt.len() < DATA_HEADER_SIZE {
        return Ok(());
    }
    let header = match DataHeader::deserialize(pkt) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };
    if header.session_id != session_id {
        return Ok(());
    }
    let ciphertext = &pkt[DATA_HEADER_SIZE..];
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&header.packet_seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = match recv_cipher.decrypt(nonce, ciphertext) {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    if plaintext.is_empty() {
        return Ok(());
    }
    match plaintext[0] {
        FRAME_DATA => {
            // [FRAME_DATA | 8-byte data_seq | payload...]
            if plaintext.len() < 9 {
                return Ok(());
            }
            let mut seq_bytes = [0u8; 8];
            seq_bytes.copy_from_slice(&plaintext[1..9]);
            let data_seq = u64::from_be_bytes(seq_bytes);
            let payload = &plaintext[9..];

            // Reassembly is required here rather than directly writing to TCP.
            // The Nebula-pivot stripped this out causing 10MB transfers to drop/drop packet fragments.
            // We just added ReceiveWindow earlier but didn't actually plug it in here
            // after the re-edits. Let's fix that.
            let ordered_payloads = recv_window.insert(data_seq, payload.to_vec());

            for p in ordered_payloads {
                // HTTP header-injection hook — runs ONCE per TCP bridge,
                // on the FIRST complete HTTP request only. After it
                // runs (success OR hard failure), `done` flips and all
                // subsequent bytes flow through untouched.
                //
                // HTTP requests can arrive split across multiple decrypted
                // chunks (TCP segmentation, MTU on the UDP carrier, large
                // cookie headers, browser pipelining). On each chunk we:
                //   1. Append to `pending_buffer`.
                //   2. Try to parse the accumulated buffer.
                //   3. If `Ok(Complete)` — rewrite + flush the rewritten
                //      header section AND any pipelined bytes after it,
                //      then `done = true`.
                //   4. If `Ok(Partial)` — keep buffering, wait for next
                //      chunk. Bail out only if we exceed
                //      MAX_HTTP_INJECT_BUFFER (non-HTTP traffic or attack).
                //   5. If `Err(...)` — non-recoverable parse error (e.g.
                //      bad request line on a non-HTTP stream). Drop the
                //      connection so we never forward garbage.
                if let Some(state) = http_injection.as_deref_mut() {
                    if !state.done {
                        state.pending_buffer.extend_from_slice(p.as_slice());

                        if state.pending_buffer.len() > MAX_HTTP_INJECT_BUFFER {
                            state.done = true;
                            *injection_failed = true;
                            warn!(
                                "http injection: buffer exceeded {} bytes without complete request for {} — dropping (not HTTP?)",
                                MAX_HTTP_INJECT_BUFFER, state.peer_email
                            );
                            return Ok(());
                        }

                        let ts = iso8601_utc_now();
                        match crate::http_injector::inject_headers(
                            state.pending_buffer.as_slice(),
                            &state.peer_email,
                            &ts,
                            state.config.hmac_secret.as_bytes(),
                        ) {
                            Ok(rewritten) => {
                                state.done = true;
                                info!(
                                    "http injection: rewrote first request for {} ({} buffered -> {} rewritten bytes)",
                                    state.peer_email,
                                    state.pending_buffer.len(),
                                    rewritten.len()
                                );
                                // `inject_headers` returns the full rewritten
                                // request (rewritten header section + the
                                // body bytes that were already buffered).
                                // Flush it as one write; any subsequent
                                // chunks land in the `done == true` branch
                                // and pass through untouched.
                                tcp_writer.write_all(&rewritten).await?;
                                state.pending_buffer.clear();
                                continue;
                            }
                            Err(e) if e.contains("Partial HTTP request") => {
                                // Need more bytes. Don't forward anything
                                // yet — keep buffering and wait for the
                                // next frame.
                                continue;
                            }
                            Err(e) => {
                                state.done = true;
                                *injection_failed = true;
                                warn!(
                                    "http injection: parse failed for {} ({}). Dropping connection.",
                                    state.peer_email, e
                                );
                                return Ok(());
                            }
                        }
                    }
                }
                tcp_writer.write_all(p.as_slice()).await?;
            }
        }
        FRAME_FIN => {
            *peer_fin = true;
            let _ = tcp_writer.shutdown().await;
        }
        FRAME_RESET => {
            *reset_received = true;
        }
        FRAME_RTT_PING | FRAME_RTT_PONG => {
            // Ignore — keepalive only in dumb-pipe mode.
        }
        FRAME_ACK | FRAME_NACK | FRAME_SACK | FRAME_CORRUPTION_NACK => {
            // Reliability frames from a pre-pivot peer; ignore silently.
        }
        FRAME_REJECT => {
            // Treat as a signal to tear down; surface as Closed.
            *peer_fin = true;
        }
        _ => {
            // Unknown / mux frames — not our concern; swallow.
        }
    }
    Ok(())
}

// ─── Service registry ───────────────────────────────────────────────────────

/// A registry of named services mapped to backend TCP addresses.
///
/// Built from `--forward` flags on the listener:
/// - `--forward ssh:127.0.0.1:22` → named service "ssh"
/// - `--forward 127.0.0.1:22` → unnamed default service
/// - Multiple `--forward` flags → multi-service listener
#[derive(Debug, Clone)]
pub struct ServiceRegistry {
    /// Services keyed by human-readable name. Preserved so error messages
    /// and logs can still surface the name a registry was configured with.
    /// Lookups from the wire (`resolve(&dst_svc_hash)`) go through
    /// `name_by_hash` first.
    pub services: HashMap<String, SocketAddr>,
    /// Reverse index: 16-byte truncated SHA-256 of the canonicalized name
    /// → service name string. Populated alongside `services`. Hash lookups
    /// match the canonical `encode_service_id(None, name)` value.
    name_by_hash: HashMap<[u8; 16], String>,
}

impl ServiceRegistry {
    /// Build a service registry from a list of `--forward` arguments.
    ///
    /// Each argument is either:
    /// - `NAME:HOST:PORT` — a named service
    /// - `HOST:PORT` — the default (unnamed) service
    pub fn from_forward_args(args: &[String]) -> Result<Self, String> {
        let mut services = HashMap::new();
        let mut name_by_hash = HashMap::new();

        for arg in args {
            let (name, addr) = parse_forward_arg(arg)?;
            if services.contains_key(&name) {
                return Err(format!("duplicate service name '{}'", name));
            }
            // Index by the canonical wire hash. DEFAULT_SERVICE keeps its
            // sentinel zero-hash so unspecified clients still resolve to it.
            let hash = if name == DEFAULT_SERVICE {
                [0u8; 16]
            } else {
                encode_service_id(None, &name)
            };
            name_by_hash.insert(hash, name.clone());
            services.insert(name, addr);
        }

        Ok(Self {
            services,
            name_by_hash,
        })
    }

    /// Look up a service by the `dst_svc_hash` bytes from the handshake header.
    ///
    /// **Option C wire decoupling.** The wire field is now an opaque
    /// 16-byte truncated SHA-256 of the canonicalized service name (see
    /// [`encode_service_id`]). This function does:
    ///   1. All-zero hash → default service sentinel (covers clients that
    ///      did not specify any service name).
    ///   2. Otherwise, direct hash lookup against `name_by_hash` populated
    ///      at registry construction time.
    ///   3. If the named service is not found and the registry has exactly
    ///      one service (the implicit default), fall back to it. This allows
    ///      gateways with a single unnamed `--forward` to handle clients
    ///      that send an explicit service name.
    pub fn resolve(&self, dst_svc_hash: &[u8; 16]) -> Option<(&str, SocketAddr)> {
        let name_opt: Option<&str> = if dst_svc_hash == &[0u8; 16] {
            Some(DEFAULT_SERVICE)
        } else {
            self.name_by_hash.get(dst_svc_hash).map(|s| s.as_str())
        };

        if let Some(name) = name_opt {
            if let Some(entry) = self.services.get_key_value(name) {
                return Some((entry.0.as_str(), *entry.1));
            }
        }

        // Fallback: if the registry only contains the default service, route
        // any unrecognized hash to it rather than rejecting outright.
        if self.services.len() == 1 && self.services.contains_key(DEFAULT_SERVICE) {
            return self
                .services
                .get_key_value(DEFAULT_SERVICE)
                .map(|(k, v)| (k.as_str(), *v));
        }

        None
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

/// Encode a service name into a 16-byte DstSvcHash field.
///
/// **DEPRECATED single-string surface.** Prefer [`encode_service_id`] which
/// accepts an optional zone for namespacing. Retained for FFI call sites
/// that have not yet been threaded with a zone context. Internally delegates
/// to `encode_service_id(None, name)` — i.e. it is now a SHA-256 hash, NOT
/// zero-padded ASCII. The `Result` return type is kept for source-compat;
/// the error arm is unreachable (hashing never fails).
pub fn encode_service_name(name: &str) -> Result<[u8; 16], String> {
    Ok(encode_service_id(None, name))
}

/// Canonicalize+hash a `(zone, name)` pair into a 16-byte routing key.
///
/// This is the on-wire `dst_svc_hash` value carried by HELLO packets. The
/// 16-byte field is opaque — relays/gateways compare it byte-wise; they do
/// NOT round-trip it back to a UTF-8 string. The collision space is 2^128,
/// identical to IPv6 SLAAC and well beyond the birthday bound for any
/// realistic service population.
///
/// Canonicalization (deterministic across all implementations):
///   1. Lowercase `zone` (if present) and `name`.
///   2. Strip trailing `.` characters from each (DNS-style root marker).
///   3. Form canonical bytes: `format!("{}/{}", zone, name)` when `zone`
///      is `Some`, else just `name`.
///   4. Truncate `SHA-256(canonical_utf8)` to the first 16 bytes.
///
/// Empty inputs are accepted and hash deterministically (do not panic).
/// Long inputs (DNS-class 253 chars and beyond) are accepted — the legacy
/// 16-byte ASCII limit is lifted by this encoder.
pub fn encode_service_id(zone: Option<&str>, name: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let name_canon = name.to_ascii_lowercase();
    let name_canon = name_canon.trim_end_matches('.');
    let canonical: String = match zone {
        Some(z) => {
            let z_canon = z.to_ascii_lowercase();
            let z_canon = z_canon.trim_end_matches('.');
            format!("{}/{}", z_canon, name_canon)
        }
        None => name_canon.to_string(),
    };
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    let out = h.finalize();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&out[..16]);
    buf
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
    let first_colon = s.find(':').ok_or_else(|| {
        format!(
            "invalid --forward argument '{}'. Expected NAME:HOST:PORT or HOST:PORT",
            s
        )
    })?;

    let name = &s[..first_colon];
    let addr_str = &s[first_colon + 1..];

    // Validate the name
    if name.is_empty() {
        return Err(format!("empty service name in '{}'", s));
    }
    if name.len() > MAX_SERVICE_NAME_LEN {
        return Err(format!(
            "service name '{}' too long ({} bytes, max {})",
            name,
            name.len(),
            MAX_SERVICE_NAME_LEN
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "service name '{}' contains invalid characters (use a-z, 0-9, -, _)",
            name
        ));
    }

    let addr: SocketAddr = addr_str
        .parse()
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

    let local_port: u16 = parts[0]
        .parse()
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

// ─── Tests ──────────────────────────────────────────────────────────────────

pub fn bridge_instrumentation_enabled() -> bool {
    // Mock implementation for test binary
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── Service registry + forward parsing tests (kept) ─────────────────

    #[test]
    fn test_parse_forward_target() {
        let addr = parse_forward_target("127.0.0.1:22").unwrap();
        assert_eq!(addr.port(), 22);
    }

    #[test]
    fn test_parse_local_forward() {
        let (port, target) = parse_local_forward("8022:remote.example:22").unwrap();
        assert_eq!(port, 8022);
        assert_eq!(target, "remote.example:22");
    }

    #[test]
    fn test_parse_local_forward_ipv6() {
        let (port, target) = parse_local_forward("8080:[::1]:80").unwrap();
        assert_eq!(port, 8080);
        assert_eq!(target, "[::1]:80");
    }

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
    }

    #[test]
    fn test_parse_forward_arg_invalid() {
        assert!(parse_forward_arg("not-a-valid-arg").is_err());
    }

    #[test]
    fn test_parse_forward_arg_name_too_long() {
        let long = "a".repeat(MAX_SERVICE_NAME_LEN + 1);
        let arg = format!("{}:127.0.0.1:22", long);
        assert!(parse_forward_arg(&arg).is_err());
    }

    #[test]
    fn test_parse_forward_arg_name_invalid_chars() {
        assert!(parse_forward_arg("bad name:127.0.0.1:22").is_err());
    }

    #[test]
    fn test_service_registry_single_default() {
        let args = vec!["127.0.0.1:22".to_string()];
        let reg = ServiceRegistry::from_forward_args(&args).unwrap();
        assert_eq!(reg.services.len(), 1);
        assert!(reg.services.contains_key(DEFAULT_SERVICE));
    }

    #[test]
    fn test_service_registry_multi() {
        let args = vec![
            "ssh:127.0.0.1:22".to_string(),
            "web:127.0.0.1:80".to_string(),
        ];
        let reg = ServiceRegistry::from_forward_args(&args).unwrap();
        assert_eq!(reg.services.len(), 2);
        assert!(reg.services.contains_key("ssh"));
        assert!(reg.services.contains_key("web"));
    }

    #[test]
    fn test_service_registry_duplicate_rejected() {
        let args = vec![
            "ssh:127.0.0.1:22".to_string(),
            "ssh:127.0.0.1:2222".to_string(),
        ];
        assert!(ServiceRegistry::from_forward_args(&args).is_err());
    }

    #[test]
    fn test_resolve_zero_dst_svc_hash() {
        let args = vec!["127.0.0.1:22".to_string()];
        let reg = ServiceRegistry::from_forward_args(&args).unwrap();
        let addr = reg.resolve(&[0u8; 16]);
        assert!(addr.is_some());
    }

    #[test]
    fn test_resolve_named_service() {
        // Option C: lookup key is the canonical 16-byte SHA-256 hash, not zero-padded ASCII.
        let args = vec!["ssh:127.0.0.1:22".to_string()];
        let reg = ServiceRegistry::from_forward_args(&args).unwrap();
        let key = encode_service_id(None, "ssh");
        let resolved = reg
            .resolve(&key)
            .expect("ssh service should resolve via hash");
        assert_eq!(resolved.0, "ssh");
    }

    #[test]
    fn test_resolve_unknown_service() {
        // Option C: an unknown name hashes to a value not present in the registry,
        // and the single-service fallback only kicks in when DEFAULT_SERVICE is
        // the only entry — here we have a named "ssh" service so an unknown
        // request must NOT resolve.
        let args = vec![
            "ssh:127.0.0.1:22".to_string(),
            "http:127.0.0.1:80".to_string(),
        ];
        let reg = ServiceRegistry::from_forward_args(&args).unwrap();
        let key = encode_service_id(None, "definitely-not-registered");
        assert!(reg.resolve(&key).is_none());
    }

    #[test]
    fn test_resolve_default_fallback() {
        // When the gateway has only an unnamed --forward (default service)
        // and the client requests a named service like "tcp:22", resolve
        // should fall back to the default service.
        let args = vec!["127.0.0.1:22".to_string()];
        let reg = ServiceRegistry::from_forward_args(&args).unwrap();

        // Request "tcp:22" which doesn't match _default exactly
        let mut name = [0u8; 16];
        let svc = b"tcp:22";
        name[..svc.len()].copy_from_slice(svc);

        // Should fall back to the default service
        let result = reg.resolve(&name);
        assert!(result.is_some());
        let (svc_name, addr) = result.unwrap();
        assert_eq!(svc_name, DEFAULT_SERVICE);
        assert_eq!(
            addr,
            "127.0.0.1:22".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_resolve_no_fallback_with_multiple_services() {
        // When the gateway has multiple named services, an unrecognized
        // name should NOT fall back to any default.
        let args = vec![
            "ssh:127.0.0.1:22".to_string(),
            "rdp:127.0.0.1:3389".to_string(),
        ];
        let reg = ServiceRegistry::from_forward_args(&args).unwrap();
        let mut name = [0u8; 16];
        let svc = b"unknown";
        name[..svc.len()].copy_from_slice(svc);
        assert!(reg.resolve(&name).is_none());
    }

    #[test]
    fn test_encode_service_name() {
        // The legacy entry point is now a thin wrapper over `encode_service_id(None, _)`.
        // It MUST be deterministic and MUST match the underlying hash exactly. The
        // historic "name too long" error path is gone — long names are valid now.
        let a = encode_service_name("ssh").unwrap();
        let b = encode_service_name("ssh").unwrap();
        assert_eq!(a, b, "deterministic");
        assert_eq!(a, encode_service_id(None, "ssh"));
        // Names longer than the old 16-byte ASCII cap must succeed (was the
        // original failure mode at ffi.rs:128).
        let long = "a".repeat(64);
        assert!(encode_service_name(&long).is_ok());
    }

    // ── encode_service_id hash-vector tests (Option C wire decoupling) ──
    //
    // These pin the canonical SHA-256-truncated-to-128-bit encoding of the
    // on-wire `dst_svc_hash` field. Canonicalization rules:
    //   • Lowercase both `zone` and `name`
    //   • Strip trailing dots
    //   • Join as `lowercase(zone) + "/" + lowercase(name)` when zone given
    //   • Use `lowercase(name)` alone when no zone
    //   • Truncate `sha256(canonical_utf8)` to first 16 bytes

    fn sha256_16(s: &str) -> [u8; 16] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        let out = h.finalize();
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&out[..16]);
        buf
    }

    #[test]
    fn test_encode_service_id_bare_name() {
        assert_eq!(encode_service_id(None, "ssh"), sha256_16("ssh"));
    }

    #[test]
    fn test_encode_service_id_zone_plus_name() {
        assert_eq!(
            encode_service_id(Some("acme.ztlp"), "bootstrap"),
            sha256_16("acme.ztlp/bootstrap")
        );
    }

    #[test]
    fn test_encode_service_id_canonicalization() {
        // Mixed case + trailing-dot zone must canonicalize to the lowercase,
        // dot-stripped form.
        assert_eq!(
            encode_service_id(Some("ACME.Ztlp."), "Bootstrap"),
            encode_service_id(Some("acme.ztlp"), "bootstrap")
        );
        // Trailing dot stripped on bare name too.
        assert_eq!(
            encode_service_id(None, "SSH."),
            encode_service_id(None, "ssh")
        );
    }

    #[test]
    fn test_encode_service_id_empty_name_is_deterministic() {
        // Must NOT panic. Deterministic hash of empty string.
        let a = encode_service_id(None, "");
        let b = encode_service_id(None, "");
        assert_eq!(a, b);
        assert_eq!(a, sha256_16(""));
    }

    #[test]
    fn test_encode_service_id_long_name_does_not_error() {
        // The original encoder bombed on names > 16 bytes. The hash encoder
        // must accept arbitrary lengths up to DNS-class 253 chars.
        let zone = "a".repeat(125);
        let name = "b".repeat(125); // 125 + "/" + 125 = 251 bytes canonical
        let h1 = encode_service_id(Some(&zone), &name);
        let h2 = encode_service_id(Some(&zone), &name);
        assert_eq!(h1, h2, "must be deterministic");
        // And still produces a 16-byte hash (compile-time guaranteed but sanity check).
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn test_encode_service_id_distinct_inputs_differ() {
        // Different inputs should (with overwhelming probability) hash differently.
        let a = encode_service_id(None, "ssh");
        let b = encode_service_id(Some("acme.ztlp"), "ssh");
        let c = encode_service_id(Some("other.ztlp"), "ssh");
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn test_reset_wait_result_empty() {
        let r = ResetWaitResult {
            reset_received: false,
            buffered_packets: Vec::new(),
        };
        assert!(!r.reset_received);
        assert!(r.buffered_packets.is_empty());
    }

    #[test]
    fn test_reset_wait_result_with_buffered() {
        let r = ResetWaitResult {
            reset_received: true,
            buffered_packets: vec![vec![1, 2, 3]],
        };
        assert!(r.reset_received);
        assert_eq!(r.buffered_packets.len(), 1);
    }

    #[test]
    fn test_reset_wait_result_no_reset_with_packets() {
        let r = ResetWaitResult {
            reset_received: false,
            buffered_packets: vec![vec![1], vec![2]],
        };
        assert!(!r.reset_received);
        assert_eq!(r.buffered_packets.len(), 2);
    }

    #[test]
    fn test_bridge_outcome_variants() {
        assert_eq!(BridgeOutcome::Closed, BridgeOutcome::Closed);
        assert_eq!(BridgeOutcome::ResetReceived, BridgeOutcome::ResetReceived);
        assert_ne!(BridgeOutcome::Closed, BridgeOutcome::ResetReceived);
    }

    // ── wait_for_first_data tests (kept — pure AEAD roundtrip) ──────────

    use crate::identity::NodeIdentity;
    use crate::pipeline::compute_header_auth_tag;
    use crate::session::SessionState;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

    async fn setup_lazy_connect_pair() -> (
        Arc<tokio::net::UdpSocket>,
        Arc<tokio::net::UdpSocket>,
        Arc<Mutex<Pipeline>>,
        SessionId,
        SocketAddr,
        SocketAddr,
        [u8; 32],
    ) {
        let _id_server = NodeIdentity::generate().unwrap();
        let id_client = NodeIdentity::generate().unwrap();

        let server_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        let session_id = SessionId::generate();
        let send_key = [0x42u8; 32];
        let recv_key = [0x43u8; 32];

        let server_session =
            SessionState::new(session_id, id_client.node_id, recv_key, send_key, false);

        let _ = recv_key;

        let mut pipeline = Pipeline::new();
        pipeline.register_session(server_session);
        let pipeline = Arc::new(Mutex::new(pipeline));

        (
            server_sock,
            client_sock,
            pipeline,
            session_id,
            client_addr,
            server_addr,
            send_key,
        )
    }

    fn build_data_packet(
        session_id: SessionId,
        send_key: &[u8; 32],
        data_seq: u64,
        packet_seq: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(send_key.into());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&packet_seq.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut plaintext = vec![FRAME_DATA];
        plaintext.extend_from_slice(&data_seq.to_be_bytes());
        plaintext.extend_from_slice(payload);

        let encrypted = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();

        let mut header = DataHeader::new(session_id, packet_seq);
        let aad = header.aad_bytes();
        header.header_auth_tag = compute_header_auth_tag(send_key, &aad);

        let mut packet = header.serialize();
        packet.extend_from_slice(&encrypted);
        packet
    }

    #[tokio::test]
    async fn test_wait_for_first_data_receives_valid_packet() {
        let (server_sock, client_sock, pipeline, session_id, client_addr, server_addr, send_key) =
            setup_lazy_connect_pair().await;

        let client_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let pkt = build_data_packet(session_id, &send_key, 0, 0, b"hello");
            client_sock.send_to(&pkt, server_addr).await.unwrap();
        });

        let result = wait_for_first_data(
            &server_sock,
            &pipeline,
            session_id,
            client_addr,
            Duration::from_secs(5),
        )
        .await;

        client_task.await.unwrap();

        assert!(
            result.is_ok(),
            "should receive first data: {:?}",
            result.err()
        );
        let packets = result.unwrap();
        assert!(!packets.is_empty());
    }

    #[tokio::test]
    async fn test_wait_for_first_data_timeout() {
        let (server_sock, _client_sock, pipeline, session_id, client_addr, _server_addr, _send_key) =
            setup_lazy_connect_pair().await;

        let result = wait_for_first_data(
            &server_sock,
            &pipeline,
            session_id,
            client_addr,
            Duration::from_millis(200),
        )
        .await;

        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("timeout"));
    }

    /// Regression test for the multi-frame inbound bug under the real
    /// multi-session listener topology.
    ///
    /// In `cmd_listen_multi_session`, packets coming off the wire (from the
    /// relay or the actual peer) arrive on the listener's main UDP socket and
    /// are routed through a per-session mpsc channel; a forwarder task then
    /// writes them into a loopback UDP socket pair which feeds the bridge.
    /// The bridge is invoked via `run_bridge_demuxed`, with `peer_addr` set
    /// to the *original* peer (e.g. the relay's external address).
    ///
    /// That means the `from` address the bridge sees on its `udp_recv` socket
    /// is the **forwarder's loopback address**, not `peer_addr`. The pre-fix
    /// code in `run_bridge_inner` rejected those packets with
    /// `if from != peer_addr { continue; }`, dropping every client→server
    /// data packet (single-frame *and* multi-frame). The only thing that
    /// "worked" was the gateway sending the local TCP backend's banner back
    /// to the client on the TX path.
    ///
    /// This test wires up the same topology and asserts that two FRAME_DATA
    /// packets are decrypted and written to the TCP backend.
    #[tokio::test]
    async fn test_run_bridge_demuxed_multi_frame_inbound_via_loopback_forwarder() {
        let (recv_socket, fwd_socket, pipeline, session_id, _peer_loopback, recv_addr, send_key) =
            setup_lazy_connect_pair().await;

        // Pretend the "real" peer is somewhere off-host. The listener would
        // record this as `peer_addr` when the HELLO arrived.
        let pretend_peer_addr: SocketAddr = "203.0.113.42:50000".parse().unwrap();

        // Build the bridge's two sockets:
        //   - udp_send_socket: the shared listener socket (we won't actually
        //     send anything outbound in this test, but it's a required arg).
        //   - udp_recv_socket: the per-session loopback socket the bridge
        //     reads from. The forwarder task (fwd_socket) writes into it.
        let udp_send_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let (tcp_side_for_bridge, mut tcp_test_side) = tokio::io::duplex(64 * 1024);

        let bridge_pipeline = pipeline.clone();
        let recv_socket_for_bridge = recv_socket.clone();
        let bridge_handle = tokio::spawn(async move {
            let _ = run_bridge_inner(
                tcp_side_for_bridge,
                udp_send_socket,
                Some(recv_socket_for_bridge),
                bridge_pipeline,
                session_id,
                pretend_peer_addr, // <-- the "real" peer, NOT recv_addr
                false,
                Vec::new(),
                None,
            )
            .await
            .map_err(|e| e.to_string());
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Build two FRAME_DATA packets and "forward" them via the loopback
        // socket pair, exactly as the real listener's forwarder does.
        let chunk_a = vec![b'A'; 1200];
        let chunk_b = vec![b'B'; 400];

        let pkt0 = build_data_packet(session_id, &send_key, 0, 0, &chunk_a);
        let pkt1 = build_data_packet(session_id, &send_key, 1, 1, &chunk_b);

        fwd_socket.send_to(&pkt0, recv_addr).await.unwrap();
        fwd_socket.send_to(&pkt1, recv_addr).await.unwrap();

        let expected_total = chunk_a.len() + chunk_b.len();
        let mut got = Vec::with_capacity(expected_total);
        let read_fut = async {
            let mut tmp = vec![0u8; 4096];
            while got.len() < expected_total {
                let n = tcp_test_side.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&tmp[..n]);
            }
        };
        let read_res = tokio::time::timeout(Duration::from_secs(3), read_fut).await;

        bridge_handle.abort();

        assert!(
            read_res.is_ok(),
            "timed out waiting for bridge to write both chunks via loopback forwarder; only got {} of {} bytes",
            got.len(),
            expected_total,
        );
        assert_eq!(
            got.len(),
            expected_total,
            "bridge wrote {} bytes, expected {}",
            got.len(),
            expected_total,
        );
        assert!(
            got[..chunk_a.len()].iter().all(|&b| b == b'A'),
            "first chunk corrupted"
        );
        assert!(
            got[chunk_a.len()..].iter().all(|&b| b == b'B'),
            "second chunk corrupted"
        );
    }

    /// Regression test for the multi-frame inbound bug.
    ///
    /// Two FRAME_DATA packets are sent back-to-back from the "client" UDP
    /// socket to the bridge:
    ///   - seq=0, payload = 1200 bytes of 'A'
    ///   - seq=1, payload =  400 bytes of 'B'
    ///
    /// `run_bridge_inner` must write BOTH chunks to the TCP side of its
    /// in-memory duplex stream.
    #[tokio::test]
    async fn test_run_bridge_inner_writes_multi_frame_inbound_data() {
        let (server_sock, client_sock, pipeline, session_id, client_addr, server_addr, send_key) =
            setup_lazy_connect_pair().await;
        let _ = server_addr;

        // Build a duplex pair: `tcp_side_for_bridge` is what the bridge thinks
        // is the local TCP backend. `tcp_test_side` is what our test reads to
        // verify the bridge wrote the decrypted payloads.
        let (tcp_side_for_bridge, mut tcp_test_side) = tokio::io::duplex(64 * 1024);

        // Spawn the bridge. It will:
        //   - read from `tcp_side_for_bridge` (we never send anything → idles)
        //   - recv from `server_sock`
        //   - decrypt and write into `tcp_side_for_bridge`'s write half,
        //     which appears on `tcp_test_side`'s read half.
        let bridge_pipeline = pipeline.clone();
        let bridge_handle = tokio::spawn(async move {
            let _ = run_bridge_inner(
                tcp_side_for_bridge,
                server_sock,
                None,
                bridge_pipeline,
                session_id,
                client_addr,
                false,
                Vec::new(),
                None,
            )
            .await
            .map_err(|e| e.to_string());
        });

        // Give the bridge a moment to enter its select loop.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send two FRAME_DATA packets back-to-back.
        let chunk_a = vec![b'A'; 1200];
        let chunk_b = vec![b'B'; 400];

        let pkt0 = build_data_packet(session_id, &send_key, 0, 0, &chunk_a);
        let pkt1 = build_data_packet(session_id, &send_key, 1, 1, &chunk_b);

        // server_addr was returned as the address `server_sock` is bound to —
        // but since `server_sock` was moved into the bridge task we already
        // captured it in server_addr above.
        client_sock.send_to(&pkt0, server_addr).await.unwrap();
        client_sock.send_to(&pkt1, server_addr).await.unwrap();

        // Read up to chunk_a.len() + chunk_b.len() bytes from the TCP side,
        // with a deadline so a hung bridge fails the test instead of hanging.
        let expected_total = chunk_a.len() + chunk_b.len();
        let mut got = Vec::with_capacity(expected_total);
        let read_fut = async {
            let mut tmp = vec![0u8; 4096];
            while got.len() < expected_total {
                let n = tcp_test_side.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&tmp[..n]);
            }
        };
        let read_res = tokio::time::timeout(Duration::from_secs(3), read_fut).await;

        // Stop the bridge.
        bridge_handle.abort();

        assert!(
            read_res.is_ok(),
            "timed out waiting for bridge to write both chunks; only got {} of {} bytes; first 16: {:02x?}",
            got.len(),
            expected_total,
            &got[..got.len().min(16)],
        );
        assert_eq!(
            got.len(),
            expected_total,
            "bridge wrote {} bytes, expected {}",
            got.len(),
            expected_total,
        );
        assert!(
            got[..chunk_a.len()].iter().all(|&b| b == b'A'),
            "first chunk corrupted"
        );
        assert!(
            got[chunk_a.len()..].iter().all(|&b| b == b'B'),
            "second chunk corrupted"
        );
    }

    #[tokio::test]
    async fn test_wait_for_first_data_ignores_wrong_session() {
        let (server_sock, client_sock, pipeline, session_id, client_addr, server_addr, send_key) =
            setup_lazy_connect_pair().await;

        let wrong_session = SessionId::generate();
        let client_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let bad_pkt = build_data_packet(wrong_session, &send_key, 0, 0, b"wrong");
            client_sock.send_to(&bad_pkt, server_addr).await.unwrap();

            tokio::time::sleep(Duration::from_millis(50)).await;
            let good_pkt = build_data_packet(session_id, &send_key, 0, 0, b"right");
            client_sock.send_to(&good_pkt, server_addr).await.unwrap();
        });

        let result = wait_for_first_data(
            &server_sock,
            &pipeline,
            session_id,
            client_addr,
            Duration::from_secs(5),
        )
        .await;

        client_task.await.unwrap();

        assert!(result.is_ok());
        let packets = result.unwrap();
        assert_eq!(packets.len(), 1);
    }
}
