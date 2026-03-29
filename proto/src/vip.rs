//! VIP (Virtual IP) proxy for ZTLP tunnel services.
//!
//! Assigns loopback IPs (`127.0.55.x`) to services and runs local TCP
//! listeners on each VIP:port. Incoming TCP connections are piped through
//! the encrypted ZTLP tunnel.
//!
//! ## Architecture (v3 — stream multiplexing)
//!
//! Each TCP connection gets its own stream_id. The client sends FRAME_OPEN
//! to create a backend connection on the gateway, FRAME_DATA with stream_id
//! to forward data, and FRAME_CLOSE to tear down. The gateway responds with
//! FRAME_DATA tagged by stream_id, and FRAME_FIN/FRAME_CLOSE per stream.
//!
//! A `StreamDispatcher` routes incoming tunnel data to per-connection channels
//! based on stream_id. No serialization — all connections run concurrently.
//!
//! Frame format (client → gateway):
//!   `[FRAME_OPEN(0x06) | stream_id(4 BE)]` — open stream
//!   `[FRAME_DATA(0x00) | stream_id(4 BE) | payload]` — data
//!   `[FRAME_CLOSE(0x05) | stream_id(4 BE)]` — close stream
//!
//! Frame format (gateway → client):
//!   `[FRAME_DATA(0x00) | stream_id(4 BE) | data_seq(8 BE) | payload]` — data
//!   `[FRAME_FIN(0x02) | stream_id(4 BE)]` — stream finished (backend closed)
//!   `[FRAME_CLOSE(0x05) | stream_id(4 BE)]` — stream error/closed

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};

use crate::packet::SessionId;
use crate::send_controller::SendController;
use crate::transport::TransportNode;

/// Swappable tunnel session state.
///
/// Wrapped in `Arc<RwLock<>>` so listener tasks can read the current session
/// and it can be swapped on reconnect without restarting TCP listeners.
pub struct TunnelSession {
    pub transport: Arc<TransportNode>,
    pub session_id: SessionId,
    pub peer_addr: SocketAddr,
    pub data_seq: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    /// Congestion-controlled sender for uploads. Shared across all connections
    /// so the entire upload path shares one congestion window.
    pub send_controller: Arc<tokio::sync::Mutex<SendController>>,
}

impl TunnelSession {
    pub fn new(
        transport: Arc<TransportNode>,
        session_id: SessionId,
        peer_addr: SocketAddr,
        data_seq: Arc<AtomicU64>,
        bytes_sent: Arc<AtomicU64>,
        send_controller: Arc<tokio::sync::Mutex<SendController>>,
    ) -> Self {
        Self {
            transport,
            session_id,
            peer_addr,
            data_seq,
            bytes_sent,
            send_controller,
        }
    }
}

// TLS support for HTTPS VIP ports (443, 8443).
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Maximum read buffer size for TCP proxy connections.
const TCP_READ_BUF_SIZE: usize = 65536;

/// Maximum concurrent TCP connections per listener.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// TLS handshake timeout in seconds.
const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// TCP connection idle timeout in seconds (no data in either direction).
const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 300;

/// Frame type for tunnel data frames.
const FRAME_DATA: u8 = 0x00;

/// Maximum TCP data bytes per ZTLP tunnel frame.
///
/// Calculation: gateway uses `@max_payload_bytes = 1200` as the max plaintext
/// frame size (including mux header). The mux header is 5 bytes:
/// `[FRAME_DATA(1) | stream_id(4)]`. So max TCP data = 1200 - 5 = 1195.
///
/// The resulting ZTLP packet on the wire:
/// header(46) + encrypted(plaintext + 16) = 46 + 1200 + 16 = 1262 bytes
/// Well under 1280 IPv6 minimum MTU and 1464 cellular MTU.
const MAX_MUX_PAYLOAD: usize = 1195;

/// Frame type for closing a multiplexed stream.
const FRAME_CLOSE: u8 = 0x05;

/// Frame type for opening a new multiplexed stream.
const FRAME_OPEN: u8 = 0x06;

/// Frame type for FIN from gateway (stream finished / backend closed).
/// Used in stream recovery logic when the gateway signals stream completion.
#[allow(dead_code)]
const FRAME_FIN: u8 = 0x02;

// Re-export the mux-layer STREAM_RESET constant from tunnel.rs.
pub use crate::tunnel::FRAME_STREAM_RESET;

// ─── Stream State Machine ───────────────────────────────────────────────────

/// State of a multiplexed stream within a VIP proxy connection.
///
/// When the gateway sends FRAME_CLOSE or FRAME_FIN for a stream, the VIP
/// proxy doesn't immediately tear down the TCP connection. Instead, if the
/// TCP connection is still alive (browser keep-alive), it transitions to
/// `Reopening` and opens a new ZTLP stream, allowing the next HTTP request
/// to flow on the same TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is active with the given stream_id.
    Active { stream_id: u32 },
    /// Stream was closed by gateway; waiting to open a new one.
    Reopening,
    /// Stream and TCP connection are both closed.
    Closed,
}

impl StreamState {
    /// Returns the stream_id if the stream is active.
    pub fn stream_id(&self) -> Option<u32> {
        match self {
            StreamState::Active { stream_id } => Some(*stream_id),
            _ => None,
        }
    }

    /// Returns true if the stream is in the Active state.
    pub fn is_active(&self) -> bool {
        matches!(self, StreamState::Active { .. })
    }

    /// Returns true if the stream is closed.
    pub fn is_closed(&self) -> bool {
        matches!(self, StreamState::Closed)
    }
}

// ─── HTTP Request Boundary Detection ────────────────────────────────────────

/// Tracks HTTP response boundaries to detect when a request-response cycle
/// is complete. This is NOT a full HTTP parser — just enough to know when
/// one response ends so we can track metrics and potentially trigger stream
/// reuse.
///
/// Supports:
/// - `Content-Length` header → count body bytes
/// - `Transfer-Encoding: chunked` → detect `0\r\n\r\n` terminator
/// - `Connection: close` → signal stream should close after response
#[derive(Debug)]
pub struct HttpTracker {
    /// Current parsing state.
    state: HttpState,
    /// Content-Length value from headers (if present).
    content_length: Option<usize>,
    /// Bytes remaining in the current body (for Content-Length mode).
    bytes_remaining: usize,
    /// Whether the response uses chunked transfer encoding.
    chunked: bool,
    /// Whether the server sent `Connection: close`.
    connection_close: bool,
    /// Number of completed request-response cycles.
    requests_completed: u64,
}

/// HTTP response parsing state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpState {
    /// Waiting for the start of a response (status line).
    WaitingForResponse,
    /// Accumulating header bytes until `\r\n\r\n`.
    ReadingHeaders(Vec<u8>),
    /// Reading body bytes (Content-Length or chunked).
    ReadingBody,
    /// Response is complete; ready for the next one.
    Complete,
}

impl Default for HttpTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpTracker {
    /// Create a new HTTP tracker in the initial state.
    pub fn new() -> Self {
        Self {
            state: HttpState::WaitingForResponse,
            content_length: None,
            bytes_remaining: 0,
            chunked: false,
            connection_close: false,
            requests_completed: 0,
        }
    }

    /// Number of completed request-response cycles.
    pub fn requests_completed(&self) -> u64 {
        self.requests_completed
    }

    /// Whether the server indicated `Connection: close`.
    pub fn is_connection_close(&self) -> bool {
        self.connection_close
    }

    /// Current parsing state.
    pub fn state(&self) -> &HttpState {
        &self.state
    }

    /// Feed response data from the server into the tracker.
    ///
    /// Call this with each chunk of data received from the tunnel.
    /// After calling, check `state()` for `Complete` or
    /// `is_connection_close()` to decide what to do.
    pub fn feed(&mut self, data: &[u8]) {
        let mut remaining = data;

        while !remaining.is_empty() {
            match &mut self.state {
                HttpState::WaitingForResponse => {
                    // Start accumulating headers
                    self.state = HttpState::ReadingHeaders(Vec::new());
                    // Don't consume — fall through to ReadingHeaders
                }
                HttpState::ReadingHeaders(ref mut buf) => {
                    // Look for end-of-headers marker: \r\n\r\n
                    buf.extend_from_slice(remaining);

                    if let Some(pos) = find_header_end(buf) {
                        // Parse headers up to the double CRLF
                        let header_bytes = buf[..pos].to_vec();
                        let body_start = pos + 4; // skip \r\n\r\n
                        let leftover = if body_start < buf.len() {
                            buf[body_start..].to_vec()
                        } else {
                            Vec::new()
                        };

                        self.parse_headers(&header_bytes);

                        if self.content_length == Some(0) {
                            // No body — response complete
                            self.complete_response();
                            remaining = &[]; // leftover handled on next feed
                            if !leftover.is_empty() {
                                // Recurse with leftover (next response)
                                self.feed(&leftover);
                            }
                        } else if self.content_length.is_some() || self.chunked {
                            self.state = HttpState::ReadingBody;
                            remaining = &[];
                            if !leftover.is_empty() {
                                self.feed(&leftover);
                            }
                        } else {
                            // No Content-Length, not chunked — could be
                            // connection-close delimited. Mark as reading body.
                            self.state = HttpState::ReadingBody;
                            remaining = &[];
                            if !leftover.is_empty() {
                                self.feed(&leftover);
                            }
                        }
                    } else {
                        // Haven't found end of headers yet; need more data
                        remaining = &[];
                    }
                }
                HttpState::ReadingBody => {
                    if self.chunked {
                        // For chunked encoding, look for the terminator
                        // `0\r\n\r\n` anywhere in the data stream.
                        if contains_chunked_terminator(remaining) {
                            self.complete_response();
                        }
                        remaining = &[];
                    } else if self.content_length.is_some() {
                        // Count down body bytes
                        let consume = remaining.len().min(self.bytes_remaining);
                        self.bytes_remaining -= consume;
                        remaining = &remaining[consume..];
                        if self.bytes_remaining == 0 {
                            self.complete_response();
                            // Any leftover belongs to the next response
                            if !remaining.is_empty() {
                                let leftover = remaining.to_vec();
                                remaining = &[];
                                self.feed(&leftover);
                            }
                        }
                    } else {
                        // No Content-Length, not chunked — read until close
                        remaining = &[];
                    }
                }
                HttpState::Complete => {
                    // Reset for next request-response cycle
                    self.state = HttpState::WaitingForResponse;
                    // Don't consume — loop will pick up WaitingForResponse
                }
            }
        }
    }

    /// Parse HTTP headers to extract Content-Length, Transfer-Encoding, Connection.
    fn parse_headers(&mut self, header_bytes: &[u8]) {
        let header_str = String::from_utf8_lossy(header_bytes);

        self.content_length = None;
        self.bytes_remaining = 0;
        self.chunked = false;
        self.connection_close = false;

        for line in header_str.split("\r\n") {
            let lower = line.to_ascii_lowercase();
            if let Some(val) = lower.strip_prefix("content-length:") {
                if let Ok(len) = val.trim().parse::<usize>() {
                    self.content_length = Some(len);
                    self.bytes_remaining = len;
                }
            } else if let Some(val) = lower.strip_prefix("transfer-encoding:") {
                if val.trim().contains("chunked") {
                    self.chunked = true;
                }
            } else if let Some(val) = lower.strip_prefix("connection:") {
                if val.trim() == "close" {
                    self.connection_close = true;
                }
            }
        }
    }

    /// Mark the current response as complete and reset for the next one.
    fn complete_response(&mut self) {
        self.requests_completed += 1;
        self.state = HttpState::Complete;
        self.content_length = None;
        self.bytes_remaining = 0;
        self.chunked = false;
        // Note: connection_close persists — once set, the connection should close
    }
}

/// Find the position of `\r\n\r\n` in a byte slice.
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Check if data contains the chunked transfer-encoding terminator.
///
/// The terminator is `0\r\n\r\n` — the last chunk has size 0.
/// We also accept `0\r\n\r\n` preceded by `\r\n` (the CRLF ending
/// the previous chunk).
fn contains_chunked_terminator(data: &[u8]) -> bool {
    data.windows(5).any(|w| w == b"0\r\n\r\n")
}

/// A registered VIP service.
#[derive(Debug, Clone)]
pub struct VipService {
    /// Human-readable name (e.g., "beta").
    pub name: String,
    /// VIP loopback address (e.g., 127.0.55.1).
    pub vip: Ipv4Addr,
    /// Ports to listen on (typically 80 and 443).
    pub ports: Vec<u16>,
}

/// Data received from the tunnel, to be forwarded to the TCP client.
#[derive(Debug)]
pub struct TunnelData {
    /// Stream ID this data belongs to (0 = legacy single-stream).
    pub stream_id: u32,
    /// The raw payload (after stripping the frame header).
    pub payload: Vec<u8>,
}

/// Stream dispatcher: routes incoming tunnel data to per-connection channels.
///
/// Each TCP connection registers with a stream_id and gets a dedicated
/// mpsc::Sender. The recv_loop dispatches tunnel data by stream_id.
pub struct StreamDispatcher {
    streams: std::sync::Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
}

impl Default for StreamDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamDispatcher {
    pub fn new() -> Self {
        Self {
            streams: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Register a new stream and return the receiver for it.
    pub fn register(&self, stream_id: u32) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(256);
        if let Ok(mut streams) = self.streams.lock() {
            streams.insert(stream_id, tx);
        }
        rx
    }

    /// Unregister a stream (called when connection closes).
    pub fn unregister(&self, stream_id: u32) {
        if let Ok(mut streams) = self.streams.lock() {
            streams.remove(&stream_id);
        }
    }

    /// Dispatch data to the appropriate stream. Returns false if stream not found.
    pub fn dispatch(&self, stream_id: u32, data: Vec<u8>) -> bool {
        if let Ok(streams) = self.streams.lock() {
            if let Some(tx) = streams.get(&stream_id) {
                return tx.try_send(data).is_ok();
            }
        }
        false
    }

    /// Signal that a stream has been closed by the remote side (drop the sender).
    pub fn close_stream(&self, stream_id: u32) {
        self.unregister(stream_id);
    }

    /// Number of active streams.
    pub fn stream_count(&self) -> usize {
        self.streams.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// The VIP proxy manager. Holds the service registry and manages TCP listeners.
pub struct VipProxy {
    /// Registered services keyed by name.
    services: HashMap<String, VipService>,
    /// Stream dispatcher for routing tunnel data to per-connection channels.
    dispatcher: Arc<StreamDispatcher>,
    /// Atomic counter for assigning stream IDs to new connections.
    next_stream_id: Arc<AtomicU32>,
    /// Stop flag for all proxy tasks.
    stop_flag: Arc<AtomicBool>,
    /// Join handles for spawned listener tasks.
    listener_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Shared tunnel session — swapped on reconnect without restarting listeners.
    session: Arc<RwLock<Option<TunnelSession>>>,
}

impl Default for VipProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl VipProxy {
    /// Create a new VIP proxy with stream multiplexing support.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            dispatcher: Arc::new(StreamDispatcher::new()),
            next_stream_id: Arc::new(AtomicU32::new(1)), // Start at 1 (0 = legacy)
            stop_flag: Arc::new(AtomicBool::new(false)),
            listener_handles: Vec::new(),
            session: Arc::new(RwLock::new(None)),
        }
    }

    /// Register a service with a VIP address and port.
    ///
    /// SECURITY: Only loopback addresses (127.0.0.0/8) are accepted. Binding
    /// to non-loopback addresses would allow the VIP proxy to be abused for
    /// port scanning or SSRF attacks against the local network.
    pub fn add_service(&mut self, name: String, vip: Ipv4Addr, port: u16) -> Result<(), String> {
        // SECURITY: Restrict VIP binding to loopback addresses only.
        if !vip.is_loopback() {
            return Err(format!(
                "VIP address {} is not a loopback address (must be 127.0.0.0/8)",
                vip
            ));
        }
        let entry = self
            .services
            .entry(name.clone())
            .or_insert_with(|| VipService {
                name,
                vip,
                ports: Vec::new(),
            });
        if !entry.ports.contains(&port) {
            entry.ports.push(port);
        }
        // Update VIP if it changed
        entry.vip = vip;
        Ok(())
    }

    /// Get the stream dispatcher (for the recv loop to dispatch data by stream_id).
    pub fn dispatcher(&self) -> Arc<StreamDispatcher> {
        self.dispatcher.clone()
    }

    /// Get a snapshot of all registered services.
    pub fn services(&self) -> &HashMap<String, VipService> {
        &self.services
    }

    /// Look up a VIP address by service name.
    pub fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        self.services.get(name).map(|s| s.vip)
    }

    /// Start TCP listeners for all registered services.
    ///
    /// Each listener accepts concurrent TCP connections. Each connection
    /// gets its own stream_id and communicates through the multiplexed tunnel.
    ///
    /// The tunnel session (transport, session_id, peer_addr) is stored in a
    /// shared `Arc<RwLock<>>` so it can be swapped on reconnect via
    /// `update_session()` without restarting the TCP listeners.
    ///
    /// Returns an `mpsc::UnboundedSender<u64>` — the caller must store this
    /// in the FFI `ActiveSession::upload_ack_tx` so the recv_loop can feed
    /// gateway ACKs to the `SendController`.
    pub async fn start(
        &mut self,
        transport: Arc<TransportNode>,
        session_id: SessionId,
        peer_addr: SocketAddr,
        data_seq: Arc<AtomicU64>,
        bytes_sent: Arc<AtomicU64>,
    ) -> Result<mpsc::UnboundedSender<u64>, String> {
        // Create a SendController with an ACK channel for congestion control
        let (ack_tx, ack_rx) = mpsc::unbounded_channel();
        let send_controller = Arc::new(tokio::sync::Mutex::new(SendController::new(
            transport.clone(),
            session_id,
            peer_addr,
            ack_rx,
        )));

        // Spawn background task for periodic flush + retransmit
        let sc_bg = send_controller.clone();
        let stop_bg = self.stop_flag.clone();
        tokio::spawn(async move {
            send_controller_background_task(sc_bg, stop_bg).await;
        });

        // Store the tunnel session
        {
            let mut sess = self.session.write().await;
            *sess = Some(TunnelSession::new(
                transport.clone(),
                session_id,
                peer_addr,
                data_seq.clone(),
                bytes_sent.clone(),
                send_controller,
            ));
        }

        // If listeners are already running, just update the session (hot-swap)
        if !self.listener_handles.is_empty() {
            tracing::info!("VIP proxy: hot-swapping tunnel session (listeners stay up)");
            // Fresh dispatcher for new session
            self.dispatcher = Arc::new(StreamDispatcher::new());
            self.next_stream_id.store(1, Ordering::SeqCst);
            return Ok(ack_tx);
        }

        // First start — create listeners
        self.dispatcher = Arc::new(StreamDispatcher::new());
        self.next_stream_id.store(1, Ordering::SeqCst);
        self.stop_flag.store(false, Ordering::SeqCst);

        for service in self.services.values() {
            for &port in &service.ports {
                let ip_addr = IpAddr::V4(service.vip);
                // SECURITY: Double-check loopback restriction at bind time.
                if !ip_addr.is_loopback() {
                    return Err(format!(
                        "refusing to bind non-loopback VIP address: {}",
                        ip_addr
                    ));
                }
                let bind_addr: SocketAddr = SocketAddr::new(ip_addr, port);

                let listener = TcpListener::bind(bind_addr)
                    .await
                    .map_err(|e| format!("failed to bind {}: {}", bind_addr, e))?;

                let stop = self.stop_flag.clone();
                let session = self.session.clone();
                let dispatcher = self.dispatcher.clone();
                let next_stream_id = self.next_stream_id.clone();

                // Build TLS acceptor for HTTPS ports
                let tls_acceptor = if is_tls_port(port) {
                    match build_tls_acceptor(&service.name) {
                        Ok(acceptor) => {
                            tracing::info!("VIP TLS enabled for {}:{}", service.vip, port);
                            Some(Arc::new(acceptor))
                        }
                        Err(e) => {
                            tracing::warn!(
                                "VIP TLS not available for {}:{}: {}",
                                service.vip,
                                port,
                                e
                            );
                            None
                        }
                    }
                } else {
                    None
                };

                let handle = tokio::spawn(async move {
                    vip_listener_task(
                        listener,
                        stop,
                        session,
                        dispatcher,
                        next_stream_id,
                        tls_acceptor,
                    )
                    .await;
                });

                self.listener_handles.push(handle);
                tracing::info!("VIP proxy listening on {}", bind_addr);
            }
        }

        Ok(ack_tx)
    }

    /// Hot-swap the tunnel session without restarting listeners.
    ///
    /// Called on tunnel reconnect — existing TCP listeners keep running
    /// and new connections will use the updated transport/session.
    pub async fn update_session(
        &self,
        transport: Arc<TransportNode>,
        session_id: SessionId,
        peer_addr: SocketAddr,
        data_seq: Arc<AtomicU64>,
        bytes_sent: Arc<AtomicU64>,
    ) -> mpsc::UnboundedSender<u64> {
        // Create fresh SendController for the new session
        let (ack_tx, ack_rx) = mpsc::unbounded_channel();
        let send_controller = Arc::new(tokio::sync::Mutex::new(SendController::new(
            transport.clone(),
            session_id,
            peer_addr,
            ack_rx,
        )));

        // Spawn background task for the new controller
        let sc_bg = send_controller.clone();
        let stop_bg = self.stop_flag.clone();
        tokio::spawn(async move {
            send_controller_background_task(sc_bg, stop_bg).await;
        });

        let mut sess = self.session.write().await;
        *sess = Some(TunnelSession::new(
            transport,
            session_id,
            peer_addr,
            data_seq,
            bytes_sent,
            send_controller,
        ));
        // Fresh dispatcher for new session
        tracing::info!("VIP proxy: tunnel session updated (hot-swap)");
        ack_tx
    }

    /// Get the shared session reference (for FFI to check if session exists).
    pub fn session_ref(&self) -> Arc<RwLock<Option<TunnelSession>>> {
        self.session.clone()
    }

    /// Stop all VIP proxy listeners and release resources.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        for handle in self.listener_handles.drain(..) {
            handle.abort();
        }
        // Note: Don't clear services — they're configuration, not runtime state.
        // They need to persist across reconnect cycles.
        tracing::info!("VIP proxy stopped");
    }
}

/// Check if a port should use TLS termination.
fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443)
}

/// Build a TLS acceptor from cert/key files in `~/.ztlp/certs/`.
fn build_tls_acceptor(service_name: &str) -> Result<TlsAcceptor, String> {
    let cert_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".ztlp")
        .join("certs");

    let patterns = [
        format!("{}.techrockstars.ztlp", service_name),
        service_name.to_string(),
    ];

    let mut cert_path = None;
    let mut key_path = None;

    for pattern in &patterns {
        let cp = cert_dir.join(format!("{}.pem", pattern));
        let kp = cert_dir.join(format!("{}.key", pattern));
        if cp.exists() && kp.exists() {
            cert_path = Some(cp);
            key_path = Some(kp);
            break;
        }
    }

    let cert_path = cert_path.ok_or_else(|| {
        format!(
            "no TLS cert found in {:?} for service '{}' (tried: {})",
            cert_dir,
            service_name,
            patterns.join(", ")
        )
    })?;
    let key_path = key_path.unwrap();

    tracing::info!("VIP TLS: loading cert from {:?}", cert_path);

    let cert_data = std::fs::read(&cert_path)
        .map_err(|e| format!("failed to read cert {:?}: {}", cert_path, e))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_data.as_slice())
        .filter_map(|r| r.ok())
        .collect();
    if certs.is_empty() {
        return Err(format!("no certificates found in {:?}", cert_path));
    }

    let key_data = std::fs::read(&key_path)
        .map_err(|e| format!("failed to read key {:?}: {}", key_path, e))?;
    let key = rustls_pemfile::private_key(&mut key_data.as_slice())
        .map_err(|e| format!("failed to parse key {:?}: {}", key_path, e))?
        .ok_or_else(|| format!("no private key found in {:?}", key_path))?;

    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config error: {}", e))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

// ─── Listener + Connection Handling ─────────────────────────────────────────

/// Background task that periodically processes ACKs, flushes pending data,
/// and retransmits timed-out packets for the SendController.
///
/// Runs every 10ms (or RTO/4, whichever is smaller) to keep the upload path
/// responsive. Exits when the stop flag is set.
async fn send_controller_background_task(
    controller: Arc<tokio::sync::Mutex<SendController>>,
    stop: Arc<AtomicBool>,
) {
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        // Short sleep — upload responsiveness matters
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let mut sc = controller.lock().await;

        // Process any pending ACKs from the recv_loop
        sc.process_acks();

        // Flush pending packets (up to cwnd)
        if let Err(e) = sc.flush().await {
            tracing::warn!("send_controller: flush error: {}", e);
        }

        // Check for retransmits
        if let Err(e) = sc.check_retransmit().await {
            tracing::warn!("send_controller: retransmit error: {}", e);
        }
    }
}

/// TCP listener task for a single VIP:port.
///
/// Accepts concurrent TCP connections. Each gets a unique stream_id and
/// runs independently through the multiplexed tunnel.
///
/// The `session` reference is read-locked per connection — if the tunnel
/// reconnects, new connections automatically use the new session.
async fn vip_listener_task(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    session: Arc<RwLock<Option<TunnelSession>>>,
    dispatcher: Arc<StreamDispatcher>,
    next_stream_id: Arc<AtomicU32>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        let accept_result = tokio::select! {
            result = listener.accept() => result,
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                continue;
            }
        };

        let (stream, client_addr) = match accept_result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("VIP accept error: {}", e);
                continue;
            }
        };

        // Read the current tunnel session — reject if no active session
        let (transport, session_id, peer_addr, data_seq, bytes_sent, send_controller) = {
            let sess_guard = session.read().await;
            match sess_guard.as_ref() {
                Some(s) => (
                    s.transport.clone(),
                    s.session_id,
                    s.peer_addr,
                    s.data_seq.clone(),
                    s.bytes_sent.clone(),
                    s.send_controller.clone(),
                ),
                None => {
                    tracing::warn!(
                        "VIP: rejecting connection from {} — no active tunnel session",
                        client_addr
                    );
                    drop(stream);
                    continue;
                }
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("VIP: max connections reached, rejecting {}", client_addr);
                drop(stream);
                continue;
            }
        };

        // Assign a unique stream_id for this connection
        let stream_id = next_stream_id.fetch_add(1, Ordering::SeqCst);

        tracing::info!(
            "VIP connection from {} stream_id={} (tls={})",
            client_addr,
            stream_id,
            tls_acceptor.is_some()
        );

        let stop = stop.clone();
        let dispatcher = dispatcher.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let _permit = permit;

            if let Some(ref acceptor) = tls_acceptor {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
                    acceptor.accept(stream),
                )
                .await
                {
                    Ok(Ok(tls_stream)) => {
                        tracing::info!(
                            "VIP TLS handshake complete from {} stream_id={}",
                            client_addr,
                            stream_id
                        );
                        let (read_half, write_half) = tokio::io::split(tls_stream);
                        handle_mux_connection(
                            read_half,
                            write_half,
                            stream_id,
                            client_addr,
                            &stop,
                            &transport,
                            session_id,
                            peer_addr,
                            &data_seq,
                            &bytes_sent,
                            &dispatcher,
                            &send_controller,
                        )
                        .await;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("VIP TLS handshake failed from {}: {}", client_addr, e);
                    }
                    Err(_) => {
                        tracing::warn!(
                            "VIP TLS handshake timeout from {} ({}s)",
                            client_addr,
                            TLS_HANDSHAKE_TIMEOUT_SECS
                        );
                    }
                }
            } else {
                let (read_half, write_half) = tokio::io::split(stream);
                handle_mux_connection(
                    read_half,
                    write_half,
                    stream_id,
                    client_addr,
                    &stop,
                    &transport,
                    session_id,
                    peer_addr,
                    &data_seq,
                    &bytes_sent,
                    &dispatcher,
                    &send_controller,
                )
                .await;
            }
        });
    }
}

/// Handle a multiplexed VIP connection.
///
/// 1. Register stream with dispatcher
/// 2. Send FRAME_OPEN to gateway
/// 3. Pipe data bidirectionally with stream_id tagging
/// 4. Send FRAME_CLOSE on teardown
/// 5. Unregister stream
#[allow(clippy::too_many_arguments)]
async fn handle_mux_connection<R, W>(
    mut read_half: R,
    mut write_half: W,
    stream_id: u32,
    client_addr: SocketAddr,
    stop: &Arc<AtomicBool>,
    transport: &Arc<TransportNode>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    data_seq: &Arc<AtomicU64>,
    bytes_sent: &Arc<AtomicU64>,
    dispatcher: &Arc<StreamDispatcher>,
    send_controller: &Arc<tokio::sync::Mutex<SendController>>,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    // 1. Register stream with dispatcher to receive tunnel data
    let mut stream_rx = dispatcher.register(stream_id);

    // 2. Send FRAME_OPEN to gateway to create backend connection
    {
        let open_frame = vec![
            FRAME_OPEN,
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            stream_id as u8,
        ];
        if let Err(e) = transport
            .send_data(session_id, &open_frame, peer_addr)
            .await
        {
            tracing::warn!("VIP: failed to send OPEN for stream {}: {}", stream_id, e);
            dispatcher.unregister(stream_id);
            return;
        }
        tracing::info!(
            "VIP: sent OPEN for stream {} from {}",
            stream_id,
            client_addr
        );
    }

    // Small delay for gateway to set up backend
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3. Bidirectional data pump
    let stop_clone = stop.clone();
    let last_activity = Arc::new(AtomicU64::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    ));
    let last_activity_write = last_activity.clone();

    // Task: tunnel → TCP (receive from dispatcher channel, write to TCP)
    let write_task = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::SeqCst) {
                break;
            }
            match tokio::time::timeout(std::time::Duration::from_millis(200), stream_rx.recv())
                .await
            {
                Ok(Some(data)) => {
                    last_activity_write.store(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        Ordering::Relaxed,
                    );
                    if let Err(e) = write_half.write_all(&data).await {
                        tracing::debug!("VIP: TCP write error stream {}: {}", stream_id, e);
                        break;
                    }
                    if let Err(e) = write_half.flush().await {
                        tracing::debug!("VIP: TCP flush error stream {}: {}", stream_id, e);
                        break;
                    }
                }
                Ok(None) => {
                    // Channel closed — stream ended by remote
                    tracing::info!(
                        "VIP: stream {} channel closed (remote FIN/CLOSE)",
                        stream_id
                    );
                    break;
                }
                Err(_) => {
                    // Timeout — check idle
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let last = last_activity.load(Ordering::Relaxed);
                    if now.saturating_sub(last) > CONNECTION_IDLE_TIMEOUT_SECS {
                        tracing::info!(
                            "VIP: stream {} idle timeout ({}s)",
                            stream_id,
                            CONNECTION_IDLE_TIMEOUT_SECS
                        );
                        break;
                    }
                    continue;
                }
            }
        }
    });

    // Main loop: TCP → tunnel (read from TCP, send through tunnel with stream_id)
    //
    // Uses the shared SendController for congestion-controlled sending.
    // Frames are enqueued and then flushed up to the current cwnd. The
    // background task handles periodic flushing and retransmits, but we
    // also flush eagerly here to minimize latency for small transfers.
    let transport = transport.clone();
    let data_seq = data_seq.clone();
    let bytes_sent = bytes_sent.clone();
    let stop = stop.clone();
    let send_controller = send_controller.clone();
    let mut buf = vec![0u8; TCP_READ_BUF_SIZE];

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        match tokio::time::timeout(std::time::Duration::from_secs(1), read_half.read(&mut buf))
            .await
        {
            Ok(Ok(0)) => break, // Connection closed
            Ok(Ok(n)) => {
                // Chunk TCP data into ZTLP-safe frames.
                // Each frame: [FRAME_DATA | stream_id(4 BE) | payload]
                // Max plaintext per ZTLP packet = 1200 bytes, so max payload = 1195.
                let data = &buf[..n];
                let mut offset = 0;
                while offset < n {
                    let chunk_end = std::cmp::min(offset + MAX_MUX_PAYLOAD, n);
                    let chunk = &data[offset..chunk_end];
                    let mut framed = Vec::with_capacity(1 + 4 + chunk.len());
                    framed.push(FRAME_DATA);
                    framed.extend_from_slice(&stream_id.to_be_bytes());
                    framed.extend_from_slice(chunk);

                    // Enqueue via SendController (congestion-controlled)
                    {
                        let mut sc = send_controller.lock().await;
                        sc.enqueue(framed);
                    }
                    data_seq.fetch_add(1, Ordering::Relaxed);
                    offset = chunk_end;
                }

                // Eagerly flush what the cwnd allows — the background task
                // handles the rest (pending queue, retransmits, ACK processing).
                {
                    let mut sc = send_controller.lock().await;
                    sc.process_acks();
                    if let Err(e) = sc.flush().await {
                        tracing::warn!("VIP tunnel send error stream {}: {}", stream_id, e);
                        break;
                    }
                }

                bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
            }
            Ok(Err(e)) => {
                tracing::debug!("VIP TCP read error stream {}: {}", stream_id, e);
                break;
            }
            Err(_) => continue,
        }
    }

    write_task.abort();

    // 4. Send FRAME_CLOSE to gateway
    {
        let close_frame = vec![
            FRAME_CLOSE,
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            stream_id as u8,
        ];
        let _ = transport
            .send_data(session_id, &close_frame, peer_addr)
            .await;
        tracing::info!("VIP: stream {} closed from {}", stream_id, client_addr);
    }

    // 5. Unregister from dispatcher
    dispatcher.unregister(stream_id);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vip_proxy_new() {
        let proxy = VipProxy::new();
        assert!(proxy.services().is_empty());
    }

    #[test]
    fn test_add_service() {
        let mut proxy = VipProxy::new();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .unwrap();

        assert_eq!(proxy.services().len(), 1);
        let svc = proxy
            .services()
            .get("beta")
            .expect("beta service should exist");
        assert_eq!(svc.vip, Ipv4Addr::new(127, 0, 55, 1));
        assert_eq!(svc.ports, vec![80]);
    }

    #[test]
    fn test_add_service_multiple_ports() {
        let mut proxy = VipProxy::new();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .unwrap();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 443)
            .unwrap();

        let svc = proxy.services().get("beta").expect("beta service");
        assert_eq!(svc.ports, vec![80, 443]);
    }

    #[test]
    fn test_add_service_duplicate_port() {
        let mut proxy = VipProxy::new();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .unwrap();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .unwrap();

        let svc = proxy.services().get("beta").expect("beta service");
        assert_eq!(svc.ports, vec![80]); // No duplicate
    }

    #[test]
    fn test_resolve() {
        let mut proxy = VipProxy::new();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .unwrap();
        proxy
            .add_service("backstage".to_string(), Ipv4Addr::new(127, 0, 55, 2), 80)
            .unwrap();

        assert_eq!(proxy.resolve("beta"), Some(Ipv4Addr::new(127, 0, 55, 1)));
        assert_eq!(
            proxy.resolve("backstage"),
            Some(Ipv4Addr::new(127, 0, 55, 2))
        );
        assert_eq!(proxy.resolve("unknown"), None);
    }

    #[test]
    fn test_dispatcher() {
        let proxy = VipProxy::new();
        let _disp = proxy.dispatcher(); // Should not panic
    }

    #[test]
    fn test_stop_without_start() {
        let mut proxy = VipProxy::new();
        proxy.stop(); // Should not panic
    }

    #[test]
    fn test_stream_dispatcher_register_dispatch() {
        let disp = StreamDispatcher::new();
        let mut rx = disp.register(1);
        assert!(disp.dispatch(1, vec![1, 2, 3]));
        assert_eq!(rx.try_recv().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_stream_dispatcher_unknown_stream() {
        let disp = StreamDispatcher::new();
        assert!(!disp.dispatch(99, vec![1, 2, 3]));
    }

    #[test]
    fn test_stream_dispatcher_unregister() {
        let disp = StreamDispatcher::new();
        let _rx = disp.register(1);
        assert_eq!(disp.stream_count(), 1);
        disp.unregister(1);
        assert_eq!(disp.stream_count(), 0);
        assert!(!disp.dispatch(1, vec![1, 2, 3]));
    }

    #[test]
    fn test_stream_dispatcher_close_stream() {
        let disp = StreamDispatcher::new();
        let _rx = disp.register(1);
        disp.close_stream(1);
        assert_eq!(disp.stream_count(), 0);
    }

    #[test]
    fn test_stream_dispatcher_multiple_streams() {
        let disp = StreamDispatcher::new();
        let mut rx1 = disp.register(1);
        let mut rx2 = disp.register(2);
        assert_eq!(disp.stream_count(), 2);

        assert!(disp.dispatch(1, vec![10]));
        assert!(disp.dispatch(2, vec![20]));

        assert_eq!(rx1.try_recv().unwrap(), vec![10]);
        assert_eq!(rx2.try_recv().unwrap(), vec![20]);
    }

    // ── Security audit tests ────────────────────────────────────────────

    #[test]
    fn test_add_service_rejects_non_loopback() {
        let mut proxy = VipProxy::new();

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(8, 8, 8, 8), 80);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("loopback"));

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(192, 168, 1, 1), 80);
        assert!(result.is_err());

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(169, 254, 1, 1), 80);
        assert!(result.is_err());

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(0, 0, 0, 0), 80);
        assert!(result.is_err());

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(255, 255, 255, 255), 80);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_service_accepts_loopback_range() {
        let mut proxy = VipProxy::new();
        assert!(proxy
            .add_service("svc1".to_string(), Ipv4Addr::new(127, 0, 0, 1), 80)
            .is_ok());
        assert!(proxy
            .add_service("svc2".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .is_ok());
        assert!(proxy
            .add_service("svc3".to_string(), Ipv4Addr::new(127, 255, 255, 254), 80)
            .is_ok());
    }

    #[test]
    fn test_add_service_rejected_leaves_no_state() {
        let mut proxy = VipProxy::new();
        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(10, 0, 0, 1), 80);
        assert!(result.is_err());
        assert!(
            proxy.services().is_empty(),
            "rejected service should not be registered"
        );
        assert_eq!(proxy.resolve("evil"), None);
    }
}
