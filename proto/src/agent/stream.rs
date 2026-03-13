//! Stream multiplexing over ZTLP tunnels.
//!
//! Multiple TCP connections share a single ZTLP session by multiplexing
//! streams inside the encrypted tunnel. Each stream has a unique 32-bit ID
//! and maps to one TCP connection.
//!
//! ## Wire format (inside encrypted ZTLP frames)
//!
//! These frame types are placed after the existing FRAME_DATA envelope.
//! Stream frames are carried as the payload of FRAME_DATA packets:
//!
//! ```text
//! STREAM_OPEN  (0x05): [0x05 | stream_id:32 | port:16]
//! STREAM_DATA  (0x06): [0x06 | stream_id:32 | data...]
//! STREAM_CLOSE (0x07): [0x07 | stream_id:32]
//! STREAM_RESET (0x04): [0x04 | stream_id:32]   (stream_id=0 → reset all)
//! ```
//!
//! ## Design
//!
//! The `StreamMux` manages the mapping between stream IDs and TCP connections.
//! It owns a set of `MuxStream` entries, each with a channel pair for sending
//! data to/from the TCP connection handler task.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use tokio::sync::mpsc;
use tracing::debug;

// ─── Stream frame types ─────────────────────────────────────────────────────

/// Stream open: [0x05 | stream_id:32 | port:16]
pub const STREAM_OPEN: u8 = 0x05;
/// Stream data: [0x06 | stream_id:32 | data...]
pub const STREAM_DATA: u8 = 0x06;
/// Stream close: [0x07 | stream_id:32]
pub const STREAM_CLOSE: u8 = 0x07;
/// Stream reset: [0x04 | stream_id:32] (reuse existing FRAME_RESET)
pub const STREAM_RESET: u8 = 0x04;

/// Minimum stream frame size (type + stream_id).
const MIN_STREAM_FRAME: usize = 5;

// ─── Stream state ───────────────────────────────────────────────────────────

/// State of a multiplexed stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamState {
    /// Stream open and active.
    Open,
    /// Local side has sent STREAM_CLOSE; waiting for remote close.
    HalfClosed,
    /// Stream fully closed.
    Closed,
}

/// A single multiplexed stream within a tunnel.
pub struct MuxStream {
    /// Unique stream ID.
    pub id: u32,
    /// Target port on the remote side.
    pub port: u16,
    /// Current state.
    pub state: StreamState,
    /// Channel to send data TO the TCP handler (data received from tunnel).
    pub tx: mpsc::Sender<Vec<u8>>,
    /// When this stream was created.
    pub created_at: Instant,
    /// Bytes sent through this stream.
    pub bytes_sent: u64,
    /// Bytes received through this stream.
    pub bytes_recv: u64,
}

/// Summary info about a stream (for status reporting).
#[derive(Debug, Clone)]
pub struct StreamInfo {
    pub id: u32,
    pub port: u16,
    pub state: StreamState,
    pub age_secs: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

// ─── Stream multiplexer ─────────────────────────────────────────────────────

/// Stream multiplexer — manages multiple streams within a single ZTLP tunnel.
pub struct StreamMux {
    /// Active streams by ID.
    streams: HashMap<u32, MuxStream>,
    /// Next stream ID to allocate (atomic for concurrent access).
    next_id: AtomicU32,
    /// Channel for sending stream frames into the tunnel.
    /// The tunnel writer task reads from this and encrypts/sends over UDP.
    tunnel_tx: mpsc::Sender<Vec<u8>>,
    /// Maximum concurrent streams.
    max_streams: usize,
}

impl StreamMux {
    /// Create a new stream multiplexer.
    ///
    /// `tunnel_tx` is used to send framed data into the ZTLP tunnel.
    /// `max_streams` limits concurrent streams (default 256).
    pub fn new(tunnel_tx: mpsc::Sender<Vec<u8>>, max_streams: usize) -> Self {
        Self {
            streams: HashMap::new(),
            next_id: AtomicU32::new(1), // 0 is reserved for "all streams"
            tunnel_tx,
            max_streams,
        }
    }

    /// Open a new stream for the given port.
    ///
    /// Returns the stream ID and a receiver channel for data from the tunnel.
    /// Sends STREAM_OPEN to the remote side.
    pub async fn open_stream(
        &mut self,
        port: u16,
    ) -> Result<(u32, mpsc::Receiver<Vec<u8>>), String> {
        if self.streams.len() >= self.max_streams {
            return Err(format!(
                "max streams exceeded ({}/{})",
                self.streams.len(),
                self.max_streams
            ));
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(256);

        // Send STREAM_OPEN frame
        let mut frame = Vec::with_capacity(7);
        frame.push(STREAM_OPEN);
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&port.to_be_bytes());

        self.tunnel_tx
            .send(frame)
            .await
            .map_err(|_| "tunnel closed".to_string())?;

        let stream = MuxStream {
            id,
            port,
            state: StreamState::Open,
            tx,
            created_at: Instant::now(),
            bytes_sent: 0,
            bytes_recv: 0,
        };

        self.streams.insert(id, stream);
        debug!("stream {} opened for port {}", id, port);

        Ok((id, rx))
    }

    /// Accept a stream opened by the remote side.
    ///
    /// Called when we receive a STREAM_OPEN frame from the tunnel.
    /// Returns the stream ID, port, and a receiver for data.
    pub fn accept_stream(
        &mut self,
        id: u32,
        port: u16,
    ) -> Result<mpsc::Receiver<Vec<u8>>, String> {
        if self.streams.contains_key(&id) {
            return Err(format!("duplicate stream ID {}", id));
        }
        if self.streams.len() >= self.max_streams {
            return Err(format!("max streams exceeded"));
        }

        let (tx, rx) = mpsc::channel(256);

        let stream = MuxStream {
            id,
            port,
            state: StreamState::Open,
            tx,
            created_at: Instant::now(),
            bytes_sent: 0,
            bytes_recv: 0,
        };

        self.streams.insert(id, stream);
        debug!("stream {} accepted for port {}", id, port);

        Ok(rx)
    }

    /// Send data on a stream.
    pub async fn send_data(&mut self, stream_id: u32, data: &[u8]) -> Result<(), String> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| format!("stream {} not found", stream_id))?;

        if stream.state != StreamState::Open {
            return Err(format!("stream {} not open ({:?})", stream_id, stream.state));
        }

        let mut frame = Vec::with_capacity(5 + data.len());
        frame.push(STREAM_DATA);
        frame.extend_from_slice(&stream_id.to_be_bytes());
        frame.extend_from_slice(data);

        stream.bytes_sent += data.len() as u64;

        self.tunnel_tx
            .send(frame)
            .await
            .map_err(|_| "tunnel closed".to_string())
    }

    /// Deliver data received from the tunnel to a stream's handler.
    pub async fn deliver_data(&mut self, stream_id: u32, data: Vec<u8>) -> Result<(), String> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| format!("stream {} not found", stream_id))?;

        stream.bytes_recv += data.len() as u64;

        stream
            .tx
            .send(data)
            .await
            .map_err(|_| format!("stream {} handler dropped", stream_id))
    }

    /// Close a stream (send STREAM_CLOSE to remote).
    pub async fn close_stream(&mut self, stream_id: u32) -> Result<(), String> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| format!("stream {} not found", stream_id))?;

        if stream.state == StreamState::Closed {
            return Ok(());
        }

        // Send STREAM_CLOSE frame
        let mut frame = Vec::with_capacity(5);
        frame.push(STREAM_CLOSE);
        frame.extend_from_slice(&stream_id.to_be_bytes());

        self.tunnel_tx
            .send(frame)
            .await
            .map_err(|_| "tunnel closed".to_string())?;

        match stream.state {
            StreamState::Open => {
                stream.state = StreamState::HalfClosed;
            }
            StreamState::HalfClosed => {
                stream.state = StreamState::Closed;
            }
            StreamState::Closed => {}
        }

        debug!("stream {} closed (state={:?})", stream_id, stream.state);
        Ok(())
    }

    /// Handle remote close of a stream.
    pub fn remote_close(&mut self, stream_id: u32) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state {
                StreamState::Open => {
                    stream.state = StreamState::HalfClosed;
                }
                StreamState::HalfClosed => {
                    stream.state = StreamState::Closed;
                }
                StreamState::Closed => {}
            }
            debug!(
                "stream {} remote closed (state={:?})",
                stream_id, stream.state
            );
        }
    }

    /// Remove a fully closed stream.
    pub fn remove_stream(&mut self, stream_id: u32) -> Option<MuxStream> {
        self.streams.remove(&stream_id)
    }

    /// Remove all closed streams.
    pub fn gc_closed(&mut self) -> usize {
        let before = self.streams.len();
        self.streams.retain(|_, s| s.state != StreamState::Closed);
        before - self.streams.len()
    }

    /// Get stream info for all active streams.
    pub fn stream_info(&self) -> Vec<StreamInfo> {
        self.streams
            .values()
            .map(|s| StreamInfo {
                id: s.id,
                port: s.port,
                state: s.state.clone(),
                age_secs: s.created_at.elapsed().as_secs(),
                bytes_sent: s.bytes_sent,
                bytes_recv: s.bytes_recv,
            })
            .collect()
    }

    /// Number of active streams.
    pub fn active_count(&self) -> usize {
        self.streams
            .values()
            .filter(|s| s.state == StreamState::Open)
            .count()
    }

    /// Total stream count (including half-closed).
    pub fn total_count(&self) -> usize {
        self.streams.len()
    }

    /// Parse a stream frame from raw bytes.
    ///
    /// Returns `(frame_type, stream_id, payload)` on success.
    pub fn parse_frame(data: &[u8]) -> Result<(u8, u32, &[u8]), String> {
        if data.len() < MIN_STREAM_FRAME {
            return Err("stream frame too short".to_string());
        }

        let frame_type = data[0];
        let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let payload = &data[5..];

        Ok((frame_type, stream_id, payload))
    }

    /// Check if a frame type byte is a stream-level frame.
    pub fn is_stream_frame(frame_type: u8) -> bool {
        matches!(
            frame_type,
            STREAM_OPEN | STREAM_DATA | STREAM_CLOSE | STREAM_RESET
        )
    }
}

// ─── Stream frame construction helpers ──────────────────────────────────────

/// Build a STREAM_OPEN frame.
pub fn build_stream_open(stream_id: u32, port: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(7);
    frame.push(STREAM_OPEN);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&port.to_be_bytes());
    frame
}

/// Build a STREAM_DATA frame.
pub fn build_stream_data(stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + data.len());
    frame.push(STREAM_DATA);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

/// Build a STREAM_CLOSE frame.
pub fn build_stream_close(stream_id: u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5);
    frame.push(STREAM_CLOSE);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame
}

/// Build a STREAM_RESET frame.
pub fn build_stream_reset(stream_id: u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5);
    frame.push(STREAM_RESET);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stream_open() {
        let frame = build_stream_open(42, 22);
        let (ftype, sid, payload) = StreamMux::parse_frame(&frame).unwrap();
        assert_eq!(ftype, STREAM_OPEN);
        assert_eq!(sid, 42);
        assert_eq!(payload.len(), 2);
        let port = u16::from_be_bytes([payload[0], payload[1]]);
        assert_eq!(port, 22);
    }

    #[test]
    fn test_parse_stream_data() {
        let frame = build_stream_data(7, b"hello world");
        let (ftype, sid, payload) = StreamMux::parse_frame(&frame).unwrap();
        assert_eq!(ftype, STREAM_DATA);
        assert_eq!(sid, 7);
        assert_eq!(payload, b"hello world");
    }

    #[test]
    fn test_parse_stream_close() {
        let frame = build_stream_close(99);
        let (ftype, sid, payload) = StreamMux::parse_frame(&frame).unwrap();
        assert_eq!(ftype, STREAM_CLOSE);
        assert_eq!(sid, 99);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_parse_stream_reset() {
        let frame = build_stream_reset(0);
        let (ftype, sid, _) = StreamMux::parse_frame(&frame).unwrap();
        assert_eq!(ftype, STREAM_RESET);
        assert_eq!(sid, 0);
    }

    #[test]
    fn test_is_stream_frame() {
        assert!(StreamMux::is_stream_frame(STREAM_OPEN));
        assert!(StreamMux::is_stream_frame(STREAM_DATA));
        assert!(StreamMux::is_stream_frame(STREAM_CLOSE));
        assert!(StreamMux::is_stream_frame(STREAM_RESET));
        assert!(!StreamMux::is_stream_frame(0x00)); // FRAME_DATA
        assert!(!StreamMux::is_stream_frame(0x01)); // FRAME_ACK
    }

    #[test]
    fn test_frame_too_short() {
        assert!(StreamMux::parse_frame(&[0x05, 0x00]).is_err());
        assert!(StreamMux::parse_frame(&[]).is_err());
    }

    #[tokio::test]
    async fn test_open_and_close_stream() {
        let (tunnel_tx, mut tunnel_rx) = mpsc::channel(16);
        let mut mux = StreamMux::new(tunnel_tx, 256);

        // Open stream
        let (sid, _data_rx) = mux.open_stream(22).await.unwrap();
        assert_eq!(sid, 1);
        assert_eq!(mux.active_count(), 1);

        // Verify STREAM_OPEN was sent
        let frame = tunnel_rx.recv().await.unwrap();
        let (ftype, id, payload) = StreamMux::parse_frame(&frame).unwrap();
        assert_eq!(ftype, STREAM_OPEN);
        assert_eq!(id, 1);
        let port = u16::from_be_bytes([payload[0], payload[1]]);
        assert_eq!(port, 22);

        // Close stream
        mux.close_stream(sid).await.unwrap();

        // Verify STREAM_CLOSE was sent
        let frame = tunnel_rx.recv().await.unwrap();
        let (ftype, id, _) = StreamMux::parse_frame(&frame).unwrap();
        assert_eq!(ftype, STREAM_CLOSE);
        assert_eq!(id, 1);
    }

    #[tokio::test]
    async fn test_send_data() {
        let (tunnel_tx, mut tunnel_rx) = mpsc::channel(16);
        let mut mux = StreamMux::new(tunnel_tx, 256);

        let (sid, _data_rx) = mux.open_stream(80).await.unwrap();
        let _ = tunnel_rx.recv().await; // consume STREAM_OPEN

        mux.send_data(sid, b"GET / HTTP/1.1\r\n").await.unwrap();

        let frame = tunnel_rx.recv().await.unwrap();
        let (ftype, id, payload) = StreamMux::parse_frame(&frame).unwrap();
        assert_eq!(ftype, STREAM_DATA);
        assert_eq!(id, sid);
        assert_eq!(payload, b"GET / HTTP/1.1\r\n");
    }

    #[tokio::test]
    async fn test_deliver_data() {
        let (tunnel_tx, _tunnel_rx) = mpsc::channel(16);
        let mut mux = StreamMux::new(tunnel_tx, 256);

        let rx = mux.accept_stream(42, 22).unwrap();
        let mut rx = rx;

        mux.deliver_data(42, b"SSH-2.0-OpenSSH".to_vec())
            .await
            .unwrap();

        let data = rx.recv().await.unwrap();
        assert_eq!(data, b"SSH-2.0-OpenSSH");
    }

    #[tokio::test]
    async fn test_max_streams() {
        let (tunnel_tx, _tunnel_rx) = mpsc::channel(1024);
        let mut mux = StreamMux::new(tunnel_tx, 2);

        let _ = mux.open_stream(22).await.unwrap();
        let _ = mux.open_stream(80).await.unwrap();
        assert!(mux.open_stream(443).await.is_err());
    }

    #[tokio::test]
    async fn test_gc_closed() {
        let (tunnel_tx, _tunnel_rx) = mpsc::channel(16);
        let mut mux = StreamMux::new(tunnel_tx, 256);

        let (sid, _rx) = mux.open_stream(22).await.unwrap();
        mux.close_stream(sid).await.unwrap();
        mux.remote_close(sid); // now fully closed

        assert_eq!(mux.total_count(), 1);
        let freed = mux.gc_closed();
        assert_eq!(freed, 1);
        assert_eq!(mux.total_count(), 0);
    }

    #[test]
    fn test_stream_info() {
        let (tunnel_tx, _) = mpsc::channel(16);
        let mut mux = StreamMux::new(tunnel_tx, 256);
        let _rx = mux.accept_stream(1, 22).unwrap();
        let _rx = mux.accept_stream(2, 443).unwrap();

        let info = mux.stream_info();
        assert_eq!(info.len(), 2);
    }

    #[tokio::test]
    async fn test_remote_close_then_local_close() {
        let (tunnel_tx, _tunnel_rx) = mpsc::channel(16);
        let mut mux = StreamMux::new(tunnel_tx, 256);

        let (sid, _rx) = mux.open_stream(22).await.unwrap();
        mux.remote_close(sid);

        // Stream should be half-closed
        assert_eq!(
            mux.streams.get(&sid).unwrap().state,
            StreamState::HalfClosed
        );

        // Local close should make it fully closed
        mux.close_stream(sid).await.unwrap();
        assert_eq!(mux.streams.get(&sid).unwrap().state, StreamState::Closed);
    }

    #[tokio::test]
    async fn test_bytes_tracking() {
        let (tunnel_tx, _tunnel_rx) = mpsc::channel(64);
        let mut mux = StreamMux::new(tunnel_tx, 256);

        let rx = mux.accept_stream(1, 22).unwrap();
        let mut _rx = rx;

        mux.send_data(1, b"hello").await.unwrap();
        mux.send_data(1, b"world").await.unwrap();
        mux.deliver_data(1, b"response".to_vec()).await.unwrap();

        let info = mux.stream_info();
        let s = info.iter().find(|i| i.id == 1).unwrap();
        assert_eq!(s.bytes_sent, 10);
        assert_eq!(s.bytes_recv, 8);
    }
}
