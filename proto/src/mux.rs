//! ZTLP mux engine — Rust-owned multiplexed tunnel state machine.
//!
//! Part of the Nebula-style collapse (Phase 2): move the mux framing, ACK
//! generation, receive-window (rwnd) policy, congestion window, pacing, and
//! retransmit logic out of `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`
//! and `PacketTunnelProvider.swift` into a single Rust module that can be
//! unit-tested on Linux and driven by `IosTunnelEngine` in production.
//!
//! # Wire frames (matching existing gateway + Swift)
//!
//! ```text
//! FRAME_DATA  = 0x00  [0x00 | stream_id(4 BE) | data_seq(8 BE) | payload]
//!                     (legacy form omits stream_id: [0x00 | data_seq(8) | pl])
//! FRAME_ACK   = 0x01  [0x01 | cumulative_ack(8 BE) | rwnd(2 BE)]
//!                     (legacy 9-byte form omits rwnd)
//! FRAME_FIN   = 0x02  [0x02 | stream_id(4 BE)]
//!                     (legacy form omits stream_id)
//! FRAME_CLOSE = 0x05  [0x05 | stream_id(4 BE)]
//! FRAME_OPEN  = 0x06  [0x06 | stream_id(4 BE) | service_name_utf8]
//! FRAME_PING  = 0x07  [0x07 | nonce(8 BE)]
//! FRAME_PONG  = 0x08  [0x08 | nonce(8 BE)]
//! ```
//!
//! # Phases
//!
//! * Task 2.1 (this commit): scaffolding — types, constants, stubs.
//! * Task 2.2: encode/decode.
//! * Task 2.3: ACK generation + rwnd policy (hold=12 fix).
//! * Task 2.4: send buffer + cwnd + retransmit.
//! * Task 2.5+: FFI and engine wiring.

#![cfg(feature = "ios-sync")]

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

// ── Wire constants ─────────────────────────────────────────────────────

pub const FRAME_DATA: u8 = 0x00;
pub const FRAME_ACK: u8 = 0x01;
pub const FRAME_FIN: u8 = 0x02;
pub const FRAME_CLOSE: u8 = 0x05;
pub const FRAME_OPEN: u8 = 0x06;
pub const FRAME_PING: u8 = 0x07;
pub const FRAME_PONG: u8 = 0x08;

/// Receive-window floor. The gateway defers send past cwnd based on this.
pub const RWND_FLOOR: u16 = 4;
/// Maximum adaptive rwnd we advertise to the gateway.
pub const RWND_ADAPTIVE_MAX: u16 = 16;
/// Rwnd used during an active browser burst.
pub const RWND_BROWSER_BURST_TARGET: u16 = 16;
/// Rwnd we hold (instead of collapsing to floor=4) shortly after outbound
/// demand. The plan calls out the pre-Nebula bug where Vaultwarden spent
/// its JS/WASM tail at rwnd=4 even with a clean router; hold=12 fixes it.
pub const RWND_POST_DEMAND_HOLD: u16 = 12;

/// Default max inflight unacked packets (cwnd). Mirrors
/// `ZTLPTunnelConnection.maxSendsInFlight` starting value.
pub const DEFAULT_CWND: u16 = 16;
/// Retransmit timeout before we resend an inflight packet.
pub const DEFAULT_RTO: Duration = Duration::from_millis(500);

// ── Frame model ────────────────────────────────────────────────────────

/// Parsed mux frame — Rust-side representation of an on-wire frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuxFrame {
    /// Data on stream `stream_id` (0 = legacy / single-stream tunnel).
    Data {
        stream_id: u32,
        data_seq: u64,
        payload: Vec<u8>,
    },
    /// Cumulative ACK with optional rwnd.
    Ack { cumulative: u64, rwnd: Option<u16> },
    /// Stream FIN (peer finished sending on this stream).
    Fin { stream_id: u32 },
    /// Stream CLOSE (explicit close).
    Close { stream_id: u32 },
    /// Stream OPEN with a service name (e.g. "vault.techrockstars.ztlp").
    Open { stream_id: u32, service: String },
    /// Session health probe.
    Ping { nonce: u64 },
    /// Session health probe response.
    Pong { nonce: u64 },
}

/// Error values returned by the frame codec. We keep the public surface small
/// on purpose — each variant corresponds to a real production failure mode.
#[derive(Debug, PartialEq, Eq)]
pub enum MuxError {
    /// Frame shorter than the smallest legal header for its type.
    ShortFrame,
    /// Frame first byte is not a known FRAME_* constant.
    UnknownFrameType(u8),
    /// UTF-8 failure when parsing a service name in FRAME_OPEN.
    InvalidServiceName,
    /// Output buffer smaller than the encoded length.
    OutputTooSmall { need: usize, got: usize },
    /// Caller passed a zero-length payload where one is required.
    EmptyPayload,
}

impl std::fmt::Display for MuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MuxError::ShortFrame => write!(f, "frame shorter than header"),
            MuxError::UnknownFrameType(t) => write!(f, "unknown frame type 0x{t:02x}"),
            MuxError::InvalidServiceName => write!(f, "FRAME_OPEN service name is not utf-8"),
            MuxError::OutputTooSmall { need, got } => {
                write!(f, "output buffer too small: need {need} got {got}")
            }
            MuxError::EmptyPayload => write!(f, "payload is empty"),
        }
    }
}

impl std::error::Error for MuxError {}

// ── Per-stream state ──────────────────────────────────────────────────

/// Per-stream lifecycle state tracked by the mux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// We sent FRAME_OPEN; waiting for first DATA/CLOSE.
    Opening,
    /// Stream is carrying data.
    Open,
    /// We sent FRAME_CLOSE but haven't fully drained inflight sends yet.
    Closing,
    /// Closed locally and remotely.
    Closed,
}

#[derive(Debug, Clone)]
pub struct MuxStream {
    pub stream_id: u32,
    pub service: String,
    pub state: StreamState,
    /// Bytes we've enqueued for this stream but not yet sent over UDP.
    pub send_buf_bytes: usize,
    /// Last time this stream was touched (for stuck-flow detection).
    pub last_touched: Instant,
}

// ── Send buffer / inflight tracking ───────────────────────────────────

/// Packet waiting for ACK. Retransmitted if not acked within `rto`.
#[derive(Debug, Clone)]
pub struct InflightPacket {
    pub data_seq: u64,
    pub stream_id: u32,
    /// Encoded plaintext mux frame (NOT encrypted). MuxEngine does not touch
    /// encryption — the caller wraps these via `ztlp_encrypt_packet`.
    pub encoded: Vec<u8>,
    pub sent_at: Instant,
    pub retransmits: u32,
}

/// Outbound queue item.
#[derive(Debug, Clone)]
pub enum OutboundItem {
    Open {
        stream_id: u32,
        service: String,
    },
    Data {
        stream_id: u32,
        payload: Vec<u8>,
    },
    Close {
        stream_id: u32,
    },
    /// Session-health probe to send out-of-band.
    Probe {
        nonce: u64,
    },
}

// ── Router stats snapshot (mirror of Swift RouterStatsSnapshot) ───────

/// Lightweight snapshot used by `MuxEngine::tick` for the rwnd policy. The
/// caller fills this from `ztlp_router_stats` in production. In Linux
/// tests we construct it directly.
#[derive(Debug, Clone, Copy, Default)]
pub struct RouterStatsSnapshot {
    pub flows: u32,
    pub outbound: u32,
    pub stream_to_flow: u32,
    pub send_buf_bytes: usize,
    pub oldest_ms: u64,
}

// ── Engine ────────────────────────────────────────────────────────────

/// The main mux state machine. One instance per tunnel session.
///
/// `MuxEngine` is **not** thread-safe on its own — wrap in a `Mutex` if the
/// caller needs cross-thread access. In production `IosTunnelEngine` owns a
/// single-threaded tick loop that drains the engine.
pub struct MuxEngine {
    // Sequence state
    next_send_data_seq: u64,
    next_expected_recv_seq: u64,
    // Stream registry
    streams: HashMap<u32, MuxStream>,
    next_stream_id: u32,
    // Outbound queue (awaiting cwnd/rwnd before encoding)
    send_queue: VecDeque<OutboundItem>,
    // Inflight packets awaiting ACK (keyed by data_seq)
    inflight: HashMap<u64, InflightPacket>,
    // Window state
    advertised_rwnd: u16,
    peer_rwnd: u16,
    cwnd: u16,
    // Rwnd policy tracking
    consecutive_rwnd_healthy_ticks: u32,
    rwnd_pressure_until: Option<Instant>,
    last_outbound_demand_at: Option<Instant>,
    rwnd_healthy_ticks_needed: u32,
    /// When we last told the callback our rwnd changed — used to throttle logs.
    last_rwnd_log: Option<Instant>,
    // Retransmit config
    rto: Duration,
}

impl MuxEngine {
    pub fn new() -> Self {
        Self {
            next_send_data_seq: 1,
            next_expected_recv_seq: 1,
            streams: HashMap::new(),
            // Stream IDs start at 1; 0 is reserved for "single-stream legacy".
            next_stream_id: 1,
            send_queue: VecDeque::new(),
            inflight: HashMap::new(),
            advertised_rwnd: RWND_FLOOR,
            peer_rwnd: RWND_FLOOR,
            cwnd: DEFAULT_CWND,
            consecutive_rwnd_healthy_ticks: 0,
            rwnd_pressure_until: None,
            last_outbound_demand_at: None,
            rwnd_healthy_ticks_needed: 3,
            last_rwnd_log: None,
            rto: DEFAULT_RTO,
        }
    }

    /// Current advertised receive window — what we tell the gateway via
    /// FRAME_ACK's rwnd field.
    pub fn advertised_rwnd(&self) -> u16 {
        self.advertised_rwnd
    }

    /// Inflight packet count.
    pub fn inflight_len(&self) -> usize {
        self.inflight.len()
    }

    /// Queue depth (not yet encoded).
    pub fn queue_len(&self) -> usize {
        self.send_queue.len()
    }

    /// Stream count.
    pub fn streams_len(&self) -> usize {
        self.streams.len()
    }

    /// Next stream_id the engine will hand out (monotonic).
    pub fn next_stream_id(&self) -> u32 {
        self.next_stream_id
    }

    // Future phases implement:
    // - encode_frame / decode_frame (Task 2.2)
    // - ack_policy + ramp / reduce rwnd (Task 2.3)
    // - take_send_bytes + on_ack + tick retransmit (Task 2.4)
}

impl Default for MuxEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mux_engine_defaults_are_sane() {
        let m = MuxEngine::new();
        assert_eq!(m.advertised_rwnd(), RWND_FLOOR);
        assert_eq!(m.inflight_len(), 0);
        assert_eq!(m.queue_len(), 0);
        assert_eq!(m.streams_len(), 0);
        assert_eq!(m.next_stream_id(), 1);
    }

    #[test]
    fn frame_constants_match_gateway_wire() {
        // These must stay aligned with proto/src/ffi.rs and the Elixir
        // gateway; a mismatch breaks the tunnel.
        assert_eq!(FRAME_DATA, 0x00);
        assert_eq!(FRAME_ACK, 0x01);
        assert_eq!(FRAME_FIN, 0x02);
        assert_eq!(FRAME_CLOSE, 0x05);
        assert_eq!(FRAME_OPEN, 0x06);
        assert_eq!(FRAME_PING, 0x07);
        assert_eq!(FRAME_PONG, 0x08);
    }

    #[test]
    fn mux_error_display_is_informative() {
        assert_eq!(
            MuxError::UnknownFrameType(0xff).to_string(),
            "unknown frame type 0xff"
        );
        assert_eq!(
            MuxError::OutputTooSmall { need: 11, got: 9 }.to_string(),
            "output buffer too small: need 11 got 9"
        );
    }
}
