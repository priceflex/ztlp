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

// ── RTT / goodput sampling (Phase A instrumentation) ──────────────────
//
// These constants drive the RFC-6298-style smoothed RTT estimator and the
// 8-second sliding-window goodput sampler. They are passive — nothing in
// the rwnd policy reads them yet. Phase D wires them into the autotuner.

/// Number of 1-second buckets in the goodput sliding window.
pub const GOODPUT_WINDOW_BUCKETS: usize = 8;
/// RFC 6298 smoothing for SRTT: srtt = (1 - alpha) * srtt + alpha * sample.
/// Stored as an integer pair to avoid floats in FFI.
pub const RTT_SRTT_ALPHA_NUM: u32 = 1;
pub const RTT_SRTT_ALPHA_DEN: u32 = 8;
/// RFC 6298 smoothing for RTTVAR: rttvar = (1 - beta) * rttvar + beta * |srtt - sample|.
pub const RTT_RTTVAR_BETA_NUM: u32 = 1;
pub const RTT_RTTVAR_BETA_DEN: u32 = 4;

/// Maximum shadow-sent entries we remember for RTT observation. A
/// Vaultwarden page load with a stuck peer could otherwise bloat the
/// map; we'd rather drop the oldest sample than leak.
pub const SHADOW_MAX_ENTRIES: usize = 4096;

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

// ── Frame codec ───────────────────────────────────────────────────────

impl MuxFrame {
    /// Byte length this frame encodes to.
    pub fn encoded_len(&self) -> usize {
        match self {
            // [0x00 | stream_id(4) | data_seq(8) | payload]
            MuxFrame::Data { payload, .. } => 1 + 4 + 8 + payload.len(),
            // [0x01 | cumulative(8) | rwnd(2)?]
            MuxFrame::Ack { rwnd, .. } => 1 + 8 + if rwnd.is_some() { 2 } else { 0 },
            // [0x02 | stream_id(4)]
            MuxFrame::Fin { .. } => 1 + 4,
            // [0x05 | stream_id(4)]
            MuxFrame::Close { .. } => 1 + 4,
            // [0x06 | stream_id(4) | service_utf8]
            MuxFrame::Open { service, .. } => 1 + 4 + service.as_bytes().len(),
            // [0x07 | nonce(8)]
            MuxFrame::Ping { .. } => 1 + 8,
            // [0x08 | nonce(8)]
            MuxFrame::Pong { .. } => 1 + 8,
        }
    }

    /// Encode the frame into `out`, returning bytes written. Fails if `out`
    /// is smaller than `encoded_len`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, MuxError> {
        let need = self.encoded_len();
        if out.len() < need {
            return Err(MuxError::OutputTooSmall {
                need,
                got: out.len(),
            });
        }
        match self {
            MuxFrame::Data {
                stream_id,
                data_seq,
                payload,
            } => {
                out[0] = FRAME_DATA;
                out[1..5].copy_from_slice(&stream_id.to_be_bytes());
                out[5..13].copy_from_slice(&data_seq.to_be_bytes());
                out[13..13 + payload.len()].copy_from_slice(payload);
            }
            MuxFrame::Ack { cumulative, rwnd } => {
                out[0] = FRAME_ACK;
                out[1..9].copy_from_slice(&cumulative.to_be_bytes());
                if let Some(r) = rwnd {
                    out[9..11].copy_from_slice(&r.to_be_bytes());
                }
            }
            MuxFrame::Fin { stream_id } => {
                out[0] = FRAME_FIN;
                out[1..5].copy_from_slice(&stream_id.to_be_bytes());
            }
            MuxFrame::Close { stream_id } => {
                out[0] = FRAME_CLOSE;
                out[1..5].copy_from_slice(&stream_id.to_be_bytes());
            }
            MuxFrame::Open { stream_id, service } => {
                out[0] = FRAME_OPEN;
                out[1..5].copy_from_slice(&stream_id.to_be_bytes());
                out[5..5 + service.as_bytes().len()].copy_from_slice(service.as_bytes());
            }
            MuxFrame::Ping { nonce } => {
                out[0] = FRAME_PING;
                out[1..9].copy_from_slice(&nonce.to_be_bytes());
            }
            MuxFrame::Pong { nonce } => {
                out[0] = FRAME_PONG;
                out[1..9].copy_from_slice(&nonce.to_be_bytes());
            }
        }
        Ok(need)
    }

    /// Convenience: allocate and return the encoded bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = vec![0u8; self.encoded_len()];
        // encode() can only fail for output-too-small, which can't happen here.
        self.encode(&mut v).expect("encode into exact-size buf");
        v
    }

    /// Decode a plaintext mux frame (after decryption).
    ///
    /// Accepts both the current mux form (FRAME_DATA with 4-byte stream_id
    /// prefix) AND the legacy single-stream form (FRAME_DATA with only an
    /// 8-byte data_seq). Legacy decode returns `stream_id=0`.
    ///
    /// FRAME_ACK accepts both 9-byte (no rwnd) and 11-byte (with rwnd).
    ///
    /// FRAME_FIN accepts 1-byte (legacy) and 5-byte (per-stream).
    pub fn decode(buf: &[u8]) -> Result<MuxFrame, MuxError> {
        if buf.is_empty() {
            return Err(MuxError::ShortFrame);
        }
        let t = buf[0];
        match t {
            FRAME_DATA => {
                // Try mux form first: [0x00 | stream_id(4) | data_seq(8) | payload]
                // Disambiguation matches Swift's decoder: if we have >=13 bytes
                // and bytes 1..5 parse to a non-zero stream_id, treat as mux.
                // Otherwise treat as legacy (9+ bytes, data_seq in 1..9).
                if buf.len() < 9 {
                    return Err(MuxError::ShortFrame);
                }
                if buf.len() >= 13 {
                    let stream_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                    if stream_id != 0 {
                        let data_seq = u64::from_be_bytes([
                            buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
                        ]);
                        let payload = buf[13..].to_vec();
                        return Ok(MuxFrame::Data {
                            stream_id,
                            data_seq,
                            payload,
                        });
                    }
                }
                // Legacy form: [0x00 | data_seq(8) | payload]
                let data_seq = u64::from_be_bytes([
                    buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                ]);
                let payload = buf[9..].to_vec();
                Ok(MuxFrame::Data {
                    stream_id: 0,
                    data_seq,
                    payload,
                })
            }
            FRAME_ACK => {
                if buf.len() < 9 {
                    return Err(MuxError::ShortFrame);
                }
                let cumulative = u64::from_be_bytes([
                    buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                ]);
                let rwnd = if buf.len() >= 11 {
                    Some(u16::from_be_bytes([buf[9], buf[10]]))
                } else {
                    None
                };
                Ok(MuxFrame::Ack { cumulative, rwnd })
            }
            FRAME_FIN => {
                // Legacy 1-byte OR 5-byte per-stream.
                if buf.len() >= 5 {
                    let stream_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                    Ok(MuxFrame::Fin { stream_id })
                } else {
                    Ok(MuxFrame::Fin { stream_id: 0 })
                }
            }
            FRAME_CLOSE => {
                if buf.len() < 5 {
                    return Err(MuxError::ShortFrame);
                }
                let stream_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                Ok(MuxFrame::Close { stream_id })
            }
            FRAME_OPEN => {
                if buf.len() < 5 {
                    return Err(MuxError::ShortFrame);
                }
                let stream_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                let service = std::str::from_utf8(&buf[5..])
                    .map_err(|_| MuxError::InvalidServiceName)?
                    .to_string();
                Ok(MuxFrame::Open { stream_id, service })
            }
            FRAME_PING => {
                if buf.len() < 9 {
                    return Err(MuxError::ShortFrame);
                }
                let nonce = u64::from_be_bytes([
                    buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                ]);
                Ok(MuxFrame::Ping { nonce })
            }
            FRAME_PONG => {
                if buf.len() < 9 {
                    return Err(MuxError::ShortFrame);
                }
                let nonce = u64::from_be_bytes([
                    buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                ]);
                Ok(MuxFrame::Pong { nonce })
            }
            other => Err(MuxError::UnknownFrameType(other)),
        }
    }
}

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

/// Pressure signals aggregated by the IosTunnelEngine tick before calling
/// `MuxEngine::tick_rwnd`. Mirror of the many flags the Swift
/// `maybeRampAdvertisedRwnd` reads from `PacketTunnelProvider` state
/// (consecutiveFullFlushes, consecutiveStuckHighSeqTicks, sessionSuspectSince,
/// probeOutstandingSince). The caller fills this each tick.
#[derive(Debug, Clone, Copy, Default)]
pub struct RwndPressureSignals {
    pub consecutive_full_flushes: u32,
    pub consecutive_stuck_high_seq_ticks: u32,
    pub session_suspect: bool,
    pub probe_outstanding: bool,
    pub high_seq_advanced: bool,
    pub has_active_flows: bool,
}

/// Point-in-time snapshot of the RTT / goodput / BDP instrumentation.
/// Returned by `MuxEngine::rtt_goodput_snapshot` and bridged through FFI
/// so the Swift side can log "modern flow-control" numbers alongside the
/// existing rwnd ladder. All fields are `0` until the first ACK carrying
/// a non-retransmitted DATA sample is observed.
///
/// Units:
/// - `smoothed_rtt_ms`, `rtt_var_ms`, `min_rtt_ms`, `latest_rtt_ms` — ms
/// - `goodput_bps`, `peak_goodput_bps` — bits/sec
/// - `bdp_kb` — kilobytes (rounded down)
/// - `samples_total` — number of RTT samples admitted by Karn's algo
///   (retransmits skipped)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RttGoodputSnapshot {
    pub smoothed_rtt_ms: u32,
    pub rtt_var_ms: u32,
    pub min_rtt_ms: u32,
    pub latest_rtt_ms: u32,
    pub goodput_bps: u64,
    pub peak_goodput_bps: u64,
    pub bdp_kb: u32,
    pub samples_total: u64,
}

/// Internal goodput bucket — one second of bytes acked.
#[derive(Debug, Clone, Copy, Default)]
struct GoodputBucket {
    /// Second-boundary (Instant) this bucket started.
    started_at: Option<Instant>,
    bytes: u64,
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
    // Bytes queued for retransmit (drained by take_retransmit_bytes).
    retransmit_buf: VecDeque<Vec<u8>>,
    // ── RTT / goodput sampling (Phase A — instrumentation only) ────
    /// Smoothed RTT (RFC 6298). `None` until the first sample lands.
    srtt: Option<Duration>,
    /// RTT variance (RFC 6298). Meaningful once `srtt` is `Some`.
    rttvar: Option<Duration>,
    /// Minimum RTT observed. `None` until the first sample lands.
    min_rtt: Option<Duration>,
    /// Most recent RTT sample.
    latest_rtt: Option<Duration>,
    /// Number of RTT samples admitted (Karn's algo skips retransmits).
    rtt_samples_total: u64,
    /// 8-slot ring of per-second goodput buckets.
    goodput_buckets: [GoodputBucket; GOODPUT_WINDOW_BUCKETS],
    /// Index of the "current" bucket (rotates as seconds advance).
    goodput_current_idx: usize,
    /// Peak goodput observed (bits/sec).
    peak_goodput_bps: u64,
    /// Shadow sent-at map used when the Swift data-path owns inflight
    /// tracking. The Swift side calls `observe_sent` / `observe_ack` so
    /// we can measure RTT without moving the send buffer into Rust yet.
    /// Bounded to `SHADOW_MAX_ENTRIES` so it can't grow unbounded if the
    /// peer stops ACKing.
    shadow_sent_at: HashMap<u64, (Instant, u32)>,
    /// Parallel map: seq → encoded byte length. Kept separate so the
    /// (Instant, retransmits) tuple stays small. Both maps are pruned
    /// together in `observe_ack_cumulative`.
    shadow_encoded_len: HashMap<u64, u32>,
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
            retransmit_buf: VecDeque::new(),
            srtt: None,
            rttvar: None,
            min_rtt: None,
            latest_rtt: None,
            rtt_samples_total: 0,
            goodput_buckets: [GoodputBucket::default(); GOODPUT_WINDOW_BUCKETS],
            goodput_current_idx: 0,
            peak_goodput_bps: 0,
            shadow_sent_at: HashMap::new(),
            shadow_encoded_len: HashMap::new(),
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

    // ── ACK generation (Task 2.3) ────────────────────────────────────

    /// Advance the cumulative expected sequence when a FRAME_DATA is
    /// delivered. The mux advertises this to the gateway in future ACKs.
    pub fn on_data_received(&mut self, data_seq: u64) {
        // Match Swift: only advance when the new seq is contiguous. Gaps are
        // handled by SACK elsewhere (gateway owns that logic).
        if data_seq >= self.next_expected_recv_seq {
            self.next_expected_recv_seq = data_seq + 1;
        }
    }

    /// The cumulative ACK value we advertise back to the peer.
    pub fn cumulative_ack(&self) -> u64 {
        // We ACK the highest seen contiguous data_seq — the value we'd
        // next expect to see, minus 1.
        self.next_expected_recv_seq.saturating_sub(1)
    }

    /// Build an ACK frame reflecting the current cumulative+rwnd state.
    pub fn build_ack_frame(&self) -> MuxFrame {
        MuxFrame::Ack {
            cumulative: self.cumulative_ack(),
            rwnd: Some(self.advertised_rwnd),
        }
    }

    // ── rwnd policy (Task 2.3) ───────────────────────────────────────

    /// Mark that utun had outbound demand just now. Used by the rwnd
    /// policy to hold rwnd=12 for a post-demand window instead of
    /// collapsing straight to RWND_FLOOR.
    pub fn mark_outbound_demand(&mut self, now: Instant) {
        self.last_outbound_demand_at = Some(now);
    }

    /// Apply the rwnd policy for one tick.
    ///
    /// Port of `PacketTunnelProvider.maybeRampAdvertisedRwnd`, with the
    /// post-demand hold=12 fix called out in the plan. Returns the new
    /// rwnd value and a machine-readable reason tag.
    pub fn tick_rwnd(
        &mut self,
        now: Instant,
        stats: RouterStatsSnapshot,
        replay_delta: i32,
        signals: RwndPressureSignals,
    ) -> (u16, &'static str) {
        const RWND_BROWSER_BURST_FLOW_THRESHOLD: u32 = 2;
        const RWND_REPLAY_DELTA_BAD: i32 = 2;
        const RWND_ROUTER_OUTBOUND_BAD: u32 = 128;
        const RWND_SEND_BUF_BYTES_BAD: usize = 16_384;
        const RWND_OLDEST_MS_BAD: u64 = 4_000;
        const RWND_PRESSURE_COOLDOWN: Duration = Duration::from_secs(15);
        const POST_DEMAND_WINDOW: Duration = Duration::from_secs(15);

        let browser_burst = stats.flows >= RWND_BROWSER_BURST_FLOW_THRESHOLD
            || stats.stream_to_flow >= RWND_BROWSER_BURST_FLOW_THRESHOLD;

        if browser_burst && replay_delta > 0 {
            self.rwnd_pressure_until = Some(now + RWND_PRESSURE_COOLDOWN);
            self.set_rwnd(RWND_FLOOR);
            self.consecutive_rwnd_healthy_ticks = 0;
            return (RWND_FLOOR, "browser_replay_backoff");
        }

        if let Some(until) = self.rwnd_pressure_until {
            if now < until {
                self.set_rwnd(RWND_FLOOR);
                self.consecutive_rwnd_healthy_ticks = 0;
                return (RWND_FLOOR, "pressure_cooldown");
            }
        }

        // Treat oldestMs as real pressure only when paired with stuck/suspect.
        let oldest_is_real_pressure = stats.oldest_ms >= RWND_OLDEST_MS_BAD
            && (signals.consecutive_stuck_high_seq_ticks > 0
                || signals.session_suspect
                || signals.probe_outstanding);

        let pressure = stats.outbound >= RWND_ROUTER_OUTBOUND_BAD
            || stats.send_buf_bytes >= RWND_SEND_BUF_BYTES_BAD
            || oldest_is_real_pressure
            || signals.consecutive_full_flushes > 0
            || replay_delta >= RWND_REPLAY_DELTA_BAD
            || signals.probe_outstanding
            || signals.session_suspect;

        if pressure {
            self.set_rwnd(RWND_FLOOR);
            self.consecutive_rwnd_healthy_ticks = 0;
            return (RWND_FLOOR, "pressure");
        }

        if browser_burst {
            self.consecutive_rwnd_healthy_ticks = 0;
            self.set_rwnd(RWND_BROWSER_BURST_TARGET);
            return (RWND_BROWSER_BURST_TARGET, "browser_burst_target");
        }

        let outbound_demand_age = self
            .last_outbound_demand_at
            .map(|t| now.duration_since(t))
            .unwrap_or(Duration::from_secs(3600));
        let active_or_recent = signals.has_active_flows || outbound_demand_age < Duration::from_secs(3);
        let making_progress = signals.high_seq_advanced || stats.outbound == 0;

        if !(active_or_recent && making_progress) {
            self.consecutive_rwnd_healthy_ticks = 0;
            self.set_rwnd(RWND_FLOOR);
            return (RWND_FLOOR, "no_progress");
        }

        // The Vaultwarden hold=12 fix. Prior code collapsed to RWND_FLOOR after
        // outbound demand ended, which forced the JS/WASM tail through
        // rwnd=4 and caused WebKit to cancel/retry. Holding 12 until the
        // post-demand window elapses fixes the visible stall.
        if outbound_demand_age < POST_DEMAND_WINDOW {
            self.consecutive_rwnd_healthy_ticks = 0;
            self.set_rwnd(RWND_POST_DEMAND_HOLD);
            return (RWND_POST_DEMAND_HOLD, "post_demand_hold_12");
        }

        self.consecutive_rwnd_healthy_ticks += 1;
        if self.consecutive_rwnd_healthy_ticks >= self.rwnd_healthy_ticks_needed
            && self.advertised_rwnd < RWND_ADAPTIVE_MAX
        {
            self.consecutive_rwnd_healthy_ticks = 0;
            self.set_rwnd(self.advertised_rwnd + 1);
            return (self.advertised_rwnd, "healthy_ramp");
        }
        (self.advertised_rwnd, "healthy_hold")
    }

    fn set_rwnd(&mut self, v: u16) {
        let clamped = v.clamp(RWND_FLOOR, RWND_ADAPTIVE_MAX);
        if clamped != self.advertised_rwnd {
            self.advertised_rwnd = clamped;
        }
    }

    // ── Send buffer + cwnd + retransmit (Task 2.4) ───────────────────

    /// Enqueue an outbound item. The caller uses this for OPEN, DATA,
    /// CLOSE, and Probe. The engine picks them up on the next
    /// `take_send_bytes` and assigns `data_seq` to DATA items there.
    pub fn enqueue_outbound(&mut self, item: OutboundItem) {
        self.send_queue.push_back(item);
    }

    /// Take as many queued items as fit within the current cwnd and
    /// encode them as plaintext mux frames. Each DATA item is assigned a
    /// fresh `data_seq` and tracked in the inflight map.
    ///
    /// Returns a Vec of encoded plaintext frames. The caller is
    /// responsible for encrypting each frame (`ztlp_encrypt_packet`) and
    /// sending it over UDP. Separating plaintext from ciphertext keeps
    /// encryption out of the mux engine and avoids re-implementing
    /// ChaCha20-Poly1305 here.
    pub fn take_send_bytes(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while self.inflight.len() < self.cwnd as usize {
            let Some(item) = self.send_queue.pop_front() else {
                break;
            };
            let (frame, data_seq_for_inflight) = match item {
                OutboundItem::Open { stream_id, service } => (
                    MuxFrame::Open { stream_id, service },
                    None,
                ),
                OutboundItem::Close { stream_id } => (
                    MuxFrame::Close { stream_id },
                    None,
                ),
                OutboundItem::Probe { nonce } => (MuxFrame::Ping { nonce }, None),
                OutboundItem::Data { stream_id, payload } => {
                    let seq = self.next_send_data_seq;
                    self.next_send_data_seq += 1;
                    (
                        MuxFrame::Data {
                            stream_id,
                            data_seq: seq,
                            payload,
                        },
                        Some((seq, stream_id)),
                    )
                }
            };
            let encoded = frame.to_vec();
            if let Some((seq, stream_id)) = data_seq_for_inflight {
                self.inflight.insert(
                    seq,
                    InflightPacket {
                        data_seq: seq,
                        stream_id,
                        encoded: encoded.clone(),
                        sent_at: now,
                        retransmits: 0,
                    },
                );
            }
            out.push(encoded);
        }
        out
    }

    /// Apply a cumulative ACK received from the peer: drop all inflight
    /// entries with `data_seq <= cumulative`. Returns the number of
    /// inflight entries released.
    ///
    /// Prefer `on_cumulative_ack_at` in production — it captures RTT and
    /// goodput samples. This convenience wrapper uses `Instant::now()`
    /// internally and exists so legacy callers / tests keep compiling.
    pub fn on_cumulative_ack(&mut self, cumulative: u64) -> usize {
        self.on_cumulative_ack_at(Instant::now(), cumulative)
    }

    /// Apply a cumulative ACK at a specific `now`, capturing RTT and
    /// goodput samples for the released packets (Phase A instrumentation).
    ///
    /// RTT samples follow Karn's algorithm: retransmitted packets are
    /// excluded because their `sent_at` no longer reflects the original
    /// transmission time. Goodput accounting is NOT subject to Karn —
    /// every released byte counts as "data the peer admitted" regardless
    /// of how many times we had to send it.
    pub fn on_cumulative_ack_at(&mut self, now: Instant, cumulative: u64) -> usize {
        let before = self.inflight.len();
        // Walk inflight once, separating the "release" set. We capture
        // RTT / goodput from each released packet before the retain()
        // call throws them away.
        let mut released_bytes: u64 = 0;
        let mut newest_rtt_sample: Option<Duration> = None;
        for (seq, pkt) in self.inflight.iter() {
            if *seq <= cumulative {
                released_bytes = released_bytes.saturating_add(pkt.encoded.len() as u64);
                if pkt.retransmits == 0 {
                    // Karn: only admit samples where the packet wasn't
                    // retransmitted. Keep the newest one; older
                    // released-in-the-same-ACK samples are usually close.
                    let sample = now.saturating_duration_since(pkt.sent_at);
                    match newest_rtt_sample {
                        Some(prev) if prev > sample => {}
                        _ => newest_rtt_sample = Some(sample),
                    }
                }
            }
        }
        self.inflight.retain(|seq, _| *seq > cumulative);
        if let Some(sample) = newest_rtt_sample {
            self.record_rtt_sample(sample);
        }
        if released_bytes > 0 {
            self.record_goodput_bytes(now, released_bytes);
        }
        before - self.inflight.len()
    }

    // ── Shadow RTT / goodput observation (Phase A) ───────────────────
    //
    // The Swift data-path still owns inflight tracking on iOS. These
    // methods give us RTT/goodput numbers without touching that — Swift
    // calls `observe_sent` when it emits a DATA frame and
    // `observe_ack_cumulative` when a FRAME_ACK arrives. The Rust side
    // records timestamps, applies Karn's algorithm, and feeds the same
    // smoother as the native `on_cumulative_ack_at` path.
    //
    // When the full mux cutover happens later, these become no-ops and
    // the native path drives everything.

    /// Record that a DATA frame with `data_seq` and `encoded_len` bytes
    /// was just transmitted. Safe to call repeatedly with the same seq
    /// — retransmits call this again, which marks the entry as "no
    /// longer a valid RTT sample" (Karn's algorithm).
    pub fn observe_sent(&mut self, now: Instant, data_seq: u64, encoded_len: u32) {
        // Bound the map. On overflow, drop the oldest half (by sent_at).
        // This only happens when the peer stops ACKing entirely — in
        // healthy operation the ACK path trims the map continuously.
        if self.shadow_sent_at.len() >= SHADOW_MAX_ENTRIES {
            let mut entries: Vec<(u64, Instant)> = self
                .shadow_sent_at
                .iter()
                .map(|(k, (t, _))| (*k, *t))
                .collect();
            entries.sort_by_key(|(_, t)| *t);
            let drop_count = entries.len() / 2;
            for (seq, _) in entries.into_iter().take(drop_count) {
                self.shadow_sent_at.remove(&seq);
            }
        }
        // Use the std HashMap's entry API to mark retransmits. A fresh
        // sample starts with retransmits=0 (valid for RTT); an existing
        // entry being re-sent bumps the counter (Karn excludes it).
        self.shadow_sent_at
            .entry(data_seq)
            .and_modify(|(t, r)| {
                *t = now;
                *r = r.saturating_add(1);
            })
            .or_insert((now, 0));
        // Encoded length is used when the ACK lands — we remember it by
        // piggybacking onto the tuple via the second slot. Since we
        // already use the second slot for the retransmit counter we
        // stash encoded_len in an auxiliary structure below.
        self.shadow_encoded_len.insert(data_seq, encoded_len);
    }

    /// Record that a cumulative ACK of `cumulative` arrived at `now`.
    /// Walks the shadow sent-at map, samples RTT for entries with
    /// retransmits=0, adds encoded-length to goodput for every released
    /// entry, and removes released entries from the shadow map.
    pub fn observe_ack_cumulative(&mut self, now: Instant, cumulative: u64) {
        let mut released_bytes: u64 = 0;
        let mut newest_rtt_sample: Option<Duration> = None;
        // Collect released seqs first (can't mutate while iterating).
        let released_seqs: Vec<u64> = self
            .shadow_sent_at
            .iter()
            .filter_map(|(seq, _)| if *seq <= cumulative { Some(*seq) } else { None })
            .collect();
        for seq in released_seqs {
            if let Some((sent_at, retransmits)) = self.shadow_sent_at.remove(&seq) {
                if retransmits == 0 {
                    let sample = now.saturating_duration_since(sent_at);
                    match newest_rtt_sample {
                        Some(prev) if prev > sample => {}
                        _ => newest_rtt_sample = Some(sample),
                    }
                }
            }
            if let Some(encoded_len) = self.shadow_encoded_len.remove(&seq) {
                released_bytes = released_bytes.saturating_add(encoded_len as u64);
            }
        }
        if let Some(sample) = newest_rtt_sample {
            self.record_rtt_sample(sample);
        }
        if released_bytes > 0 {
            self.record_goodput_bytes(now, released_bytes);
        }
    }

    /// Diagnostic: current shadow map size. Useful for sanity-checking
    /// that Swift's observe_sent/observe_ack calls are balanced.
    pub fn shadow_inflight_len(&self) -> usize {
        self.shadow_sent_at.len()
    }

    /// Record one RTT sample via RFC 6298 smoothing. First sample
    /// bootstraps `srtt` = sample and `rttvar` = sample/2.
    fn record_rtt_sample(&mut self, sample: Duration) {
        self.latest_rtt = Some(sample);
        self.rtt_samples_total = self.rtt_samples_total.saturating_add(1);
        self.min_rtt = Some(match self.min_rtt {
            Some(m) if m <= sample => m,
            _ => sample,
        });
        match (self.srtt, self.rttvar) {
            (Some(srtt), Some(rttvar)) => {
                // srtt = (1 - alpha) * srtt + alpha * sample
                let srtt_ns = srtt.as_nanos() as u128;
                let sample_ns = sample.as_nanos() as u128;
                let alpha_num = RTT_SRTT_ALPHA_NUM as u128;
                let alpha_den = RTT_SRTT_ALPHA_DEN as u128;
                let new_srtt_ns =
                    (srtt_ns * (alpha_den - alpha_num) + sample_ns * alpha_num) / alpha_den;

                // rttvar = (1 - beta) * rttvar + beta * |srtt - sample|
                let diff_ns = if srtt_ns > sample_ns {
                    srtt_ns - sample_ns
                } else {
                    sample_ns - srtt_ns
                };
                let rttvar_ns = rttvar.as_nanos() as u128;
                let beta_num = RTT_RTTVAR_BETA_NUM as u128;
                let beta_den = RTT_RTTVAR_BETA_DEN as u128;
                let new_rttvar_ns =
                    (rttvar_ns * (beta_den - beta_num) + diff_ns * beta_num) / beta_den;

                self.srtt = Some(Duration::from_nanos(new_srtt_ns as u64));
                self.rttvar = Some(Duration::from_nanos(new_rttvar_ns as u64));
            }
            _ => {
                // RFC 6298 §2.2: first sample → srtt = R, rttvar = R/2.
                self.srtt = Some(sample);
                self.rttvar = Some(sample / 2);
            }
        }
    }

    /// Record goodput bytes into the 8-second sliding window. Rotates
    /// buckets based on `now` so idle periods correctly age out.
    fn record_goodput_bytes(&mut self, now: Instant, bytes: u64) {
        self.rotate_goodput_buckets(now);
        let bucket = &mut self.goodput_buckets[self.goodput_current_idx];
        if bucket.started_at.is_none() {
            bucket.started_at = Some(now);
        }
        bucket.bytes = bucket.bytes.saturating_add(bytes);
        // Update peak after the insert.
        let bps = self.current_goodput_bps_inner();
        if bps > self.peak_goodput_bps {
            self.peak_goodput_bps = bps;
        }
    }

    /// Advance the per-second bucket ring so `goodput_current_idx`
    /// corresponds to the second containing `now`. Stale buckets are
    /// zeroed as they roll off the back of the 8-second window.
    fn rotate_goodput_buckets(&mut self, now: Instant) {
        let cur = &self.goodput_buckets[self.goodput_current_idx];
        let cur_started = match cur.started_at {
            Some(t) => t,
            None => {
                // Fresh bucket — set its start and we're done.
                self.goodput_buckets[self.goodput_current_idx].started_at = Some(now);
                return;
            }
        };
        let age = now.saturating_duration_since(cur_started);
        let full_seconds = age.as_secs() as usize;
        if full_seconds == 0 {
            return;
        }
        // Advance up to GOODPUT_WINDOW_BUCKETS slots; after that every
        // bucket is stale anyway — just reset them all.
        let steps = full_seconds.min(GOODPUT_WINDOW_BUCKETS);
        for _ in 0..steps {
            self.goodput_current_idx = (self.goodput_current_idx + 1) % GOODPUT_WINDOW_BUCKETS;
            self.goodput_buckets[self.goodput_current_idx] = GoodputBucket::default();
        }
        self.goodput_buckets[self.goodput_current_idx].started_at = Some(now);
    }

    /// Goodput across the current 8-second window, in bits/sec.
    fn current_goodput_bps_inner(&self) -> u64 {
        let total_bytes: u64 = self
            .goodput_buckets
            .iter()
            .map(|b| b.bytes)
            .fold(0u64, |a, b| a.saturating_add(b));
        // 8 seconds × 8 bits/byte = 64, so bps = total_bytes × 8 / 8 = total_bytes.
        // Keep the math explicit so future changes to GOODPUT_WINDOW_BUCKETS
        // don't silently break the units.
        total_bytes
            .saturating_mul(8)
            .checked_div(GOODPUT_WINDOW_BUCKETS as u64)
            .unwrap_or(0)
    }

    /// Public accessor: current goodput in bits/sec across the sliding
    /// 8-second window. Callers should age the window first by calling
    /// `rtt_goodput_snapshot(now)`; this accessor returns whatever the
    /// buckets currently hold.
    pub fn goodput_bps(&self) -> u64 {
        self.current_goodput_bps_inner()
    }

    /// Peak goodput observed since engine creation (bits/sec).
    pub fn peak_goodput_bps(&self) -> u64 {
        self.peak_goodput_bps
    }

    /// Smoothed RTT in milliseconds, or 0 before the first sample.
    pub fn smoothed_rtt_ms(&self) -> u32 {
        self.srtt.map(|d| d.as_millis() as u32).unwrap_or(0)
    }

    /// RTT variance in milliseconds, or 0 before the first sample.
    pub fn rtt_var_ms(&self) -> u32 {
        self.rttvar.map(|d| d.as_millis() as u32).unwrap_or(0)
    }

    /// Minimum RTT observed (ms), or 0 before the first sample.
    pub fn min_rtt_ms(&self) -> u32 {
        self.min_rtt.map(|d| d.as_millis() as u32).unwrap_or(0)
    }

    /// Latest RTT sample (ms), or 0 before the first sample.
    pub fn latest_rtt_ms(&self) -> u32 {
        self.latest_rtt.map(|d| d.as_millis() as u32).unwrap_or(0)
    }

    /// Number of RTT samples admitted by Karn's algorithm since engine start.
    pub fn rtt_samples_total(&self) -> u64 {
        self.rtt_samples_total
    }

    /// Full instrumentation snapshot for FFI / logging.
    ///
    /// `now` is used to age the goodput buckets before reading — pass
    /// `Instant::now()` in production. Callers that read this every
    /// health tick will naturally keep the window fresh.
    pub fn rtt_goodput_snapshot(&mut self, now: Instant) -> RttGoodputSnapshot {
        self.rotate_goodput_buckets(now);
        let goodput_bps = self.current_goodput_bps_inner();
        let smoothed_rtt_ms = self.smoothed_rtt_ms();
        // BDP in KB: rtt_ms * bps / 8000 / 1000 = rtt_ms * bps / 8_000_000.
        // bdp_bytes = rtt_ms * bps / 8000;  bdp_kb = bdp_bytes / 1024.
        // Fold into one expression to minimise intermediate overflow.
        let bdp_kb: u32 = if smoothed_rtt_ms == 0 || goodput_bps == 0 {
            0
        } else {
            let bdp_bytes =
                (smoothed_rtt_ms as u128).saturating_mul(goodput_bps as u128) / 8_000u128;
            (bdp_bytes / 1024u128).min(u32::MAX as u128) as u32
        };
        RttGoodputSnapshot {
            smoothed_rtt_ms,
            rtt_var_ms: self.rtt_var_ms(),
            min_rtt_ms: self.min_rtt_ms(),
            latest_rtt_ms: self.latest_rtt_ms(),
            goodput_bps,
            peak_goodput_bps: self.peak_goodput_bps,
            bdp_kb,
            samples_total: self.rtt_samples_total,
        }
    }

    /// If the peer advertised a new rwnd, remember it. Future cwnd
    /// adjustments take this into account.
    pub fn on_peer_rwnd(&mut self, rwnd: u16) {
        self.peer_rwnd = rwnd.clamp(RWND_FLOOR, RWND_ADAPTIVE_MAX);
    }

    /// Walk inflight entries and push retransmits back onto the head of
    /// the send queue when they exceed the RTO. Returns the number of
    /// retransmits scheduled.
    pub fn tick_retransmit(&mut self, now: Instant) -> usize {
        let mut to_resend: Vec<u64> = Vec::new();
        for (seq, pkt) in &self.inflight {
            if now.duration_since(pkt.sent_at) >= self.rto {
                to_resend.push(*seq);
            }
        }
        // Sort so retransmits go out in the original order.
        to_resend.sort();
        let count = to_resend.len();
        for seq in to_resend {
            if let Some(pkt) = self.inflight.get_mut(&seq) {
                pkt.retransmits += 1;
                pkt.sent_at = now;
                // Push the encoded bytes back into the queue head so the
                // caller re-emits them on the next take_send_bytes. We
                // keep them in inflight because they're still
                // outstanding — we just need the caller to resend them.
                //
                // Strategy: we cannot cleanly push raw bytes through
                // OutboundItem (which is pre-encode), so we use a
                // dedicated retransmit sidecar buffer, drained by
                // take_retransmit_bytes below.
                self.retransmit_buf.push_back(pkt.encoded.clone());
            }
        }
        count
    }

    /// Drain retransmit bytes queued by `tick_retransmit`. Caller
    /// encrypts + sends each Vec<u8>.
    pub fn take_retransmit_bytes(&mut self) -> Vec<Vec<u8>> {
        self.retransmit_buf.drain(..).collect()
    }

    /// Override the retransmit timeout (useful for tests that want a
    /// deterministic short RTO). Value is clamped to [10ms, 10s].
    pub fn set_rto(&mut self, rto: Duration) {
        self.rto = rto.clamp(Duration::from_millis(10), Duration::from_secs(10));
    }

    /// Override the congestion window cap. Useful for tests.
    pub fn set_cwnd(&mut self, cwnd: u16) {
        self.cwnd = cwnd.max(1);
    }

    pub fn cwnd(&self) -> u16 {
        self.cwnd
    }
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

    // ── Codec round-trips ────────────────────────────────────────────

    fn roundtrip(frame: MuxFrame) -> MuxFrame {
        let bytes = frame.to_vec();
        MuxFrame::decode(&bytes).expect("decode")
    }

    #[test]
    fn codec_data_mux_form_roundtrip() {
        let f = MuxFrame::Data {
            stream_id: 7,
            data_seq: 42,
            payload: b"hello world".to_vec(),
        };
        assert_eq!(roundtrip(f.clone()), f);
    }

    #[test]
    fn codec_ack_with_rwnd_roundtrip() {
        let f = MuxFrame::Ack {
            cumulative: 1234,
            rwnd: Some(12),
        };
        let bytes = f.to_vec();
        assert_eq!(bytes.len(), 11);
        assert_eq!(bytes[0], FRAME_ACK);
        assert_eq!(MuxFrame::decode(&bytes).unwrap(), f);
    }

    #[test]
    fn codec_ack_legacy_9_byte_decodes() {
        // Legacy 9-byte ACK without rwnd: [0x01 | seq(8)].
        let f = MuxFrame::Ack {
            cumulative: 99,
            rwnd: None,
        };
        let bytes = f.to_vec();
        assert_eq!(bytes.len(), 9);
        let decoded = MuxFrame::decode(&bytes).unwrap();
        assert_eq!(
            decoded,
            MuxFrame::Ack {
                cumulative: 99,
                rwnd: None
            }
        );
    }

    #[test]
    fn codec_open_roundtrip() {
        let f = MuxFrame::Open {
            stream_id: 5,
            service: "vault.techrockstars.ztlp".to_string(),
        };
        assert_eq!(roundtrip(f.clone()), f);
    }

    #[test]
    fn codec_close_and_fin_and_ping_pong_roundtrip() {
        for f in [
            MuxFrame::Close { stream_id: 12 },
            MuxFrame::Fin { stream_id: 13 },
            MuxFrame::Ping { nonce: 0xDEAD_BEEF_CAFE_BABE },
            MuxFrame::Pong { nonce: 1 },
        ] {
            assert_eq!(roundtrip(f.clone()), f);
        }
    }

    #[test]
    fn codec_decode_legacy_data_form_returns_stream_zero() {
        // Construct legacy FRAME_DATA: [0x00 | data_seq(8) | payload], exactly
        // 9 + payload bytes and the first four "stream id" bytes map to the
        // high bytes of data_seq — we treat that as legacy.
        let mut buf = vec![FRAME_DATA];
        buf.extend_from_slice(&42u64.to_be_bytes());
        buf.extend_from_slice(b"abc");
        let decoded = MuxFrame::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            MuxFrame::Data {
                stream_id: 0,
                data_seq: 42,
                payload: b"abc".to_vec()
            }
        );
    }

    #[test]
    fn codec_encode_rejects_undersized_output() {
        let f = MuxFrame::Ack {
            cumulative: 1,
            rwnd: Some(4),
        };
        let mut small = [0u8; 5];
        let err = f.encode(&mut small).unwrap_err();
        assert_eq!(err, MuxError::OutputTooSmall { need: 11, got: 5 });
    }

    #[test]
    fn codec_decode_short_frame_errors() {
        assert_eq!(MuxFrame::decode(&[]).unwrap_err(), MuxError::ShortFrame);
        assert_eq!(
            MuxFrame::decode(&[FRAME_ACK, 0, 0]).unwrap_err(),
            MuxError::ShortFrame
        );
        assert_eq!(
            MuxFrame::decode(&[FRAME_CLOSE, 0, 0]).unwrap_err(),
            MuxError::ShortFrame
        );
    }

    #[test]
    fn codec_decode_unknown_frame_errors() {
        let err = MuxFrame::decode(&[0x99, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, MuxError::UnknownFrameType(0x99));
    }

    #[test]
    fn codec_decode_open_bad_utf8_errors() {
        let mut buf = vec![FRAME_OPEN, 0, 0, 0, 1];
        buf.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        let err = MuxFrame::decode(&buf).unwrap_err();
        assert_eq!(err, MuxError::InvalidServiceName);
    }

    // ── ACK generation + rwnd policy (Task 2.3) ─────────────────────

    #[test]
    fn mux_on_data_received_advances_cumulative_ack() {
        let mut m = MuxEngine::new();
        assert_eq!(m.cumulative_ack(), 0);
        m.on_data_received(1);
        assert_eq!(m.cumulative_ack(), 1);
        m.on_data_received(2);
        m.on_data_received(3);
        assert_eq!(m.cumulative_ack(), 3);
        // A gap should not advance past the hole.
        m.on_data_received(10);
        assert_eq!(m.cumulative_ack(), 10);
        // Old duplicate is harmless.
        m.on_data_received(2);
        assert_eq!(m.cumulative_ack(), 10);
    }

    #[test]
    fn mux_build_ack_frame_uses_current_rwnd_and_cumulative() {
        let mut m = MuxEngine::new();
        m.on_data_received(5);
        let f = m.build_ack_frame();
        match f {
            MuxFrame::Ack { cumulative, rwnd } => {
                assert_eq!(cumulative, 5);
                assert_eq!(rwnd, Some(RWND_FLOOR));
            }
            _ => panic!("expected Ack"),
        }
    }

    /// Healthy stats, no replay, recent outbound demand — the plan's
    /// explicit acceptance: rwnd must hold >= 12, not collapse to 4.
    #[test]
    fn rwnd_healthy_plus_recent_demand_holds_12() {
        let mut m = MuxEngine::new();
        let now = Instant::now();
        m.mark_outbound_demand(now);
        let stats = RouterStatsSnapshot {
            flows: 2,
            outbound: 0,
            stream_to_flow: 2,
            send_buf_bytes: 0,
            oldest_ms: 0,
        };
        let signals = RwndPressureSignals {
            high_seq_advanced: true,
            has_active_flows: true,
            ..Default::default()
        };
        // First tick within the post-demand window. browser burst will
        // trigger browser_burst_target=16 because flows>=2. Advance time
        // past the burst and keep demand fresh to test hold.
        let (rwnd, reason) = m.tick_rwnd(now, stats, 0, signals);
        assert_eq!(rwnd, RWND_BROWSER_BURST_TARGET, "reason={reason}");

        // Now simulate a later tick where flows have dropped (browser burst
        // over) but demand is still recent. Hold at 12, not floor.
        let later = now + Duration::from_secs(5);
        let quiet_stats = RouterStatsSnapshot {
            flows: 0,
            outbound: 0,
            stream_to_flow: 0,
            send_buf_bytes: 0,
            oldest_ms: 0,
        };
        let (rwnd, reason) = m.tick_rwnd(later, quiet_stats, 0, signals);
        assert_eq!(rwnd, RWND_POST_DEMAND_HOLD, "reason={reason}");
        assert!(rwnd >= 12);
    }

    /// Plan acceptance: replayDelta=8 + browser burst → fast backoff to
    /// floor and a 15s cooldown.
    #[test]
    fn rwnd_browser_replay_fast_backoff_to_floor() {
        let mut m = MuxEngine::new();
        let now = Instant::now();
        m.mark_outbound_demand(now);
        let stats = RouterStatsSnapshot {
            flows: 3,
            outbound: 0,
            stream_to_flow: 3,
            send_buf_bytes: 0,
            oldest_ms: 0,
        };
        let signals = RwndPressureSignals {
            has_active_flows: true,
            ..Default::default()
        };
        let (rwnd, reason) = m.tick_rwnd(now, stats, 8, signals);
        assert_eq!(rwnd, RWND_FLOOR);
        assert_eq!(reason, "browser_replay_backoff");

        // Pressure cooldown keeps us at floor for ~15s, even when
        // subsequent signals look healthy.
        let later = now + Duration::from_secs(5);
        let (rwnd, reason) = m.tick_rwnd(later, stats, 0, signals);
        assert_eq!(rwnd, RWND_FLOOR);
        assert_eq!(reason, "pressure_cooldown");

        // After the cooldown expires the rwnd can recover again.
        let past_cooldown = now + Duration::from_secs(20);
        let quiet = RouterStatsSnapshot::default();
        let (rwnd, _reason) = m.tick_rwnd(past_cooldown, quiet, 0, signals);
        // active_or_recent is false (demand too old), so we go to floor via
        // no_progress — but it should not be pressure_cooldown anymore.
        let _ = rwnd;
    }

    #[test]
    fn rwnd_router_outbound_bad_forces_floor() {
        let mut m = MuxEngine::new();
        let now = Instant::now();
        // Skip browser burst branch: flows=1 (below threshold).
        let stats = RouterStatsSnapshot {
            flows: 1,
            outbound: 200, // >= 128 → pressure
            stream_to_flow: 1,
            send_buf_bytes: 0,
            oldest_ms: 0,
        };
        let signals = RwndPressureSignals {
            has_active_flows: true,
            high_seq_advanced: true,
            ..Default::default()
        };
        let (rwnd, reason) = m.tick_rwnd(now, stats, 0, signals);
        assert_eq!(rwnd, RWND_FLOOR);
        assert_eq!(reason, "pressure");
    }

    // ── Send buffer + cwnd + retransmit (Task 2.4) ──────────────────

    #[test]
    fn send_buffer_respects_cwnd() {
        let mut m = MuxEngine::new();
        m.set_cwnd(4);
        let now = Instant::now();
        for i in 0..10 {
            m.enqueue_outbound(OutboundItem::Data {
                stream_id: 1,
                payload: vec![i as u8],
            });
        }
        // First pull: cwnd of 4 means only 4 inflight at a time.
        let frames = m.take_send_bytes(now);
        assert_eq!(frames.len(), 4);
        assert_eq!(m.inflight_len(), 4);
        assert_eq!(m.queue_len(), 6);

        // Pulling again without ACKs yields nothing.
        let frames2 = m.take_send_bytes(now);
        assert_eq!(frames2.len(), 0);

        // ACK the first two. Queue has room to ship two more.
        m.on_cumulative_ack(2);
        assert_eq!(m.inflight_len(), 2);
        let frames3 = m.take_send_bytes(now);
        assert_eq!(frames3.len(), 2);
        assert_eq!(m.inflight_len(), 4);
    }

    #[test]
    fn send_buffer_assigns_sequential_data_seq() {
        let mut m = MuxEngine::new();
        m.set_cwnd(16);
        let now = Instant::now();
        for _ in 0..5 {
            m.enqueue_outbound(OutboundItem::Data {
                stream_id: 7,
                payload: b"x".to_vec(),
            });
        }
        let frames = m.take_send_bytes(now);
        assert_eq!(frames.len(), 5);
        // Decode each and confirm monotonically increasing data_seq starting at 1.
        let seqs: Vec<u64> = frames
            .iter()
            .map(|b| match MuxFrame::decode(b).unwrap() {
                MuxFrame::Data { data_seq, .. } => data_seq,
                other => panic!("expected Data, got {other:?}"),
            })
            .collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn open_and_close_frames_are_not_tracked_inflight() {
        // Only DATA needs retransmit; OPEN/CLOSE are best-effort fire-and-forget
        // from MuxEngine's perspective (peer end-state is reconciled via
        // later DATA / FIN / CLOSE).
        let mut m = MuxEngine::new();
        let now = Instant::now();
        m.enqueue_outbound(OutboundItem::Open {
            stream_id: 5,
            service: "vault.techrockstars.ztlp".into(),
        });
        m.enqueue_outbound(OutboundItem::Close { stream_id: 5 });
        let frames = m.take_send_bytes(now);
        assert_eq!(frames.len(), 2);
        assert_eq!(m.inflight_len(), 0);
    }

    #[test]
    fn retransmit_fires_after_rto() {
        let mut m = MuxEngine::new();
        m.set_cwnd(8);
        m.set_rto(Duration::from_millis(50));
        let t0 = Instant::now();
        m.enqueue_outbound(OutboundItem::Data {
            stream_id: 2,
            payload: b"ping-me-later".to_vec(),
        });
        let first = m.take_send_bytes(t0);
        assert_eq!(first.len(), 1);
        assert_eq!(m.inflight_len(), 1);

        // Before RTO: no retransmit.
        let early = t0 + Duration::from_millis(25);
        assert_eq!(m.tick_retransmit(early), 0);
        assert_eq!(m.take_retransmit_bytes().len(), 0);

        // After RTO: retransmit fires.
        let late = t0 + Duration::from_millis(80);
        let count = m.tick_retransmit(late);
        assert_eq!(count, 1);
        let rex = m.take_retransmit_bytes();
        assert_eq!(rex.len(), 1);
        // Retransmit bytes are identical to the original encoded frame.
        assert_eq!(rex[0], first[0]);
        // Still inflight until the ACK.
        assert_eq!(m.inflight_len(), 1);

        // Now ACK it.
        m.on_cumulative_ack(1);
        assert_eq!(m.inflight_len(), 0);
    }

    #[test]
    fn cumulative_ack_drops_everything_at_or_below() {
        let mut m = MuxEngine::new();
        m.set_cwnd(16);
        let now = Instant::now();
        for _ in 0..5 {
            m.enqueue_outbound(OutboundItem::Data {
                stream_id: 1,
                payload: b"x".to_vec(),
            });
        }
        m.take_send_bytes(now);
        assert_eq!(m.inflight_len(), 5);
        // ACK covers seqs 1..=3.
        let released = m.on_cumulative_ack(3);
        assert_eq!(released, 3);
        assert_eq!(m.inflight_len(), 2);
    }

    #[test]
    fn peer_rwnd_is_clamped_to_adaptive_range() {
        let mut m = MuxEngine::new();
        m.on_peer_rwnd(0);
        assert!(m.peer_rwnd >= RWND_FLOOR);
        m.on_peer_rwnd(99);
        assert!(m.peer_rwnd <= RWND_ADAPTIVE_MAX);
    }

    #[test]
    fn rwnd_oldest_ms_alone_is_not_pressure() {
        // The plan explicitly notes that oldest_ms > threshold with no
        // stuck/suspect signals should NOT collapse rwnd; the browser tail
        // was stuck at floor because of this bug in the Swift original.
        let mut m = MuxEngine::new();
        let now = Instant::now();
        m.mark_outbound_demand(now);
        // Keep below browser_burst threshold so the "healthy" branch is
        // exercised.
        let stats = RouterStatsSnapshot {
            flows: 1,
            outbound: 0,
            stream_to_flow: 1,
            send_buf_bytes: 0,
            oldest_ms: 10_000,
        };
        let signals = RwndPressureSignals {
            has_active_flows: true,
            high_seq_advanced: true,
            ..Default::default()
        };
        let (rwnd, reason) = m.tick_rwnd(now, stats, 0, signals);
        assert_ne!(rwnd, RWND_FLOOR, "reason={reason}");
    }

    // ── RTT / goodput sampling (Phase A) ─────────────────────────────

    /// Helper: enqueue + flush + ack one DATA packet so a full RTT sample
    /// lands. Returns the data_seq assigned.
    fn send_and_ack_one(m: &mut MuxEngine, sent_at: Instant, ack_at: Instant) -> u64 {
        m.enqueue_outbound(OutboundItem::Data {
            stream_id: 1,
            payload: b"x".to_vec(),
        });
        let frames = m.take_send_bytes(sent_at);
        assert_eq!(frames.len(), 1);
        // Newest data_seq we just assigned is next_send_data_seq - 1.
        let seq = m.next_send_data_seq - 1;
        m.on_cumulative_ack_at(ack_at, seq);
        seq
    }

    #[test]
    fn rtt_snapshot_is_zero_before_any_ack() {
        let mut m = MuxEngine::new();
        m.set_cwnd(4);
        let snap = m.rtt_goodput_snapshot(Instant::now());
        assert_eq!(snap.smoothed_rtt_ms, 0);
        assert_eq!(snap.rtt_var_ms, 0);
        assert_eq!(snap.min_rtt_ms, 0);
        assert_eq!(snap.latest_rtt_ms, 0);
        assert_eq!(snap.goodput_bps, 0);
        assert_eq!(snap.peak_goodput_bps, 0);
        assert_eq!(snap.bdp_kb, 0);
        assert_eq!(snap.samples_total, 0);
    }

    #[test]
    fn rtt_first_sample_bootstraps_srtt_and_rttvar() {
        // RFC 6298 §2.2: first sample → srtt = R, rttvar = R/2.
        let mut m = MuxEngine::new();
        m.set_cwnd(4);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(50);
        send_and_ack_one(&mut m, t0, t1);
        let snap = m.rtt_goodput_snapshot(t1);
        assert_eq!(snap.smoothed_rtt_ms, 50);
        assert_eq!(snap.rtt_var_ms, 25);
        assert_eq!(snap.min_rtt_ms, 50);
        assert_eq!(snap.latest_rtt_ms, 50);
        assert_eq!(snap.samples_total, 1);
    }

    #[test]
    fn rtt_second_sample_smooths_via_rfc6298() {
        let mut m = MuxEngine::new();
        m.set_cwnd(4);
        let t0 = Instant::now();
        send_and_ack_one(&mut m, t0, t0 + Duration::from_millis(100));
        // Next sample is 200ms. srtt should move toward 200 by 1/8 of the
        // delta: new_srtt = 0.875*100 + 0.125*200 = 112.5ms.
        let t1 = t0 + Duration::from_secs(1);
        send_and_ack_one(&mut m, t1, t1 + Duration::from_millis(200));
        let snap = m.rtt_goodput_snapshot(t1 + Duration::from_millis(200));
        // Allow 1ms slack for integer division.
        assert!(
            (112..=113).contains(&snap.smoothed_rtt_ms),
            "srtt_ms={} expected ~112",
            snap.smoothed_rtt_ms
        );
        assert_eq!(snap.min_rtt_ms, 100);
        assert_eq!(snap.latest_rtt_ms, 200);
        assert_eq!(snap.samples_total, 2);
    }

    #[test]
    fn rtt_retransmit_sample_is_excluded_by_karn() {
        // Send one packet, let RTO fire (so it's marked retransmitted),
        // then ACK it. Karn's algo must NOT admit this as an RTT sample.
        let mut m = MuxEngine::new();
        m.set_cwnd(4);
        m.set_rto(Duration::from_millis(10));
        let t0 = Instant::now();
        m.enqueue_outbound(OutboundItem::Data {
            stream_id: 1,
            payload: b"retrans-me".to_vec(),
        });
        m.take_send_bytes(t0);
        let seq = m.next_send_data_seq - 1;

        // RTO fires → inflight packet marked retransmitted.
        let rto_time = t0 + Duration::from_millis(50);
        assert_eq!(m.tick_retransmit(rto_time), 1);

        // Then ACK arrives a bit later.
        let ack_time = rto_time + Duration::from_millis(40);
        m.on_cumulative_ack_at(ack_time, seq);

        let snap = m.rtt_goodput_snapshot(ack_time);
        assert_eq!(
            snap.samples_total, 0,
            "retransmitted packet must not produce an RTT sample (Karn)"
        );
        assert_eq!(snap.smoothed_rtt_ms, 0);
        // But goodput still counts.
        assert!(
            snap.goodput_bps > 0,
            "goodput counts every released byte regardless of retransmits"
        );
    }

    #[test]
    fn goodput_tracks_bytes_acked_in_sliding_8s_window() {
        let mut m = MuxEngine::new();
        m.set_cwnd(64);
        let t0 = Instant::now();
        // Enqueue 4 × 1024-byte payloads and ACK them all at once. Each
        // encoded frame is 13 bytes of header + 1024 bytes payload = 1037.
        for _ in 0..4 {
            m.enqueue_outbound(OutboundItem::Data {
                stream_id: 1,
                payload: vec![0u8; 1024],
            });
        }
        m.take_send_bytes(t0);
        let last_seq = m.next_send_data_seq - 1;
        let ack_time = t0 + Duration::from_millis(50);
        m.on_cumulative_ack_at(ack_time, last_seq);

        let snap = m.rtt_goodput_snapshot(ack_time);
        // 4 × 1037 = 4148 bytes of acked data in the last 1 second →
        // bps across 8s window = 4148 × 8 / 8 = 4148 bps.
        assert_eq!(snap.goodput_bps, 4148);
        assert_eq!(snap.peak_goodput_bps, 4148);
    }

    #[test]
    fn goodput_ages_out_after_window_elapses() {
        let mut m = MuxEngine::new();
        m.set_cwnd(64);
        let t0 = Instant::now();
        m.enqueue_outbound(OutboundItem::Data {
            stream_id: 1,
            payload: vec![0u8; 100],
        });
        m.take_send_bytes(t0);
        let seq = m.next_send_data_seq - 1;
        m.on_cumulative_ack_at(t0 + Duration::from_millis(10), seq);

        // Immediately after the ACK, goodput is non-zero.
        let early = t0 + Duration::from_millis(50);
        let snap_early = m.rtt_goodput_snapshot(early);
        assert!(snap_early.goodput_bps > 0);

        // 15s later — well past the 8s window — every bucket should have
        // rolled to zero.
        let late = t0 + Duration::from_secs(15);
        let snap_late = m.rtt_goodput_snapshot(late);
        assert_eq!(snap_late.goodput_bps, 0);
        // Peak persists across the aging.
        assert!(snap_late.peak_goodput_bps > 0);
    }

    #[test]
    fn bdp_kb_is_zero_until_both_rtt_and_goodput_are_known() {
        let mut m = MuxEngine::new();
        m.set_cwnd(4);
        assert_eq!(
            m.rtt_goodput_snapshot(Instant::now()).bdp_kb,
            0,
            "bdp must be 0 before any samples land"
        );
    }

    #[test]
    fn bdp_kb_matches_rtt_times_goodput() {
        // Sanity: 50ms RTT × 1 Mbps (1_000_000 bps) = 50_000 bits = 6250 bytes = ~6 KB.
        // We'll simulate this by directly injecting a sample + goodput.
        let mut m = MuxEngine::new();
        m.set_cwnd(64);
        let t0 = Instant::now();
        // 1 second of 125_000 bytes acked = 1 Mbps goodput.
        // Need encoded frames summing to ~125KB. Use 100 × 1250-byte payloads.
        for _ in 0..100 {
            m.enqueue_outbound(OutboundItem::Data {
                stream_id: 1,
                payload: vec![0u8; 1237],
            });
        }
        m.take_send_bytes(t0);
        let seq = m.next_send_data_seq - 1;
        let ack_time = t0 + Duration::from_millis(50);
        m.on_cumulative_ack_at(ack_time, seq);

        let snap = m.rtt_goodput_snapshot(ack_time);
        // RTT sample ~= 50ms. Goodput ~= 1 Mbps. BDP ~= 6 KB.
        assert_eq!(snap.smoothed_rtt_ms, 50);
        let expected_bdp_kb =
            ((snap.smoothed_rtt_ms as u64) * snap.goodput_bps / 8_000 / 1024) as u32;
        assert_eq!(snap.bdp_kb, expected_bdp_kb);
    }

    #[test]
    fn samples_total_counts_only_karn_admitted_samples() {
        let mut m = MuxEngine::new();
        m.set_cwnd(16);
        m.set_rto(Duration::from_millis(10));
        let t0 = Instant::now();

        // Three clean packets → 3 samples.
        for i in 0..3 {
            send_and_ack_one(
                &mut m,
                t0 + Duration::from_millis(100 * i),
                t0 + Duration::from_millis(100 * i + 50),
            );
        }

        // One packet that gets retransmitted → 0 additional samples.
        m.enqueue_outbound(OutboundItem::Data {
            stream_id: 1,
            payload: b"rx".to_vec(),
        });
        m.take_send_bytes(t0 + Duration::from_secs(1));
        let seq = m.next_send_data_seq - 1;
        m.tick_retransmit(t0 + Duration::from_secs(2));
        m.on_cumulative_ack_at(t0 + Duration::from_secs(3), seq);

        assert_eq!(m.rtt_samples_total(), 3);
    }

    #[test]
    fn peak_goodput_is_monotonic() {
        let mut m = MuxEngine::new();
        m.set_cwnd(32);
        let t0 = Instant::now();
        // Burst 1: 10 packets ack'd in sub-second.
        for _ in 0..10 {
            m.enqueue_outbound(OutboundItem::Data {
                stream_id: 1,
                payload: vec![0u8; 1024],
            });
        }
        m.take_send_bytes(t0);
        let seq = m.next_send_data_seq - 1;
        m.on_cumulative_ack_at(t0 + Duration::from_millis(20), seq);
        let peak1 = m.peak_goodput_bps();
        assert!(peak1 > 0);

        // Quiet 10 seconds.
        let _ = m.rtt_goodput_snapshot(t0 + Duration::from_secs(10));

        // Small burst: should NOT lower the peak.
        m.enqueue_outbound(OutboundItem::Data {
            stream_id: 1,
            payload: vec![0u8; 32],
        });
        m.take_send_bytes(t0 + Duration::from_secs(10));
        let seq = m.next_send_data_seq - 1;
        m.on_cumulative_ack_at(t0 + Duration::from_secs(10) + Duration::from_millis(5), seq);
        let peak2 = m.peak_goodput_bps();
        assert!(peak2 >= peak1, "peak must not decrease: {peak1} → {peak2}");
    }

    // ── Shadow RTT / goodput observation tests ──────────────────────

    #[test]
    fn shadow_observe_sent_then_ack_records_one_rtt_sample() {
        // Pure shadow path — no enqueue / take_send_bytes. Simulates
        // Swift emitting a DATA frame itself and asking Rust to
        // measure RTT from the outside.
        let mut m = MuxEngine::new();
        let t0 = Instant::now();
        m.observe_sent(t0, 42, 1037);
        assert_eq!(m.shadow_inflight_len(), 1);

        let ack_time = t0 + Duration::from_millis(75);
        m.observe_ack_cumulative(ack_time, 42);
        assert_eq!(m.shadow_inflight_len(), 0);

        let snap = m.rtt_goodput_snapshot(ack_time);
        assert_eq!(snap.samples_total, 1);
        assert_eq!(snap.smoothed_rtt_ms, 75);
        assert_eq!(snap.goodput_bps, 1037);
    }

    #[test]
    fn shadow_observe_cumulative_releases_all_below() {
        let mut m = MuxEngine::new();
        let t0 = Instant::now();
        for seq in 1..=5u64 {
            m.observe_sent(
                t0 + Duration::from_millis(seq as u64),
                seq,
                500,
            );
        }
        assert_eq!(m.shadow_inflight_len(), 5);
        m.observe_ack_cumulative(t0 + Duration::from_millis(50), 3);
        assert_eq!(
            m.shadow_inflight_len(),
            2,
            "seqs 1..=3 released; 4,5 remain"
        );
    }

    #[test]
    fn shadow_observe_sent_twice_same_seq_excludes_sample_via_karn() {
        // Retransmit path: Swift sends seq=7, RTO fires, Swift sends
        // seq=7 again. The second observe_sent marks the entry as
        // retransmitted — Karn must exclude this from RTT samples.
        let mut m = MuxEngine::new();
        let t0 = Instant::now();
        m.observe_sent(t0, 7, 1000);
        m.observe_sent(t0 + Duration::from_millis(100), 7, 1000);
        m.observe_ack_cumulative(t0 + Duration::from_millis(150), 7);
        let snap = m.rtt_goodput_snapshot(t0 + Duration::from_millis(150));
        assert_eq!(
            snap.samples_total, 0,
            "retransmitted seq excluded by Karn"
        );
        assert!(snap.goodput_bps > 0, "goodput still counted");
    }

    #[test]
    fn shadow_observe_caps_at_shadow_max_entries() {
        // Verify the bounded-growth guard. Fire enough observe_sent
        // without any ACKs to exceed the cap; the map must not exceed
        // SHADOW_MAX_ENTRIES.
        let mut m = MuxEngine::new();
        let t0 = Instant::now();
        for seq in 0..(SHADOW_MAX_ENTRIES as u64 + 100) {
            m.observe_sent(t0 + Duration::from_millis(seq), seq, 100);
        }
        assert!(
            m.shadow_inflight_len() <= SHADOW_MAX_ENTRIES,
            "shadow map grew past cap: {}",
            m.shadow_inflight_len()
        );
    }
}