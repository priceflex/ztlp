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

/// ACK frame v2 — byte-unit (KB) receive window (Phase B: modern flow control).
///
/// Wire layout: `[0x10 | cumulative_ack(8 BE) | window_kb(2 BE)]` = 11 bytes.
/// Unit of `window_kb` is 1024 bytes. Max advertised window 65_535 KB = 64 MB.
///
/// Upgrade semantics: once a peer sends any FRAME_ACK_V2 we remember that and
/// reply in V2 for the rest of the session. Peers that never send V2 keep
/// receiving V1 — wire-level backward compatible.
///
/// Gateway→client ACKs stay on FRAME_ACK(0x01)+SACK format; only the
/// client→gateway rwnd advertisement uses V2. The gateway converts
/// `window_kb` → packet-equivalent via `packets = (window_kb * 1024) / 1140`
/// before feeding it into its existing packet-count cwnd math.
pub const FRAME_ACK_V2: u8 = 0x10;

/// Window unit for FRAME_ACK_V2 (in bytes).
pub const ACK_V2_WINDOW_UNIT_BYTES: u32 = 1024;

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

/// Heuristic "typical DATA frame size" used to convert the V1 frame-count
/// window into a byte-equivalent for diagnostics and for the V2 ceiling
/// when we're still speaking V1. Matches `@max_payload_bytes` on the
/// gateway side (1140 bytes).
pub const RWND_V1_FRAME_SIZE_HINT: u32 = 1140;

/// Default initial byte window we advertise when we start sending V2.
/// 16 KB — roughly a TCP initial cwnd, sized so a first page load fits
/// without immediately stalling on the rwnd. Configurable via
/// `MuxEngine::set_initial_window_kb` before the first V2 emit.
pub const DEFAULT_INITIAL_WINDOW_KB: u16 = 16;

/// Maximum shadow-sent entries we remember for RTT observation. A
/// Vaultwarden page load with a stuck peer could otherwise bloat the
/// map; we'd rather drop the oldest sample than leak.
pub const SHADOW_MAX_ENTRIES: usize = 4096;

// ── Phase D: Autotune (BBR-lite) ──────────────────────────────────────
//
// Target = smoothed_rtt × peak_goodput × safety_factor. Clamped to
// [min_window_kb, max_window_kb]. Safety factor reflects confidence —
// 2.0 on healthy ticks (widen aggressively past the current estimate),
// 0.5 on pressure/replay/loss (clamp back toward min).
//
// The autotuner only drives the byte window; the V1 packet-count ladder
// is left alone so V1-only peers (old gateway) keep working unchanged.

/// Minimum autotune window. Fresh slow-start + anti-abuse floor. Same
/// order of magnitude as the V1 floor (4 × 1140 ≈ 4.6 KB) so legacy
/// behaviour is preserved when falling back.
pub const AUTOTUNE_MIN_WINDOW_KB: u16 = 8;
/// Maximum autotune window. 4 MB is QUIC-ish default — plenty of room
/// for a high-BDP path (100 ms × 100 Mbps ≈ 1.25 MB) without letting
/// the peer advertise something catastrophic like 64 MB.
pub const AUTOTUNE_MAX_WINDOW_KB: u16 = 4096;
/// Safety factor on a healthy tick (target = srtt × goodput × 2.0).
/// Stored as rational to keep the arithmetic integer-only for FFI
/// simplicity.
pub const AUTOTUNE_HEALTHY_SAFETY_NUM: u32 = 2;
pub const AUTOTUNE_HEALTHY_SAFETY_DEN: u32 = 1;
/// Safety factor on a pressure/replay tick — drives the target back
/// down toward the floor without slamming straight to it.
pub const AUTOTUNE_PRESSURE_SAFETY_NUM: u32 = 1;
pub const AUTOTUNE_PRESSURE_SAFETY_DEN: u32 = 2;
/// How many healthy ticks in a row before autotune starts widening past
/// the current target. Mirrors the V1 ladder's `rwnd_healthy_ticks_needed`.
pub const AUTOTUNE_WIDEN_TICKS_NEEDED: u32 = 3;

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
    /// Cumulative ACK with optional rwnd (v1 — frame-count).
    Ack { cumulative: u64, rwnd: Option<u16> },
    /// Cumulative ACK with byte-unit receive window advertisement
    /// (v2 — Phase B). `window_kb` is in units of 1024 bytes; the
    /// on-wire field is `u16`, giving a 64 MB max advertised window.
    /// Emitted when the engine's peer is known to speak v2.
    AckV2 { cumulative: u64, window_kb: u16 },
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
            // [0x10 | cumulative(8) | window_kb(2)]
            MuxFrame::AckV2 { .. } => 1 + 8 + 2,
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
            MuxFrame::AckV2 {
                cumulative,
                window_kb,
            } => {
                out[0] = FRAME_ACK_V2;
                out[1..9].copy_from_slice(&cumulative.to_be_bytes());
                out[9..11].copy_from_slice(&window_kb.to_be_bytes());
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
            FRAME_ACK_V2 => {
                // Strict: window_kb is mandatory, so 11 bytes exactly.
                if buf.len() < 11 {
                    return Err(MuxError::ShortFrame);
                }
                let cumulative = u64::from_be_bytes([
                    buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                ]);
                let window_kb = u16::from_be_bytes([buf[9], buf[10]]);
                Ok(MuxFrame::AckV2 {
                    cumulative,
                    window_kb,
                })
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
pub struct MuxEngine {}
//#[cfg(test)]
//mod tests {
//    use super::*;
//
//    #[test]
//    fn mux_engine_defaults_are_sane() {
//        let m = MuxEngine::new();
//        assert_eq!(m.advertised_rwnd(), RWND_FLOOR);
//        assert_eq!(m.inflight_len(), 0);
//        assert_eq!(m.queue_len(), 0);
//        assert_eq!(m.streams_len(), 0);
//        assert_eq!(m.next_stream_id(), 1);
//    }
//
//    #[test]
//    fn frame_constants_match_gateway_wire() {
//        // These must stay aligned with proto/src/ffi.rs and the Elixir
//        // gateway; a mismatch breaks the tunnel.
//        assert_eq!(FRAME_DATA, 0x00);
//        assert_eq!(FRAME_ACK, 0x01);
//        assert_eq!(FRAME_FIN, 0x02);
//        assert_eq!(FRAME_CLOSE, 0x05);
//        assert_eq!(FRAME_OPEN, 0x06);
//        assert_eq!(FRAME_PING, 0x07);
//        assert_eq!(FRAME_PONG, 0x08);
//    }
//
//    #[test]
//    fn mux_error_display_is_informative() {
//        assert_eq!(
//            MuxError::UnknownFrameType(0xff).to_string(),
//            "unknown frame type 0xff"
//        );
//        assert_eq!(
//            MuxError::OutputTooSmall { need: 11, got: 9 }.to_string(),
//            "output buffer too small: need 11 got 9"
//        );
//    }
//
//    // ── Codec round-trips ────────────────────────────────────────────
//
//    fn roundtrip(frame: MuxFrame) -> MuxFrame {
//        let bytes = frame.to_vec();
//        MuxFrame::decode(&bytes).expect("decode")
//    }
//
//    #[test]
//    fn codec_data_mux_form_roundtrip() {
//        let f = MuxFrame::Data {
//            stream_id: 7,
//            data_seq: 42,
//            payload: b"hello world".to_vec(),
//        };
//        assert_eq!(roundtrip(f.clone()), f);
//    }
//
//    #[test]
//    fn codec_ack_with_rwnd_roundtrip() {
//        let f = MuxFrame::Ack {
//            cumulative: 1234,
//            rwnd: Some(12),
//        };
//        let bytes = f.to_vec();
//        assert_eq!(bytes.len(), 11);
//        assert_eq!(bytes[0], FRAME_ACK);
//        assert_eq!(MuxFrame::decode(&bytes).unwrap(), f);
//    }
//
//    #[test]
//    fn codec_ack_legacy_9_byte_decodes() {
//        // Legacy 9-byte ACK without rwnd: [0x01 | seq(8)].
//        let f = MuxFrame::Ack {
//            cumulative: 99,
//            rwnd: None,
//        };
//        let bytes = f.to_vec();
//        assert_eq!(bytes.len(), 9);
//        let decoded = MuxFrame::decode(&bytes).unwrap();
//        assert_eq!(
//            decoded,
//            MuxFrame::Ack {
//                cumulative: 99,
//                rwnd: None
//            }
//        );
//    }
//
//    #[test]
//    fn codec_open_roundtrip() {
//        let f = MuxFrame::Open {
//            stream_id: 5,
//            service: "vault.techrockstars.ztlp".to_string(),
//        };
//        assert_eq!(roundtrip(f.clone()), f);
//    }
//
//    #[test]
//    fn codec_close_and_fin_and_ping_pong_roundtrip() {
//        for f in [
//            MuxFrame::Close { stream_id: 12 },
//            MuxFrame::Fin { stream_id: 13 },
//            MuxFrame::Ping {
//                nonce: 0xDEAD_BEEF_CAFE_BABE,
//            },
//            MuxFrame::Pong { nonce: 1 },
//        ] {
//            assert_eq!(roundtrip(f.clone()), f);
//        }
//    }
//
//    #[test]
//    fn codec_decode_legacy_data_form_returns_stream_zero() {
//        // Construct legacy FRAME_DATA: [0x00 | data_seq(8) | payload], exactly
//        // 9 + payload bytes and the first four "stream id" bytes map to the
//        // high bytes of data_seq — we treat that as legacy.
//        let mut buf = vec![FRAME_DATA];
//        buf.extend_from_slice(&42u64.to_be_bytes());
//        buf.extend_from_slice(b"abc");
//        let decoded = MuxFrame::decode(&buf).unwrap();
//        assert_eq!(
//            decoded,
//            MuxFrame::Data {
//                stream_id: 0,
//                data_seq: 42,
//                payload: b"abc".to_vec()
//            }
//        );
//    }
//
//    #[test]
//    fn codec_encode_rejects_undersized_output() {
//        let f = MuxFrame::Ack {
//            cumulative: 1,
//            rwnd: Some(4),
//        };
//        let mut small = [0u8; 5];
//        let err = f.encode(&mut small).unwrap_err();
//        assert_eq!(err, MuxError::OutputTooSmall { need: 11, got: 5 });
//    }
//
//    #[test]
//    fn codec_decode_short_frame_errors() {
//        assert_eq!(MuxFrame::decode(&[]).unwrap_err(), MuxError::ShortFrame);
//        assert_eq!(
//            MuxFrame::decode(&[FRAME_ACK, 0, 0]).unwrap_err(),
//            MuxError::ShortFrame
//        );
//        assert_eq!(
//            MuxFrame::decode(&[FRAME_CLOSE, 0, 0]).unwrap_err(),
//            MuxError::ShortFrame
//        );
//    }
//
//    #[test]
//    fn codec_decode_unknown_frame_errors() {
//        let err = MuxFrame::decode(&[0x99, 0, 0, 0, 0]).unwrap_err();
//        assert_eq!(err, MuxError::UnknownFrameType(0x99));
//    }
//
//    #[test]
//    fn codec_decode_open_bad_utf8_errors() {
//        let mut buf = vec![FRAME_OPEN, 0, 0, 0, 1];
//        buf.extend_from_slice(&[0xff, 0xfe, 0xfd]);
//        let err = MuxFrame::decode(&buf).unwrap_err();
//        assert_eq!(err, MuxError::InvalidServiceName);
//    }
//
//    // ── ACK generation + rwnd policy (Task 2.3) ─────────────────────
//
//    #[test]
//    fn mux_on_data_received_advances_cumulative_ack() {
//        let mut m = MuxEngine::new();
//        assert_eq!(m.cumulative_ack(), 0);
//        m.on_data_received(1);
//        assert_eq!(m.cumulative_ack(), 1);
//        m.on_data_received(2);
//        m.on_data_received(3);
//        assert_eq!(m.cumulative_ack(), 3);
//        // A gap should not advance past the hole.
//        m.on_data_received(10);
//        assert_eq!(m.cumulative_ack(), 10);
//        // Old duplicate is harmless.
//        m.on_data_received(2);
//        assert_eq!(m.cumulative_ack(), 10);
//    }
//
//    #[test]
//    fn mux_build_ack_frame_uses_current_rwnd_and_cumulative() {
//        let mut m = MuxEngine::new();
//        m.on_data_received(5);
//        let f = m.build_ack_frame();
//        match f {
//            MuxFrame::Ack { cumulative, rwnd } => {
//                assert_eq!(cumulative, 5);
//                assert_eq!(rwnd, Some(RWND_FLOOR));
//            }
//            _ => panic!("expected Ack"),
//        }
//    }
//
//    /// Healthy stats, no replay, recent outbound demand — the plan's
//    /// explicit acceptance: rwnd must hold >= 12, not collapse to 4.
//    #[test]
//    fn rwnd_healthy_plus_recent_demand_holds_12() {
//        let mut m = MuxEngine::new();
//        let now = Instant::now();
//        m.mark_outbound_demand(now);
//        let stats = RouterStatsSnapshot {
//            flows: 2,
//            outbound: 0,
//            stream_to_flow: 2,
//            send_buf_bytes: 0,
//            oldest_ms: 0,
//        };
//        let signals = RwndPressureSignals {
//            high_seq_advanced: true,
//            has_active_flows: true,
//            ..Default::default()
//        };
//        // First tick within the post-demand window. browser burst will
//        // trigger browser_burst_target=16 because flows>=2. Advance time
//        // past the burst and keep demand fresh to test hold.
//        let (rwnd, reason) = m.tick_rwnd(now, stats, 0, signals);
//        assert_eq!(rwnd, RWND_BROWSER_BURST_TARGET, "reason={reason}");
//
//        // Now simulate a later tick where flows have dropped (browser burst
//        // over) but demand is still recent. Hold at 12, not floor.
//        let later = now + Duration::from_secs(5);
//        let quiet_stats = RouterStatsSnapshot {
//            flows: 0,
//            outbound: 0,
//            stream_to_flow: 0,
//            send_buf_bytes: 0,
//            oldest_ms: 0,
//        };
//        let (rwnd, reason) = m.tick_rwnd(later, quiet_stats, 0, signals);
//        assert_eq!(rwnd, RWND_POST_DEMAND_HOLD, "reason={reason}");
//        assert!(rwnd >= 12);
//    }
//
//    /// Plan acceptance: replayDelta=8 + browser burst → fast backoff to
//    /// floor and a 15s cooldown.
//    #[test]
//    fn rwnd_browser_replay_fast_backoff_to_floor() {
//        let mut m = MuxEngine::new();
//        let now = Instant::now();
//        m.mark_outbound_demand(now);
//        let stats = RouterStatsSnapshot {
//            flows: 3,
//            outbound: 0,
//            stream_to_flow: 3,
//            send_buf_bytes: 0,
//            oldest_ms: 0,
//        };
//        let signals = RwndPressureSignals {
//            has_active_flows: true,
//            ..Default::default()
//        };
//        let (rwnd, reason) = m.tick_rwnd(now, stats, 8, signals);
//        assert_eq!(rwnd, RWND_FLOOR);
//        assert_eq!(reason, "browser_replay_backoff");
//
//        // Pressure cooldown keeps us at floor for ~15s, even when
//        // subsequent signals look healthy.
//        let later = now + Duration::from_secs(5);
//        let (rwnd, reason) = m.tick_rwnd(later, stats, 0, signals);
//        assert_eq!(rwnd, RWND_FLOOR);
//        assert_eq!(reason, "pressure_cooldown");
//
//        // After the cooldown expires the rwnd can recover again.
//        let past_cooldown = now + Duration::from_secs(20);
//        let quiet = RouterStatsSnapshot::default();
//        let (rwnd, _reason) = m.tick_rwnd(past_cooldown, quiet, 0, signals);
//        // active_or_recent is false (demand too old), so we go to floor via
//        // no_progress — but it should not be pressure_cooldown anymore.
//        let _ = rwnd;
//    }
//
//    #[test]
//    fn rwnd_router_outbound_bad_forces_floor() {
//        let mut m = MuxEngine::new();
//        let now = Instant::now();
//        // Skip browser burst branch: flows=1 (below threshold).
//        let stats = RouterStatsSnapshot {
//            flows: 1,
//            outbound: 200, // >= 128 → pressure
//            stream_to_flow: 1,
//            send_buf_bytes: 0,
//            oldest_ms: 0,
//        };
//        let signals = RwndPressureSignals {
//            has_active_flows: true,
//            high_seq_advanced: true,
//            ..Default::default()
//        };
//        let (rwnd, reason) = m.tick_rwnd(now, stats, 0, signals);
//        assert_eq!(rwnd, RWND_FLOOR);
//        assert_eq!(reason, "pressure");
//    }
//
//    // ── Send buffer + cwnd + retransmit (Task 2.4) ──────────────────
//
//    #[test]
//    fn send_buffer_respects_cwnd() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(4);
//        let now = Instant::now();
//        for i in 0..10 {
//            m.enqueue_outbound(OutboundItem::Data {
//                stream_id: 1,
//                payload: vec![i as u8],
//            });
//        }
//        // First pull: cwnd of 4 means only 4 inflight at a time.
//        let frames = m.take_send_bytes(now);
//        assert_eq!(frames.len(), 4);
//        assert_eq!(m.inflight_len(), 4);
//        assert_eq!(m.queue_len(), 6);
//
//        // Pulling again without ACKs yields nothing.
//        let frames2 = m.take_send_bytes(now);
//        assert_eq!(frames2.len(), 0);
//
//        // ACK the first two. Queue has room to ship two more.
//        m.on_cumulative_ack(2);
//        assert_eq!(m.inflight_len(), 2);
//        let frames3 = m.take_send_bytes(now);
//        assert_eq!(frames3.len(), 2);
//        assert_eq!(m.inflight_len(), 4);
//    }
//
//    #[test]
//    fn send_buffer_assigns_sequential_data_seq() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(16);
//        let now = Instant::now();
//        for _ in 0..5 {
//            m.enqueue_outbound(OutboundItem::Data {
//                stream_id: 7,
//                payload: b"x".to_vec(),
//            });
//        }
//        let frames = m.take_send_bytes(now);
//        assert_eq!(frames.len(), 5);
//        // Decode each and confirm monotonically increasing data_seq starting at 1.
//        let seqs: Vec<u64> = frames
//            .iter()
//            .map(|b| match MuxFrame::decode(b).unwrap() {
//                MuxFrame::Data { data_seq, .. } => data_seq,
//                other => panic!("expected Data, got {other:?}"),
//            })
//            .collect();
//        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
//    }
//
//    #[test]
//    fn open_and_close_frames_are_not_tracked_inflight() {
//        // Only DATA needs retransmit; OPEN/CLOSE are best-effort fire-and-forget
//        // from MuxEngine's perspective (peer end-state is reconciled via
//        // later DATA / FIN / CLOSE).
//        let mut m = MuxEngine::new();
//        let now = Instant::now();
//        m.enqueue_outbound(OutboundItem::Open {
//            stream_id: 5,
//            service: "vault.techrockstars.ztlp".into(),
//        });
//        m.enqueue_outbound(OutboundItem::Close { stream_id: 5 });
//        let frames = m.take_send_bytes(now);
//        assert_eq!(frames.len(), 2);
//        assert_eq!(m.inflight_len(), 0);
//    }
//
//    #[test]
//    fn retransmit_fires_after_rto() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(8);
//        m.set_rto(Duration::from_millis(50));
//        let t0 = Instant::now();
//        m.enqueue_outbound(OutboundItem::Data {
//            stream_id: 2,
//            payload: b"ping-me-later".to_vec(),
//        });
//        let first = m.take_send_bytes(t0);
//        assert_eq!(first.len(), 1);
//        assert_eq!(m.inflight_len(), 1);
//
//        // Before RTO: no retransmit.
//        let early = t0 + Duration::from_millis(25);
//        assert_eq!(m.tick_retransmit(early), 0);
//        assert_eq!(m.take_retransmit_bytes().len(), 0);
//
//        // After RTO: retransmit fires.
//        let late = t0 + Duration::from_millis(80);
//        let count = m.tick_retransmit(late);
//        assert_eq!(count, 1);
//        let rex = m.take_retransmit_bytes();
//        assert_eq!(rex.len(), 1);
//        // Retransmit bytes are identical to the original encoded frame.
//        assert_eq!(rex[0], first[0]);
//        // Still inflight until the ACK.
//        assert_eq!(m.inflight_len(), 1);
//
//        // Now ACK it.
//        m.on_cumulative_ack(1);
//        assert_eq!(m.inflight_len(), 0);
//    }
//
//    #[test]
//    fn cumulative_ack_drops_everything_at_or_below() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(16);
//        let now = Instant::now();
//        for _ in 0..5 {
//            m.enqueue_outbound(OutboundItem::Data {
//                stream_id: 1,
//                payload: b"x".to_vec(),
//            });
//        }
//        m.take_send_bytes(now);
//        assert_eq!(m.inflight_len(), 5);
//        // ACK covers seqs 1..=3.
//        let released = m.on_cumulative_ack(3);
//        assert_eq!(released, 3);
//        assert_eq!(m.inflight_len(), 2);
//    }
//
//    #[test]
//    fn peer_rwnd_is_clamped_to_adaptive_range() {
//        let mut m = MuxEngine::new();
//        m.on_peer_rwnd(0);
//        assert!(m.peer_rwnd >= RWND_FLOOR);
//        m.on_peer_rwnd(99);
//        assert!(m.peer_rwnd <= RWND_ADAPTIVE_MAX);
//    }
//
//    #[test]
//    fn rwnd_oldest_ms_alone_is_not_pressure() {
//        // The plan explicitly notes that oldest_ms > threshold with no
//        // stuck/suspect signals should NOT collapse rwnd; the browser tail
//        // was stuck at floor because of this bug in the Swift original.
//        let mut m = MuxEngine::new();
//        let now = Instant::now();
//        m.mark_outbound_demand(now);
//        // Keep below browser_burst threshold so the "healthy" branch is
//        // exercised.
//        let stats = RouterStatsSnapshot {
//            flows: 1,
//            outbound: 0,
//            stream_to_flow: 1,
//            send_buf_bytes: 0,
//            oldest_ms: 10_000,
//        };
//        let signals = RwndPressureSignals {
//            has_active_flows: true,
//            high_seq_advanced: true,
//            ..Default::default()
//        };
//        let (rwnd, reason) = m.tick_rwnd(now, stats, 0, signals);
//        assert_ne!(rwnd, RWND_FLOOR, "reason={reason}");
//    }
//
//    // ── RTT / goodput sampling (Phase A) ─────────────────────────────
//
//    /// Helper: enqueue + flush + ack one DATA packet so a full RTT sample
//    /// lands. Returns the data_seq assigned.
//    fn send_and_ack_one(m: &mut MuxEngine, sent_at: Instant, ack_at: Instant) -> u64 {
//        m.enqueue_outbound(OutboundItem::Data {
//            stream_id: 1,
//            payload: b"x".to_vec(),
//        });
//        let frames = m.take_send_bytes(sent_at);
//        assert_eq!(frames.len(), 1);
//        // Newest data_seq we just assigned is next_send_data_seq - 1.
//        let seq = m.next_send_data_seq - 1;
//        m.on_cumulative_ack_at(ack_at, seq);
//        seq
//    }
//
//    #[test]
//    fn rtt_snapshot_is_zero_before_any_ack() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(4);
//        let snap = m.rtt_goodput_snapshot(Instant::now());
//        assert_eq!(snap.smoothed_rtt_ms, 0);
//        assert_eq!(snap.rtt_var_ms, 0);
//        assert_eq!(snap.min_rtt_ms, 0);
//        assert_eq!(snap.latest_rtt_ms, 0);
//        assert_eq!(snap.goodput_bps, 0);
//        assert_eq!(snap.peak_goodput_bps, 0);
//        assert_eq!(snap.bdp_kb, 0);
//        assert_eq!(snap.samples_total, 0);
//    }
//
//    #[test]
//    fn rtt_first_sample_bootstraps_srtt_and_rttvar() {
//        // RFC 6298 §2.2: first sample → srtt = R, rttvar = R/2.
//        let mut m = MuxEngine::new();
//        m.set_cwnd(4);
//        let t0 = Instant::now();
//        let t1 = t0 + Duration::from_millis(50);
//        send_and_ack_one(&mut m, t0, t1);
//        let snap = m.rtt_goodput_snapshot(t1);
//        assert_eq!(snap.smoothed_rtt_ms, 50);
//        assert_eq!(snap.rtt_var_ms, 25);
//        assert_eq!(snap.min_rtt_ms, 50);
//        assert_eq!(snap.latest_rtt_ms, 50);
//        assert_eq!(snap.samples_total, 1);
//    }
//
//    #[test]
//    fn rtt_second_sample_smooths_via_rfc6298() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(4);
//        let t0 = Instant::now();
//        send_and_ack_one(&mut m, t0, t0 + Duration::from_millis(100));
//        // Next sample is 200ms. srtt should move toward 200 by 1/8 of the
//        // delta: new_srtt = 0.875*100 + 0.125*200 = 112.5ms.
//        let t1 = t0 + Duration::from_secs(1);
//        send_and_ack_one(&mut m, t1, t1 + Duration::from_millis(200));
//        let snap = m.rtt_goodput_snapshot(t1 + Duration::from_millis(200));
//        // Allow 1ms slack for integer division.
//        assert!(
//            (112..=113).contains(&snap.smoothed_rtt_ms),
//            "srtt_ms={} expected ~112",
//            snap.smoothed_rtt_ms
//        );
//        assert_eq!(snap.min_rtt_ms, 100);
//        assert_eq!(snap.latest_rtt_ms, 200);
//        assert_eq!(snap.samples_total, 2);
//    }
//
//    #[test]
//    fn rtt_retransmit_sample_is_excluded_by_karn() {
//        // Send one packet, let RTO fire (so it's marked retransmitted),
//        // then ACK it. Karn's algo must NOT admit this as an RTT sample.
//        let mut m = MuxEngine::new();
//        m.set_cwnd(4);
//        m.set_rto(Duration::from_millis(10));
//        let t0 = Instant::now();
//        m.enqueue_outbound(OutboundItem::Data {
//            stream_id: 1,
//            payload: b"retrans-me".to_vec(),
//        });
//        m.take_send_bytes(t0);
//        let seq = m.next_send_data_seq - 1;
//
//        // RTO fires → inflight packet marked retransmitted.
//        let rto_time = t0 + Duration::from_millis(50);
//        assert_eq!(m.tick_retransmit(rto_time), 1);
//
//        // Then ACK arrives a bit later.
//        let ack_time = rto_time + Duration::from_millis(40);
//        m.on_cumulative_ack_at(ack_time, seq);
//
//        let snap = m.rtt_goodput_snapshot(ack_time);
//        assert_eq!(
//            snap.samples_total, 0,
//            "retransmitted packet must not produce an RTT sample (Karn)"
//        );
//        assert_eq!(snap.smoothed_rtt_ms, 0);
//        // But goodput still counts.
//        assert!(
//            snap.goodput_bps > 0,
//            "goodput counts every released byte regardless of retransmits"
//        );
//    }
//
//    #[test]
//    fn goodput_tracks_bytes_acked_in_sliding_8s_window() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(64);
//        let t0 = Instant::now();
//        // Enqueue 4 × 1024-byte payloads and ACK them all at once. Each
//        // encoded frame is 13 bytes of header + 1024 bytes payload = 1037.
//        for _ in 0..4 {
//            m.enqueue_outbound(OutboundItem::Data {
//                stream_id: 1,
//                payload: vec![0u8; 1024],
//            });
//        }
//        m.take_send_bytes(t0);
//        let last_seq = m.next_send_data_seq - 1;
//        let ack_time = t0 + Duration::from_millis(50);
//        m.on_cumulative_ack_at(ack_time, last_seq);
//
//        let snap = m.rtt_goodput_snapshot(ack_time);
//        // 4 × 1037 = 4148 bytes of acked data in the last 1 second →
//        // bps across 8s window = 4148 × 8 / 8 = 4148 bps.
//        assert_eq!(snap.goodput_bps, 4148);
//        assert_eq!(snap.peak_goodput_bps, 4148);
//    }
//
//    #[test]
//    fn goodput_ages_out_after_window_elapses() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(64);
//        let t0 = Instant::now();
//        m.enqueue_outbound(OutboundItem::Data {
//            stream_id: 1,
//            payload: vec![0u8; 100],
//        });
//        m.take_send_bytes(t0);
//        let seq = m.next_send_data_seq - 1;
//        m.on_cumulative_ack_at(t0 + Duration::from_millis(10), seq);
//
//        // Immediately after the ACK, goodput is non-zero.
//        let early = t0 + Duration::from_millis(50);
//        let snap_early = m.rtt_goodput_snapshot(early);
//        assert!(snap_early.goodput_bps > 0);
//
//        // 15s later — well past the 8s window — every bucket should have
//        // rolled to zero.
//        let late = t0 + Duration::from_secs(15);
//        let snap_late = m.rtt_goodput_snapshot(late);
//        assert_eq!(snap_late.goodput_bps, 0);
//        // Peak persists across the aging.
//        assert!(snap_late.peak_goodput_bps > 0);
//    }
//
//    #[test]
//    fn bdp_kb_is_zero_until_both_rtt_and_goodput_are_known() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(4);
//        assert_eq!(
//            m.rtt_goodput_snapshot(Instant::now()).bdp_kb,
//            0,
//            "bdp must be 0 before any samples land"
//        );
//    }
//
//    #[test]
//    fn bdp_kb_matches_rtt_times_goodput() {
//        // Sanity: 50ms RTT × 1 Mbps (1_000_000 bps) = 50_000 bits = 6250 bytes = ~6 KB.
//        // We'll simulate this by directly injecting a sample + goodput.
//        let mut m = MuxEngine::new();
//        m.set_cwnd(64);
//        let t0 = Instant::now();
//        // 1 second of 125_000 bytes acked = 1 Mbps goodput.
//        // Need encoded frames summing to ~125KB. Use 100 × 1250-byte payloads.
//        for _ in 0..100 {
//            m.enqueue_outbound(OutboundItem::Data {
//                stream_id: 1,
//                payload: vec![0u8; 1237],
//            });
//        }
//        m.take_send_bytes(t0);
//        let seq = m.next_send_data_seq - 1;
//        let ack_time = t0 + Duration::from_millis(50);
//        m.on_cumulative_ack_at(ack_time, seq);
//
//        let snap = m.rtt_goodput_snapshot(ack_time);
//        // RTT sample ~= 50ms. Goodput ~= 1 Mbps. BDP ~= 6 KB.
//        assert_eq!(snap.smoothed_rtt_ms, 50);
//        let expected_bdp_kb =
//            ((snap.smoothed_rtt_ms as u64) * snap.goodput_bps / 8_000 / 1024) as u32;
//        assert_eq!(snap.bdp_kb, expected_bdp_kb);
//    }
//
//    #[test]
//    fn samples_total_counts_only_karn_admitted_samples() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(16);
//        m.set_rto(Duration::from_millis(10));
//        let t0 = Instant::now();
//
//        // Three clean packets → 3 samples.
//        for i in 0..3 {
//            send_and_ack_one(
//                &mut m,
//                t0 + Duration::from_millis(100 * i),
//                t0 + Duration::from_millis(100 * i + 50),
//            );
//        }
//
//        // One packet that gets retransmitted → 0 additional samples.
//        m.enqueue_outbound(OutboundItem::Data {
//            stream_id: 1,
//            payload: b"rx".to_vec(),
//        });
//        m.take_send_bytes(t0 + Duration::from_secs(1));
//        let seq = m.next_send_data_seq - 1;
//        m.tick_retransmit(t0 + Duration::from_secs(2));
//        m.on_cumulative_ack_at(t0 + Duration::from_secs(3), seq);
//
//        assert_eq!(m.rtt_samples_total(), 3);
//    }
//
//    #[test]
//    fn peak_goodput_is_monotonic() {
//        let mut m = MuxEngine::new();
//        m.set_cwnd(32);
//        let t0 = Instant::now();
//        // Burst 1: 10 packets ack'd in sub-second.
//        for _ in 0..10 {
//            m.enqueue_outbound(OutboundItem::Data {
//                stream_id: 1,
//                payload: vec![0u8; 1024],
//            });
//        }
//        m.take_send_bytes(t0);
//        let seq = m.next_send_data_seq - 1;
//        m.on_cumulative_ack_at(t0 + Duration::from_millis(20), seq);
//        let peak1 = m.peak_goodput_bps();
//        assert!(peak1 > 0);
//
//        // Quiet 10 seconds.
//        let _ = m.rtt_goodput_snapshot(t0 + Duration::from_secs(10));
//
//        // Small burst: should NOT lower the peak.
//        m.enqueue_outbound(OutboundItem::Data {
//            stream_id: 1,
//            payload: vec![0u8; 32],
//        });
//        m.take_send_bytes(t0 + Duration::from_secs(10));
//        let seq = m.next_send_data_seq - 1;
//        m.on_cumulative_ack_at(t0 + Duration::from_secs(10) + Duration::from_millis(5), seq);
//        let peak2 = m.peak_goodput_bps();
//        assert!(peak2 >= peak1, "peak must not decrease: {peak1} → {peak2}");
//    }
//
//    // ── Shadow RTT / goodput observation tests ──────────────────────
//
//    #[test]
//    fn shadow_observe_sent_then_ack_records_one_rtt_sample() {
//        // Pure shadow path — no enqueue / take_send_bytes. Simulates
//        // Swift emitting a DATA frame itself and asking Rust to
//        // measure RTT from the outside.
//        let mut m = MuxEngine::new();
//        let t0 = Instant::now();
//        m.observe_sent(t0, 42, 1037);
//        assert_eq!(m.shadow_inflight_len(), 1);
//
//        let ack_time = t0 + Duration::from_millis(75);
//        m.observe_ack_cumulative(ack_time, 42);
//        assert_eq!(m.shadow_inflight_len(), 0);
//
//        let snap = m.rtt_goodput_snapshot(ack_time);
//        assert_eq!(snap.samples_total, 1);
//        assert_eq!(snap.smoothed_rtt_ms, 75);
//        assert_eq!(snap.goodput_bps, 1037);
//    }
//
//    #[test]
//    fn shadow_observe_cumulative_releases_all_below() {
//        let mut m = MuxEngine::new();
//        let t0 = Instant::now();
//        for seq in 1..=5u64 {
//            m.observe_sent(t0 + Duration::from_millis(seq as u64), seq, 500);
//        }
//        assert_eq!(m.shadow_inflight_len(), 5);
//        m.observe_ack_cumulative(t0 + Duration::from_millis(50), 3);
//        assert_eq!(
//            m.shadow_inflight_len(),
//            2,
//            "seqs 1..=3 released; 4,5 remain"
//        );
//    }
//
//    #[test]
//    fn shadow_observe_sent_twice_same_seq_excludes_sample_via_karn() {
//        // Retransmit path: Swift sends seq=7, RTO fires, Swift sends
//        // seq=7 again. The second observe_sent marks the entry as
//        // retransmitted — Karn must exclude this from RTT samples.
//        let mut m = MuxEngine::new();
//        let t0 = Instant::now();
//        m.observe_sent(t0, 7, 1000);
//        m.observe_sent(t0 + Duration::from_millis(100), 7, 1000);
//        m.observe_ack_cumulative(t0 + Duration::from_millis(150), 7);
//        let snap = m.rtt_goodput_snapshot(t0 + Duration::from_millis(150));
//        assert_eq!(snap.samples_total, 0, "retransmitted seq excluded by Karn");
//        assert!(snap.goodput_bps > 0, "goodput still counted");
//    }
//
//    #[test]
//    fn shadow_observe_caps_at_shadow_max_entries() {
//        // Verify the bounded-growth guard. Fire enough observe_sent
//        // without any ACKs to exceed the cap; the map must not exceed
//        // SHADOW_MAX_ENTRIES.
//        let mut m = MuxEngine::new();
//        let t0 = Instant::now();
//        for seq in 0..(SHADOW_MAX_ENTRIES as u64 + 100) {
//            m.observe_sent(t0 + Duration::from_millis(seq), seq, 100);
//        }
//        assert!(
//            m.shadow_inflight_len() <= SHADOW_MAX_ENTRIES,
//            "shadow map grew past cap: {}",
//            m.shadow_inflight_len()
//        );
//    }
//
//    // ── FRAME_ACK_V2 / byte-unit window (Phase B) ───────────────────
//
//    #[test]
//    fn codec_ack_v2_roundtrip() {
//        let f = MuxFrame::AckV2 {
//            cumulative: 0xDEAD_BEEF_CAFE_BABE,
//            window_kb: 64,
//        };
//        let bytes = f.to_vec();
//        assert_eq!(bytes.len(), 11);
//        assert_eq!(bytes[0], FRAME_ACK_V2);
//        assert_eq!(MuxFrame::decode(&bytes).unwrap(), f);
//    }
//
//    #[test]
//    fn codec_ack_v2_short_frame_errors() {
//        // 10 bytes (missing 1 byte of window_kb) must be rejected.
//        let mut buf = vec![FRAME_ACK_V2];
//        buf.extend_from_slice(&42u64.to_be_bytes());
//        buf.push(0); // 10 total
//        assert_eq!(MuxFrame::decode(&buf).unwrap_err(), MuxError::ShortFrame);
//    }
//
//    #[test]
//    fn codec_v1_and_v2_are_distinguishable_by_type() {
//        let v1 = MuxFrame::Ack {
//            cumulative: 99,
//            rwnd: Some(16),
//        };
//        let v2 = MuxFrame::AckV2 {
//            cumulative: 99,
//            window_kb: 16,
//        };
//        assert_ne!(v1.to_vec()[0], v2.to_vec()[0]);
//        // Both are 11 bytes — type byte is the only differentiator.
//        assert_eq!(v1.to_vec().len(), v2.to_vec().len());
//    }
//
//    #[test]
//    fn build_ack_frame_emits_v1_until_peer_speaks_v2() {
//        let mut m = MuxEngine::new();
//        match m.build_ack_frame() {
//            MuxFrame::Ack { .. } => {}
//            other => panic!("expected V1 before peer speaks V2, got {other:?}"),
//        }
//        m.note_peer_sent_v2();
//        match m.build_ack_frame() {
//            MuxFrame::AckV2 { .. } => {}
//            other => panic!("expected V2 after peer speaks V2, got {other:?}"),
//        }
//    }
//
//    #[test]
//    fn note_peer_sent_v2_is_sticky_and_upgrades_initial_window() {
//        let mut m = MuxEngine::new();
//        assert!(!m.peer_speaks_v2());
//        // Before V2: byte window tracks V1 floor × hint (4 × 1140 = 4560).
//        assert_eq!(m.advertised_window_bytes(), 4 * RWND_V1_FRAME_SIZE_HINT);
//        m.note_peer_sent_v2();
//        assert!(m.peer_speaks_v2());
//        // After first V2: window bumps to DEFAULT_INITIAL_WINDOW_KB × 1024.
//        assert_eq!(
//            m.advertised_window_bytes(),
//            DEFAULT_INITIAL_WINDOW_KB as u32 * ACK_V2_WINDOW_UNIT_BYTES
//        );
//        // Second call doesn't downgrade.
//        m.note_peer_sent_v2();
//        assert_eq!(
//            m.advertised_window_bytes(),
//            DEFAULT_INITIAL_WINDOW_KB as u32 * ACK_V2_WINDOW_UNIT_BYTES
//        );
//    }
//
//    #[test]
//    fn set_initial_window_kb_affects_first_v2_reply() {
//        let mut m = MuxEngine::new();
//        m.set_initial_window_kb(32);
//        m.note_peer_sent_v2();
//        // note_peer_sent_v2 bumps only if DEFAULT > current — we set 32
//        // KB explicitly (> 16 KB default), so the explicit setting wins.
//        assert_eq!(m.advertised_window_bytes(), 32 * ACK_V2_WINDOW_UNIT_BYTES);
//    }
//
//    #[test]
//    fn set_initial_window_kb_is_ignored_after_peer_speaks_v2() {
//        let mut m = MuxEngine::new();
//        m.note_peer_sent_v2();
//        let before = m.advertised_window_bytes();
//        m.set_initial_window_kb(128);
//        // Unchanged — set_initial_window_kb gates on !peer_speaks_v2.
//        assert_eq!(m.advertised_window_bytes(), before);
//    }
//
//    #[test]
//    fn advertised_window_kb_rounds_up() {
//        let mut m = MuxEngine::new();
//        // Directly nudge the byte window to a non-KB boundary via
//        // set_initial_window_kb (which multiplies by 1024 exactly, so
//        // we rely on the V1 fallback path for a fractional value).
//        // Easiest: use the V1 ladder which sets bytes = rwnd × 1140.
//        // 4 × 1140 = 4560 bytes = 4.45 KB → rounds up to 5.
//        assert_eq!(m.advertised_window_bytes(), 4560);
//        assert_eq!(m.advertised_window_kb(), 5);
//    }
//
//    #[test]
//    fn v1_ladder_keeps_byte_window_in_sync_until_v2() {
//        let mut m = MuxEngine::new();
//        let now = Instant::now();
//        m.mark_outbound_demand(now);
//        let stats = RouterStatsSnapshot {
//            flows: 2,
//            stream_to_flow: 2,
//            ..Default::default()
//        };
//        let signals = RwndPressureSignals {
//            high_seq_advanced: true,
//            has_active_flows: true,
//            ..Default::default()
//        };
//        // Drive the V1 ladder to browser burst target (16).
//        let (rwnd, _) = m.tick_rwnd(now, stats, 0, signals);
//        assert_eq!(rwnd, 16);
//        assert_eq!(m.advertised_window_bytes(), 16 * RWND_V1_FRAME_SIZE_HINT);
//        // Switching to V2 freezes the byte window at the current value
//        // unless the default is larger.
//        m.note_peer_sent_v2();
//        assert_eq!(
//            m.advertised_window_bytes(),
//            16 * RWND_V1_FRAME_SIZE_HINT,
//            "V1 × hint (18240) > V2 default (16 KB = 16384), so V1 value wins"
//        );
//    }
//
//    #[test]
//    fn build_ack_frame_v2_advertises_correct_kb() {
//        let mut m = MuxEngine::new();
//        m.set_initial_window_kb(42);
//        m.note_peer_sent_v2();
//        m.on_data_received(100);
//        match m.build_ack_frame() {
//            MuxFrame::AckV2 {
//                cumulative,
//                window_kb,
//            } => {
//                assert_eq!(cumulative, 100);
//                assert_eq!(window_kb, 42);
//            }
//            other => panic!("expected AckV2, got {other:?}"),
//        }
//    }
//
//    // ── Phase D: autotune tests ──────────────────────────────────
//
//    /// Helper: build a healthy pressure-signal bag (no replays, flows=1
//    /// so `browser_burst` is false, recent outbound demand so
//    /// `active_or_recent=true`).
//    fn healthy_inputs() -> (RouterStatsSnapshot, i32, RwndPressureSignals) {
//        let stats = RouterStatsSnapshot {
//            flows: 1,
//            outbound: 0,
//            stream_to_flow: 0,
//            send_buf_bytes: 0,
//            oldest_ms: 0,
//        };
//        let signals = RwndPressureSignals {
//            consecutive_full_flushes: 0,
//            consecutive_stuck_high_seq_ticks: 0,
//            session_suspect: false,
//            probe_outstanding: false,
//            high_seq_advanced: true,
//            has_active_flows: true,
//        };
//        (stats, 0, signals)
//    }
//
//    /// Inject an srtt sample + a peak goodput so `autotune_compute_target_bytes`
//    /// can produce a non-trivial target. Uses `observe_sent` +
//    /// `observe_ack_cumulative` to drive the real code path.
//    ///
//    /// Every ACK creates an RTT sample (RFC 6298 smoothing), so we keep
//    /// the observe_sent → observe_ack gap at exactly `rtt_ms` for every
//    /// seq — otherwise the smoothed RTT collapses to the most-recent
//    /// (usually tiny) latency gap.
//    fn seed_rtt_goodput(m: &mut MuxEngine, now: Instant, rtt_ms: u64, bytes_per_sec: u64) {
//        // Push acked bytes into the current 1-second bucket. Each pair
//        // of (observe_sent, observe_ack) has a gap of exactly `rtt_ms`
//        // so the RFC 6298 smoother holds srtt at `rtt_ms`.
//        let chunk = 1000u64;
//        let chunks = (bytes_per_sec / chunk).max(1);
//        for i in 0..chunks {
//            let seq = 1 + i;
//            // Stagger sends inside the first 900 ms so all acks land in
//            // the same 1-sec goodput bucket and peak sees the full rate.
//            let sent_at = now + Duration::from_millis((i * 900) / chunks.max(1));
//            let ack_at = sent_at + Duration::from_millis(rtt_ms);
//            m.observe_sent(sent_at, seq, chunk as u32);
//            m.observe_ack_cumulative(ack_at, seq);
//        }
//    }
//
//    #[test]
//    fn autotune_defaults_to_min_max_constants() {
//        let m = MuxEngine::new();
//        assert_eq!(
//            m.autotune_bounds_kb(),
//            (AUTOTUNE_MIN_WINDOW_KB, AUTOTUNE_MAX_WINDOW_KB)
//        );
//        assert_eq!(m.autotune_target_kb(), 0);
//        assert_eq!(m.autotune_reason(), "init");
//    }
//
//    #[test]
//    fn autotune_bounds_are_clamped_and_swapped() {
//        let mut m = MuxEngine::new();
//        // Swap min > max.
//        m.set_autotune_bounds_kb(2048, 16);
//        let (lo, hi) = m.autotune_bounds_kb();
//        assert!(lo <= hi);
//        // Lo clamped to AUTOTUNE_MIN_WINDOW_KB floor.
//        assert!(lo >= AUTOTUNE_MIN_WINDOW_KB);
//        // Hi clamped to AUTOTUNE_MAX_WINDOW_KB.
//        assert!(hi <= AUTOTUNE_MAX_WINDOW_KB);
//    }
//
//    #[test]
//    fn autotune_is_v1_legacy_noop_when_peer_has_not_upgraded() {
//        let mut m = MuxEngine::new();
//        let (stats, replay, signals) = healthy_inputs();
//        let t0 = Instant::now();
//        m.mark_outbound_demand(t0);
//        for _ in 0..5 {
//            let (_v1, _r) = m.tick_rwnd(t0, stats, replay, signals);
//        }
//        assert!(!m.peer_speaks_v2());
//        assert_eq!(m.autotune_reason(), "v1_legacy");
//        // V1 ladder should still have done its thing — byte hint follows rwnd.
//        assert_eq!(
//            m.advertised_window_bytes(),
//            m.advertised_rwnd() as u32 * RWND_V1_FRAME_SIZE_HINT
//        );
//    }
//
//    #[test]
//    fn autotune_no_sample_when_v2_active_but_no_rtt_yet() {
//        let mut m = MuxEngine::new();
//        m.note_peer_sent_v2();
//        let (stats, replay, signals) = healthy_inputs();
//        let t0 = Instant::now();
//        m.mark_outbound_demand(t0);
//        let _ = m.tick_rwnd(t0, stats, replay, signals);
//        assert_eq!(m.autotune_reason(), "no_sample");
//        assert_eq!(m.autotune_target_kb(), 0);
//        // Window held at the V2 default (16 KB).
//        assert_eq!(
//            m.advertised_window_bytes(),
//            DEFAULT_INITIAL_WINDOW_KB as u32 * ACK_V2_WINDOW_UNIT_BYTES
//        );
//    }
//
//    #[test]
//    fn autotune_widens_past_v1_ceiling_on_healthy_fast_path() {
//        let mut m = MuxEngine::new();
//        m.note_peer_sent_v2();
//        let t0 = Instant::now();
//        // 50 ms RTT, 10 Mbps goodput. Goodput is computed as
//        // `total_bytes × 8 / GOODPUT_WINDOW_BUCKETS(=8) = total_bytes bits/sec`
//        // so to represent 10 Mbps we need 10_000_000 bytes in the window.
//        // BDP @ 10 Mbps × 50 ms = 62,500 bytes; safety 2× = 125 KB.
//        seed_rtt_goodput(&mut m, t0, 50, 10_000_000);
//        let (stats, replay, signals) = healthy_inputs();
//        m.mark_outbound_demand(t0 + Duration::from_millis(1200));
//
//        // Drive AUTOTUNE_WIDEN_TICKS_NEEDED healthy ticks.
//        let mut last_bytes = m.advertised_window_bytes();
//        for i in 0..(AUTOTUNE_WIDEN_TICKS_NEEDED + 1) {
//            let now = t0 + Duration::from_millis(1500 + i as u64 * 1000);
//            let _ = m.tick_rwnd(now, stats, replay, signals);
//            last_bytes = m.advertised_window_bytes();
//        }
//        assert!(
//            last_bytes > 18 * 1024,
//            "autotune should widen past the V1 ceiling (18 KB), got {last_bytes} bytes ({} KB)",
//            last_bytes / 1024
//        );
//        // Final reason should be a widen or hold-at-target.
//        let reason = m.autotune_reason();
//        assert!(
//            matches!(
//                reason,
//                "widen_healthy" | "hold_at_target" | "hold_pre_widen"
//            ),
//            "unexpected autotune reason: {reason}"
//        );
//    }
//
//    #[test]
//    fn autotune_clamps_to_max_window() {
//        let mut m = MuxEngine::new();
//        m.note_peer_sent_v2();
//        // Set max to something small so we can verify the clamp.
//        m.set_autotune_bounds_kb(AUTOTUNE_MIN_WINDOW_KB, 64);
//        let t0 = Instant::now();
//        // 200 ms RTT, 100 Mbps → BDP ≈ 2.5 MB, safety 2× → 5 MB wanted,
//        // clamped to 64 KB.
//        seed_rtt_goodput(&mut m, t0, 200, 100_000_000);
//        let (stats, replay, signals) = healthy_inputs();
//        m.mark_outbound_demand(t0 + Duration::from_millis(1200));
//        for i in 0..(AUTOTUNE_WIDEN_TICKS_NEEDED + 2) {
//            let now = t0 + Duration::from_millis(1500 + i as u64 * 1000);
//            let _ = m.tick_rwnd(now, stats, replay, signals);
//        }
//        assert!(
//            m.advertised_window_bytes() <= 64 * 1024,
//            "window should be clamped at 64 KB, got {} bytes",
//            m.advertised_window_bytes()
//        );
//    }
//
//    #[test]
//    fn autotune_clamps_down_on_pressure() {
//        let mut m = MuxEngine::new();
//        m.note_peer_sent_v2();
//        let t0 = Instant::now();
//        seed_rtt_goodput(&mut m, t0, 50, 10_000_000);
//        // Widen first.
//        let (stats, replay, signals) = healthy_inputs();
//        m.mark_outbound_demand(t0 + Duration::from_millis(1200));
//        for i in 0..(AUTOTUNE_WIDEN_TICKS_NEEDED + 1) {
//            let now = t0 + Duration::from_millis(1500 + i as u64 * 1000);
//            let _ = m.tick_rwnd(now, stats, replay, signals);
//        }
//        let widened = m.advertised_window_bytes();
//        assert!(widened > DEFAULT_INITIAL_WINDOW_KB as u32 * 1024);
//        // Now introduce pressure — probe_outstanding triggers V1 "pressure"
//        // reason, which the pressure-matcher passes to autotune_tick.
//        let mut bad = signals;
//        bad.probe_outstanding = true;
//        let now = t0 + Duration::from_millis(10_000);
//        let _ = m.tick_rwnd(now, stats, replay, bad);
//        assert_eq!(m.autotune_reason(), "pressure_clamp");
//        assert!(
//            m.advertised_window_bytes() < widened,
//            "pressure should shrink window: was {widened}, now {}",
//            m.advertised_window_bytes()
//        );
//        assert!(
//            m.advertised_window_bytes() >= AUTOTUNE_MIN_WINDOW_KB as u32 * 1024,
//            "pressure should not shrink below min_kb"
//        );
//    }
//
//    #[test]
//    fn autotune_healthy_ticks_gate_widening() {
//        let mut m = MuxEngine::new();
//        m.note_peer_sent_v2();
//        let t0 = Instant::now();
//        seed_rtt_goodput(&mut m, t0, 50, 10_000_000);
//        let (stats, replay, signals) = healthy_inputs();
//        m.mark_outbound_demand(t0 + Duration::from_millis(1200));
//
//        // First healthy tick: target much larger than current, but
//        // we shouldn't widen yet (need AUTOTUNE_WIDEN_TICKS_NEEDED in a row).
//        let before = m.advertised_window_bytes();
//        let now = t0 + Duration::from_millis(1500);
//        let _ = m.tick_rwnd(now, stats, replay, signals);
//        assert_eq!(m.autotune_reason(), "hold_pre_widen");
//        assert_eq!(m.advertised_window_bytes(), before);
//
//        // Subsequent ticks increment the healthy counter. On tick
//        // AUTOTUNE_WIDEN_TICKS_NEEDED the widen fires. We already did
//        // 1 tick above, so do (NEEDED - 1) more and check.
//        for i in 1..AUTOTUNE_WIDEN_TICKS_NEEDED {
//            let now = t0 + Duration::from_millis(1500 + i as u64 * 1000);
//            let (_v1, _r) = m.tick_rwnd(now, stats, replay, signals);
//            if i < AUTOTUNE_WIDEN_TICKS_NEEDED - 1 {
//                assert_eq!(m.autotune_reason(), "hold_pre_widen", "tick {i}");
//                assert_eq!(m.advertised_window_bytes(), before);
//            } else {
//                // The NEEDED-th call performs the widen.
//                assert_eq!(m.autotune_reason(), "widen_healthy", "tick {i}");
//                assert!(m.advertised_window_bytes() > before);
//            }
//        }
//    }
//
//    #[test]
//    fn autotune_target_kb_is_exposed_and_nonzero_when_v2_active() {
//        let mut m = MuxEngine::new();
//        m.note_peer_sent_v2();
//        let t0 = Instant::now();
//        seed_rtt_goodput(&mut m, t0, 100, 5_000_000); // 100 ms × 5 Mbps
//        let (stats, replay, signals) = healthy_inputs();
//        m.mark_outbound_demand(t0 + Duration::from_millis(1200));
//        let now = t0 + Duration::from_millis(1500);
//        let _ = m.tick_rwnd(now, stats, replay, signals);
//        assert!(
//            m.autotune_target_kb() > 0,
//            "target_kb should be non-zero once autotune has computed a value"
//        );
//        assert!(m.autotune_target_kb() >= AUTOTUNE_MIN_WINDOW_KB);
//    }
//
//    /// Cold-start regression: on the very first autotune tick, a tiny
//    /// goodput sample (`peak_goodput_bps` just a few hundred bps) produces
//    /// a target below the initial window. The healthy path must NOT shrink
//    /// the advertised window below `DEFAULT_INITIAL_WINDOW_KB` — otherwise
//    /// the small window itself caps real throughput and autotune gets
//    /// stuck at the floor forever (observed on-device 2026-05-03).
//    #[test]
//    fn autotune_does_not_shrink_below_initial_window_on_cold_start() {
//        let mut m = MuxEngine::new();
//        m.note_peer_sent_v2();
//        let initial = m.advertised_window_bytes();
//        assert_eq!(initial, DEFAULT_INITIAL_WINDOW_KB as u32 * 1024);
//
//        let t0 = Instant::now();
//        // Tiny goodput sample — matches the 796 bps / 35 ms RTT we saw
//        // on-device (BDP ≈ 3.5 bytes, × 2 safety = 7 bytes, clamps to
//        // AUTOTUNE_MIN_WINDOW_KB = 8 KB, which is *below* initial 16 KB).
//        seed_rtt_goodput(&mut m, t0, 35, 796);
//        let (stats, replay, signals) = healthy_inputs();
//        m.mark_outbound_demand(t0 + Duration::from_millis(1200));
//        let now = t0 + Duration::from_millis(1500);
//        let _ = m.tick_rwnd(now, stats, replay, signals);
//
//        // Healthy path: reason may be "shrink_to_target" (target was
//        // below current) but the advertised window must not fall below
//        // the initial window.
//        assert!(
//            m.advertised_window_bytes() >= initial,
//            "healthy autotune shrank below initial ({initial} bytes): got {} bytes (reason={})",
//            m.advertised_window_bytes(),
//            m.autotune_reason()
//        );
//    }
//
//    /// Companion to the cold-start test: pressure SHOULD be allowed to
//    /// shrink below the initial window, because pressure means real
//    /// congestion and we want to back off hard. Only the healthy path
//    /// has the initial-window floor.
//    #[test]
//    fn autotune_pressure_may_shrink_below_initial_window() {
//        let mut m = MuxEngine::new();
//        m.note_peer_sent_v2();
//        let t0 = Instant::now();
//        // Tiny sample → target bytes ~= min_bytes, way below initial.
//        seed_rtt_goodput(&mut m, t0, 35, 796);
//        let (stats, replay, signals) = healthy_inputs();
//        // Pressure signal: probe_outstanding triggers V1 "pressure"
//        // reason, which autotune_tick interprets as pressure.
//        let mut bad = signals;
//        bad.probe_outstanding = true;
//        m.mark_outbound_demand(t0 + Duration::from_millis(1200));
//        let now = t0 + Duration::from_millis(1500);
//        let _ = m.tick_rwnd(now, stats, replay, bad);
//
//        assert_eq!(m.autotune_reason(), "pressure_clamp");
//        assert!(
//            m.advertised_window_bytes() >= AUTOTUNE_MIN_WINDOW_KB as u32 * 1024,
//            "pressure path must still respect absolute min_kb floor"
//        );
//        assert!(
//            m.advertised_window_bytes() < DEFAULT_INITIAL_WINDOW_KB as u32 * 1024,
//            "pressure path should be allowed to go below initial window"
//        );
//    }
//}
