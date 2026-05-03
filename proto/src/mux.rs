//! ZTLP mux engine — Nebula-style (stream framing only).
//!
//! After the Nebula-style pivot (Phase R2) the mux engine is deliberately
//! dumb: it owns stream framing and a fire-and-forget send queue, and
//! nothing else. No ACKs, no retransmits, no cwnd/rwnd, no RTT sampling,
//! no autotune, no shadow-BBR. If a UDP packet is lost, the inner TCP
//! end-to-end bytestream re-sends — the tunnel is a pure datagram pipe.
//!
//! The file retains:
//!  - `FRAME_DATA / FRAME_FIN / FRAME_CLOSE / FRAME_OPEN / FRAME_PING /
//!    FRAME_PONG` parse + build.
//!  - Per-stream lifecycle tracking (`StreamState`, `MuxStream`) — just
//!    enough to remember which stream_ids are open.
//!  - `MuxEngine::{new, next_stream_id, enqueue_outbound, take_send_bytes,
//!    on_data_received, cumulative_ack}`.
//!
//! The old reliability surface (FRAME_ACK / FRAME_ACK_V2, InflightPacket,
//! RouterStatsSnapshot, RwndPressureSignals, RttGoodputSnapshot,
//! tick_rwnd, tick_retransmit, observe_sent, observe_ack_cumulative,
//! autotune_*, shadow_*, etc.) was removed in the Nebula-style pivot
//! (R2). The matching `ztlp_mux_*` FFI wrappers in `ffi.rs` are stubbed
//! as no-ops pending R4 deletion.

#![cfg(feature = "ios-sync")]

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

// ── Wire constants ─────────────────────────────────────────────────────

pub const FRAME_DATA: u8 = 0x00;
pub const FRAME_FIN: u8 = 0x02;
pub const FRAME_CLOSE: u8 = 0x05;
pub const FRAME_OPEN: u8 = 0x06;
pub const FRAME_PING: u8 = 0x07;
pub const FRAME_PONG: u8 = 0x08;

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

/// Error values returned by the frame codec.
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

    /// Encode the frame into `out`, returning bytes written.
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
        self.encode(&mut v).expect("encode into exact-size buf");
        v
    }

    /// Decode a plaintext mux frame (after decryption).
    ///
    /// Accepts both the current mux form (FRAME_DATA with 4-byte stream_id
    /// prefix) AND the legacy single-stream form (FRAME_DATA with only an
    /// 8-byte data_seq). Legacy decode returns `stream_id=0`.
    ///
    /// FRAME_FIN accepts 1-byte (legacy) and 5-byte (per-stream).
    pub fn decode(buf: &[u8]) -> Result<MuxFrame, MuxError> {
        if buf.is_empty() {
            return Err(MuxError::ShortFrame);
        }
        let t = buf[0];
        match t {
            FRAME_DATA => {
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
            FRAME_FIN => {
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
    /// Last time this stream was touched (for stuck-flow detection).
    pub last_touched: Instant,
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

// ── Engine ────────────────────────────────────────────────────────────

/// Fire-and-forget mux state machine. One instance per tunnel session.
///
/// Not thread-safe on its own — wrap in a `Mutex` if the caller needs
/// cross-thread access.
pub struct MuxEngine {
    /// Monotonic counter handed out to DATA frames. Still included on the
    /// wire for compatibility with older peers that parse it, but the
    /// value is no longer used for ACK/retransmit — receivers ignore it.
    next_send_data_seq: u64,
    /// Highest contiguous DATA seq observed. Retained purely so the
    /// legacy `cumulative_ack` accessor keeps returning a plausible
    /// number; nothing on the wire uses it anymore.
    next_expected_recv_seq: u64,
    /// Stream registry.
    streams: HashMap<u32, MuxStream>,
    next_stream_id: u32,
    /// Outbound queue (pre-encode). Drained in FIFO order by
    /// `take_send_bytes`. No cwnd/rwnd gating: every queued frame is
    /// encoded and handed to the caller immediately.
    send_queue: VecDeque<OutboundItem>,
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
        }
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

    /// Advance the cumulative expected sequence when a FRAME_DATA is
    /// delivered. Retained for callers that still surface "last seq
    /// received" for diagnostics; no ACK is produced.
    pub fn on_data_received(&mut self, data_seq: u64) {
        if data_seq >= self.next_expected_recv_seq {
            self.next_expected_recv_seq = data_seq + 1;
        }
    }

    /// Diagnostic: highest contiguous seq observed.
    pub fn cumulative_ack(&self) -> u64 {
        self.next_expected_recv_seq.saturating_sub(1)
    }

    /// Enqueue an outbound item. Picked up on the next `take_send_bytes`.
    pub fn enqueue_outbound(&mut self, item: OutboundItem) {
        self.send_queue.push_back(item);
    }

    /// Drain every queued item as an encoded plaintext mux frame. The
    /// caller is responsible for encrypting each frame and sending it
    /// over UDP. No cwnd, no inflight tracking, no retransmit — a frame
    /// handed back here is forgotten immediately.
    pub fn take_send_bytes(&mut self, _now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(self.send_queue.len());
        while let Some(item) = self.send_queue.pop_front() {
            let frame = match item {
                OutboundItem::Open { stream_id, service } => MuxFrame::Open { stream_id, service },
                OutboundItem::Close { stream_id } => MuxFrame::Close { stream_id },
                OutboundItem::Probe { nonce } => MuxFrame::Ping { nonce },
                OutboundItem::Data { stream_id, payload } => {
                    let seq = self.next_send_data_seq;
                    self.next_send_data_seq += 1;
                    MuxFrame::Data {
                        stream_id,
                        data_seq: seq,
                        payload,
                    }
                }
            };
            out.push(frame.to_vec());
        }
        out
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
        assert_eq!(m.queue_len(), 0);
        assert_eq!(m.streams_len(), 0);
        assert_eq!(m.next_stream_id(), 1);
        assert_eq!(m.cumulative_ack(), 0);
    }

    #[test]
    fn frame_constants_match_gateway_wire() {
        // These must stay aligned with proto/src/ffi.rs and the Elixir
        // gateway; a mismatch breaks the tunnel.
        assert_eq!(FRAME_DATA, 0x00);
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
            MuxFrame::Ping {
                nonce: 0xDEAD_BEEF_CAFE_BABE,
            },
            MuxFrame::Pong { nonce: 1 },
        ] {
            assert_eq!(roundtrip(f.clone()), f);
        }
    }

    #[test]
    fn codec_decode_legacy_data_form_returns_stream_zero() {
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
        let f = MuxFrame::Close { stream_id: 1 };
        let mut small = [0u8; 2];
        let err = f.encode(&mut small).unwrap_err();
        assert_eq!(err, MuxError::OutputTooSmall { need: 5, got: 2 });
    }

    #[test]
    fn codec_decode_short_frame_errors() {
        assert_eq!(MuxFrame::decode(&[]).unwrap_err(), MuxError::ShortFrame);
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

    #[test]
    fn mux_on_data_received_advances_cumulative_ack() {
        let mut m = MuxEngine::new();
        assert_eq!(m.cumulative_ack(), 0);
        m.on_data_received(1);
        assert_eq!(m.cumulative_ack(), 1);
        m.on_data_received(2);
        m.on_data_received(3);
        assert_eq!(m.cumulative_ack(), 3);
        m.on_data_received(10);
        assert_eq!(m.cumulative_ack(), 10);
        m.on_data_received(2);
        assert_eq!(m.cumulative_ack(), 10);
    }

    #[test]
    fn take_send_bytes_drains_queue_and_assigns_data_seq() {
        let mut m = MuxEngine::new();
        m.enqueue_outbound(OutboundItem::Open {
            stream_id: 1,
            service: "svc".to_string(),
        });
        m.enqueue_outbound(OutboundItem::Data {
            stream_id: 1,
            payload: vec![1, 2, 3],
        });
        m.enqueue_outbound(OutboundItem::Data {
            stream_id: 1,
            payload: vec![4, 5],
        });
        m.enqueue_outbound(OutboundItem::Close { stream_id: 1 });
        let out = m.take_send_bytes(Instant::now());
        assert_eq!(out.len(), 4);
        // Second frame is DATA with data_seq=1
        let decoded = MuxFrame::decode(&out[1]).unwrap();
        match decoded {
            MuxFrame::Data { data_seq, .. } => assert_eq!(data_seq, 1),
            _ => panic!("expected Data"),
        }
        let decoded3 = MuxFrame::decode(&out[2]).unwrap();
        match decoded3 {
            MuxFrame::Data { data_seq, .. } => assert_eq!(data_seq, 2),
            _ => panic!("expected Data"),
        }
        assert_eq!(m.queue_len(), 0);
    }
}
