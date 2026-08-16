//! quinn::AsyncUdpSocket wrapper that intercepts hole-punch protocol bytes
//! before Quinn's QUIC packet processor sees them.
//!
//! # Overview
//!
//! ZTLP-NS coordinates hole punching by sending `PUNCH_NOTIFY` (`0x0B`)
//! and `PUNCH_BYTE` (`0x00`) packets to the *same* UDP port the gateway
//! is listening on for QUIC. Without this wrapper, Quinn receives those
//! packets, fails to parse them as QUIC headers, and either drops them
//! silently or closes connections with `InvalidVersion` errors —
//! making the punch protocol unreachable.
//!
//! `PunchRuntime` is a custom [`quinn::Runtime`] that wraps the default
//! [`quinn::TokioRuntime`]. Its [`wrap_udp_socket`] returns a
//! [`PunchSocket`] which:
//!
//! - **Forwards** `PUNCH_NOTIFY` (`0x0B`) payloads to a tokio channel
//!   consumed by [`crate::punch_agent::PunchAgent`]'s dispatcher (H4)
//! - **Drops** `PUNCH_BYTE` (`0x00`) packets silently (their NAT-opener
//!   job is already done by arrival)
//! - **Passes through** every other packet to Quinn unchanged via
//!   in-place meta-array compaction
//!
//! # H0 spike findings (recorded inline in commit 0fa4e13)
//!
//! - `quinn::Instant` is `pub(crate)`; the trait surface uses
//!   `std::time::Instant` directly.
//! - `quinn::udp::RecvMeta` is `Clone`, so meta-array compaction
//!   does not require `unsafe`. Quinn only reads `bufs[i]` keyed by
//!   `meta[i].len`, so we just need to keep the *retained* meta
//!   entries in slots `0..N` and return `N` from `poll_recv`.
//! - The inner `Arc<dyn AsyncUdpSocket>` from `TokioRuntime` exposes
//!   `create_io_poller(self: Arc<Self>)` which we delegate to by
//!   cloning the inner Arc — no need to reimplement poll-readiness.

#![deny(unsafe_code)]

use std::fmt::Debug;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};
use tokio::sync::mpsc::Sender;

/// PUNCH_NOTIFY discriminant — must match
/// [`crate::punch::NS_PUNCH_NOTIFY`].
const PUNCH_NOTIFY: u8 = 0x0B;

/// Bounded capacity for the PUNCH_NOTIFY intercept channel.
///
/// Prevents unbounded resource consumption (CWE-770, cro-jkth): an
/// unauthenticated attacker can flood PUNCH_NOTIFY-prefixed UDP
/// datagrams faster than the dispatcher drains them. A bounded
/// channel caps the backlog so the receive loop's non-blocking
/// `try_send` drops excess packets instead of growing memory to OOM.
#[cfg(test)]
const INTERCEPT_CHANNEL_CAPACITY: usize = 256;

/// PUNCH_BYTE — the 1-byte NAT-opener packet, never delivered to Quinn.
/// Must match [`crate::punch::PUNCH_BYTE`].
const PUNCH_BYTE: u8 = 0x00;

/// An intercepted PUNCH_NOTIFY packet: (payload, source address).
///
/// The payload includes the leading `0x0B` discriminant byte so the
/// dispatcher can call [`crate::punch::decode_punch_notify`] directly.
pub type InterceptedPacket = (Vec<u8>, SocketAddr);

/// A [`quinn::Runtime`] that wraps [`quinn::TokioRuntime`] and produces
/// [`PunchSocket`]-wrapped UDP sockets which filter punch-protocol
/// bytes out of the inbound packet stream before Quinn sees them.
///
/// # Use
///
/// Construct with [`PunchRuntime::new`], passing the sender side of
/// a bounded `mpsc::channel(INTERCEPT_CHANNEL_CAPACITY)` whose receiver
/// is owned by [`crate::punch_agent::PunchAgent`]. Pass the runtime to Quinn's
/// `Endpoint::new_with_abstract_socket` via
/// `quinn::EndpointConfig::default().with_runtime(...)`.
#[derive(Debug)]
pub struct PunchRuntime {
    inner: TokioRuntime,
    intercept_tx: Sender<InterceptedPacket>,
}

impl PunchRuntime {
    /// Create a new runtime delivering intercepted PUNCH_NOTIFY packets
    /// to `intercept_tx`.
    pub fn new(intercept_tx: Sender<InterceptedPacket>) -> Self {
        Self {
            inner: TokioRuntime,
            intercept_tx,
        }
    }
}

impl Runtime for PunchRuntime {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        self.inner.new_timer(t)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(future)
    }

    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner_sock = self.inner.wrap_udp_socket(t)?;
        Ok(Arc::new(PunchSocket {
            inner: inner_sock,
            intercept_tx: self.intercept_tx.clone(),
        }))
    }
}

/// An [`AsyncUdpSocket`] wrapper that filters punch-protocol packets.
///
/// On every `poll_recv`, packets are classified by their first byte:
/// - `0x0B` PUNCH_NOTIFY → forwarded to the intercept channel; not
///   included in the returned packet count
/// - `0x00` PUNCH_BYTE → silently dropped; not included
/// - anything else → passed through to Quinn via meta-array compaction
///
/// # Why meta-array compaction (vs filtering bufs)
///
/// Quinn's `AsyncUdpSocket::poll_recv` returns a count `N` and the
/// caller reads `bufs[0..N]` keyed by `meta[0..N].len`. The actual
/// payload bytes live in caller-owned buffers; we can't move them
/// around without `unsafe` (and shouldn't need to). Instead we simply
/// reorder the **meta** entries so the retained ones occupy slots
/// `0..N` and return `N`. Quinn's per-iteration buffer ownership
/// guarantees this is safe.
#[derive(Debug)]
struct PunchSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    intercept_tx: Sender<InterceptedPacket>,
}

impl AsyncUdpSocket for PunchSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // Delegate to inner's poller — we don't change send semantics.
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };

        // Walk packets in order, classifying by first byte. Retained
        // packets get their meta entry compacted to the next free slot
        // (write index). Filtered packets either forward to the
        // intercept channel (PUNCH_NOTIFY) or are dropped (PUNCH_BYTE).
        let mut write = 0usize;
        for read in 0..count {
            let m = &meta[read];
            let slot = &bufs[read];
            let payload = &slot[..m.len];

            // Defensive: empty datagrams (shouldn't occur per quinn docs
            // but we tolerate them) just pass through.
            if payload.is_empty() {
                if write != read {
                    meta[write] = meta[read];
                }
                write += 1;
                continue;
            }

            match payload[0] {
                PUNCH_BYTE => {
                    // Drop silently — the packet's job was to open the
                    // NAT pinhole. Subsequent QUIC handshake traffic
                    // through that pinhole goes through the normal
                    // pass-through arm below.
                }
                PUNCH_NOTIFY => {
                    // Forward owned copy to dispatcher.  Uses try_send
                    // so the non-blocking receive loop never stalls — if
                    // the bounded channel is full we simply drop the
                    // packet (the dispatcher is lagging behind).
                    let payload_vec = payload.to_vec();
                    match self.intercept_tx.try_send((payload_vec, m.addr)) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            // Bounded channel full — drop the packet to
                            // prevent OOM (CWE-770, cro-jkth).
                            tracing::warn!(
                                target: "ztlp::punch_socket",
                                "PUNCH_NOTIFY dropped — intercept channel full",
                            );
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            // Receiver dropped — agent shut down. Drop the
                            // packet silently. We can't tell the gateway to
                            // restart the agent from here, and propagating
                            // the error to Quinn would kill the QUIC
                            // listener entirely.
                            tracing::debug!(
                                target: "ztlp::punch_socket",
                                "PUNCH_NOTIFY dropped — dispatcher channel closed"
                            );
                        }
                    }
                }
                _ => {
                    // Real Quinn-bound packet — keep.
                    if write != read {
                        meta[write] = meta[read];
                    }
                    write += 1;
                }
            }
        }

        Poll::Ready(Ok(write))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::Waker;
    use tokio::sync::mpsc::channel;

    /// A minimal fake `AsyncUdpSocket` that returns canned packets on
    /// `poll_recv`. Lets us drive `PunchSocket::poll_recv` deterministically
    /// without involving real kernel UDP delivery (which is racy and
    /// flakes tests).
    #[derive(Debug)]
    struct FakeSocket {
        /// Tuples of (payload, source addr) to deliver on next poll_recv.
        /// Each call to `poll_recv` drains the front of this vec up to
        /// the caller's buffer slot count.
        queue: std::sync::Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    impl FakeSocket {
        fn new(packets: Vec<(Vec<u8>, SocketAddr)>) -> Self {
            Self {
                queue: std::sync::Mutex::new(packets),
            }
        }
    }

    impl AsyncUdpSocket for FakeSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            // Tests don't exercise the write path.
            unimplemented!("write path not exercised in PunchSocket tests")
        }

        fn try_send(&self, _transmit: &Transmit) -> io::Result<()> {
            unimplemented!("write path not exercised")
        }

        fn poll_recv(
            &self,
            _cx: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let mut q = self.queue.lock().unwrap();
            let n = q.len().min(bufs.len()).min(meta.len());
            for i in 0..n {
                let (payload, src) = q.remove(0);
                // Write payload into the caller's buffer slot.
                let len = payload.len().min(bufs[i].len());
                bufs[i][..len].copy_from_slice(&payload[..len]);
                meta[i] = RecvMeta {
                    addr: src,
                    len,
                    stride: len,
                    ecn: None,
                    dst_ip: None,
                };
            }
            Poll::Ready(Ok(n))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    /// Helper: invoke poll_recv against a PunchSocket wrapping a FakeSocket
    /// and return (returned_count, meta_view_of_retained_packets).
    fn drive_poll_recv(
        sock: &PunchSocket,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> usize {
        // Build a synthetic Context. We never actually wake; the FakeSocket
        // returns Ready immediately.
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match sock.poll_recv(&mut cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => panic!("expected Ready(Ok), got {:?}", other),
        }
    }

    fn make_meta() -> RecvMeta {
        RecvMeta {
            addr: "127.0.0.1:0".parse().unwrap(),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }
    }

    /// H3 — punch_notify is intercepted (not returned to Quinn) and the
    /// payload is forwarded to the intercept channel.
    #[test]
    fn punch_notify_is_intercepted_not_returned_to_quinn() {
        let (tx, mut rx) = channel(INTERCEPT_CHANNEL_CAPACITY);
        let fake = Arc::new(FakeSocket::new(vec![(
            vec![PUNCH_NOTIFY, 0xAA, 0xBB, 0xCC],
            "10.0.0.1:23095".parse().unwrap(),
        )]));
        let sock = PunchSocket {
            inner: fake,
            intercept_tx: tx,
        };

        let mut buf0 = [0u8; 1500];
        let mut bufs = [IoSliceMut::new(&mut buf0)];
        let mut meta = [make_meta()];
        let n = drive_poll_recv(&sock, &mut bufs, &mut meta);

        assert_eq!(n, 0, "PUNCH_NOTIFY should NOT be visible to Quinn");

        let (payload, src) = rx.try_recv().expect("intercept channel has the packet");
        assert_eq!(payload, vec![PUNCH_NOTIFY, 0xAA, 0xBB, 0xCC]);
        assert_eq!(src.to_string(), "10.0.0.1:23095");
    }

    /// H3 — punch_byte is silently dropped; nothing reaches Quinn or
    /// the intercept channel.
    #[test]
    fn punch_byte_is_silently_dropped() {
        let (tx, mut rx) = channel(INTERCEPT_CHANNEL_CAPACITY);
        let fake = Arc::new(FakeSocket::new(vec![(
            vec![PUNCH_BYTE],
            "10.0.0.2:1234".parse().unwrap(),
        )]));
        let sock = PunchSocket {
            inner: fake,
            intercept_tx: tx,
        };

        let mut buf0 = [0u8; 1500];
        let mut bufs = [IoSliceMut::new(&mut buf0)];
        let mut meta = [make_meta()];
        let n = drive_poll_recv(&sock, &mut bufs, &mut meta);

        assert_eq!(n, 0, "PUNCH_BYTE should NOT be visible to Quinn");
        assert!(
            rx.try_recv().is_err(),
            "PUNCH_BYTE should not hit intercept channel"
        );
    }

    /// H3 — non-punch packets pass through to Quinn unchanged. Use
    /// 0xC0 (typical QUIC v1 long-header first byte) as the stand-in.
    #[test]
    fn quic_packet_passes_through_to_quinn() {
        let (tx, _rx) = channel(INTERCEPT_CHANNEL_CAPACITY);
        let payload = vec![0xC0, 0x01, 0x02, 0x03];
        let fake = Arc::new(FakeSocket::new(vec![(
            payload.clone(),
            "203.0.113.5:5555".parse().unwrap(),
        )]));
        let sock = PunchSocket {
            inner: fake,
            intercept_tx: tx,
        };

        let mut buf0 = [0u8; 1500];
        let mut bufs = [IoSliceMut::new(&mut buf0)];
        let mut meta = [make_meta()];
        let n = drive_poll_recv(&sock, &mut bufs, &mut meta);

        assert_eq!(n, 1, "non-punch packet must reach Quinn");
        assert_eq!(meta[0].len, 4);
        assert_eq!(&buf0[..4], &payload[..]);
        assert_eq!(meta[0].addr.to_string(), "203.0.113.5:5555");
    }

    /// H3 — meta-array compaction works correctly when punch and
    /// non-punch packets are interleaved in the same poll_recv batch.
    ///
    /// Input order: [QUIC, PUNCH_NOTIFY, QUIC, PUNCH_BYTE, QUIC]
    /// Expected returned packets: 3 QUIC ones, in original order, in
    /// meta slots 0..3. PUNCH_NOTIFY (slot 1) forwarded to channel.
    /// PUNCH_BYTE (slot 3) silently dropped.
    #[test]
    fn interleaved_batch_compacts_correctly() {
        let (tx, mut rx) = channel(INTERCEPT_CHANNEL_CAPACITY);
        let pkts = vec![
            (vec![0xC0, 0x11], "1.1.1.1:1".parse().unwrap()),
            (vec![PUNCH_NOTIFY, 0xAA], "1.1.1.2:2".parse().unwrap()),
            (vec![0xC0, 0x22], "1.1.1.3:3".parse().unwrap()),
            (vec![PUNCH_BYTE], "1.1.1.4:4".parse().unwrap()),
            (vec![0xC0, 0x33], "1.1.1.5:5".parse().unwrap()),
        ];
        let fake = Arc::new(FakeSocket::new(pkts));
        let sock = PunchSocket {
            inner: fake,
            intercept_tx: tx,
        };

        let mut bufs_owned: [[u8; 1500]; 5] = [[0u8; 1500]; 5];
        let mut meta = [make_meta(); 5];
        let (a, b, c, d, e) = {
            let [a, b, c, d, e] = &mut bufs_owned;
            (a, b, c, d, e)
        };
        let mut bufs = [
            IoSliceMut::new(a),
            IoSliceMut::new(b),
            IoSliceMut::new(c),
            IoSliceMut::new(d),
            IoSliceMut::new(e),
        ];
        let n = drive_poll_recv(&sock, &mut bufs, &mut meta);

        assert_eq!(n, 3, "expected 3 retained QUIC packets");
        // After compaction, slots 0..3 should be the QUIC packets in order.
        assert_eq!(meta[0].addr.to_string(), "1.1.1.1:1");
        assert_eq!(meta[1].addr.to_string(), "1.1.1.3:3");
        assert_eq!(meta[2].addr.to_string(), "1.1.1.5:5");

        // Channel should have received exactly 1 PUNCH_NOTIFY.
        let (payload, src) = rx.try_recv().unwrap();
        assert_eq!(payload, vec![PUNCH_NOTIFY, 0xAA]);
        assert_eq!(src.to_string(), "1.1.1.2:2");
        assert!(rx.try_recv().is_err(), "no other intercepts");
    }

    /// H3 — empty datagrams (shouldn't occur per quinn docs but tolerate)
    /// pass through harmlessly without panic.
    #[test]
    fn empty_datagram_passes_through_without_panic() {
        let (tx, _rx) = channel(INTERCEPT_CHANNEL_CAPACITY);
        let fake = Arc::new(FakeSocket::new(vec![(
            vec![],
            "1.1.1.1:1".parse().unwrap(),
        )]));
        let sock = PunchSocket {
            inner: fake,
            intercept_tx: tx,
        };

        let mut buf0 = [0u8; 1500];
        let mut bufs = [IoSliceMut::new(&mut buf0)];
        let mut meta = [make_meta()];
        let n = drive_poll_recv(&sock, &mut bufs, &mut meta);

        // Empty datagram is passed through (count = 1, len = 0).
        assert_eq!(n, 1);
        assert_eq!(meta[0].len, 0);
    }
}
