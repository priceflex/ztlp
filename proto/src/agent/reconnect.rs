//! Reconnect logic for the shared-connection mode (`[tunnel]
//! reuse_connections`, which the `mobile` profile turns on).
//!
//! A phone changes network under a running agent. The shared QUIC
//! connection to a gateway then points at a path that no longer exists,
//! and nothing tells QUIC until its idle timeout fires a minute later.
//! This module holds the pieces that make a request survive that, each
//! written without a network so it can be tested here:
//!
//! * [`ReplayBuffer`]: the request bytes already forwarded on a reused
//!   connection, kept (bounded) until the first backend byte arrives.
//! * [`first_exchange`]: forwards the start of a request on a REUSED
//!   connection and, when the gateway stays silent for
//!   [`LIVENESS_WINDOW`], carries the same bytes on a fresh connection,
//!   once.
//! * [`retry_dial`]: keeps dialing with a short backoff while there is
//!   briefly no usable network.
//! * [`race_direct_relay`]: direct candidates with a short head start, the
//!   relay in parallel after it.
//! * [`ChangeSignal`]: coalesces a burst of "the network changed" calls.
//! * [`UseState`] / [`Lease`]: is anybody using a shared connection.
//!
//! Nothing here runs when connections are not shared (the desktop
//! default): every caller checks the mode first.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};

/// How long a request waits on a REUSED shared connection for any sign of
/// life from the gateway before that connection is declared dead.
///
/// A live gateway acknowledges the request within one round trip plus
/// QUIC's 25 ms ack delay, and QUIC retransmits several times inside this
/// window, so three seconds without a single datagram is not packet loss.
/// It is far below the first-byte deadline (15 s by default), so the
/// replayed request still has most of that budget.
pub(crate) const LIVENESS_WINDOW: Duration = Duration::from_secs(3);

/// Most request bytes kept per client connection for a replay.
pub(crate) const REPLAY_CAP: usize = 64 * 1024;

/// Most request bytes kept for replay by the whole process. A connection
/// that would exceed it simply is not replayable.
pub(crate) const REPLAY_TOTAL_CAP: usize = 4 * 1024 * 1024;

/// Head start the direct candidates get before the relay is dialed in
/// parallel. A same-LAN handshake (QUIC + Noise, about three round trips)
/// finishes in tens of milliseconds and a direct WAN path with a 60 ms
/// round trip in under 200 ms, so a working direct path still wins without
/// the relay ever being contacted; a dead one costs 200 ms instead of 750.
pub(crate) const RELAY_HEAD_START: Duration = Duration::from_millis(200);

/// First pause between two dial tries while the network is away; doubles
/// up to [`DIAL_RETRY_MAX_BACKOFF`].
pub(crate) const DIAL_RETRY_FIRST_BACKOFF: Duration = Duration::from_millis(250);
pub(crate) const DIAL_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(1);

/// Longest a single dial try may take while retrying. A try started with
/// no network never completes (its first packets were lost and the relay
/// never learned the route), so it is abandoned and started again.
pub(crate) const DIAL_ATTEMPT_CAP: Duration = Duration::from_secs(5);

/// After its budget ran out, a retried dial reports the failure this much
/// later. The caller's own first-byte timer started a moment before the
/// dial's and must fire first, so the client gets the deadline's answer
/// (the 504 page), not a bare close a few microseconds earlier.
pub(crate) const DIAL_GIVE_UP_GRACE: Duration = Duration::from_millis(100);

/// Calls to "the network changed" closer together than this are one event
/// (the first acts at once, the rest collapse into one more run).
pub(crate) const NETWORK_CHANGE_COALESCE: Duration = Duration::from_millis(250);

/// Sites re-dialed in the background after a network change, at most.
pub(crate) const PREWARM_MAX_SITES: usize = 8;

/// Budget of one background re-dial.
pub(crate) const PREWARM_DIAL_BUDGET: Duration = Duration::from_secs(10);

/// Mobile profile: a shared connection nobody has used for this long is
/// closed (its 15 s keep-alive stops with it); the next request dials.
pub(crate) const MOBILE_IDLE_CLOSE: Duration = Duration::from_secs(120);

/// How often idle shared connections are looked for.
pub(crate) const IDLE_REAP_INTERVAL: Duration = Duration::from_secs(15);

// ── Replay buffer ─────────────────────────────────────────────────────────

/// A byte budget shared by every [`ReplayBuffer`] of the process.
pub(crate) struct ReplayBudget {
    used: AtomicUsize,
    cap: usize,
}

impl ReplayBudget {
    pub(crate) const fn new(cap: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            cap,
        }
    }

    fn reserve(&self, n: usize) -> bool {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |u| {
                u.checked_add(n).filter(|total| *total <= self.cap)
            })
            .is_ok()
    }

    fn give_back(&self, n: usize) {
        self.used.fetch_sub(n, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::SeqCst)
    }
}

static GLOBAL_REPLAY_BUDGET: ReplayBudget = ReplayBudget::new(REPLAY_TOTAL_CAP);

/// The request bytes forwarded so far on one client connection, kept so
/// they can be sent again on a fresh tunnel connection.
///
/// It holds at most `cap` bytes. Recording past the cap (or past the
/// process-wide budget) frees everything and the buffer stays unusable:
/// a request that large is never replayed. [`ReplayBuffer::release`] frees
/// it for good once a replay can no longer happen.
pub(crate) struct ReplayBuffer {
    buf: Vec<u8>,
    cap: usize,
    usable: bool,
    budget: &'static ReplayBudget,
}

impl ReplayBuffer {
    pub(crate) fn new(cap: usize) -> Self {
        Self::with_budget(cap, &GLOBAL_REPLAY_BUDGET)
    }

    pub(crate) fn with_budget(cap: usize, budget: &'static ReplayBudget) -> Self {
        Self {
            buf: Vec::new(),
            cap,
            usable: true,
            budget,
        }
    }

    /// Remember `bytes`. Returns `false` (and frees the buffer) when they
    /// do not fit.
    pub(crate) fn record(&mut self, bytes: &[u8]) -> bool {
        if !self.usable {
            return false;
        }
        if self.buf.len() + bytes.len() > self.cap || !self.budget.reserve(bytes.len()) {
            self.release();
            return false;
        }
        // No amortised doubling: the allocation never exceeds the cap.
        self.buf.reserve_exact(bytes.len());
        self.buf.extend_from_slice(bytes);
        true
    }

    /// Whether everything forwarded so far is still held.
    pub(crate) fn can_replay(&self) -> bool {
        self.usable
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Bytes of memory held right now.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.buf.capacity()
    }

    /// Free the buffer; nothing can be replayed afterwards.
    pub(crate) fn release(&mut self) {
        self.budget.give_back(self.buf.len());
        self.buf = Vec::new();
        self.usable = false;
    }
}

impl Drop for ReplayBuffer {
    fn drop(&mut self) {
        self.budget.give_back(self.buf.len());
    }
}

// ── First exchange on a reused connection ─────────────────────────────────

/// The sending half of a tunnel data stream, in ZTLP frames.
pub(crate) trait FrameSend: Send {
    fn send_frame(&mut self, payload: &[u8]) -> impl Future<Output = Result<(), String>> + Send;
    /// No more request bytes will follow.
    fn finish(&mut self);
}

/// The receiving half of a tunnel data stream, in ZTLP frames.
pub(crate) trait FrameRecv: Send + 'static {
    fn recv_frame(&mut self) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
}

/// One data stream on a tunnel connection.
pub(crate) struct Leg<S, R, K> {
    pub send: S,
    pub recv: R,
    /// Whatever must stay alive as long as the stream is used.
    pub keep: K,
    /// Datagrams received from the gateway on this connection so far. It
    /// only ever grows; a value that stands still means the path is dead.
    pub progress: Box<dyn Fn() -> u64 + Send + Sync>,
}

/// The first backend frame: resolves to the receive half and that frame
/// (or the error that ended the stream before it).
pub(crate) type FirstFrame<R> = Pin<Box<dyn Future<Output = (R, Result<Vec<u8>, String>)> + Send>>;

/// Where [`first_exchange`] leaves a connection.
pub(crate) struct Handoff<S, R, K> {
    pub send: S,
    pub keep: K,
    /// Await this before reading anything else from the tunnel. It may
    /// already be complete.
    pub first: FirstFrame<R>,
    /// The client closed its sending side (and `send` was finished).
    pub client_eof: bool,
    /// The request was moved to a freshly dialed connection.
    pub replayed: bool,
}

/// Why [`first_exchange`] gave a connection up.
#[derive(Debug, Clone)]
pub(crate) struct Dead {
    pub reason: String,
    /// Nothing came back within the window (as opposed to the stream
    /// failing): the whole connection is dead and may be closed.
    pub silent: bool,
}

/// Why [`first_exchange`] ended without a usable tunnel.
#[derive(Debug)]
pub(crate) enum ExchangeEnd {
    /// The client closed before anything came back (`eof_ends` only).
    ClientClosed,
    /// The connection was dead and the fresh dial failed too.
    RedialFailed(String),
}

pub(crate) struct ExchangeConfig {
    pub window: Duration,
    pub cap: usize,
    /// Treat the client closing its sending side as the end of the
    /// connection (the plain path does); otherwise the stream is finished
    /// and the answer is still awaited.
    pub eof_ends: bool,
}

fn first_frame_of<R: FrameRecv>(mut recv: R) -> FirstFrame<R> {
    Box::pin(async move {
        let r = recv.recv_frame().await;
        (recv, r)
    })
}

async fn send_chunks<S: FrameSend>(send: &mut S, bytes: &[u8]) -> Result<(), String> {
    // A frame carries at most 64 KiB; stay well under it.
    for part in bytes.chunks(60_000) {
        send.send_frame(part).await?;
    }
    Ok(())
}

/// Carry the start of a client request on a REUSED shared connection.
///
/// Client bytes are read, passed through `transform` (`None` = the client
/// closed; the plain path passes them through unchanged) and forwarded,
/// while the first backend frame is awaited. The connection is treated as
/// dead when, with everything forwarded so far still in the replay buffer:
///
/// * the stream fails before the first backend frame, or
/// * `cfg.window` passes after the first forwarded byte with no backend
///   frame, and
/// * in both cases not one datagram arrived from the gateway since that
///   first byte was forwarded (`Leg::progress` stood still). A gateway
///   that acknowledged anything may have the request, so it is never sent
///   twice.
///
/// Then `redial` is called (once, with the reason), the held bytes are
/// sent on the new leg and the function returns. It also returns as soon
/// as a replay stops being possible: the first backend frame arrived, the
/// request outgrew the buffer, or the gateway showed it is alive. The
/// caller continues with its normal pumps from the returned [`Handoff`].
/// The replay buffer is freed before returning in every case.
pub(crate) async fn first_exchange<C, S, R, K, D, DFut>(
    client: &mut C,
    transform: &mut (dyn FnMut(Option<&[u8]>) -> Vec<u8> + Send),
    initial: &[u8],
    leg: Leg<S, R, K>,
    cfg: ExchangeConfig,
    redial: D,
) -> Result<Handoff<S, R, K>, ExchangeEnd>
where
    C: AsyncRead + Unpin + Send,
    S: FrameSend,
    R: FrameRecv,
    K: Send,
    D: FnOnce(Dead) -> DFut + Send,
    DFut: Future<Output = Result<Leg<S, R, K>, String>> + Send,
{
    let Leg {
        mut send,
        recv,
        keep,
        progress,
    } = leg;
    let mut first = first_frame_of(recv);
    let mut replay = ReplayBuffer::new(cfg.cap);
    let mut client_eof = false;
    let mut finished = false;
    // Set when the first request byte is forwarded.
    let mut forwarded: Option<(tokio::time::Instant, u64)> = None;
    // 16 KiB at a time is plenty for a request head; the steady-state
    // pumps use their own larger buffer afterwards.
    let mut buf = vec![0u8; 16 * 1024];
    let mut pending: Vec<u8> = if initial.is_empty() {
        Vec::new()
    } else {
        transform(Some(initial))
    };

    // Why the connection is given up, or `None` to hand over as is.
    let dead: Option<Dead> = loop {
        // Forward what is waiting (the head the caller already read, or
        // the bytes of the last read).
        if !pending.is_empty() {
            let out = std::mem::take(&mut pending);
            if forwarded.is_none() {
                forwarded = Some((tokio::time::Instant::now(), progress()));
            }
            let fits = replay.record(&out);
            let deadline = forwarded.map(|(at, _)| at + cfg.window).unwrap();
            let mut timed_out = false;
            let sent = if fits {
                // Bounded: a dead connection's send window may be full.
                match tokio::time::timeout_at(deadline, send_chunks(&mut send, &out)).await {
                    Ok(r) => r,
                    Err(_) => {
                        timed_out = true;
                        Err(format!(
                            "the request could not be sent within {:?}",
                            cfg.window
                        ))
                    }
                }
            } else {
                send_chunks(&mut send, &out).await
            };
            match sent {
                Ok(()) if fits => {}
                // Too large to replay: from here on it is an ordinary
                // connection.
                Ok(()) => break None,
                Err(e) => {
                    let silent = matches!(forwarded, Some((_, base)) if progress() == base);
                    if fits && silent {
                        break Some(Dead {
                            reason: e,
                            silent: timed_out,
                        });
                    }
                    // Not replayable: the pumps will meet the same error.
                    break None;
                }
            }
        }
        if client_eof && !finished {
            send.finish();
            finished = true;
        }

        let window_end = forwarded.map(|(at, _)| at + cfg.window);
        tokio::select! {
            biased;
            (recv, r) = &mut first => {
                match r {
                    Ok(frame) => {
                        replay.release();
                        return Ok(Handoff {
                            send,
                            keep,
                            first: Box::pin(async move { (recv, Ok(frame)) }),
                            client_eof,
                            replayed: false,
                        });
                    }
                    Err(e) => {
                        // Nothing forwarded yet is as good as silence:
                        // there is nothing the gateway could have run.
                        let silent = match forwarded {
                            Some((_, base)) => progress() == base,
                            None => true,
                        };
                        if replay.can_replay() && silent {
                            break Some(Dead {
                                reason: e,
                                silent: false,
                            });
                        }
                        replay.release();
                        return Ok(Handoff {
                            send,
                            keep,
                            first: Box::pin(async move { (recv, Err(e)) }),
                            client_eof,
                            replayed: false,
                        });
                    }
                }
            }
            _ = async { tokio::time::sleep_until(window_end.unwrap()).await },
                if window_end.is_some() =>
            {
                let (_, base) = forwarded.unwrap();
                if progress() != base {
                    // The gateway is there; the backend is just slow.
                    break None;
                }
                break Some(Dead {
                    reason: format!("no answer within {:?}", cfg.window),
                    silent: true,
                });
            }
            n = client.read(&mut buf), if !client_eof => {
                match n {
                    Ok(n) if n > 0 => pending = transform(Some(&buf[..n])),
                    _ => {
                        if cfg.eof_ends {
                            return Err(ExchangeEnd::ClientClosed);
                        }
                        // What the transform still held goes out like
                        // any other bytes; the stream is finished after.
                        client_eof = true;
                        pending = transform(None);
                    }
                }
            }
        }
    };
    drop(buf);

    let Some(dead) = dead else {
        replay.release();
        if client_eof && !finished {
            send.finish();
        }
        return Ok(Handoff {
            send,
            keep,
            first,
            client_eof,
            replayed: false,
        });
    };

    // The old leg goes away first, so its stream is reset before the
    // request is sent again.
    drop(first);
    drop(send);
    drop(keep);
    let fresh = redial(dead).await.map_err(ExchangeEnd::RedialFailed)?;
    let Leg {
        mut send,
        recv,
        keep,
        progress: _,
    } = fresh;
    let sent = send_chunks(&mut send, replay.bytes()).await;
    replay.release();
    if client_eof {
        send.finish();
    }
    let first: FirstFrame<R> = match sent {
        Ok(()) => first_frame_of(recv),
        Err(e) => Box::pin(async move { (recv, Err(e)) }),
    };
    Ok(Handoff {
        send,
        keep,
        first,
        client_eof,
        replayed: true,
    })
}

// ── Dial retry ────────────────────────────────────────────────────────────

pub(crate) type DialError = Box<dyn std::error::Error + Send + Sync>;

/// Run `attempt` until it succeeds, fails for good (`is_permanent`), or
/// `give_up_at` passes.
///
/// `give_up_at = None` is exactly one unbounded try (callers without a
/// deadline). Otherwise a try is abandoned after [`DIAL_ATTEMPT_CAP`], and
/// tries are separated by a pause that starts at
/// [`DIAL_RETRY_FIRST_BACKOFF`] and doubles up to
/// [`DIAL_RETRY_MAX_BACKOFF`]. A change of `epoch` (the network changed)
/// abandons the running try and starts the next one at once. The last
/// error is returned [`DIAL_GIVE_UP_GRACE`] after `give_up_at`, not before,
/// so the caller's own deadline handling (the 504 page) is what the client
/// sees.
pub(crate) async fn retry_dial<T, F, Fut>(
    what: &str,
    give_up_at: Option<tokio::time::Instant>,
    mut epoch: Option<tokio::sync::watch::Receiver<u64>>,
    is_permanent: impl Fn(&str) -> bool,
    mut attempt: F,
) -> Result<T, DialError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, DialError>>,
{
    let Some(give_up_at) = give_up_at else {
        return attempt().await;
    };
    async fn changed(epoch: &mut Option<tokio::sync::watch::Receiver<u64>>) {
        match epoch {
            Some(rx) => {
                if rx.changed().await.is_err() {
                    std::future::pending::<()>().await
                }
            }
            None => std::future::pending().await,
        }
    }
    if let Some(rx) = epoch.as_mut() {
        rx.borrow_and_update();
    }
    let mut backoff = DIAL_RETRY_FIRST_BACKOFF;
    let mut last: Option<DialError> = None;
    loop {
        let left = give_up_at.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return match last {
                Some(e) => {
                    tokio::time::sleep(DIAL_GIVE_UP_GRACE).await;
                    Err(e)
                }
                None => Err(format!("no tunnel for {what} within the first-byte deadline").into()),
            };
        }
        let cap = left.min(DIAL_ATTEMPT_CAP);
        let result = tokio::select! {
            r = tokio::time::timeout(cap, attempt()) => match r {
                Ok(r) => r,
                Err(_) => Err(format!("dial attempt did not finish within {cap:?}").into()),
            },
            _ = changed(&mut epoch) => {
                tracing::info!("dial for {what}: the network changed, dialing again");
                continue;
            }
        };
        let err = match result {
            Ok(t) => return Ok(t),
            Err(e) => e,
        };
        let msg = err.to_string();
        if is_permanent(&msg) {
            return Err(err);
        }
        let left = give_up_at.saturating_duration_since(tokio::time::Instant::now());
        let pause = backoff.min(left);
        if !pause.is_zero() {
            tracing::info!(
                "dial for {what} failed ({msg}); trying again in {pause:?} ({left:?} left)"
            );
            tokio::select! {
                _ = tokio::time::sleep(pause) => {}
                _ = changed(&mut epoch) => {}
            }
        }
        last = Some(err);
        backoff = (backoff * 2).min(DIAL_RETRY_MAX_BACKOFF);
    }
}

// ── Direct with a head start, then the relay in parallel ──────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RaceWinner {
    Direct,
    Relay,
}

/// Start `direct`; when it has not finished after `head_start` (or failed
/// earlier), start `relay` next to it and take whichever succeeds first.
/// `direct` is polled first, so it wins when both are ready together. The
/// loser is dropped, which cancels its handshake or closes its connection.
/// Both failing returns both errors.
pub(crate) async fn race_direct_relay<T, E, DF, RF, RFut>(
    direct: DF,
    relay: RF,
    head_start: Duration,
) -> Result<(T, RaceWinner), (E, E)>
where
    DF: Future<Output = Result<T, E>>,
    RF: FnOnce() -> RFut,
    RFut: Future<Output = Result<T, E>>,
{
    tokio::pin!(direct);
    let mut direct_err: Option<E> = None;
    tokio::select! {
        biased;
        r = &mut direct => match r {
            Ok(t) => return Ok((t, RaceWinner::Direct)),
            Err(e) => direct_err = Some(e),
        },
        _ = tokio::time::sleep(head_start) => {}
    }
    let relay = relay();
    tokio::pin!(relay);
    let mut relay_err: Option<E> = None;
    loop {
        tokio::select! {
            biased;
            r = &mut direct, if direct_err.is_none() => match r {
                Ok(t) => return Ok((t, RaceWinner::Direct)),
                Err(e) => direct_err = Some(e),
            },
            r = &mut relay, if relay_err.is_none() => match r {
                Ok(t) => return Ok((t, RaceWinner::Relay)),
                Err(e) => relay_err = Some(e),
            },
        }
        if direct_err.is_some() && relay_err.is_some() {
            return Err((direct_err.take().unwrap(), relay_err.take().unwrap()));
        }
    }
}

// ── "The network changed", coalesced ──────────────────────────────────────

/// Collects calls that may come from any thread, in bursts, and has one
/// task act on them: the first call of a burst at once, everything that
/// arrives during the following window as one more run.
pub(crate) struct ChangeSignal {
    pending: AtomicBool,
    notify: tokio::sync::Notify,
    servers: AtomicUsize,
    effective: AtomicU64,
}

impl ChangeSignal {
    pub(crate) const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            notify: tokio::sync::Notify::const_new(),
            servers: AtomicUsize::new(0),
            effective: AtomicU64::new(0),
        }
    }

    /// Record a change. Returns `false` (and does nothing) when no task is
    /// serving the signal. Never blocks.
    pub(crate) fn raise(&self) -> bool {
        if self.servers.load(Ordering::SeqCst) == 0 {
            return false;
        }
        self.pending.store(true, Ordering::SeqCst);
        self.notify.notify_one();
        true
    }

    /// How many times the action has run.
    pub(crate) fn effective(&self) -> u64 {
        self.effective.load(Ordering::SeqCst)
    }

    /// Whether a task is serving the signal.
    #[cfg(test)]
    pub(crate) fn is_served(&self) -> bool {
        self.servers.load(Ordering::SeqCst) > 0
    }

    /// Serve the signal until the future is dropped.
    pub(crate) async fn serve(&self, window: Duration, mut action: impl FnMut()) {
        struct Serving<'a>(&'a ChangeSignal);
        impl Drop for Serving<'_> {
            fn drop(&mut self) {
                self.0.servers.fetch_sub(1, Ordering::SeqCst);
            }
        }
        // Nothing raised before this task existed is acted on.
        self.pending.store(false, Ordering::SeqCst);
        self.servers.fetch_add(1, Ordering::SeqCst);
        let _serving = Serving(self);
        loop {
            self.notify.notified().await;
            if !self.pending.swap(false, Ordering::SeqCst) {
                continue;
            }
            self.effective.fetch_add(1, Ordering::SeqCst);
            action();
            tokio::time::sleep(window).await;
        }
    }
}

// ── Is a shared connection in use ─────────────────────────────────────────

/// Use count of one shared connection and when it last became unused.
pub(crate) struct UseState {
    uses: AtomicUsize,
    idle_since: Mutex<Instant>,
}

impl UseState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            uses: AtomicUsize::new(0),
            idle_since: Mutex::new(Instant::now()),
        })
    }

    /// Mark one more user; the returned lease ends the use when dropped.
    pub(crate) fn acquire(self: &Arc<Self>) -> Lease {
        self.uses.fetch_add(1, Ordering::SeqCst);
        Lease(self.clone())
    }

    pub(crate) fn in_use(&self) -> bool {
        self.uses.load(Ordering::SeqCst) > 0
    }

    /// How long nobody has used the connection; `None` while in use.
    pub(crate) fn idle_for(&self, now: Instant) -> Option<Duration> {
        if self.in_use() {
            return None;
        }
        let since = *self.idle_since.lock().unwrap_or_else(|p| p.into_inner());
        Some(now.saturating_duration_since(since))
    }
}

/// One client connection's use of a shared connection.
pub(crate) struct Lease(Arc<UseState>);

impl Drop for Lease {
    fn drop(&mut self) {
        *self.0.idle_since.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
        self.0.uses.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::mpsc;

    fn budget(cap: usize) -> &'static ReplayBudget {
        Box::leak(Box::new(ReplayBudget::new(cap)))
    }

    // ---- replay buffer ----

    #[test]
    fn replay_buffer_holds_what_was_recorded_in_order() {
        let mut b = ReplayBuffer::with_budget(16, budget(1024));
        assert!(b.can_replay());
        assert!(b.record(b"GET / "));
        assert!(b.record(b"HTTP/1.1"));
        assert_eq!(b.bytes(), b"GET / HTTP/1.1");
        assert!(b.can_replay());
    }

    #[test]
    fn replay_buffer_never_holds_more_than_its_cap() {
        let bud = budget(1 << 20);
        let mut b = ReplayBuffer::with_budget(REPLAY_CAP, bud);
        let chunk = vec![7u8; 1000];
        let mut recorded = 0;
        while b.record(&chunk) {
            recorded += chunk.len();
            assert!(b.held() <= REPLAY_CAP, "{} bytes held", b.held());
        }
        assert_eq!(recorded, 65_000, "the 66th kilobyte does not fit");
        // going over the cap frees everything and stays that way
        assert!(!b.can_replay());
        assert_eq!(b.held(), 0);
        assert_eq!(b.bytes(), b"");
        assert!(!b.record(b"x"));
        assert_eq!(bud.used(), 0);
    }

    #[test]
    fn exactly_the_cap_fits_one_byte_more_does_not() {
        let mut b = ReplayBuffer::with_budget(8, budget(64));
        assert!(b.record(b"12345678"));
        assert!(b.can_replay());
        let mut b = ReplayBuffer::with_budget(8, budget(64));
        assert!(!b.record(b"123456789"));
        assert!(!b.can_replay());
    }

    #[test]
    fn release_frees_the_memory_and_the_budget() {
        let bud = budget(1024);
        let mut b = ReplayBuffer::with_budget(512, bud);
        assert!(b.record(&[1u8; 300]));
        assert_eq!(bud.used(), 300);
        assert!(b.held() >= 300);
        b.release();
        assert_eq!(b.held(), 0);
        assert_eq!(bud.used(), 0);
        assert!(!b.can_replay());
        // releasing or dropping again does not give the budget back twice
        b.release();
        drop(b);
        assert_eq!(bud.used(), 0);
    }

    #[test]
    fn dropping_a_buffer_gives_its_budget_back() {
        let bud = budget(1024);
        {
            let mut b = ReplayBuffer::with_budget(512, bud);
            assert!(b.record(&[1u8; 200]));
            assert_eq!(bud.used(), 200);
        }
        assert_eq!(bud.used(), 0);
    }

    #[test]
    fn the_process_wide_budget_bounds_all_buffers_together() {
        let bud = budget(1000);
        let mut a = ReplayBuffer::with_budget(800, bud);
        let mut b = ReplayBuffer::with_budget(800, bud);
        assert!(a.record(&[0u8; 700]));
        assert!(!b.record(&[0u8; 400]), "700 + 400 is over the total");
        assert!(!b.can_replay());
        assert_eq!(bud.used(), 700);
        drop(a);
        let mut c = ReplayBuffer::with_budget(800, bud);
        assert!(c.record(&[0u8; 400]));
    }

    #[test]
    fn the_caps_are_the_documented_ones() {
        assert_eq!(REPLAY_CAP, 64 * 1024);
        assert!(REPLAY_TOTAL_CAP <= 4 * 1024 * 1024);
        assert!(LIVENESS_WINDOW >= Duration::from_secs(3));
        assert!(LIVENESS_WINDOW <= Duration::from_secs(4));
        assert!(RELAY_HEAD_START >= Duration::from_millis(150));
        assert!(RELAY_HEAD_START <= Duration::from_millis(250));
    }

    // ---- first exchange: in-memory legs ----

    /// What the "gateway" side of a fake leg sees and controls.
    struct Far {
        /// Frames the agent sent on this leg.
        got: mpsc::UnboundedReceiver<Vec<u8>>,
        /// Frames (or a stream error) for the agent.
        answer: mpsc::UnboundedSender<Result<Vec<u8>, String>>,
        /// Datagram counter the agent reads as `progress`.
        datagrams: Arc<AtomicU64>,
        finished: Arc<AtomicBool>,
    }

    struct FakeSend {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        finished: Arc<AtomicBool>,
    }
    struct FakeRecv(mpsc::UnboundedReceiver<Result<Vec<u8>, String>>);

    impl FrameSend for FakeSend {
        async fn send_frame(&mut self, payload: &[u8]) -> Result<(), String> {
            self.tx
                .send(payload.to_vec())
                .map_err(|_| "stream closed".to_string())
        }
        fn finish(&mut self) {
            self.finished.store(true, Ordering::SeqCst);
        }
    }
    impl FrameRecv for FakeRecv {
        async fn recv_frame(&mut self) -> Result<Vec<u8>, String> {
            match self.0.recv().await {
                Some(r) => r,
                None => std::future::pending().await,
            }
        }
    }

    type TestLeg = Leg<FakeSend, FakeRecv, &'static str>;

    fn leg(tag: &'static str) -> (TestLeg, Far) {
        let (tx, got) = mpsc::unbounded_channel();
        let (answer, rx) = mpsc::unbounded_channel();
        let datagrams = Arc::new(AtomicU64::new(100));
        let finished = Arc::new(AtomicBool::new(false));
        let d = datagrams.clone();
        (
            Leg {
                send: FakeSend {
                    tx,
                    finished: finished.clone(),
                },
                recv: FakeRecv(rx),
                keep: tag,
                progress: Box::new(move || d.load(Ordering::SeqCst)),
            },
            Far {
                got,
                answer,
                datagrams,
                finished,
            },
        )
    }

    fn cfg() -> ExchangeConfig {
        ExchangeConfig {
            window: LIVENESS_WINDOW,
            cap: REPLAY_CAP,
            eof_ends: false,
        }
    }

    fn passthrough() -> impl FnMut(Option<&[u8]>) -> Vec<u8> + Send {
        |c: Option<&[u8]>| c.map(|b| b.to_vec()).unwrap_or_default()
    }

    fn drain(far: &mut Far) -> Vec<u8> {
        let mut all = Vec::new();
        while let Ok(f) = far.got.try_recv() {
            all.extend_from_slice(&f);
        }
        all
    }

    /// A redial that must not happen.
    async fn no_redial(dead: Dead) -> Result<TestLeg, String> {
        panic!("unexpected redial: {dead:?}")
    }

    const REQ: &[u8] = b"GET /page HTTP/1.1\r\nHost: wiki.example.ztlp\r\n\r\n";

    #[tokio::test(start_paused = true)]
    async fn a_silent_reused_connection_is_replaced_within_the_liveness_window() {
        let (dead, mut dead_far) = leg("dead");
        let (fresh, mut fresh_far) = leg("fresh");
        let (mut client, mut agent_side) = tokio::io::duplex(4096);
        client.write_all(REQ).await.unwrap();

        let started = tokio::time::Instant::now();
        let mut t = passthrough();
        let redialed_at = Arc::new(Mutex::new(None));
        let at = redialed_at.clone();
        let h = first_exchange(
            &mut agent_side,
            &mut t,
            b"",
            dead,
            cfg(),
            |why| async move {
                assert!(why.silent, "the whole connection may be closed");
                *at.lock().unwrap() = Some((tokio::time::Instant::now(), why.reason));
                Ok(fresh)
            },
        )
        .await
        .ok()
        .unwrap();

        let (when, reason) = redialed_at.lock().unwrap().clone().unwrap();
        assert_eq!(when - started, LIVENESS_WINDOW, "not the 60 s idle timeout");
        assert!(reason.contains("no answer within 3s"), "{reason}");
        assert!(h.replayed);
        assert_eq!(h.keep, "fresh");
        // the same request went out on both, whole and once
        assert_eq!(drain(&mut dead_far), REQ);
        assert_eq!(drain(&mut fresh_far), REQ);
        // and the answer comes from the fresh one; the client stayed open
        fresh_far
            .answer
            .send(Ok(b"HTTP/1.1 200 OK".to_vec()))
            .unwrap();
        let (_recv, first) = h.first.await;
        assert_eq!(first.unwrap(), b"HTTP/1.1 200 OK");
        client.write_all(b"more").await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_head_the_caller_already_read_is_forwarded_and_replayed_too() {
        let (dead, mut dead_far) = leg("dead");
        let (fresh, mut fresh_far) = leg("fresh");
        let (_client, mut agent_side) = tokio::io::duplex(4096);
        // the transform (the header stamper on the TLS path) sees the head
        let mut t = |c: Option<&[u8]>| {
            c.map(|b| [b"X:".as_slice(), b].concat())
                .unwrap_or_default()
        };
        let h = first_exchange(&mut agent_side, &mut t, REQ, dead, cfg(), |_| async {
            Ok(fresh)
        })
        .await
        .ok()
        .unwrap();
        assert!(h.replayed);
        let want = [b"X:".as_slice(), REQ].concat();
        assert_eq!(drain(&mut dead_far), want);
        assert_eq!(drain(&mut fresh_far), want, "replayed as it was sent");
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_inside_the_window_means_no_redial_and_frees_the_buffer() {
        let (live, mut far) = leg("live");
        let (mut client, mut agent_side) = tokio::io::duplex(4096);
        client.write_all(REQ).await.unwrap();
        let answer = far.answer.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            answer.send(Ok(b"HTTP/1.1 200 OK".to_vec())).unwrap();
        });
        let before = GLOBAL_REPLAY_BUDGET.used();
        let mut t = passthrough();
        let h = first_exchange(&mut agent_side, &mut t, b"", live, cfg(), no_redial)
            .await
            .ok()
            .unwrap();
        assert!(!h.replayed);
        assert_eq!(h.keep, "live");
        assert_eq!(drain(&mut far), REQ);
        let (_recv, first) = h.first.await;
        assert_eq!(first.unwrap(), b"HTTP/1.1 200 OK");
        // nothing of this request is held any more (other tests may hold
        // their own bytes at the same moment, never less than before)
        assert!(GLOBAL_REPLAY_BUDGET.used() <= before + REPLAY_CAP);
    }

    #[tokio::test(start_paused = true)]
    async fn a_gateway_that_is_alive_but_slow_is_not_redialed() {
        // The gateway acknowledged the request (datagrams arrived); the
        // backend takes ten seconds. Sending the request again could run
        // it twice.
        let (live, far) = leg("live");
        let (mut client, mut agent_side) = tokio::io::duplex(4096);
        client.write_all(REQ).await.unwrap();
        let datagrams = far.datagrams.clone();
        let answer = far.answer.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            datagrams.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(10)).await;
            answer.send(Ok(b"slow".to_vec())).unwrap();
        });
        let started = tokio::time::Instant::now();
        let mut t = passthrough();
        let h = first_exchange(&mut agent_side, &mut t, b"", live, cfg(), no_redial)
            .await
            .ok()
            .unwrap();
        assert!(!h.replayed);
        assert_eq!(
            started.elapsed(),
            LIVENESS_WINDOW,
            "handed over at the window"
        );
        let (_recv, first) = h.first.await;
        assert_eq!(first.unwrap(), b"slow", "the same stream still answers");
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_replayed_once_a_backend_byte_arrived() {
        // First byte, then the stream dies: the caller owns it from here
        // and there is no second dial.
        let (live, far) = leg("live");
        let (mut client, mut agent_side) = tokio::io::duplex(4096);
        client.write_all(REQ).await.unwrap();
        far.answer
            .send(Ok(b"HTTP/1.1 200 OK\r\n".to_vec()))
            .unwrap();
        far.answer.send(Err("connection lost".into())).unwrap();
        let mut t = passthrough();
        let h = first_exchange(&mut agent_side, &mut t, b"", live, cfg(), no_redial)
            .await
            .ok()
            .unwrap();
        assert!(!h.replayed);
        let (mut recv, first) = h.first.await;
        assert_eq!(first.unwrap(), b"HTTP/1.1 200 OK\r\n");
        assert_eq!(recv.recv_frame().await.unwrap_err(), "connection lost");
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_larger_than_the_cap_is_not_replayed() {
        let (dead, mut far) = leg("dead");
        let (mut client, mut agent_side) = tokio::io::duplex(256 * 1024);
        let big = vec![b'u'; REPLAY_CAP + 1];
        client.write_all(&big).await.unwrap();
        let before = GLOBAL_REPLAY_BUDGET.used();
        let mut t = passthrough();
        let h = first_exchange(&mut agent_side, &mut t, b"", dead, cfg(), no_redial)
            .await
            .ok()
            .unwrap();
        assert!(!h.replayed);
        // every byte was still forwarded, in order
        assert_eq!(drain(&mut far), big);
        assert!(GLOBAL_REPLAY_BUDGET.used() <= before + REPLAY_CAP);
        // and the connection now behaves as before: it waits on that leg
        // for as long as the caller lets it (no redial at the window)
        let waited = tokio::time::timeout(Duration::from_secs(30), h.first).await;
        assert!(waited.is_err(), "still waiting on the original stream");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_error_with_no_sign_of_life_is_redialed_at_once() {
        // What `ztlp_ios_network_changed` causes: the shared connection is
        // closed under a request that was waiting for its first byte.
        let (dead, far) = leg("dead");
        let (fresh, mut fresh_far) = leg("fresh");
        let (mut client, mut agent_side) = tokio::io::duplex(4096);
        client.write_all(REQ).await.unwrap();
        let answer = far.answer.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            answer.send(Err("closed: network changed".into())).unwrap();
        });
        let started = tokio::time::Instant::now();
        let mut t = passthrough();
        let h = first_exchange(
            &mut agent_side,
            &mut t,
            b"",
            dead,
            cfg(),
            |why| async move {
                assert_eq!(why.reason, "closed: network changed");
                assert!(
                    !why.silent,
                    "a stream error says nothing about other streams"
                );
                Ok(fresh)
            },
        )
        .await
        .ok()
        .unwrap();
        assert_eq!(started.elapsed(), Duration::from_millis(500));
        assert!(h.replayed);
        assert_eq!(drain(&mut fresh_far), REQ);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_error_after_the_gateway_acknowledged_is_not_replayed() {
        let (live, far) = leg("live");
        let (mut client, mut agent_side) = tokio::io::duplex(4096);
        client.write_all(REQ).await.unwrap();
        let datagrams = far.datagrams.clone();
        let answer = far.answer.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            datagrams.fetch_add(3, Ordering::SeqCst);
            answer.send(Err("reset by gateway".into())).unwrap();
        });
        let mut t = passthrough();
        let h = first_exchange(&mut agent_side, &mut t, b"", live, cfg(), no_redial)
            .await
            .ok()
            .unwrap();
        assert!(!h.replayed);
        let (_recv, first) = h.first.await;
        assert_eq!(first.unwrap_err(), "reset by gateway");
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_with_no_request_yet_is_not_timed() {
        // A browser preconnect: nothing sent, so nothing to wait for. The
        // window starts with the first request byte.
        let (dead, mut dead_far) = leg("dead");
        let (fresh, mut fresh_far) = leg("fresh");
        let (mut client, mut agent_side) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            client.write_all(REQ).await.unwrap();
            client
        });
        let started = tokio::time::Instant::now();
        let mut t = passthrough();
        let h = first_exchange(&mut agent_side, &mut t, b"", dead, cfg(), |_| async {
            Ok(fresh)
        })
        .await
        .ok()
        .unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(20) + LIVENESS_WINDOW);
        assert!(h.replayed);
        assert_eq!(drain(&mut dead_far), REQ);
        assert_eq!(drain(&mut fresh_far), REQ);
        drop(writer);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_redial_is_reported_and_nothing_else_is_tried() {
        let (dead, _far) = leg("dead");
        let (mut client, mut agent_side) = tokio::io::duplex(4096);
        client.write_all(REQ).await.unwrap();
        let mut t = passthrough();
        let end = first_exchange(&mut agent_side, &mut t, b"", dead, cfg(), |_| async {
            Err::<TestLeg, _>("all 2 dial attempts failed".to_string())
        })
        .await
        .err()
        .unwrap();
        match end {
            ExchangeEnd::RedialFailed(e) => assert_eq!(e, "all 2 dial attempts failed"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn client_close_ends_the_plain_path_and_finishes_the_stream_otherwise() {
        // plain path (port 80): the client going away ends it
        let (l, _far) = leg("a");
        let (client, mut agent_side) = tokio::io::duplex(4096);
        drop(client);
        let mut t = passthrough();
        let plain = ExchangeConfig {
            eof_ends: true,
            ..cfg()
        };
        let end = first_exchange(&mut agent_side, &mut t, b"", l, plain, no_redial)
            .await
            .err()
            .unwrap();
        assert!(matches!(end, ExchangeEnd::ClientClosed));

        // TLS path: the request is complete, the answer is still wanted
        let (l, mut far) = leg("b");
        let (mut client, mut agent_side) = tokio::io::duplex(4096);
        client.write_all(REQ).await.unwrap();
        client.shutdown().await.unwrap();
        let answer = far.answer.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            answer.send(Ok(b"ok".to_vec())).unwrap();
        });
        let mut t = passthrough();
        let h = first_exchange(&mut agent_side, &mut t, b"", l, cfg(), no_redial)
            .await
            .ok()
            .unwrap();
        assert!(h.client_eof);
        assert!(far.finished.load(Ordering::SeqCst));
        assert_eq!(drain(&mut far), REQ);
    }

    // ---- dial retry ----

    fn never_permanent(_: &str) -> bool {
        false
    }

    #[tokio::test(start_paused = true)]
    async fn dial_retry_keeps_trying_until_the_network_is_back() {
        let tries = AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        let got = retry_dial(
            "wiki.example.ztlp",
            Some(tokio::time::Instant::now() + Duration::from_secs(15)),
            None,
            never_permanent,
            || async {
                let n = tries.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 4 {
                    Err::<u32, DialError>("Network is unreachable".into())
                } else {
                    Ok(n as u32)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(got, 4);
        // pauses of 250 ms, 500 ms and 1 s
        assert_eq!(started.elapsed(), Duration::from_millis(1750));
    }

    #[tokio::test(start_paused = true)]
    async fn dial_retry_gives_up_at_the_deadline_with_the_last_error() {
        let tries = AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        let err = retry_dial(
            "wiki.example.ztlp",
            Some(tokio::time::Instant::now() + Duration::from_secs(15)),
            None,
            never_permanent,
            || async {
                let n = tries.fetch_add(1, Ordering::SeqCst) + 1;
                Err::<u32, DialError>(format!("no route (try {n})").into())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(15) + DIAL_GIVE_UP_GRACE,
            "after the caller's deadline, and only just"
        );
        let n = tries.load(Ordering::SeqCst);
        assert_eq!(err.to_string(), format!("no route (try {n})"));
        assert!((15..=18).contains(&n), "{n} tries in 15 s");
    }

    #[tokio::test(start_paused = true)]
    async fn dial_retry_does_not_repeat_a_permanent_failure() {
        let tries = AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        let err = retry_dial(
            "wiki.example.ztlp",
            Some(tokio::time::Instant::now() + Duration::from_secs(15)),
            None,
            |m: &str| m.contains("certificate"),
            || async {
                tries.fetch_add(1, Ordering::SeqCst);
                Err::<u32, DialError>("certificate does not match".into())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "certificate does not match");
        assert_eq!(tries.load(Ordering::SeqCst), 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_deadline_there_is_exactly_one_try() {
        let tries = AtomicUsize::new(0);
        let err = retry_dial("x", None, None, never_permanent, || async {
            tries.fetch_add(1, Ordering::SeqCst);
            Err::<u32, DialError>("no route".into())
        })
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "no route");
        assert_eq!(tries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiter_whose_deadline_already_passed_does_not_dial() {
        let tries = AtomicUsize::new(0);
        let err = retry_dial(
            "wiki.example.ztlp",
            Some(tokio::time::Instant::now()),
            None,
            never_permanent,
            || async {
                tries.fetch_add(1, Ordering::SeqCst);
                Ok::<u32, DialError>(1)
            },
        )
        .await
        .unwrap_err();
        assert_eq!(tries.load(Ordering::SeqCst), 0);
        assert!(err.to_string().contains("first-byte deadline"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stuck_try_is_abandoned_and_a_network_change_restarts_it_at_once() {
        // try 1 hangs (started with no network); the change signal at 1 s
        // abandons it and try 2 succeeds immediately
        let (tx, rx) = tokio::sync::watch::channel(0u64);
        let tries = AtomicUsize::new(0);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tx.send(1).unwrap();
            std::future::pending::<()>().await;
        });
        let started = tokio::time::Instant::now();
        let got = retry_dial(
            "wiki.example.ztlp",
            Some(tokio::time::Instant::now() + Duration::from_secs(15)),
            Some(rx),
            never_permanent,
            || async {
                if tries.fetch_add(1, Ordering::SeqCst) == 0 {
                    std::future::pending::<()>().await;
                }
                Ok::<u32, DialError>(7)
            },
        )
        .await
        .unwrap();
        assert_eq!(got, 7);
        assert_eq!(started.elapsed(), Duration::from_secs(1));

        // with no signal the cap ends the stuck try
        let tries = AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        retry_dial(
            "wiki.example.ztlp",
            Some(tokio::time::Instant::now() + Duration::from_secs(15)),
            None,
            never_permanent,
            || async {
                if tries.fetch_add(1, Ordering::SeqCst) == 0 {
                    std::future::pending::<()>().await;
                }
                Ok::<u32, DialError>(7)
            },
        )
        .await
        .unwrap();
        assert_eq!(
            started.elapsed(),
            DIAL_ATTEMPT_CAP + DIAL_RETRY_FIRST_BACKOFF
        );
    }

    // ---- direct / relay race ----

    async fn after(
        ms: u64,
        r: Result<&'static str, &'static str>,
    ) -> Result<&'static str, &'static str> {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        r
    }

    #[tokio::test(start_paused = true)]
    async fn a_live_direct_path_wins_and_the_relay_is_never_started() {
        let relay_started = AtomicBool::new(false);
        let started = tokio::time::Instant::now();
        let got = race_direct_relay(
            after(30, Ok("direct")),
            || {
                relay_started.store(true, Ordering::SeqCst);
                after(300, Ok("relay"))
            },
            RELAY_HEAD_START,
        )
        .await
        .unwrap();
        assert_eq!(got, ("direct", RaceWinner::Direct));
        assert_eq!(started.elapsed(), Duration::from_millis(30));
        assert!(!relay_started.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn a_dead_direct_path_costs_the_head_start_not_its_full_timeout() {
        // direct: no answer for 750 ms (its own timeout); relay: 310 ms
        let started = tokio::time::Instant::now();
        let got = race_direct_relay(
            after(750, Err("direct candidate did not answer within 750ms")),
            || after(310, Ok("relay")),
            RELAY_HEAD_START,
        )
        .await
        .unwrap();
        assert_eq!(got, ("relay", RaceWinner::Relay));
        assert_eq!(
            started.elapsed(),
            RELAY_HEAD_START + Duration::from_millis(310),
            "510 ms, where one after the other took 1060 ms"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_direct_path_that_fails_fast_starts_the_relay_without_waiting() {
        let started = tokio::time::Instant::now();
        let got = race_direct_relay(
            after(5, Err("Network is unreachable")),
            || after(310, Ok("relay")),
            RELAY_HEAD_START,
        )
        .await
        .unwrap();
        assert_eq!(got.1, RaceWinner::Relay);
        assert_eq!(started.elapsed(), Duration::from_millis(315));
    }

    #[tokio::test(start_paused = true)]
    async fn a_slower_direct_path_still_wins_when_it_finishes_before_the_relay() {
        // direct needs 350 ms (after the head start), the relay 310 ms
        // from 200 ms on = 510 ms: direct is first and is taken
        let got = race_direct_relay(
            after(350, Ok("direct")),
            || after(310, Ok("relay")),
            RELAY_HEAD_START,
        )
        .await
        .unwrap();
        assert_eq!(got.1, RaceWinner::Direct);
    }

    #[tokio::test(start_paused = true)]
    async fn direct_is_preferred_when_both_are_ready_together() {
        let got = race_direct_relay(
            after(500, Ok("direct")),
            || after(300, Ok("relay")),
            RELAY_HEAD_START,
        )
        .await
        .unwrap();
        assert_eq!(got, ("direct", RaceWinner::Direct));
    }

    #[tokio::test(start_paused = true)]
    async fn the_loser_is_cancelled() {
        struct Flag(Arc<AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Flag(cancelled.clone());
        let got = race_direct_relay(
            async move {
                let _held = flag;
                after(750, Err("timeout")).await
            },
            || after(100, Ok("relay")),
            RELAY_HEAD_START,
        )
        .await
        .unwrap();
        assert_eq!(got.1, RaceWinner::Relay);
        assert!(
            cancelled.load(Ordering::SeqCst),
            "the direct attempt was dropped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn both_dead_reports_both_errors_when_the_later_one_ends() {
        let started = tokio::time::Instant::now();
        let err = race_direct_relay(
            after(750, Err::<&str, _>("direct timeout")),
            || after(15_000, Err("relay timeout")),
            RELAY_HEAD_START,
        )
        .await
        .unwrap_err();
        assert_eq!(err, ("direct timeout", "relay timeout"));
        assert_eq!(
            started.elapsed(),
            RELAY_HEAD_START + Duration::from_secs(15)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_head_start_starts_both_at_once() {
        // what a name whose last connection went through the relay gets
        let started = tokio::time::Instant::now();
        let got = race_direct_relay(
            after(750, Err("direct timeout")),
            || after(310, Ok("relay")),
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert_eq!(got.1, RaceWinner::Relay);
        assert_eq!(started.elapsed(), Duration::from_millis(310));
    }

    // ---- change signal ----

    #[tokio::test(start_paused = true)]
    async fn a_change_with_nobody_serving_is_a_no_op() {
        let s = ChangeSignal::new();
        assert!(!s.raise());
        assert!(!s.is_served());
        assert_eq!(s.effective(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_of_changes_runs_the_action_once_now_and_once_after() {
        let s: &'static ChangeSignal = Box::leak(Box::new(ChangeSignal::new()));
        let runs = Arc::new(AtomicUsize::new(0));
        let r = runs.clone();
        let server = tokio::spawn(s.serve(NETWORK_CHANGE_COALESCE, move || {
            r.fetch_add(1, Ordering::SeqCst);
        }));
        tokio::task::yield_now().await;
        assert!(s.is_served());

        assert!(s.raise());
        tokio::task::yield_now().await;
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "the first call acts at once"
        );
        for _ in 0..50 {
            assert!(s.raise());
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1, "still inside the window");
        tokio::time::sleep(NETWORK_CHANGE_COALESCE).await;
        assert_eq!(runs.load(Ordering::SeqCst), 2, "the other 50 are one run");
        assert_eq!(s.effective(), 2);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 2, "and nothing after that");

        // a later, separate change acts again
        assert!(s.raise());
        tokio::task::yield_now().await;
        assert_eq!(runs.load(Ordering::SeqCst), 3);

        // once the serving task is gone, calls are no-ops again
        server.abort();
        let _ = server.await;
        assert!(!s.is_served());
        assert!(!s.raise());
        assert_eq!(s.effective(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_raised_before_serving_started_is_not_acted_on() {
        let s: &'static ChangeSignal = Box::leak(Box::new(ChangeSignal::new()));
        s.pending.store(true, Ordering::SeqCst);
        s.notify.notify_one();
        let server = tokio::spawn(s.serve(NETWORK_CHANGE_COALESCE, || {}));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(s.effective(), 0);
        server.abort();
    }

    // ---- use state ----

    #[test]
    fn a_connection_is_idle_only_while_nobody_holds_a_lease() {
        let u = UseState::new();
        let t0 = Instant::now();
        assert!(u.idle_for(t0 + Duration::from_secs(5)).unwrap() >= Duration::from_secs(4));
        let a = u.acquire();
        let b = u.acquire();
        assert!(u.in_use());
        assert_eq!(u.idle_for(Instant::now() + Duration::from_secs(600)), None);
        drop(a);
        assert_eq!(u.idle_for(Instant::now() + Duration::from_secs(600)), None);
        drop(b);
        // idle time counts from the moment the last user left
        let idle = u.idle_for(Instant::now()).unwrap();
        assert!(idle < Duration::from_secs(1), "{idle:?}");
        assert!(u.idle_for(Instant::now() + MOBILE_IDLE_CLOSE).unwrap() >= MOBILE_IDLE_CLOSE);
    }
}
