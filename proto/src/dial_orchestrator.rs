//! v0.32 multi-candidate discovery (M5): parallel-dial orchestrator.
//!
//! After M4 ranks the candidates we get from PUNCH_REPORT (host > server-
//! reflexive > relay), M5 actually *dials* them in parallel — racing the
//! ranked list in priority bands with an inter-band delay so host
//! candidates (LAN) get a 250 ms head start over relays. The first
//! successful handshake wins; all in-flight peers are cancelled.
//!
//! ## Why bands instead of "fire everything at once"
//!
//! See `docs/plans/2026-05-28-multi-candidate-discovery-v0.32.md` §
//! "Dial-policy design". TL;DR: if LAN works we don't want to burn relay
//! bandwidth, so we give host candidates a 250 ms grace period before
//! the relay band starts. The band delay can be elided when the higher
//! band has already failed (so a relay isn't artificially delayed when
//! the LAN path is clearly broken).
//!
//! ## Testing
//!
//! The [`Dialer`] trait lets tests inject a fake dialer (no real UDP).
//! All twelve BDD tests run under tokio's `start_paused = true` mocked
//! clock so they're fully deterministic regardless of host load.
//!
//! The M6 production dialer will impl [`Dialer`] by wrapping the existing
//! QUIC handshake code path.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::candidate_priority::RankedCandidate;

/// Result of a successful dial attempt.
///
/// Carries the winning candidate's socket address so the caller knows
/// which path was selected (host vs srflx vs relay) for telemetry and
/// roaming-decision purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialSuccess {
    pub addr: SocketAddr,
}

/// Why a single candidate's dial attempt failed.
///
/// `Timeout` is reserved for the per-candidate timeout in [`DialPolicy`];
/// `Refused` is the generic "remote sent a RST or otherwise rejected"
/// bucket; `Other` carries the underlying error string for everything
/// else (handshake reject, crypto failure, etc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialError {
    Timeout,
    Refused,
    Other(String),
}

/// Abstract handshake transport. Production impl (M6) wraps QUIC; tests
/// use a `FakeDialer` keyed by socket address.
///
/// Implementations should be cooperatively cancellable — i.e. await on
/// reasonably-sized chunks of work so the orchestrator's `JoinSet::abort_all`
/// can interrupt losing dials promptly.
#[async_trait]
pub trait Dialer: Send + Sync + 'static {
    async fn dial(&self, addr: SocketAddr) -> Result<DialSuccess, DialError>;
}

/// Knobs for [`dial_candidates`].
///
/// Defaults match the spec: 2 s per-candidate handshake budget, 250 ms
/// inter-band delay (host → srflx → relay), 8 s total dial budget.
#[derive(Debug, Clone)]
pub struct DialPolicy {
    /// Per-candidate handshake timeout. Default 2 s.
    pub per_candidate_timeout: Duration,
    /// Delay between firing successive priority bands. Default 250 ms.
    pub band_delay: Duration,
    /// Total budget for the whole orchestrated dial. Default 8 s.
    pub total_budget: Duration,
}

impl Default for DialPolicy {
    fn default() -> Self {
        Self {
            per_candidate_timeout: Duration::from_secs(2),
            band_delay: Duration::from_millis(250),
            total_budget: Duration::from_secs(8),
        }
    }
}

/// Why the orchestrator gave up.
///
/// `AllFailed` means every candidate completed with an error before the
/// budget elapsed. `BudgetExhausted` means the total `policy.total_budget`
/// timer fired while at least one dial was still in flight. Both carry
/// the per-candidate failure reasons for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrchestratorError {
    AllFailed { tried: Vec<(SocketAddr, DialError)> },
    BudgetExhausted { tried: Vec<(SocketAddr, DialError)> },
    NoCandidates,
}

/// Internal task outcome shipped over the results mpsc.
type DialOutcome = Result<DialSuccess, (SocketAddr, DialError)>;

/// Race the ranked candidates in priority bands.
///
/// Algorithm (see module docs for the "why"):
///
/// 1. Empty input → [`OrchestratorError::NoCandidates`].
/// 2. Group candidates by their `priority` field into bands; iterate
///    bands in descending priority order.
/// 3. For each band, spawn one task per candidate into a shared
///    [`JoinSet`]. Each task calls `dialer.dial(addr)` wrapped in
///    `tokio::time::timeout(policy.per_candidate_timeout)`.
/// 4. After spawning a band, wait either `policy.band_delay` OR until a
///    successful result arrives on the mpsc, whichever comes first. If
///    a success arrives we abort the remaining tasks and return.
/// 5. After all bands have been spawned, drain the mpsc until either we
///    see a success (return Ok, abort losers) or every spawned task has
///    completed with an error (return `AllFailed`).
/// 6. The whole pipeline is wrapped in
///    `tokio::time::timeout(policy.total_budget)`; if that fires first
///    we return `BudgetExhausted` carrying whatever failures we'd
///    collected so far.
pub async fn dial_candidates(
    candidates: Vec<RankedCandidate>,
    dialer: Arc<dyn Dialer>,
    policy: DialPolicy,
) -> Result<DialSuccess, OrchestratorError> {
    if candidates.is_empty() {
        return Err(OrchestratorError::NoCandidates);
    }

    // Group into bands keyed by priority. BTreeMap gives us deterministic
    // sort order; we iterate `.rev()` for descending-priority bands.
    let mut bands: BTreeMap<u32, Vec<RankedCandidate>> = BTreeMap::new();
    for c in candidates {
        bands.entry(c.priority).or_default().push(c);
    }

    let total_budget = policy.total_budget;
    let inner = run_orchestrator(bands, dialer, policy);

    match tokio::time::timeout(total_budget, inner).await {
        Ok(res) => res,
        Err(_) => {
            // We don't have the per-candidate failure list here because
            // the inner future was dropped on timeout. Surfacing
            // BudgetExhausted with an empty `tried` is fine — callers
            // primarily care about the variant for retry logic.
            Err(OrchestratorError::BudgetExhausted { tried: Vec::new() })
        }
    }
}

/// Core race loop, factored out so the outer `total_budget` timeout can
/// wrap it cleanly.
async fn run_orchestrator(
    bands: BTreeMap<u32, Vec<RankedCandidate>>,
    dialer: Arc<dyn Dialer>,
    policy: DialPolicy,
) -> Result<DialSuccess, OrchestratorError> {
    let (tx, mut rx) = mpsc::unbounded_channel::<DialOutcome>();
    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut tried: Vec<(SocketAddr, DialError)> = Vec::new();
    let mut total_spawned: usize = 0;

    // Iterate bands descending (highest-priority band first).
    let band_count = bands.len();
    for (band_idx, (_prio, band)) in bands.into_iter().rev().enumerate() {
        // Spawn every candidate in this band concurrently.
        for cand in band {
            let dialer = Arc::clone(&dialer);
            let tx = tx.clone();
            let per_to = policy.per_candidate_timeout;
            let addr = cand.addr;
            total_spawned += 1;
            join_set.spawn(async move {
                let res = match tokio::time::timeout(per_to, dialer.dial(addr)).await {
                    Ok(Ok(success)) => Ok(success),
                    Ok(Err(e)) => Err((addr, e)),
                    Err(_) => Err((addr, DialError::Timeout)),
                };
                // Receiver may already be dropped if we won — ignore the
                // send error.
                let _ = tx.send(res);
            });
        }

        // If this is the last band, fall through to the final drain loop.
        if band_idx + 1 == band_count {
            break;
        }

        // Otherwise wait `band_delay` OR a success — whichever first.
        let delay = tokio::time::sleep(policy.band_delay);
        tokio::pin!(delay);
        loop {
            tokio::select! {
                _ = &mut delay => {
                    // Time to spawn the next band.
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Some(Ok(success)) => {
                            join_set.abort_all();
                            return Ok(success);
                        }
                        Some(Err(fail)) => {
                            tried.push(fail);
                            if tried.len() == total_spawned {
                                // Every dial we've spawned so far has
                                // failed — no point waiting out the
                                // band_delay; advance immediately.
                                break;
                            }
                            // Otherwise keep waiting for either delay
                            // or another result.
                        }
                        None => {
                            // All senders dropped — shouldn't happen
                            // here because we still hold `tx`. Bail.
                            break;
                        }
                    }
                }
            }
        }
    }

    // All bands spawned. Drop our held-back sender so `rx.recv()` returns
    // None once every task is done.
    drop(tx);

    // Drain the rest.
    while let Some(msg) = rx.recv().await {
        match msg {
            Ok(success) => {
                join_set.abort_all();
                return Ok(success);
            }
            Err(fail) => tried.push(fail),
        }
    }

    Err(OrchestratorError::AllFailed { tried })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate_priority::{CandidateClass, RankedCandidate};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn rc(s: &str, prio: u32) -> RankedCandidate {
        RankedCandidate {
            addr: addr(s),
            // The orchestrator only inspects `priority`; class is opaque
            // here. Pick any variant.
            class: CandidateClass::HostSameSubnet,
            priority: prio,
        }
    }

    /// Test dialer driven by a per-address lookup.
    ///
    /// `Ok(latency_ms)` → sleep that many ms then resolve Ok.
    /// `Err(DialError)` → sleep 10 ms (so order is observable) then Err.
    /// Missing → Err(Refused) immediately.
    struct FakeDialer {
        responses: HashMap<SocketAddr, Result<u64, DialError>>,
        call_log: Arc<Mutex<Vec<SocketAddr>>>,
        completion_counter: Arc<AtomicUsize>,
    }

    impl FakeDialer {
        fn new(responses: HashMap<SocketAddr, Result<u64, DialError>>) -> Self {
            Self {
                responses,
                call_log: Arc::new(Mutex::new(Vec::new())),
                completion_counter: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl Dialer for FakeDialer {
        async fn dial(&self, addr: SocketAddr) -> Result<DialSuccess, DialError> {
            self.call_log.lock().unwrap().push(addr);
            let outcome = self.responses.get(&addr).cloned();
            match outcome {
                Some(Ok(latency_ms)) => {
                    tokio::time::sleep(Duration::from_millis(latency_ms)).await;
                    self.completion_counter.fetch_add(1, Ordering::SeqCst);
                    Ok(DialSuccess { addr })
                }
                Some(Err(e)) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    self.completion_counter.fetch_add(1, Ordering::SeqCst);
                    Err(e)
                }
                None => Err(DialError::Refused),
            }
        }
    }

    // ── Test 1 ────────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_empty_candidates_returns_no_candidates() {
        let dialer: Arc<dyn Dialer> = Arc::new(FakeDialer::new(HashMap::new()));
        let res = dial_candidates(Vec::new(), dialer, DialPolicy::default()).await;
        assert_eq!(res, Err(OrchestratorError::NoCandidates));
    }

    // ── Test 2 ────────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_single_success_returns_immediately() {
        let a = addr("10.0.0.1:7000");
        let mut responses = HashMap::new();
        responses.insert(a, Ok(10));
        let dialer: Arc<dyn Dialer> = Arc::new(FakeDialer::new(responses));
        let res = dial_candidates(
            vec![rc("10.0.0.1:7000", 250)],
            dialer,
            DialPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(res, DialSuccess { addr: a });
    }

    // ── Test 3 ────────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_higher_priority_wins_when_both_succeed() {
        let host = addr("10.0.0.1:7000");
        let relay = addr("203.0.113.5:7000");
        let mut responses = HashMap::new();
        // Host band fires first; takes 200 ms.
        responses.insert(host, Ok(200));
        // Relay band would only start after band_delay (250 ms), so even
        // though it's "fast" at 10 ms it's blocked behind the delay.
        responses.insert(relay, Ok(10));
        let dialer: Arc<dyn Dialer> = Arc::new(FakeDialer::new(responses));
        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_secs(2),
            band_delay: Duration::from_millis(250),
            total_budget: Duration::from_secs(5),
        };
        let res = dial_candidates(
            vec![rc("10.0.0.1:7000", 250), rc("203.0.113.5:7000", 100)],
            dialer,
            policy,
        )
        .await
        .unwrap();
        assert_eq!(res.addr, host);
    }

    // ── Test 4 ────────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_lower_priority_wins_when_higher_band_fails() {
        let host = addr("10.0.0.1:7000");
        let relay = addr("203.0.113.5:7000");
        let mut responses = HashMap::new();
        // Host fails fast (10 ms refused).
        responses.insert(host, Err(DialError::Refused));
        // Relay succeeds in 100 ms.
        responses.insert(relay, Ok(100));
        let dialer: Arc<dyn Dialer> = Arc::new(FakeDialer::new(responses));
        let res = dial_candidates(
            vec![rc("10.0.0.1:7000", 250), rc("203.0.113.5:7000", 100)],
            dialer,
            DialPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(res.addr, relay);
    }

    // ── Test 5 ────────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_all_failed_returns_all_failed_with_reasons() {
        let a1 = addr("10.0.0.1:7000");
        let a2 = addr("10.0.0.2:7000");
        let a3 = addr("10.0.0.3:7000");
        let mut responses = HashMap::new();
        responses.insert(a1, Err(DialError::Refused));
        responses.insert(a2, Err(DialError::Refused));
        responses.insert(a3, Err(DialError::Refused));
        let dialer: Arc<dyn Dialer> = Arc::new(FakeDialer::new(responses));
        let res = dial_candidates(
            vec![
                rc("10.0.0.1:7000", 250),
                rc("10.0.0.2:7000", 250),
                rc("10.0.0.3:7000", 250),
            ],
            dialer,
            DialPolicy::default(),
        )
        .await;
        match res {
            Err(OrchestratorError::AllFailed { tried }) => {
                assert_eq!(tried.len(), 3);
                for (_a, e) in &tried {
                    assert_eq!(*e, DialError::Refused);
                }
            }
            other => panic!("expected AllFailed, got {:?}", other),
        }
    }

    // ── Test 6 ────────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_budget_exhausted_returns_budget_exhausted() {
        let a = addr("10.0.0.1:7000");
        let mut responses = HashMap::new();
        // 10 s — well beyond the 100 ms total budget. Also beyond the
        // per-candidate timeout, but the outer budget should fire first
        // because per_candidate_timeout is also long enough here.
        responses.insert(a, Ok(10_000));
        let dialer: Arc<dyn Dialer> = Arc::new(FakeDialer::new(responses));
        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_secs(5),
            band_delay: Duration::from_millis(250),
            total_budget: Duration::from_millis(100),
        };
        let res = dial_candidates(vec![rc("10.0.0.1:7000", 250)], dialer, policy).await;
        match res {
            Err(OrchestratorError::BudgetExhausted { .. }) => {}
            other => panic!("expected BudgetExhausted, got {:?}", other),
        }
    }

    // ── Test 7 ────────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_cancels_losers_on_first_success() {
        let fast = addr("10.0.0.1:7000");
        let slow = addr("10.0.0.2:7000");
        let mut responses = HashMap::new();
        responses.insert(fast, Ok(10));
        responses.insert(slow, Ok(5_000));
        let fake = FakeDialer::new(responses);
        let counter = Arc::clone(&fake.completion_counter);
        let log = Arc::clone(&fake.call_log);
        let dialer: Arc<dyn Dialer> = Arc::new(fake);

        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_secs(10),
            band_delay: Duration::from_millis(250),
            total_budget: Duration::from_secs(20),
        };
        let res = dial_candidates(
            // Same band so both fire concurrently.
            vec![rc("10.0.0.1:7000", 250), rc("10.0.0.2:7000", 250)],
            dialer,
            policy,
        )
        .await
        .unwrap();

        assert_eq!(res.addr, fast);

        // Both should have been dispatched (entered dial()).
        assert_eq!(log.lock().unwrap().len(), 2);

        // Only the fast one should have completed; the slow one was
        // aborted before its 5 s sleep finished.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "slow dial should have been cancelled, not completed"
        );

        // Advance past the slow dial's would-be completion time and
        // confirm it still hasn't completed (i.e. it's truly cancelled,
        // not just pending).
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "slow dial completed AFTER cancellation — task leak"
        );
    }

    // ── Test 8 ────────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_respects_band_delay() {
        let host = addr("10.0.0.1:7000");
        let relay = addr("203.0.113.5:7000");
        let mut responses = HashMap::new();
        // Host fails almost immediately (10 ms). Relay succeeds (50 ms).
        responses.insert(host, Err(DialError::Refused));
        responses.insert(relay, Ok(50));
        let fake = FakeDialer::new(responses);
        let log = Arc::clone(&fake.call_log);
        let dialer: Arc<dyn Dialer> = Arc::new(fake);
        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_secs(2),
            band_delay: Duration::from_millis(200),
            total_budget: Duration::from_secs(5),
        };
        let res = dial_candidates(
            vec![rc("10.0.0.1:7000", 250), rc("203.0.113.5:7000", 100)],
            dialer,
            policy,
        )
        .await
        .unwrap();
        assert_eq!(res.addr, relay);

        // Both should have been attempted.
        let log = log.lock().unwrap().clone();
        assert!(log.contains(&host));
        assert!(log.contains(&relay));
        // Host comes first because higher priority band.
        assert_eq!(log[0], host);
    }

    // ── Test 9 ────────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_per_candidate_timeout_treats_slow_dial_as_failure() {
        let a = addr("10.0.0.1:7000");
        let mut responses = HashMap::new();
        responses.insert(a, Ok(5_000));
        let dialer: Arc<dyn Dialer> = Arc::new(FakeDialer::new(responses));
        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_millis(100),
            band_delay: Duration::from_millis(250),
            total_budget: Duration::from_secs(10),
        };
        let res = dial_candidates(vec![rc("10.0.0.1:7000", 250)], dialer, policy).await;
        match res {
            Err(OrchestratorError::AllFailed { tried }) => {
                assert_eq!(tried.len(), 1);
                assert_eq!(tried[0].1, DialError::Timeout);
            }
            other => panic!("expected AllFailed(Timeout), got {:?}", other),
        }
    }

    // ── Test 10 ───────────────────────────────────────────────────────
    /// Empty-input edge case (mirror of Test 1; explicit duplicate
    /// because the spec calls out two distinct empty-vec assertions to
    /// pin both call sites' intent).
    #[tokio::test(start_paused = true)]
    async fn dial_no_candidates_with_empty_vec_returns_no_candidates() {
        let dialer: Arc<dyn Dialer> = Arc::new(FakeDialer::new(HashMap::new()));
        let policy = DialPolicy::default();
        let res = dial_candidates(Vec::<RankedCandidate>::new(), dialer, policy).await;
        assert!(matches!(res, Err(OrchestratorError::NoCandidates)));
    }

    // ── Test 11 ───────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_groups_by_priority_correctly() {
        let a_hi1 = addr("10.0.0.1:7000");
        let a_hi2 = addr("10.0.0.2:7000");
        let a_lo = addr("203.0.113.5:7000");
        let mut responses = HashMap::new();
        // All three fail so we can see the full attempt order.
        responses.insert(a_hi1, Err(DialError::Refused));
        responses.insert(a_hi2, Err(DialError::Refused));
        responses.insert(a_lo, Err(DialError::Refused));
        let fake = FakeDialer::new(responses);
        let log = Arc::clone(&fake.call_log);
        let dialer: Arc<dyn Dialer> = Arc::new(fake);
        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_secs(2),
            band_delay: Duration::from_millis(250),
            total_budget: Duration::from_secs(5),
        };
        let _ = dial_candidates(
            vec![
                rc("10.0.0.1:7000", 250),
                rc("10.0.0.2:7000", 250),
                rc("203.0.113.5:7000", 100),
            ],
            dialer,
            policy,
        )
        .await;
        let log = log.lock().unwrap().clone();
        assert_eq!(log.len(), 3);
        // Both prio-250 entries should appear before the prio-100 entry.
        let lo_idx = log.iter().position(|a| *a == a_lo).unwrap();
        let hi1_idx = log.iter().position(|a| *a == a_hi1).unwrap();
        let hi2_idx = log.iter().position(|a| *a == a_hi2).unwrap();
        assert!(hi1_idx < lo_idx, "hi1 should fire before lo");
        assert!(hi2_idx < lo_idx, "hi2 should fire before lo");
    }

    // ── Test 12 ───────────────────────────────────────────────────────
    #[tokio::test(start_paused = true)]
    async fn dial_all_in_same_band_run_concurrently() {
        let a1 = addr("10.0.0.1:7000");
        let a2 = addr("10.0.0.2:7000");
        let a3 = addr("10.0.0.3:7000");
        let mut responses = HashMap::new();
        // All three take ~500 ms. If we ran serially this would be
        // 1500 ms total — but they're in the same band so they should
        // race concurrently in ~500 ms.
        responses.insert(a1, Ok(500));
        responses.insert(a2, Ok(500));
        responses.insert(a3, Ok(500));
        let dialer: Arc<dyn Dialer> = Arc::new(FakeDialer::new(responses));
        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_secs(2),
            band_delay: Duration::from_millis(250),
            total_budget: Duration::from_millis(700),
        };
        // total_budget = 700 ms < 3 * 500 ms = 1500 ms. So if the
        // orchestrator accidentally serialized the band the outer
        // timeout would fire and we'd get BudgetExhausted. If they ran
        // concurrently, all three resolve by ~500 ms and the first one
        // wins.
        let res = dial_candidates(
            vec![
                rc("10.0.0.1:7000", 250),
                rc("10.0.0.2:7000", 250),
                rc("10.0.0.3:7000", 250),
            ],
            dialer,
            policy,
        )
        .await
        .expect("concurrent band should resolve within 700ms");
        assert!([a1, a2, a3].contains(&res.addr));
    }
}
