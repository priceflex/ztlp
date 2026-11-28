//! Shared-connection cache for the agent's client dial path.
//!
//! With `[tunnel] reuse_connections` on (the `mobile` profile turns it on),
//! every client connection to the same ZTLP name and port rides ONE QUIC
//! connection: the first request dials and runs the Noise handshake, later
//! requests only open a new bidirectional stream on it (the gateway loops
//! `accept_bi` per connection). That bounds memory by the connection-level
//! flow-control window instead of by the number of browser tabs.
//!
//! The cache is generic over the key and the connection type so its logic
//! (reuse while open, redial after close, one dial under concurrency) is
//! tested without a network.
//!
//! There is deliberately NO global cap on streams or connections: a cap
//! lets slow readers of one site hold every permit and starve unrelated
//! sites. Memory is bounded per gateway by the connection window instead.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

/// One slot per key. The async mutex is held for the whole dial so that
/// concurrent first requests for the same key wait for, and then share,
/// one connection instead of each dialing their own.
type Slot<C> = Arc<tokio::sync::Mutex<Option<C>>>;

/// A keyed cache of live connections. `C` is a cheap handle (cloning it
/// yields another handle to the same connection).
pub struct ConnCache<K, C> {
    slots: Mutex<HashMap<K, Slot<C>>>,
}

impl<K, C> Default for ConnCache<K, C> {
    fn default() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
        }
    }
}

impl<K, C> ConnCache<K, C>
where
    K: Hash + Eq + Clone,
    C: Clone,
{
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(&self, key: &K) -> Slot<C> {
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        slots.entry(key.clone()).or_default().clone()
    }

    /// Return the cached connection for `key` when `is_open` says it is
    /// still usable, otherwise run `dial` and cache its result.
    ///
    /// The boolean is `true` when an existing connection was reused. A
    /// failed dial caches nothing: the next caller dials again.
    ///
    /// `is_open` runs under the slot's lock, once per call that finds a
    /// cached connection, so it may also mark the connection as in use:
    /// nothing that goes through [`ConnCache::take_where`] can remove the
    /// connection between that mark and the return.
    pub async fn get_or_dial<F, Fut, E>(
        &self,
        key: &K,
        is_open: impl Fn(&C) -> bool,
        dial: F,
    ) -> Result<(C, bool), E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<C, E>>,
    {
        let slot = self.slot(key);
        let mut guard = slot.lock().await;
        if let Some(conn) = guard.as_ref() {
            if is_open(conn) {
                return Ok((conn.clone(), true));
            }
        }
        // Closed (or never dialed): drop the dead handle before dialing so
        // a cancelled dial leaves an empty slot, not a stale connection.
        *guard = None;
        let conn = dial().await?;
        *guard = Some(conn.clone());
        Ok((conn, false))
    }

    /// Forget the cached connection for `key` (streams already open on it
    /// keep running; the next request dials a fresh connection). Returns
    /// `true` when something was removed. Never blocks: a slot that is
    /// mid-dial is left alone.
    pub fn invalidate(&self, key: &K) -> bool {
        let slot = {
            let slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
            slots.get(key).cloned()
        };
        let Some(slot) = slot else {
            return false;
        };
        let removed = match slot.try_lock() {
            Ok(mut guard) => guard.take().is_some(),
            Err(_) => false,
        };
        removed
    }

    /// Forget the cached connection for `key` when `pred` accepts it (the
    /// caller saw THAT connection fail; one dialed since must stay).
    /// Never blocks: a slot that is in use at this instant is left alone.
    pub fn invalidate_if(&self, key: &K, pred: impl FnOnce(&C) -> bool) -> bool {
        let slot = {
            let slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
            slots.get(key).cloned()
        };
        let Some(slot) = slot else {
            return false;
        };
        let removed = match slot.try_lock() {
            Ok(mut guard) => match guard.as_ref() {
                Some(c) if pred(c) => guard.take().is_some(),
                _ => false,
            },
            Err(_) => false,
        };
        removed
    }

    /// Remove and return every cached connection `pred` accepts. Slots
    /// that are mid-dial are left alone (their dial has not produced a
    /// connection yet).
    pub fn take_where(&self, pred: impl Fn(&C) -> bool) -> Vec<C> {
        let slots: Vec<Slot<C>> = {
            let slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
            slots.values().cloned().collect()
        };
        let mut taken = Vec::new();
        for slot in slots {
            if let Ok(mut guard) = slot.try_lock() {
                if guard.as_ref().map(&pred).unwrap_or(false) {
                    taken.extend(guard.take());
                }
            }
        }
        taken
    }

    /// Number of cached connections `is_open` accepts. Slots that are
    /// mid-dial are not counted.
    pub fn count_open(&self, is_open: impl Fn(&C) -> bool) -> usize {
        let slots: Vec<Slot<C>> = {
            let slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
            slots.values().cloned().collect()
        };
        slots
            .iter()
            .filter(|s| match s.try_lock() {
                Ok(guard) => guard.as_ref().map(&is_open).unwrap_or(false),
                Err(_) => false,
            })
            .count()
    }

    /// Drop every cached connection (agent shutdown). Slots that are
    /// mid-dial are removed from the map; their dial result is then
    /// discarded with the slot.
    pub fn clear(&self) {
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        slots.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    /// A fake connection: an id plus a shared "closed" flag.
    #[derive(Clone, Debug)]
    struct FakeConn {
        id: usize,
        closed: Arc<AtomicBool>,
    }

    fn open(c: &FakeConn) -> bool {
        !c.closed.load(Ordering::SeqCst)
    }

    struct Dialer {
        dials: AtomicUsize,
    }

    impl Dialer {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                dials: AtomicUsize::new(0),
            })
        }
        async fn dial(&self) -> Result<FakeConn, String> {
            let id = self.dials.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(FakeConn {
                id,
                closed: Arc::new(AtomicBool::new(false)),
            })
        }
        fn count(&self) -> usize {
            self.dials.load(Ordering::SeqCst)
        }
    }

    type Key = (String, u16);

    fn key(name: &str, port: u16) -> Key {
        (name.to_string(), port)
    }

    #[tokio::test]
    async fn second_request_reuses_the_open_connection() {
        let cache: ConnCache<Key, FakeConn> = ConnCache::new();
        let d = Dialer::new();
        let k = key("web.example.ztlp", 443);

        let (a, reused_a) = cache.get_or_dial(&k, open, || d.dial()).await.unwrap();
        let (b, reused_b) = cache.get_or_dial(&k, open, || d.dial()).await.unwrap();

        assert!(!reused_a);
        assert!(reused_b);
        assert_eq!(a.id, b.id);
        assert_eq!(d.count(), 1);
    }

    #[tokio::test]
    async fn a_closed_connection_is_redialed() {
        let cache: ConnCache<Key, FakeConn> = ConnCache::new();
        let d = Dialer::new();
        let k = key("web.example.ztlp", 443);

        let (a, _) = cache.get_or_dial(&k, open, || d.dial()).await.unwrap();
        a.closed.store(true, Ordering::SeqCst);
        let (b, reused) = cache.get_or_dial(&k, open, || d.dial()).await.unwrap();

        assert!(!reused);
        assert_ne!(a.id, b.id);
        assert_eq!(d.count(), 2);
        // and the fresh one is what later requests share
        let (c, reused) = cache.get_or_dial(&k, open, || d.dial()).await.unwrap();
        assert!(reused);
        assert_eq!(c.id, b.id);
    }

    #[tokio::test]
    async fn different_names_and_ports_get_their_own_connections() {
        let cache: ConnCache<Key, FakeConn> = ConnCache::new();
        let d = Dialer::new();

        let (a, _) = cache
            .get_or_dial(&key("web.example.ztlp", 443), open, || d.dial())
            .await
            .unwrap();
        let (b, _) = cache
            .get_or_dial(&key("web.example.ztlp", 80), open, || d.dial())
            .await
            .unwrap();
        let (c, _) = cache
            .get_or_dial(&key("api.example.ztlp", 443), open, || d.dial())
            .await
            .unwrap();

        assert_eq!(d.count(), 3);
        assert!(a.id != b.id && b.id != c.id && a.id != c.id);
        assert_eq!(cache.count_open(open), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_requests_share_one_dial() {
        let cache: Arc<ConnCache<Key, FakeConn>> = Arc::new(ConnCache::new());
        let d = Dialer::new();
        let k = key("web.example.ztlp", 443);

        let mut tasks = Vec::new();
        for _ in 0..32 {
            let cache = cache.clone();
            let d = d.clone();
            let k = k.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_dial(&k, open, || async {
                        // a slow handshake: everyone else must wait for it
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        d.dial().await
                    })
                    .await
                    .unwrap()
            }));
        }
        let mut ids = Vec::new();
        let mut fresh = 0;
        for t in tasks {
            let (c, reused) = t.await.unwrap();
            ids.push(c.id);
            if !reused {
                fresh += 1;
            }
        }
        assert_eq!(d.count(), 1, "exactly one dial for 32 concurrent requests");
        assert_eq!(fresh, 1);
        assert!(ids.iter().all(|id| *id == ids[0]));
    }

    #[tokio::test]
    async fn a_failed_dial_caches_nothing_and_the_next_request_dials_again() {
        let cache: ConnCache<Key, FakeConn> = ConnCache::new();
        let d = Dialer::new();
        let k = key("web.example.ztlp", 443);

        let err = cache
            .get_or_dial(&k, open, || async {
                Err::<FakeConn, _>("no route".to_string())
            })
            .await
            .unwrap_err();
        assert_eq!(err, "no route");
        assert_eq!(cache.count_open(open), 0);

        let (_, reused) = cache.get_or_dial(&k, open, || d.dial()).await.unwrap();
        assert!(!reused);
        assert_eq!(d.count(), 1);
    }

    #[tokio::test]
    async fn invalidate_forces_a_redial_but_only_for_that_key() {
        let cache: ConnCache<Key, FakeConn> = ConnCache::new();
        let d = Dialer::new();
        let k1 = key("web.example.ztlp", 443);
        let k2 = key("api.example.ztlp", 443);

        let (a, _) = cache.get_or_dial(&k1, open, || d.dial()).await.unwrap();
        let (b, _) = cache.get_or_dial(&k2, open, || d.dial()).await.unwrap();

        assert!(cache.invalidate(&k1));
        assert!(!cache.invalidate(&k1), "second invalidate finds nothing");
        assert!(!cache.invalidate(&key("unknown.example.ztlp", 1)));

        let (a2, reused) = cache.get_or_dial(&k1, open, || d.dial()).await.unwrap();
        assert!(!reused);
        assert_ne!(a.id, a2.id);
        let (b2, reused) = cache.get_or_dial(&k2, open, || d.dial()).await.unwrap();
        assert!(reused);
        assert_eq!(b.id, b2.id);
    }

    #[tokio::test]
    async fn invalidate_if_only_removes_the_connection_the_caller_saw_fail() {
        let cache: ConnCache<Key, FakeConn> = ConnCache::new();
        let d = Dialer::new();
        let k = key("web.example.ztlp", 443);

        let (dead, _) = cache.get_or_dial(&k, open, || d.dial()).await.unwrap();
        // someone else already replaced it
        assert!(cache.invalidate(&k));
        let (fresh, _) = cache.get_or_dial(&k, open, || d.dial()).await.unwrap();

        assert!(!cache.invalidate_if(&k, |c| c.id == dead.id));
        let (again, reused) = cache.get_or_dial(&k, open, || d.dial()).await.unwrap();
        assert!(reused, "the fresh connection survived");
        assert_eq!(again.id, fresh.id);

        assert!(cache.invalidate_if(&k, |c| c.id == fresh.id));
        assert!(!cache.invalidate_if(&k, |_| true), "nothing left");
        assert!(!cache.invalidate_if(&key("unknown.example.ztlp", 1), |_| true));
    }

    #[tokio::test]
    async fn take_where_returns_and_forgets_the_matching_connections() {
        let cache: ConnCache<Key, FakeConn> = ConnCache::new();
        let d = Dialer::new();
        let (a, _) = cache
            .get_or_dial(&key("a.example.ztlp", 443), open, || d.dial())
            .await
            .unwrap();
        let (b, _) = cache
            .get_or_dial(&key("b.example.ztlp", 443), open, || d.dial())
            .await
            .unwrap();

        let taken = cache.take_where(|c| c.id == a.id);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].id, a.id);
        assert_eq!(cache.count_open(open), 1);

        let taken = cache.take_where(|_| true);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].id, b.id);
        assert_eq!(cache.count_open(open), 0);
        assert!(cache.take_where(|_| true).is_empty());

        // and the next request dials again
        let (_, reused) = cache
            .get_or_dial(&key("a.example.ztlp", 443), open, || d.dial())
            .await
            .unwrap();
        assert!(!reused);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn take_where_leaves_a_dial_in_flight_alone() {
        let cache: Arc<ConnCache<Key, FakeConn>> = Arc::new(ConnCache::new());
        let d = Dialer::new();
        let k = key("web.example.ztlp", 443);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        let task = {
            let (cache, d, k) = (cache.clone(), d.clone(), k.clone());
            tokio::spawn(async move {
                cache
                    .get_or_dial(&k, open, || async {
                        let _ = started_tx.send(());
                        let _ = go_rx.await;
                        d.dial().await
                    })
                    .await
                    .unwrap()
            })
        };
        started_rx.await.unwrap();
        assert!(cache.take_where(|_| true).is_empty());
        go_tx.send(()).unwrap();
        let (c, reused) = task.await.unwrap();
        assert!(!reused);
        // the dial's result is cached as usual
        let (c2, reused) = cache.get_or_dial(&k, open, || d.dial()).await.unwrap();
        assert!(reused);
        assert_eq!(c.id, c2.id);
    }

    #[tokio::test]
    async fn count_open_ignores_closed_connections_and_clear_empties_the_cache() {
        let cache: ConnCache<Key, FakeConn> = ConnCache::new();
        let d = Dialer::new();
        let (a, _) = cache
            .get_or_dial(&key("a.example.ztlp", 443), open, || d.dial())
            .await
            .unwrap();
        cache
            .get_or_dial(&key("b.example.ztlp", 443), open, || d.dial())
            .await
            .unwrap();
        assert_eq!(cache.count_open(open), 2);
        a.closed.store(true, Ordering::SeqCst);
        assert_eq!(cache.count_open(open), 1);
        cache.clear();
        assert_eq!(cache.count_open(open), 0);
    }
}
