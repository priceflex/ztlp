//! Splash gate: readiness tracking and `/.ztlp/ready` routing.
//! See docs/BROWSER-SPLASH-PAGE-PLAN.md.
//!
//! The tracker is NOT a tunnel cache. It only records that a dial to a
//! host:port succeeded recently, so the splash page's poll can answer
//! "ready". The reload that follows makes its own fresh dial.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a successful dial keeps answering `ready: true`.
pub const READY_TTL: Duration = Duration::from_secs(30);
/// A warm-up dial older than this is treated as lost and may be restarted.
pub const WARMING_STALE: Duration = Duration::from_secs(30);
/// Upper bound on tracked keys (hostnames are attacker-influenced).
pub const MAX_TRACKED: usize = 1024;

#[derive(Debug, Clone, Copy)]
enum Entry {
    Warming(Instant),
    Ready(Instant),
}

pub struct ReadyTracker {
    inner: Mutex<HashMap<String, Entry>>,
}

impl ReadyTracker {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// True if a dial to `key` succeeded within `READY_TTL` of `now`.
    pub fn is_ready(&self, key: &str, now: Instant) -> bool {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        matches!(map.get(key), Some(Entry::Ready(at)) if now.saturating_duration_since(*at) < READY_TTL)
    }

    /// Start a warm-up for `key`. Returns true if the caller should run the
    /// dial (nothing in flight); false if one is already running. Clears any
    /// previous ready state so a stale "ready" cannot cause a reload loop.
    pub fn begin_warm(&self, key: &str, now: Instant) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(Entry::Warming(since)) = map.get(key) {
            if now.saturating_duration_since(*since) < WARMING_STALE {
                return false;
            }
        }
        Self::make_room(&mut map, key, now);
        map.insert(key.to_string(), Entry::Warming(now));
        true
    }

    /// Record the result of a warm-up dial.
    pub fn finish(&self, key: &str, ok: bool, now: Instant) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if ok {
            Self::make_room(&mut map, key, now);
            map.insert(key.to_string(), Entry::Ready(now));
        } else {
            map.remove(key);
        }
    }

    /// Keep the map bounded: drop expired entries first, then (if still
    /// full) the oldest ones.
    fn make_room(map: &mut HashMap<String, Entry>, key: &str, now: Instant) {
        if map.len() < MAX_TRACKED || map.contains_key(key) {
            return;
        }
        map.retain(|_, e| match e {
            Entry::Ready(at) => now.saturating_duration_since(*at) < READY_TTL,
            Entry::Warming(at) => now.saturating_duration_since(*at) < WARMING_STALE,
        });
        while map.len() >= MAX_TRACKED {
            let oldest = map
                .iter()
                .min_by_key(|(_, e)| match e {
                    Entry::Ready(at) | Entry::Warming(at) => *at,
                })
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    map.remove(&k);
                }
                None => break,
            }
        }
    }
}

impl Default for ReadyTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// What the agent should do with a request head.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// `GET /.ztlp/ready`: agent answers itself, never forwarded.
    ReadyProbe,
    /// Another method on the agent-owned ready path: answer 405.
    ReadyWrongMethod,
    /// Everything else: normal path.
    Normal,
}

pub fn route_request(head: &[u8]) -> Route {
    let Ok(text) = std::str::from_utf8(head) else {
        return Route::Normal;
    };
    let line = text.split("\r\n").next().unwrap_or("");
    let mut parts = line.split(' ');
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Route::Normal;
    };
    let path = target.split('?').next().unwrap_or("");
    if path != "/.ztlp/ready" {
        return Route::Normal;
    }
    if method == "GET" {
        Route::ReadyProbe
    } else {
        Route::ReadyWrongMethod
    }
}

fn simple_response(status: &str, extra: &str, content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         {extra}\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// `200 {"ready":<bool>}` response.
pub fn ready_response(ready: bool) -> Vec<u8> {
    let body = if ready {
        r#"{"ready":true}"#
    } else {
        r#"{"ready":false}"#
    };
    simple_response("200 OK", "", "application/json", body)
}

/// `405` for non-GET on the ready path.
pub fn method_not_allowed_response() -> Vec<u8> {
    simple_response(
        "405 Method Not Allowed",
        "Allow: GET\r\n",
        "text/plain; charset=utf-8",
        "Method Not Allowed",
    )
}

/// Tracker key for a host and port.
pub fn tracker_key(host: &str, port: u16) -> String {
    format!("{}:{}", host.to_ascii_lowercase(), port)
}

// ─── Orchestrator ───────────────────────────────────────────────────────────

use std::future::Future;
use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncRead, AsyncWrite};

/// Process-wide tracker shared by every connection handler.
pub fn global_tracker() -> Arc<ReadyTracker> {
    static T: OnceLock<Arc<ReadyTracker>> = OnceLock::new();
    T.get_or_init(|| Arc::new(ReadyTracker::new())).clone()
}

#[derive(Debug, Clone, Copy)]
pub struct GateConfig {
    /// How long a browser page load waits for the tunnel before the splash.
    pub grace: Duration,
    /// Cap on the request head read before dialing.
    pub head_max: usize,
    /// Overall deadline for the head read (idle preconnects fall through).
    pub head_timeout: Duration,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            grace: Duration::from_secs(1),
            head_max: super::splash::MAX_HEAD_BYTES,
            head_timeout: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Served {
    ReadyProbe,
    MethodNotAllowed,
    Splash,
}

#[derive(Debug)]
pub enum GateOutcome<T, E> {
    /// Tunnel is up. Replay `head` into it, then bridge the stream.
    Proceed { head: Vec<u8>, tunnel: T },
    /// The dial failed on the normal path (no splash was shown).
    DialFailed { head: Vec<u8>, error: E },
    /// The dial task panicked or was cancelled.
    DialAborted { head: Vec<u8> },
    /// The agent answered the client itself; the connection is finished.
    Served(Served),
}

pub async fn run_gated<S, T, E, F, Fut>(
    stream: &mut S,
    host: &str,
    key: &str,
    tracker: Arc<ReadyTracker>,
    cfg: GateConfig,
    dial: F,
) -> GateOutcome<T, E>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
{
    use super::splash::{is_browser_navigation, read_request_head, splash_response, HeadRead};
    use tokio::io::AsyncWriteExt;

    let head = read_request_head(stream, cfg.head_max, cfg.head_timeout).await;
    let complete = matches!(head, HeadRead::Complete(_));
    let bytes = head.into_bytes();

    // Agent-owned path: answered here, before (and without) any dial.
    if complete {
        let reply = match route_request(&bytes) {
            Route::ReadyProbe => Some((
                ready_response(tracker.is_ready(key, Instant::now())),
                Served::ReadyProbe,
            )),
            Route::ReadyWrongMethod => {
                Some((method_not_allowed_response(), Served::MethodNotAllowed))
            }
            Route::Normal => None,
        };
        if let Some((resp, served)) = reply {
            let _ = stream.write_all(&resp).await;
            let _ = stream.shutdown().await;
            return GateOutcome::Served(served);
        }
    }

    let browser = complete && is_browser_navigation(&bytes);
    let mut handle = tokio::spawn(dial());

    if browser {
        match tokio::time::timeout(cfg.grace, &mut handle).await {
            Ok(joined) => return into_outcome(joined, bytes),
            Err(_elapsed) => {
                // Slow dial for a real page load: show the splash. The dial
                // keeps running only so the page's poll can learn the result.
                tracker.begin_warm(key, Instant::now());
                let _ = stream.write_all(&splash_response(host)).await;
                let _ = stream.shutdown().await;
                let key = key.to_string();
                tokio::spawn(async move {
                    let ok = matches!(handle.await, Ok(Ok(_)));
                    tracker.finish(&key, ok, Instant::now());
                });
                return GateOutcome::Served(Served::Splash);
            }
        }
    }

    into_outcome(handle.await, bytes)
}

fn into_outcome<T, E>(
    joined: Result<Result<T, E>, tokio::task::JoinError>,
    head: Vec<u8>,
) -> GateOutcome<T, E> {
    match joined {
        Ok(Ok(tunnel)) => GateOutcome::Proceed { head, tunnel },
        Ok(Err(error)) => GateOutcome::DialFailed { head, error },
        Err(_) => GateOutcome::DialAborted { head },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn unknown_key_is_not_ready() {
        assert!(!ReadyTracker::new().is_ready("a:443", t0()));
    }

    #[test]
    fn first_begin_warm_runs_second_does_not() {
        let t = ReadyTracker::new();
        let n = t0();
        assert!(t.begin_warm("a:443", n));
        assert!(!t.begin_warm("a:443", n));
    }

    #[test]
    fn finish_ok_makes_ready_until_ttl() {
        let t = ReadyTracker::new();
        let n = t0();
        t.begin_warm("a:443", n);
        assert!(!t.is_ready("a:443", n), "warming is not ready");
        t.finish("a:443", true, n);
        assert!(t.is_ready("a:443", n));
        assert!(t.is_ready("a:443", n + READY_TTL - Duration::from_millis(1)));
        assert!(!t.is_ready("a:443", n + READY_TTL));
    }

    #[test]
    fn finish_failure_is_not_ready_and_allows_retry() {
        let t = ReadyTracker::new();
        let n = t0();
        t.begin_warm("a:443", n);
        t.finish("a:443", false, n);
        assert!(!t.is_ready("a:443", n));
        assert!(t.begin_warm("a:443", n), "a failed warm-up can be retried");
    }

    #[test]
    fn begin_warm_clears_stale_ready() {
        // Prevents a reload loop: a splash for a slow dial must wait for a
        // FRESH success, not the previous one.
        let t = ReadyTracker::new();
        let n = t0();
        t.begin_warm("a:443", n);
        t.finish("a:443", true, n);
        assert!(t.is_ready("a:443", n));
        assert!(t.begin_warm("a:443", n));
        assert!(!t.is_ready("a:443", n));
    }

    #[test]
    fn lost_warmup_is_restartable_after_stale_window() {
        let t = ReadyTracker::new();
        let n = t0();
        assert!(t.begin_warm("a:443", n));
        assert!(!t.begin_warm("a:443", n + WARMING_STALE - Duration::from_millis(1)));
        assert!(t.begin_warm("a:443", n + WARMING_STALE));
    }

    #[test]
    fn keys_are_independent() {
        let t = ReadyTracker::new();
        let n = t0();
        t.begin_warm("a:443", n);
        t.finish("a:443", true, n);
        assert!(t.is_ready("a:443", n));
        assert!(!t.is_ready("b:443", n));
        assert!(!t.is_ready("a:8443", n));
    }

    #[test]
    fn tracker_size_is_bounded() {
        let t = ReadyTracker::new();
        let n = t0();
        for i in 0..(MAX_TRACKED + 500) {
            let k = format!("h{i}:443");
            t.begin_warm(&k, n);
            t.finish(&k, true, n);
        }
        assert!(t.inner.lock().unwrap().len() <= MAX_TRACKED);
    }

    #[test]
    fn tracker_key_is_case_insensitive_on_host() {
        assert_eq!(
            tracker_key("App.Zone.ZTLP", 443),
            tracker_key("app.zone.ztlp", 443)
        );
        assert_ne!(tracker_key("a", 443), tracker_key("a", 8443));
    }

    // ---- routing ----
    fn head(line: &str) -> Vec<u8> {
        format!("{line}\r\nHost: a.ztlp\r\n\r\n").into_bytes()
    }

    #[test]
    fn get_ready_is_probe() {
        assert_eq!(
            route_request(&head("GET /.ztlp/ready HTTP/1.1")),
            Route::ReadyProbe
        );
    }

    #[test]
    fn ready_with_query_string_is_probe() {
        assert_eq!(
            route_request(&head("GET /.ztlp/ready?t=123 HTTP/1.1")),
            Route::ReadyProbe
        );
    }

    #[test]
    fn post_to_ready_is_wrong_method() {
        assert_eq!(
            route_request(&head("POST /.ztlp/ready HTTP/1.1")),
            Route::ReadyWrongMethod
        );
        assert_eq!(
            route_request(&head("HEAD /.ztlp/ready HTTP/1.1")),
            Route::ReadyWrongMethod
        );
    }

    #[test]
    fn other_paths_are_normal() {
        for line in [
            "GET / HTTP/1.1",
            "GET /.ztlp/other HTTP/1.1",
            "GET /.ztlp/ready/extra HTTP/1.1",
            "GET /.ztlp/readyx HTTP/1.1",
            "GET /api/.ztlp/ready HTTP/1.1",
            "POST /login HTTP/1.1",
        ] {
            assert_eq!(route_request(&head(line)), Route::Normal, "{line}");
        }
    }

    #[test]
    fn garbage_and_empty_are_normal() {
        assert_eq!(route_request(b""), Route::Normal);
        assert_eq!(route_request(b"\x16\x03\x01\x02"), Route::Normal);
        assert_eq!(route_request(b"GET"), Route::Normal);
    }

    // ---- responses ----
    fn split(r: &[u8]) -> (String, String) {
        let i = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        (
            String::from_utf8(r[..i].to_vec()).unwrap(),
            String::from_utf8(r[i + 4..].to_vec()).unwrap(),
        )
    }

    #[test]
    fn ready_response_true_and_false_bodies() {
        let (h, b) = split(&ready_response(true));
        assert!(h.starts_with("HTTP/1.1 200 "));
        assert_eq!(b, r#"{"ready":true}"#);
        let (_, b) = split(&ready_response(false));
        assert_eq!(b, r#"{"ready":false}"#);
    }

    #[test]
    fn ready_response_headers() {
        let (h, b) = split(&ready_response(true));
        let lower = h.to_ascii_lowercase();
        assert!(lower.contains("content-type: application/json"));
        assert!(lower.contains("cache-control: no-store"));
        assert!(lower.contains("connection: close"));
        assert!(lower.contains("x-content-type-options: nosniff"));
        assert!(lower.contains(&format!("content-length: {}", b.len())));
    }

    #[test]
    fn ready_response_leaks_nothing_else() {
        let (_, b) = split(&ready_response(false));
        assert!(!b.contains("name") && !b.contains("host") && !b.contains("ztlp"));
    }

    #[test]
    fn method_not_allowed_is_405_with_allow_get() {
        let (h, _) = split(&method_not_allowed_response());
        assert!(h.starts_with("HTTP/1.1 405 "));
        assert!(h.to_ascii_lowercase().contains("allow: get"));
        assert!(h.to_ascii_lowercase().contains("connection: close"));
    }

    // ---- orchestrator ----
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const HOST: &str = "app.zone.ztlp";

    fn key() -> String {
        tracker_key(HOST, 443)
    }

    fn browser_get() -> Vec<u8> {
        b"GET / HTTP/1.1\r\nHost: app.zone.ztlp\r\nAccept: text/html\r\n\
Sec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n\r\n"
            .to_vec()
    }
    fn curl_get() -> Vec<u8> {
        b"GET / HTTP/1.1\r\nHost: app.zone.ztlp\r\nAccept: */*\r\n\r\n".to_vec()
    }
    fn browser_post() -> Vec<u8> {
        b"POST /x HTTP/1.1\r\nHost: app.zone.ztlp\r\nAccept: text/html\r\n\
Sec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\nContent-Length: 0\r\n\r\n"
            .to_vec()
    }

    /// Run the gate against a duplex "browser". Returns the outcome, what the
    /// browser received, and how many times the dial was started.
    async fn drive(
        request: &[u8],
        dial_after: Duration,
        dial_ok: bool,
        tracker: Arc<ReadyTracker>,
    ) -> (GateOutcome<u32, String>, Vec<u8>, usize) {
        let (mut browser, mut agent) = tokio::io::duplex(256 * 1024);
        browser.write_all(request).await.unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let d2 = dials.clone();
        let out = run_gated(
            &mut agent,
            HOST,
            &key(),
            tracker,
            GateConfig::default(),
            move || {
                d2.fetch_add(1, Ordering::SeqCst);
                async move {
                    tokio::time::sleep(dial_after).await;
                    if dial_ok {
                        Ok(7u32)
                    } else {
                        Err("boom".to_string())
                    }
                }
            },
        )
        .await;
        drop(agent);
        let mut got = Vec::new();
        let _ = browser.read_to_end(&mut got).await;
        (out, got, dials.load(Ordering::SeqCst))
    }

    #[tokio::test(start_paused = true)]
    async fn fast_dial_browser_proceeds_without_splash() {
        let (out, got, dials) = drive(
            &browser_get(),
            Duration::from_millis(150),
            true,
            Arc::new(ReadyTracker::new()),
        )
        .await;
        match out {
            GateOutcome::Proceed { head, tunnel } => {
                assert_eq!(head, browser_get(), "head must be replayable byte for byte");
                assert_eq!(tunnel, 7);
            }
            other => panic!("expected Proceed, got {other:?}"),
        }
        assert!(got.is_empty(), "browser must receive nothing from the gate");
        assert_eq!(dials, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_dial_browser_gets_splash_and_connection_closes() {
        let tracker = Arc::new(ReadyTracker::new());
        let (out, got, dials) = drive(
            &browser_get(),
            Duration::from_secs(5),
            true,
            tracker.clone(),
        )
        .await;
        assert!(
            matches!(out, GateOutcome::Served(Served::Splash)),
            "{out:?}"
        );
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("HTTP/1.1 200 "), "{text:.80}");
        assert!(text.contains(HOST));
        assert!(text.contains("/.ztlp/ready"));
        assert_eq!(dials, 1, "the splash must not start a second dial");
    }

    #[tokio::test(start_paused = true)]
    async fn splash_dial_success_marks_ready_after_it_finishes() {
        let tracker = Arc::new(ReadyTracker::new());
        let (_o, _g, _d) = drive(
            &browser_get(),
            Duration::from_secs(5),
            true,
            tracker.clone(),
        )
        .await;
        assert!(
            !tracker.is_ready(&key(), Instant::now()),
            "not ready before dial ends"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(tracker.is_ready(&key(), Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn splash_dial_failure_never_marks_ready() {
        let tracker = Arc::new(ReadyTracker::new());
        let (_o, _g, _d) = drive(
            &browser_get(),
            Duration::from_secs(5),
            false,
            tracker.clone(),
        )
        .await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(!tracker.is_ready(&key(), Instant::now()));
        assert!(
            tracker.begin_warm(&key(), Instant::now()),
            "can retry after failure"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn splash_clears_a_stale_ready_flag() {
        let tracker = Arc::new(ReadyTracker::new());
        tracker.begin_warm(&key(), Instant::now());
        tracker.finish(&key(), true, Instant::now());
        let (_o, _g, _d) = drive(
            &browser_get(),
            Duration::from_secs(5),
            true,
            tracker.clone(),
        )
        .await;
        assert!(
            !tracker.is_ready(&key(), Instant::now()),
            "old success must not trigger a reload loop"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_dial_non_browser_never_gets_splash() {
        for req in [curl_get(), browser_post()] {
            let (out, got, _d) = drive(
                &req,
                Duration::from_secs(5),
                true,
                Arc::new(ReadyTracker::new()),
            )
            .await;
            assert!(matches!(out, GateOutcome::Proceed { .. }), "{out:?}");
            assert!(
                got.is_empty(),
                "non-browser got bytes: {:?}",
                String::from_utf8_lossy(&got)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failed_dial_on_normal_path_reports_error_without_splash() {
        let (out, got, _d) = drive(
            &curl_get(),
            Duration::from_millis(50),
            false,
            Arc::new(ReadyTracker::new()),
        )
        .await;
        assert!(
            matches!(out, GateOutcome::DialFailed { ref error, .. } if error == "boom"),
            "{out:?}"
        );
        assert!(got.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn fast_failed_dial_for_browser_reports_error_not_splash() {
        let (out, got, _d) = drive(
            &browser_get(),
            Duration::from_millis(50),
            false,
            Arc::new(ReadyTracker::new()),
        )
        .await;
        assert!(matches!(out, GateOutcome::DialFailed { .. }), "{out:?}");
        assert!(got.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn ready_probe_false_then_true_and_never_dials() {
        let req = b"GET /.ztlp/ready HTTP/1.1\r\nHost: app.zone.ztlp\r\n\r\n";
        let tracker = Arc::new(ReadyTracker::new());
        let (out, got, dials) = drive(req, Duration::from_secs(1), true, tracker.clone()).await;
        assert!(matches!(out, GateOutcome::Served(Served::ReadyProbe)));
        assert!(String::from_utf8_lossy(&got).ends_with(r#"{"ready":false}"#));
        assert_eq!(dials, 0, "a probe must never start a dial");

        tracker.begin_warm(&key(), Instant::now());
        tracker.finish(&key(), true, Instant::now());
        let (_o, got, dials) = drive(req, Duration::from_secs(1), true, tracker).await;
        assert!(String::from_utf8_lossy(&got).ends_with(r#"{"ready":true}"#));
        assert_eq!(dials, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn ready_probe_is_per_host_and_port() {
        let req = b"GET /.ztlp/ready HTTP/1.1\r\nHost: app.zone.ztlp\r\n\r\n";
        let tracker = Arc::new(ReadyTracker::new());
        let other = tracker_key("other.zone.ztlp", 443);
        tracker.begin_warm(&other, Instant::now());
        tracker.finish(&other, true, Instant::now());
        let (_o, got, _d) = drive(req, Duration::from_secs(1), true, tracker).await;
        assert!(String::from_utf8_lossy(&got).ends_with(r#"{"ready":false}"#));
    }

    #[tokio::test(start_paused = true)]
    async fn post_to_ready_path_gets_405_and_never_dials() {
        let req = b"POST /.ztlp/ready HTTP/1.1\r\nHost: app.zone.ztlp\r\nContent-Length: 0\r\n\r\n";
        let (out, got, dials) = drive(
            req,
            Duration::from_secs(1),
            true,
            Arc::new(ReadyTracker::new()),
        )
        .await;
        assert!(matches!(out, GateOutcome::Served(Served::MethodNotAllowed)));
        assert!(String::from_utf8_lossy(&got).starts_with("HTTP/1.1 405 "));
        assert_eq!(dials, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_preconnect_falls_through_to_normal_dial() {
        // Browser opens a socket and sends nothing; after the head timeout the
        // gate must dial and hand back an empty head (no splash possible).
        let (mut browser, mut agent) = tokio::io::duplex(1024);
        let tracker = Arc::new(ReadyTracker::new());
        let out = run_gated(
            &mut agent,
            HOST,
            &key(),
            tracker,
            GateConfig::default(),
            || async { Ok::<u32, String>(9) },
        )
        .await;
        match out {
            GateOutcome::Proceed { head, tunnel } => {
                assert!(head.is_empty());
                assert_eq!(tunnel, 9);
            }
            other => panic!("expected Proceed, got {other:?}"),
        }
        drop(agent);
        let mut got = Vec::new();
        let _ = browser.read_to_end(&mut got).await;
        assert!(got.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn oversize_head_is_forwarded_not_splashed() {
        let mut req = b"GET / HTTP/1.1\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\nAccept: text/html\r\nX: ".to_vec();
        req.extend(std::iter::repeat(b'a').take(40_000));
        let (out, got, _d) = drive(
            &req,
            Duration::from_secs(5),
            true,
            Arc::new(ReadyTracker::new()),
        )
        .await;
        match out {
            GateOutcome::Proceed { head, .. } => assert!(head.len() >= 16 * 1024),
            other => panic!("expected Proceed, got {other:?}"),
        }
        assert!(got.is_empty());
    }
}
