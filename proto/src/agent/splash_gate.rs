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
}
