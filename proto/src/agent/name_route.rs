//! Name-routed single-address mode (`[dns] single_address`).
//!
//! Normally every site gets its own virtual IP and the listener a client
//! connects to says which site it wants. Where the host has exactly one
//! usable local address (iOS: only 127.0.0.1 on loopback, and traffic to
//! the tunnel's own addresses never reaches a socket), every site name
//! resolves to that one address and the agent tells sites apart by NAME:
//! the TLS server name on port 443, the HTTP `Host` header on port 80.
//!
//! This module only finds the name and the site. The connection is then
//! handed, unread, to the same code that carries a VIP connection.

use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::identity::NodeId;

use super::dns::DnsResolverState;
use super::proxy::NsResolution;

/// Most request-head bytes looked at to find the `Host` header.
pub(crate) const MAX_HTTP_HEAD: usize = 8 * 1024;
/// Most ClientHello bytes looked at to find the server name (one full TLS
/// record plus its header).
pub(crate) const MAX_CLIENT_HELLO: usize = 16 * 1024 + 5;
/// Time a client gets to deliver its name once it has started sending.
pub(crate) const SNIFF_TIMEOUT: Duration = Duration::from_secs(5);
/// A connection that sends nothing at all for this long is closed
/// (browsers open spare connections and leave them idle).
const IDLE_BEFORE_FIRST_BYTE: Duration = Duration::from_secs(60);
/// Connections whose first bytes are being examined at the same time; the
/// rest wait. Bounds the scratch memory of this step to about 1 MiB.
const MAX_SNIFFERS: usize = 64;
/// Upper bound for one name-server lookup made for a connection.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Sites remembered at once (positive and negative entries together).
pub(crate) const MAX_SITES: usize = 64;
/// How long a resolved site is used before the name server is asked again
/// (the resolver's A-record TTL).
pub(crate) const SITE_TTL: Duration = Duration::from_secs(300);
/// How long "this name does not resolve" is remembered.
pub(crate) const NEGATIVE_TTL: Duration = Duration::from_secs(10);

/// Result of looking for a site name in the bytes received so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NameParse {
    /// The name, lower-cased, without port or trailing dot.
    Found(String),
    /// Nothing wrong yet, but the name has not arrived.
    NeedMore,
    /// The request is complete enough to know it carries no name.
    Missing,
    /// Not a request this port understands, or an unusable name.
    Invalid,
}

/// A `Host` header value (or any host[:port]) as a lower-case DNS name.
/// `None` for an empty value, an IP literal in brackets, or characters a
/// DNS name cannot contain.
pub(crate) fn normalize_host(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.starts_with('[') {
        return None;
    }
    let host = match s.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        Some(_) => return None,
        None => s,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// Could `line` (no line end yet) still become an HTTP request line?
fn plausible_request_line(line: &[u8]) -> bool {
    let method_len = line.iter().position(|&b| b == b' ').unwrap_or(line.len());
    method_len <= 16
        && line[..method_len].iter().all(|b| b.is_ascii_alphabetic())
        && line
            .iter()
            .all(|&b| (0x20..0x7f).contains(&b) || b == b'\r')
}

/// `METHOD target HTTP/1.x`
fn is_request_line(line: &[u8]) -> bool {
    if !plausible_request_line(line) {
        return false;
    }
    let mut parts = line.split(|&b| b == b' ').filter(|p| !p.is_empty());
    let (Some(_method), Some(_target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    version == b"HTTP/1.1" || version == b"HTTP/1.0"
}

/// Find the `Host` header in the start of an HTTP/1.x request.
///
/// Answers as soon as the `Host` line is complete; the rest of the head
/// need not have arrived. Only the first `Host` header is looked at.
pub(crate) fn host_from_head(buf: &[u8]) -> NameParse {
    let mut rest = buf;
    let mut first = true;
    loop {
        let Some(nl) = rest.iter().position(|&b| b == b'\n') else {
            // an unfinished line
            if first && !plausible_request_line(rest) {
                return NameParse::Invalid;
            }
            return NameParse::NeedMore;
        };
        let line = &rest[..nl];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        rest = &rest[nl + 1..];
        if first {
            first = false;
            if !is_request_line(line) {
                return NameParse::Invalid;
            }
            continue;
        }
        if line.is_empty() {
            return NameParse::Missing;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            if line[..colon].eq_ignore_ascii_case(b"host") {
                return match std::str::from_utf8(&line[colon + 1..])
                    .ok()
                    .and_then(normalize_host)
                {
                    Some(host) => NameParse::Found(host),
                    None => NameParse::Invalid,
                };
            }
        }
    }
}

/// Where a site is, as the VIP path needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// Full ZTLP name (lower case).
    pub ztlp_name: String,
    /// Best gateway address from the last resolution.
    pub peer_addr: Option<SocketAddr>,
    /// Gateway NodeID from the last resolution.
    pub peer_node_id: Option<NodeId>,
}

/// What the site table knows about a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lookup {
    Hit(Site),
    /// The name failed to resolve a moment ago.
    Negative,
    Miss,
}

/// Resolver-side state of single-address mode: the address every site name
/// is answered with, and a small bounded table name -> site.
#[derive(Debug)]
pub struct SingleAddress {
    /// The one address (A record for every site; listeners on 443 and 80).
    pub addr: Ipv4Addr,
    sites: HashMap<String, SiteEntry>,
}

#[derive(Debug)]
struct SiteEntry {
    /// `None` = negative entry.
    site: Option<Site>,
    expires: Instant,
}

impl SingleAddress {
    pub fn new(addr: Ipv4Addr) -> Self {
        Self {
            addr,
            sites: HashMap::new(),
        }
    }

    /// Remember a successful resolution. Returns the site.
    ///
    /// Also publishes the gateway's address list and certificate
    /// expectation for the dialer, exactly as a VIP allocation does.
    pub(crate) fn record(&mut self, name: &str, r: &NsResolution, now: Instant) -> Site {
        let name = name.to_ascii_lowercase();
        let site = Site {
            ztlp_name: name.clone(),
            peer_addr: Some(r.addr),
            peer_node_id: r.node_id,
        };
        self.make_room(&name, now);
        super::daemon::set_peer_candidates(&name, &r.candidates);
        super::daemon::set_peer_cert(&name, &r.cert);
        self.sites.insert(
            name,
            SiteEntry {
                site: Some(site.clone()),
                expires: now + SITE_TTL,
            },
        );
        site
    }

    /// Remove an entry and what was published for the dialer with it, so
    /// the dialer's per-name caches stay as bounded as this table.
    fn remove(&mut self, name: &str) {
        if let Some(entry) = self.sites.remove(name) {
            if entry.site.is_some() {
                super::daemon::forget_peer_candidates(name);
            }
        }
    }

    /// Make sure inserting `name` keeps the table within [`MAX_SITES`]:
    /// expired entries go first, then whatever expires soonest.
    fn make_room(&mut self, name: &str, now: Instant) {
        if self.sites.contains_key(name) || self.sites.len() < MAX_SITES {
            return;
        }
        self.purge_expired(now);
        while self.sites.len() >= MAX_SITES {
            let Some(victim) = self
                .sites
                .iter()
                .min_by_key(|(_, e)| e.expires)
                .map(|(n, _)| n.clone())
            else {
                break;
            };
            self.remove(&victim);
        }
    }

    /// Remember that `name` did not resolve.
    pub(crate) fn record_failure(&mut self, name: &str, now: Instant) {
        let name = name.to_ascii_lowercase();
        self.remove(&name);
        self.make_room(&name, now);
        self.sites.insert(
            name,
            SiteEntry {
                site: None,
                expires: now + NEGATIVE_TTL,
            },
        );
    }

    pub(crate) fn lookup(&self, name: &str, now: Instant) -> Lookup {
        match self.sites.get(&name.to_ascii_lowercase()) {
            Some(e) if e.expires > now => match &e.site {
                Some(site) => Lookup::Hit(site.clone()),
                None => Lookup::Negative,
            },
            _ => Lookup::Miss,
        }
    }

    /// Drop expired entries. Returns how many were removed.
    pub(crate) fn purge_expired(&mut self, now: Instant) -> usize {
        let expired: Vec<String> = self
            .sites
            .iter()
            .filter(|(_, e)| e.expires <= now)
            .map(|(n, _)| n.clone())
            .collect();
        for name in &expired {
            self.remove(name);
        }
        expired.len()
    }

    /// Sites currently known (resolved and not expired).
    pub fn live_sites(&self, now: Instant) -> usize {
        self.sites
            .values()
            .filter(|e| e.site.is_some() && e.expires > now)
            .count()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.sites.len()
    }
}

/// Lets through a few log lines per minute and counts the rest, so a
/// client that keeps asking for names the agent does not serve cannot
/// fill the log.
#[derive(Debug)]
pub(crate) struct RejectLog {
    inner: std::sync::Mutex<RejectLogState>,
}

#[derive(Debug)]
struct RejectLogState {
    window_start: Option<Instant>,
    logged: u32,
    suppressed: u64,
}

impl RejectLog {
    pub(crate) const PER_WINDOW: u32 = 5;
    pub(crate) const WINDOW: Duration = Duration::from_secs(60);

    pub(crate) const fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(RejectLogState {
                window_start: None,
                logged: 0,
                suppressed: 0,
            }),
        }
    }

    /// `Some(n)`: write the line (`n` earlier lines were left out since the
    /// last one written). `None`: stay quiet.
    pub(crate) fn admit(&self, now: Instant) -> Option<u64> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match g.window_start {
            Some(start) if now.saturating_duration_since(start) < Self::WINDOW => {}
            _ => {
                g.window_start = Some(now);
                g.logged = 0;
            }
        }
        if g.logged < Self::PER_WINDOW {
            g.logged += 1;
            Some(std::mem::take(&mut g.suppressed))
        } else {
            g.suppressed += 1;
            None
        }
    }
}

/// Find the server name in the start of a TLS ClientHello.
pub(crate) fn sni_from_client_hello(buf: &[u8]) -> NameParse {
    use tokio_rustls::rustls::server::Acceptor;

    // A TLS handshake record: type 0x16, version 3.x.
    if buf.first().is_some_and(|&b| b != 0x16) || buf.get(1).is_some_and(|&b| b != 0x03) {
        return NameParse::Invalid;
    }
    let mut acceptor = Acceptor::default();
    let mut rest = buf;
    while !rest.is_empty() {
        match acceptor.read_tls(&mut rest) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => return NameParse::Invalid,
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                return match accepted
                    .client_hello()
                    .server_name()
                    .and_then(normalize_host)
                {
                    Some(name) => NameParse::Found(name),
                    None => NameParse::Missing,
                };
            }
            Ok(None) => {}
            Err(_) => return NameParse::Invalid,
        }
    }
    NameParse::NeedMore
}

/// Which bytes of a new connection carry the site name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameSource {
    /// TLS server name (port 443).
    Sni,
    /// HTTP `Host` header (port 80).
    HttpHost,
}

/// Why a connection was not carried anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reject {
    /// The client went away before sending a name.
    Closed,
    /// The name did not arrive in time.
    Timeout,
    /// The name was not within the bytes the agent is willing to look at.
    TooLarge,
    /// A complete request without a name (no SNI, no `Host`).
    NoName,
    /// Not TLS / not HTTP, or an unusable name.
    Invalid,
    /// A name this agent does not serve.
    NotASite(String),
    /// The session is locked; no new names.
    Frozen(String),
    /// A name in the agent's zones that the name server does not know.
    Unresolved(String),
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reject::Closed => write!(f, "closed before sending a name"),
            Reject::Timeout => write!(f, "no name within {SNIFF_TIMEOUT:?}"),
            Reject::TooLarge => write!(f, "name not found within the size limit"),
            Reject::NoName => write!(f, "no server name"),
            Reject::Invalid => write!(f, "not a usable request"),
            Reject::NotASite(n) => write!(f, "'{n}' is not a name this agent serves"),
            Reject::Frozen(n) => write!(f, "'{n}' refused while the session is locked"),
            Reject::Unresolved(n) => write!(f, "'{n}' does not resolve at the name server"),
        }
    }
}

impl Reject {
    /// The short plain answer a port-80 client gets.
    pub(crate) fn http_response(&self) -> Vec<u8> {
        let (status, text) = match self {
            Reject::Closed | Reject::Invalid => ("400 Bad Request", "Bad request."),
            Reject::NoName => ("400 Bad Request", "Missing Host header."),
            Reject::Timeout => ("408 Request Timeout", "Request timed out."),
            Reject::TooLarge => (
                "431 Request Header Fields Too Large",
                "Host header not found in the first 8 KiB.",
            ),
            Reject::NotASite(_) => (
                "421 Misdirected Request",
                "This host name is not a ZTLP site.",
            ),
            Reject::Frozen(_) => ("403 Forbidden", "ZTLP is locked."),
            Reject::Unresolved(_) => ("404 Not Found", "Unknown ZTLP site."),
        };
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{text}\n",
            text.len() + 1
        )
        .into_bytes()
    }
}

/// Read the site name from the first bytes of `stream` WITHOUT consuming
/// them (`MSG_PEEK`): whatever handles the connection next sees the whole
/// ClientHello / request. Bounded in size (8 KiB of request head, one TLS
/// record) and in time.
pub(crate) async fn peek_name(
    stream: &TcpStream,
    source: NameSource,
    limit: Duration,
) -> Result<String, Reject> {
    let (start, max) = match source {
        NameSource::HttpHost => (1024, MAX_HTTP_HEAD),
        NameSource::Sni => (2048, MAX_CLIENT_HELLO),
    };
    let deadline = tokio::time::Instant::now() + limit;
    let mut buf = vec![0u8; start];
    let mut pause = Duration::from_millis(1);
    loop {
        let n = match tokio::time::timeout_at(deadline, stream.peek(&mut buf)).await {
            Err(_) => return Err(Reject::Timeout),
            Ok(Err(_)) | Ok(Ok(0)) => return Err(Reject::Closed),
            Ok(Ok(n)) => n,
        };
        let parsed = match source {
            NameSource::HttpHost => host_from_head(&buf[..n]),
            NameSource::Sni => sni_from_client_hello(&buf[..n]),
        };
        match parsed {
            NameParse::Found(name) => return Ok(name),
            NameParse::Missing => return Err(Reject::NoName),
            NameParse::Invalid => return Err(Reject::Invalid),
            NameParse::NeedMore => {}
        }
        if n == buf.len() {
            if buf.len() >= max {
                return Err(Reject::TooLarge);
            }
            let grown = (buf.len() * 2).min(max);
            buf.resize(grown, 0);
            continue;
        }
        // A peek returns at once while the same bytes are waiting, so
        // pause briefly for the rest to arrive.
        if tokio::time::Instant::now() + pause >= deadline {
            return Err(Reject::Timeout);
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(Duration::from_millis(50));
    }
}

/// Map a name a client asked for (SNI or `Host`) to its site, with the
/// rules the resolver applies to a DNS query for the same name: lower
/// case, the health name is not a site, the name must be one the agent
/// handles (`*.ztlp` or a `[dns] domain_map` entry, mapped the same way),
/// nothing new while the session is locked, and it must resolve at the
/// name server. A site resolved in the last [`SITE_TTL`] (by a DNS query or
/// an earlier connection) is used without asking again.
///
/// `ns` performs the name-server lookup (`proxy::ns_resolve` in the
/// daemon; a stub in tests).
pub(crate) async fn resolve_site<F, Fut>(
    state: &Mutex<DnsResolverState>,
    host: &str,
    frozen: bool,
    ns: F,
) -> Result<Site, Reject>
where
    F: FnOnce(String, String) -> Fut,
    Fut: Future<Output = Result<NsResolution, Box<dyn std::error::Error + Send + Sync>>>,
{
    let host = normalize_host(host).ok_or(Reject::Invalid)?;
    if super::peruser::is_health_name(&host) {
        return Err(Reject::NotASite(host));
    }
    let (name, ns_server, known) = {
        let st = state.lock().await;
        let Some(single) = st.single.as_ref() else {
            return Err(Reject::NotASite(host));
        };
        let Some(name) = st.domain_mapper.to_ztlp_name(&host) else {
            return Err(Reject::NotASite(host));
        };
        let known = single.lookup(&name, Instant::now());
        (name, st.ns_server.clone(), known)
    };
    if super::peruser::dns_decision(&name, frozen) == super::peruser::DnsDecision::Refuse {
        return Err(Reject::Frozen(name));
    }
    match known {
        Lookup::Hit(site) => return Ok(site),
        Lookup::Negative => return Err(Reject::Unresolved(name)),
        Lookup::Miss => {}
    }

    info!(
        "[single-address] resolving {} via ZTLP-NS ({})",
        name, ns_server
    );
    let result = tokio::time::timeout(RESOLVE_TIMEOUT, ns(name.clone(), ns_server)).await;
    let mut st = state.lock().await;
    let Some(single) = st.single.as_mut() else {
        return Err(Reject::NotASite(host));
    };
    match result {
        Ok(Ok(resolution)) => Ok(single.record(&name, &resolution, Instant::now())),
        Ok(Err(e)) => {
            debug!("[single-address] {} did not resolve: {}", name, e);
            single.record_failure(&name, Instant::now());
            Err(Reject::Unresolved(name))
        }
        Err(_) => {
            debug!("[single-address] resolving {} timed out", name);
            single.record_failure(&name, Instant::now());
            Err(Reject::Unresolved(name))
        }
    }
}

/// One log line per refused connection, a few per minute at most.
static REJECTS: RejectLog = RejectLog::new();

/// Refuse a connection: one rate-limited log line; a port-80 client also
/// gets a short plain answer. Nothing is dialed.
async fn refuse(mut stream: TcpStream, source: NameSource, client: SocketAddr, why: Reject) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if why == Reject::Closed {
        debug!("single-address: {} {}", client, why);
        return;
    }
    if let Some(skipped) = REJECTS.admit(Instant::now()) {
        let what = match source {
            NameSource::Sni => "TLS",
            NameSource::HttpHost => "HTTP",
        };
        if skipped > 0 {
            warn!(
                "single-address: refused {} connection from {}: {} \
                 ({} more refusals not logged)",
                what, client, why, skipped
            );
        } else {
            warn!(
                "single-address: refused {} connection from {}: {}",
                what, client, why
            );
        }
    }
    if source != NameSource::HttpHost {
        // TLS: closing before the ServerHello fails the client's handshake.
        return;
    }
    let answer = why.http_response();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = stream.write_all(&answer).await;
        let _ = stream.shutdown().await;
    })
    .await;
    // The request was only peeked at. Closing a socket with unread bytes
    // resets it and the client may never see the answer: take the bytes
    // out first (bounded, brief).
    let _ = tokio::time::timeout(Duration::from_millis(250), async {
        let mut scratch = [0u8; 1024];
        let mut taken = 0usize;
        while taken < MAX_HTTP_HEAD {
            match stream.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(n) => taken += n,
            }
        }
    })
    .await;
}

/// Accept loop of one single-address listener.
///
/// For every connection: `admit` (the VIP listeners' local-client and
/// session-lock checks), find the name without consuming it, `resolve` it
/// to a site, then `carry` the untouched connection. A connection whose
/// name is missing, foreign or unresolvable is refused without dialing.
/// Runs until the task is aborted.
pub(crate) async fn run_listener<A, R, RFut, C, CFut>(
    listener: TcpListener,
    source: NameSource,
    admit: A,
    resolve: R,
    carry: C,
) where
    A: Fn(&TcpStream, SocketAddr) -> bool + Send + 'static,
    R: Fn(String) -> RFut + Clone + Send + Sync + 'static,
    RFut: Future<Output = Result<Site, Reject>> + Send,
    C: Fn(TcpStream, Site, SocketAddr) -> CFut + Clone + Send + Sync + 'static,
    CFut: Future<Output = ()> + Send,
{
    let sniffers = Arc::new(tokio::sync::Semaphore::new(MAX_SNIFFERS));
    loop {
        let (stream, client) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                debug!("single-address accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !admit(&stream, client) {
            continue;
        }
        let sniffers = sniffers.clone();
        let resolve = resolve.clone();
        let carry = carry.clone();
        tokio::spawn(async move {
            // Nothing is allocated for a connection until it sends.
            match tokio::time::timeout(IDLE_BEFORE_FIRST_BYTE, stream.readable()).await {
                Ok(Ok(())) => {}
                _ => return,
            }
            let host = {
                let Ok(_permit) = sniffers.acquire().await else {
                    return;
                };
                peek_name(&stream, source, SNIFF_TIMEOUT).await
            };
            let site = match host {
                Ok(host) => resolve(host).await,
                Err(why) => Err(why),
            };
            match site {
                Ok(site) => carry(stream, site, client).await,
                Err(why) => refuse(stream, source, client, why).await,
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(s: &str) -> NameParse {
        NameParse::Found(s.to_string())
    }

    // ── Host header ─────────────────────────────────────────────────────

    #[test]
    fn host_is_lower_cased_and_loses_its_port() {
        assert_eq!(
            host_from_head(b"GET / HTTP/1.1\r\nHost: App.Example.ZTLP:8080\r\n\r\n"),
            found("app.example.ztlp")
        );
        assert_eq!(
            host_from_head(b"GET /x HTTP/1.1\r\nAccept: */*\r\nhOsT:app.example.ztlp\r\n\r\n"),
            found("app.example.ztlp")
        );
        assert_eq!(
            host_from_head(b"POST / HTTP/1.1\r\nHOST: \t app.example.ztlp. \r\nX: y\r\n\r\n"),
            found("app.example.ztlp")
        );
        // bare LF line ends
        assert_eq!(
            host_from_head(b"GET / HTTP/1.1\nHost: app.example.ztlp\n\n"),
            found("app.example.ztlp")
        );
    }

    #[test]
    fn host_is_found_as_soon_as_its_line_is_complete() {
        // the rest of the head has not arrived (and may be large)
        assert_eq!(
            host_from_head(b"GET / HTTP/1.1\r\nHost: app.example.ztlp\r\nCookie: abc"),
            found("app.example.ztlp")
        );
    }

    #[test]
    fn a_head_split_across_reads_asks_for_more_until_the_host_line_ends() {
        let head =
            b"GET /index.html HTTP/1.1\r\nUser-Agent: t\r\nHost: app.example.ztlp:80\r\n\r\n";
        let host_line_end = head.windows(4).position(|w| w == b"80\r\n").unwrap() + 4;
        for cut in 0..head.len() {
            let got = host_from_head(&head[..cut]);
            if cut < host_line_end {
                assert_eq!(got, NameParse::NeedMore, "prefix of {cut} bytes");
            } else {
                assert_eq!(got, found("app.example.ztlp"), "prefix of {cut} bytes");
            }
        }
    }

    #[test]
    fn a_complete_head_without_host_is_missing() {
        assert_eq!(
            host_from_head(b"GET / HTTP/1.0\r\n\r\n"),
            NameParse::Missing
        );
        assert_eq!(
            host_from_head(b"GET / HTTP/1.1\r\nX-Host: a.example.ztlp\r\nHostess: b\r\n\r\n"),
            NameParse::Missing
        );
    }

    #[test]
    fn things_that_are_not_http_or_not_a_name_are_invalid() {
        // a TLS ClientHello sent to the plain port
        assert_eq!(
            host_from_head(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00]),
            NameParse::Invalid
        );
        assert_eq!(host_from_head(b"\x00\x01\x02\x03"), NameParse::Invalid);
        assert_eq!(host_from_head(b"hello there\r\n\r\n"), NameParse::Invalid);
        for bad in [
            "Host:\r\n",
            "Host: \r\n",
            "Host: [2001:db8::1]:80\r\n",
            "Host: a b.example.ztlp\r\n",
            "Host: app.example.ztlp/path\r\n",
            "Host: :80\r\n",
        ] {
            let head = format!("GET / HTTP/1.1\r\n{bad}\r\n");
            assert_eq!(
                host_from_head(head.as_bytes()),
                NameParse::Invalid,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn normalize_host_strips_port_dot_and_case() {
        assert_eq!(
            normalize_host("App.Example.ZTLP").as_deref(),
            Some("app.example.ztlp")
        );
        assert_eq!(
            normalize_host(" app.example.ztlp.:443 ").as_deref(),
            Some("app.example.ztlp")
        );
        assert_eq!(normalize_host("127.0.0.1:80").as_deref(), Some("127.0.0.1"));
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("."), None);
        assert_eq!(normalize_host("[::1]:80"), None);
        assert_eq!(normalize_host("a:b"), None);
        assert_eq!(normalize_host(&"a".repeat(254)), None);
    }

    // ── site table ──────────────────────────────────────────────────────

    fn resolution(name: &str, addr: &str) -> NsResolution {
        NsResolution {
            addr: addr.parse().unwrap(),
            node_id: None,
            ztlp_name: name.to_string(),
            candidates: vec![addr.parse().unwrap()],
            cert: Default::default(),
        }
    }

    #[test]
    fn sites_are_remembered_until_they_expire() {
        let t0 = Instant::now();
        let mut s = SingleAddress::new(Ipv4Addr::LOCALHOST);
        assert_eq!(s.lookup("a.example.ztlp", t0), Lookup::Miss);
        let site = s.record(
            "a.example.ztlp",
            &resolution("a.example.ztlp", "192.0.2.10:23095"),
            t0,
        );
        assert_eq!(site.ztlp_name, "a.example.ztlp");
        assert_eq!(site.peer_addr, Some("192.0.2.10:23095".parse().unwrap()));
        assert_eq!(s.lookup("a.example.ztlp", t0), Lookup::Hit(site.clone()));
        assert_eq!(s.live_sites(t0), 1);
        let late = t0 + SITE_TTL + Duration::from_secs(1);
        assert_eq!(s.lookup("a.example.ztlp", late), Lookup::Miss);
        assert_eq!(s.live_sites(late), 0);
        assert_eq!(s.purge_expired(late), 1);
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn a_failed_name_is_negative_for_a_short_while_and_replaces_the_site() {
        let t0 = Instant::now();
        let mut s = SingleAddress::new(Ipv4Addr::LOCALHOST);
        s.record(
            "a.example.ztlp",
            &resolution("a.example.ztlp", "192.0.2.10:23095"),
            t0,
        );
        s.record_failure("a.example.ztlp", t0);
        assert_eq!(s.lookup("a.example.ztlp", t0), Lookup::Negative);
        assert_eq!(s.live_sites(t0), 0);
        assert_eq!(
            s.lookup("a.example.ztlp", t0 + NEGATIVE_TTL + Duration::from_secs(1)),
            Lookup::Miss
        );
        // a later success wins again
        s.record(
            "a.example.ztlp",
            &resolution("a.example.ztlp", "192.0.2.11:23095"),
            t0,
        );
        assert!(matches!(s.lookup("a.example.ztlp", t0), Lookup::Hit(_)));
    }

    #[test]
    fn the_site_table_never_grows_past_its_cap() {
        let t0 = Instant::now();
        let mut s = SingleAddress::new(Ipv4Addr::LOCALHOST);
        for i in 0..(MAX_SITES * 4) {
            let name = format!("s{i}.example.ztlp");
            let now = t0 + Duration::from_millis(i as u64);
            if i % 2 == 0 {
                s.record(&name, &resolution(&name, "192.0.2.10:23095"), now);
            } else {
                s.record_failure(&name, now);
            }
            assert!(s.len() <= MAX_SITES, "{} entries", s.len());
        }
        // the newest entry survived
        let last = format!("s{}.example.ztlp", MAX_SITES * 4 - 2);
        assert!(matches!(
            s.lookup(&last, t0 + Duration::from_secs(1)),
            Lookup::Hit(_)
        ));
    }

    // ── TLS server name ─────────────────────────────────────────────────

    /// A real ClientHello, as rustls sends it for `server`.
    fn client_hello(server: &str) -> Vec<u8> {
        use tokio_rustls::rustls;
        crate::agent::ensure_rustls_crypto_provider();
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(server.to_string()).unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn sni_is_read_from_a_client_hello_once_it_is_complete() {
        let hello = client_hello("Wiki.Office.Example.ZTLP");
        assert_eq!(
            sni_from_client_hello(&hello),
            found("wiki.office.example.ztlp")
        );
        // any shorter prefix: not yet, and never a wrong answer
        for cut in 0..hello.len() {
            assert_eq!(
                sni_from_client_hello(&hello[..cut]),
                NameParse::NeedMore,
                "prefix of {cut} of {} bytes",
                hello.len()
            );
        }
    }

    #[test]
    fn a_client_hello_without_a_server_name_is_missing_and_other_bytes_invalid() {
        // rustls sends no SNI for an IP address
        assert_eq!(
            sni_from_client_hello(&client_hello("192.0.2.1")),
            NameParse::Missing
        );
        assert_eq!(
            sni_from_client_hello(b"GET / HTTP/1.1\r\nHost: a.example.ztlp\r\n\r\n"),
            NameParse::Invalid
        );
        assert_eq!(sni_from_client_hello(&[0x16, 0x99]), NameParse::Invalid);
        // a handshake record that is not a ClientHello
        let mut junk = vec![0x16, 0x03, 0x03, 0x00, 0x04];
        junk.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        assert_eq!(sni_from_client_hello(&junk), NameParse::Invalid);
    }

    // ── peeking ─────────────────────────────────────────────────────────

    async fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (server, _) = l.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn peeking_finds_a_host_sent_in_pieces_and_leaves_every_byte_unread() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, mut server) = pair().await;
        let head = b"GET /a HTTP/1.1\r\nUser-Agent: t\r\nHost: Wiki.Office.Example.ZTLP:80\r\n\r\n";
        let writer = tokio::spawn(async move {
            for piece in head.chunks(7) {
                client.write_all(piece).await.unwrap();
                client.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
            client
        });
        let name = peek_name(&server, NameSource::HttpHost, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(name, "wiki.office.example.ztlp");
        let _client = writer.await.unwrap();
        // the handler that comes next reads the request from its first byte
        let mut got = vec![0u8; head.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], &head[..]);
    }

    #[tokio::test]
    async fn peeking_gives_up_on_an_oversized_head_a_slow_client_and_a_closed_one() {
        use tokio::io::AsyncWriteExt;
        // more than 8 KiB of headers and still no Host
        let (mut client, server) = pair().await;
        let mut head = b"GET / HTTP/1.1\r\n".to_vec();
        while head.len() < MAX_HTTP_HEAD + 512 {
            head.extend_from_slice(b"X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        client.write_all(&head).await.unwrap();
        assert_eq!(
            peek_name(&server, NameSource::HttpHost, Duration::from_secs(5)).await,
            Err(Reject::TooLarge)
        );

        // a head that never completes
        let (mut client, server) = pair().await;
        client.write_all(b"GET / HTTP/1.1\r\nHos").await.unwrap();
        let started = Instant::now();
        assert_eq!(
            peek_name(&server, NameSource::HttpHost, Duration::from_millis(200)).await,
            Err(Reject::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(2));

        // closed without a byte
        let (client, server) = pair().await;
        drop(client);
        assert_eq!(
            peek_name(&server, NameSource::Sni, Duration::from_secs(5)).await,
            Err(Reject::Closed)
        );
    }

    // ── name -> site ────────────────────────────────────────────────────

    type BoxErr = Box<dyn std::error::Error + Send + Sync>;

    fn state() -> Mutex<DnsResolverState> {
        let mut map = HashMap::new();
        map.insert(
            "apps.example.com".to_string(),
            "office.example.ztlp".to_string(),
        );
        Mutex::new(DnsResolverState {
            vip_pool: super::super::vip_pool::VipPool::new("127.100.0.0/24").unwrap(),
            domain_mapper: super::super::domain_map::DomainMapper::new(&map),
            ns_server: "192.0.2.1:23096".to_string(),
            upstream_dns: "192.0.2.53:53".to_string(),
            vip_state_path: None,
            health_vip: Ipv4Addr::LOCALHOST,
            single: Some(SingleAddress::new(Ipv4Addr::LOCALHOST)),
        })
    }

    /// A name server stub: knows names starting with "wiki." or "mail.",
    /// and counts how often it is asked.
    fn ns_stub(
        asked: Arc<std::sync::Mutex<Vec<String>>>,
    ) -> impl FnOnce(String, String) -> std::future::Ready<Result<NsResolution, BoxErr>> {
        move |name, ns_server| {
            assert_eq!(ns_server, "192.0.2.1:23096");
            asked.lock().unwrap().push(name.clone());
            std::future::ready(if name.starts_with("wiki.") {
                Ok(resolution(&name, "192.0.2.10:23095"))
            } else if name.starts_with("mail.") {
                Ok(resolution(&name, "192.0.2.20:23095"))
            } else {
                Err(format!("{name}: not found").into())
            })
        }
    }

    #[tokio::test]
    async fn names_map_to_the_site_the_resolver_would_have_given() {
        let st = state();
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        // upper case, with a port and a trailing dot
        let site = resolve_site(
            &st,
            "Wiki.Office.Example.ZTLP.:443",
            false,
            ns_stub(asked.clone()),
        )
        .await
        .unwrap();
        assert_eq!(site.ztlp_name, "wiki.office.example.ztlp");
        assert_eq!(site.peer_addr, Some("192.0.2.10:23095".parse().unwrap()));
        // the custom-domain form of the same site is the same site, and it
        // is already known: the name server is not asked again
        let same = resolve_site(&st, "wiki.apps.example.com", false, ns_stub(asked.clone()))
            .await
            .unwrap();
        assert_eq!(same, site);
        // another name is another site
        let mail = resolve_site(
            &st,
            "mail.office.example.ztlp",
            false,
            ns_stub(asked.clone()),
        )
        .await
        .unwrap();
        assert_eq!(mail.peer_addr, Some("192.0.2.20:23095".parse().unwrap()));
        assert_eq!(
            *asked.lock().unwrap(),
            vec!["wiki.office.example.ztlp", "mail.office.example.ztlp"]
        );
    }

    #[tokio::test]
    async fn foreign_health_and_malformed_names_are_refused_without_asking_the_name_server() {
        let st = state();
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        for (host, want) in [
            (
                "www.example.com",
                Reject::NotASite("www.example.com".into()),
            ),
            ("127.0.0.1", Reject::NotASite("127.0.0.1".into())),
            ("localhost", Reject::NotASite("localhost".into())),
            (
                "ztlp-health.ztlp",
                Reject::NotASite("ztlp-health.ztlp".into()),
            ),
            (
                "ZTLP-Health.ztlp:8443",
                Reject::NotASite("ztlp-health.ztlp".into()),
            ),
            ("", Reject::Invalid),
            ("a b.office.example.ztlp", Reject::Invalid),
        ] {
            assert_eq!(
                resolve_site(&st, host, false, ns_stub(asked.clone())).await,
                Err(want),
                "{host:?}"
            );
        }
        // a locked session refuses even a good name
        assert_eq!(
            resolve_site(
                &st,
                "wiki.office.example.ztlp",
                true,
                ns_stub(asked.clone())
            )
            .await,
            Err(Reject::Frozen("wiki.office.example.ztlp".into()))
        );
        assert!(asked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_name_that_does_not_resolve_is_refused_and_not_asked_again_at_once() {
        let st = state();
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        for _ in 0..3 {
            assert_eq!(
                resolve_site(
                    &st,
                    "gone.office.example.ztlp",
                    false,
                    ns_stub(asked.clone())
                )
                .await,
                Err(Reject::Unresolved("gone.office.example.ztlp".into()))
            );
        }
        assert_eq!(asked.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn nothing_is_a_site_when_the_mode_is_off() {
        let st = state();
        st.lock().await.single = None;
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        assert!(matches!(
            resolve_site(
                &st,
                "wiki.office.example.ztlp",
                false,
                ns_stub(asked.clone())
            )
            .await,
            Err(Reject::NotASite(_))
        ));
        assert!(asked.lock().unwrap().is_empty());
    }

    // ── the listeners, end to end on loopback ───────────────────────────
    //
    // Real sockets, the real accept loop, name lookup and refusal paths.
    // The name server is the stub above. "Upstream" is a stub at the
    // carry step that answers with the site it was handed, so each test
    // shows which site a connection was routed to and that the carrier
    // received the connection from its first byte.

    fn stub_resolver(
        st: Arc<Mutex<DnsResolverState>>,
    ) -> impl Fn(String) -> std::pin::Pin<Box<dyn Future<Output = Result<Site, Reject>> + Send>>
           + Clone
           + Send
           + Sync
           + 'static {
        move |host: String| {
            let st = st.clone();
            Box::pin(async move {
                let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
                resolve_site(&st, &host, false, ns_stub(asked)).await
            })
        }
    }

    async fn http_get(addr: SocketAddr, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn http_connections_reach_the_site_named_by_host_with_the_request_intact() {
        let st = Arc::new(state());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let carried = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = carried.clone();
        // upstream stub: echo the site and the request head it received
        let carry = move |mut stream: TcpStream, site: Site, _client: SocketAddr| {
            let count = count.clone();
            async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut head = Vec::new();
                let mut buf = [0u8; 512];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let body = format!(
                    "site={} gateway={:?}\n{}",
                    site.ztlp_name,
                    site.peer_addr,
                    String::from_utf8_lossy(&head)
                );
                let _ = stream
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}").as_bytes(),
                    )
                    .await;
                let _ = stream.shutdown().await;
            }
        };
        let task = tokio::spawn(run_listener(
            listener,
            NameSource::HttpHost,
            |_: &TcpStream, _| true,
            stub_resolver(st.clone()),
            carry,
        ));

        let wiki_req = "GET /w HTTP/1.1\r\nHost: WIKI.office.example.ztlp\r\nX-A: 1\r\n\r\n";
        let wiki = http_get(addr, wiki_req).await;
        assert!(wiki.starts_with("HTTP/1.1 200 OK"), "{wiki}");
        assert!(wiki.contains("site=wiki.office.example.ztlp"), "{wiki}");
        assert!(wiki.contains("192.0.2.10:23095"), "{wiki}");
        assert!(
            wiki.ends_with(wiki_req),
            "request must arrive whole: {wiki}"
        );

        let mail_req = "GET /m HTTP/1.1\r\nHost: mail.office.example.ztlp:80\r\n\r\n";
        let mail = http_get(addr, mail_req).await;
        assert!(mail.contains("site=mail.office.example.ztlp"), "{mail}");
        assert!(mail.contains("192.0.2.20:23095"), "{mail}");
        assert!(mail.ends_with(mail_req), "{mail}");
        assert_eq!(carried.load(std::sync::atomic::Ordering::SeqCst), 2);

        // refused with a short plain 4xx, never carried
        for (req, status) in [
            ("GET / HTTP/1.0\r\n\r\n", "400"),
            ("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "421"),
            ("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "421"),
            (
                "GET / HTTP/1.1\r\nHost: gone.office.example.ztlp\r\n\r\n",
                "404",
            ),
            ("\x16\x03\x01\x00\x05hello", "400"),
        ] {
            let got = http_get(addr, req).await;
            assert!(
                got.starts_with(&format!("HTTP/1.1 {status} ")),
                "{req:?} -> {got:?}"
            );
            assert!(got.len() < 300, "short answer: {got:?}");
        }
        assert_eq!(carried.load(std::sync::atomic::Ordering::SeqCst), 2);
        task.abort();
    }

    #[tokio::test]
    async fn tls_connections_reach_the_site_named_by_sni_and_the_handshake_still_works() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls;
        crate::agent::ensure_rustls_crypto_provider();

        // The agent's own certificate machinery: a CA that mints a leaf for
        // the server name the client asks for.
        let (ca, ca_pem, _key) =
            crate::agent::cert_mint::IntermediateCa::generate_for_test().unwrap();
        let cert_dir = tempfile::tempdir().unwrap();
        let resolver = Arc::new(crate::agent::local_tls::SniCertResolver::with_mint_ca(
            cert_dir.path().to_path_buf(),
            Arc::new(ca),
        ));
        let acceptor = crate::agent::local_tls::create_tls_acceptor(resolver).unwrap();

        let st = Arc::new(state());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let carried = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = carried.clone();
        // upstream stub: do what the VIP path does first on 443 (accept TLS
        // on the untouched socket), then answer with the site
        let carry = move |stream: TcpStream, site: Site, _client: SocketAddr| {
            let acceptor = acceptor.clone();
            let count = count.clone();
            async move {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut tls = acceptor.accept(stream).await.expect("server handshake");
                let mut buf = [0u8; 256];
                let n = tls.read(&mut buf).await.unwrap();
                let reply = format!(
                    "site={} got={}",
                    site.ztlp_name,
                    String::from_utf8_lossy(&buf[..n])
                );
                tls.write_all(reply.as_bytes()).await.unwrap();
                let _ = tls.shutdown().await;
            }
        };
        let task = tokio::spawn(run_listener(
            listener,
            NameSource::Sni,
            |_: &TcpStream, _| true,
            stub_resolver(st.clone()),
            carry,
        ));

        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));

        for (name, want) in [
            (
                "wiki.office.example.ztlp",
                "site=wiki.office.example.ztlp got=ping-wiki",
            ),
            (
                "mail.office.example.ztlp",
                "site=mail.office.example.ztlp got=ping-mail",
            ),
        ] {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let sni = rustls::pki_types::ServerName::try_from(name).unwrap();
            // the certificate is checked against `name`: a leaf for the
            // wrong site would fail here
            let mut tls = connector.connect(sni, tcp).await.expect("client handshake");
            let ping = format!("ping-{}", &name[..4]);
            tls.write_all(ping.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut out)).await;
            assert_eq!(String::from_utf8_lossy(&out), want);
        }
        assert_eq!(carried.load(std::sync::atomic::Ordering::SeqCst), 2);

        // a name outside the agent's zones, one that does not resolve, and
        // no server name at all: the handshake fails and nothing is carried
        for name in ["www.example.com", "gone.office.example.ztlp", "192.0.2.1"] {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let sni = rustls::pki_types::ServerName::try_from(name).unwrap();
            let r = tokio::time::timeout(Duration::from_secs(5), connector.connect(sni, tcp))
                .await
                .expect("refusal is prompt");
            assert!(r.is_err(), "{name} must not complete a handshake");
        }
        assert_eq!(carried.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(
            !cert_dir.path().join("www_example_com.pem").exists()
                && std::fs::read_dir(cert_dir.path()).unwrap().count() <= 4,
            "no certificate is minted for a refused name"
        );
        task.abort();
    }

    // ── reject log ──────────────────────────────────────────────────────

    #[test]
    fn reject_log_lets_a_few_lines_through_per_window_and_counts_the_rest() {
        let log = RejectLog::new();
        let t0 = Instant::now();
        for _ in 0..RejectLog::PER_WINDOW {
            assert_eq!(log.admit(t0), Some(0));
        }
        for _ in 0..1000 {
            assert_eq!(log.admit(t0 + Duration::from_secs(1)), None);
        }
        // next window: one line, saying how many were left out
        let t1 = t0 + RejectLog::WINDOW + Duration::from_secs(1);
        assert_eq!(log.admit(t1), Some(1000));
        assert_eq!(log.admit(t1), Some(0));
    }
}
