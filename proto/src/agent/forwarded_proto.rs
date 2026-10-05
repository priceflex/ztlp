//! `X-Forwarded-Proto: https` stamping for TLS-terminated agent connections.
//!
//! The agent terminates TLS locally (the browser gets a padlock) and then
//! forwards the DECRYPTED bytes through the tunnel, so the backend sees plain
//! HTTP. A framework behind it (found live 2026-10-05 with a Rails app) then
//! believes the request is `http://`, and rejects every https form POST
//! because the browser's `Origin: https://host` does not match the app's
//! `request.base_url` (`http://host`): HTTP 422, CSRF protection.
//!
//! The fix is the standard reverse-proxy one: tell the backend the client
//! connection was https. [`ForwardedProtoStamper`] rewrites each HTTP/1.x
//! request head on a keep-alive connection, removing any client-supplied
//! `X-Forwarded-Proto` (the agent KNOWS the scheme; a client must not choose
//! it) and adding `X-Forwarded-Proto: https`.
//!
//! It is a streaming state machine because requests arrive in arbitrary
//! chunks: a head can be split anywhere, a body can contain `\r\n\r\n`, and
//! several requests can be pipelined in one read. Bodies pass through
//! verbatim (`Content-Length` framing). Chunked bodies, upgrades
//! (WebSocket) and anything that does not look like HTTP/1.x fall back to
//! passthrough for the rest of the connection, so a stamper can never break a
//! non-HTTP protocol running over the same TLS port.

/// Cap on buffered head bytes before giving up and passing through (defends
/// against a client that never finishes a head).
const MAX_HEAD: usize = 64 * 1024;

/// The header the agent adds to every request on a TLS-terminated connection.
pub const FORWARDED_PROTO_HEADER: &str = "X-Forwarded-Proto: https";

enum State {
    /// Buffering a request head until `\r\n\r\n`.
    Headers,
    /// Passing through `n` more body bytes of the current request.
    Body(usize),
    /// No more parsing (chunked, upgrade, not HTTP, or malformed framing).
    Passthrough,
}

/// How the body of a request is framed, from its head.
enum Framing {
    Length(usize),
    /// Chunked or upgrade/CONNECT-style: stop parsing after this head.
    Opaque,
}

pub struct ForwardedProtoStamper {
    buf: Vec<u8>,
    state: State,
}

impl Default for ForwardedProtoStamper {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardedProtoStamper {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            state: State::Headers,
        }
    }

    /// Feed a chunk of client-to-backend bytes; returns the bytes to forward.
    /// May return an empty vec while a head is still buffering (callers must
    /// not treat that as EOF).
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(chunk.len() + 64);
        let mut input: Vec<u8> = chunk.to_vec();

        loop {
            match self.state {
                State::Passthrough => {
                    out.extend_from_slice(&input);
                    return out;
                }
                State::Body(ref mut remaining) => {
                    if input.len() <= *remaining {
                        *remaining -= input.len();
                        out.extend_from_slice(&input);
                        return out;
                    }
                    let rest = input.split_off(*remaining);
                    out.extend_from_slice(&input);
                    self.state = State::Headers;
                    input = rest;
                    if input.is_empty() {
                        return out;
                    }
                }
                State::Headers => {
                    self.buf.extend_from_slice(&input);

                    // Not HTTP at all? Release the bytes the moment we can tell.
                    if !looks_like_http_start(&self.buf) {
                        out.append(&mut self.buf);
                        self.state = State::Passthrough;
                        return out;
                    }
                    // The cap bounds the HEAD, not the whole buffer: a complete,
                    // small head followed by body or pipelined bytes in the same
                    // read must still be stamped (PR #119 review).
                    let Some(pos) = find_head_end(&self.buf).filter(|p| p + 4 <= MAX_HEAD) else {
                        if self.buf.len() > MAX_HEAD {
                            // No head end within the cap: hostile or not HTTP.
                            out.append(&mut self.buf);
                            self.state = State::Passthrough;
                        }
                        return out; // otherwise: head incomplete, hold
                    };
                    let split = pos + 4;
                    let head: Vec<u8> = self.buf[..split].to_vec();
                    let rest: Vec<u8> = self.buf[split..].to_vec();
                    self.buf.clear();

                    match stamp_head(&head) {
                        Some((stamped, framing)) => {
                            out.extend_from_slice(&stamped);
                            match framing {
                                Framing::Opaque => {
                                    out.extend_from_slice(&rest);
                                    self.state = State::Passthrough;
                                    return out;
                                }
                                Framing::Length(n) => {
                                    self.state = State::Body(n);
                                    if rest.is_empty() {
                                        return out;
                                    }
                                    input = rest;
                                }
                            }
                        }
                        None => {
                            // Not a parseable HTTP/1.x request head: forward
                            // untouched and stop parsing this connection.
                            out.extend_from_slice(&head);
                            out.extend_from_slice(&rest);
                            self.state = State::Passthrough;
                            return out;
                        }
                    }
                }
            }
        }
    }

    /// Flush anything still buffered (call at EOF so a truncated head is not
    /// silently dropped).
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Cheap "could this be the start of an HTTP/1.x request?" check on the bytes
/// buffered so far, so a non-HTTP protocol is released immediately instead of
/// being held waiting for a blank line that never comes.
fn looks_like_http_start(buf: &[u8]) -> bool {
    // method: 1..=16 uppercase ASCII letters, then a space
    for (i, b) in buf.iter().enumerate() {
        if *b == b' ' {
            return i > 0;
        }
        if !b.is_ascii_uppercase() || i >= 16 {
            return false;
        }
    }
    true // still inside the method token
}

/// Rewrite one request head. Returns the stamped head and how its body is
/// framed, or `None` if it is not an HTTP/1.x request head.
fn stamp_head(head: &[u8]) -> Option<(Vec<u8>, Framing)> {
    let text = std::str::from_utf8(head).ok()?;
    let body = text.strip_suffix("\r\n\r\n")?;
    let mut lines = body.split("\r\n");

    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let (method, _target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !version.starts_with("HTTP/1.") || method.is_empty() {
        return None;
    }

    let mut kept: Vec<&str> = Vec::new();
    let mut dropping = false;
    let mut content_lengths: Vec<&str> = Vec::new();
    let mut opaque = method.eq_ignore_ascii_case("CONNECT");

    for line in lines {
        // Obsolete line folding: a continuation belongs to the previous header.
        if line.starts_with(' ') || line.starts_with('\t') {
            if !dropping {
                kept.push(line);
            }
            continue;
        }
        dropping = false;
        let (name, value) = line.split_once(':').map(|(n, v)| (n.trim(), v.trim()))?;
        if name.eq_ignore_ascii_case("x-forwarded-proto") {
            dropping = true; // the agent decides the scheme, never the client
            continue;
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_lengths.push(value);
        } else if (name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked"))
            || name.eq_ignore_ascii_case("upgrade")
            || (name.eq_ignore_ascii_case("connection")
                && value.to_ascii_lowercase().contains("upgrade"))
        {
            opaque = true;
        }
        kept.push(line);
    }

    let framing = if opaque {
        Framing::Opaque
    } else {
        match content_lengths.as_slice() {
            [] => Framing::Length(0),
            [first, rest @ ..] => match first.parse::<usize>() {
                // duplicate Content-Length values are only safe if they agree
                Ok(n) if rest.iter().all(|v| v.parse::<usize>().ok() == Some(n)) => {
                    Framing::Length(n)
                }
                _ => Framing::Opaque,
            },
        }
    };

    let mut out = String::with_capacity(head.len() + FORWARDED_PROTO_HEADER.len() + 4);
    out.push_str(request_line);
    out.push_str("\r\n");
    for l in kept {
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str(FORWARDED_PROTO_HEADER);
    out.push_str("\r\n\r\n");
    Some((out.into_bytes(), framing))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp_all(input: &[u8]) -> String {
        let mut s = ForwardedProtoStamper::new();
        let mut out = s.feed(input);
        out.extend(s.finish());
        String::from_utf8_lossy(&out).into_owned()
    }

    fn count(haystack: &str, needle: &str) -> usize {
        haystack.matches(needle).count()
    }

    const GET: &[u8] = b"GET /up HTTP/1.1\r\nHost: www.app.ztlp\r\nAccept: */*\r\n\r\n";

    #[test]
    fn stamps_a_simple_get_and_keeps_the_rest_intact() {
        let out = stamp_all(GET);
        assert!(out.starts_with("GET /up HTTP/1.1\r\n"), "{out:?}");
        assert!(out.contains("Host: www.app.ztlp\r\n"));
        assert!(out.contains("Accept: */*\r\n"));
        assert_eq!(count(&out, "X-Forwarded-Proto: https\r\n"), 1, "{out:?}");
        assert!(
            out.ends_with("\r\n\r\n"),
            "head must still end with a blank line"
        );
    }

    #[test]
    fn replaces_a_client_supplied_forwarded_proto_case_insensitively() {
        for spoof in [
            "X-Forwarded-Proto: http",
            "x-forwarded-proto:http",
            "X-FORWARDED-PROTO:   ftp",
        ] {
            let req = format!("GET / HTTP/1.1\r\nHost: a\r\n{spoof}\r\n\r\n");
            let out = stamp_all(req.as_bytes());
            assert_eq!(
                out.to_lowercase().matches("x-forwarded-proto:").count(),
                1,
                "exactly one header after replacing {spoof:?}: {out:?}"
            );
            assert!(out.contains("X-Forwarded-Proto: https\r\n"), "{out:?}");
            assert!(
                !out.contains("ftp") && !out.contains(": http\r\n"),
                "{out:?}"
            );
        }
    }

    #[test]
    fn the_422_request_shape_gets_the_header() {
        // What Chrome sent for the failing form POST.
        let req = b"POST /public/results HTTP/1.1\r\nHost: www.app.ztlp\r\nOrigin: https://www.app.ztlp\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\nsearch=ab";
        let out = stamp_all(req);
        assert!(out.contains("X-Forwarded-Proto: https\r\n"));
        assert!(
            out.ends_with("\r\n\r\nsearch=ab"),
            "body must be untouched: {out:?}"
        );
    }

    #[test]
    fn every_request_on_a_keep_alive_connection_is_stamped() {
        let mut s = ForwardedProtoStamper::new();
        let a = s.feed(GET);
        let b = s.feed(GET);
        for o in [a, b] {
            let t = String::from_utf8(o).unwrap();
            assert_eq!(count(&t, "X-Forwarded-Proto: https\r\n"), 1, "{t:?}");
        }
    }

    #[test]
    fn pipelined_requests_in_one_chunk_are_all_stamped() {
        let mut two = GET.to_vec();
        two.extend_from_slice(GET);
        let out = stamp_all(&two);
        assert_eq!(count(&out, "X-Forwarded-Proto: https\r\n"), 2, "{out:?}");
        assert_eq!(count(&out, "GET /up HTTP/1.1\r\n"), 2);
    }

    #[test]
    fn a_body_containing_a_blank_line_does_not_confuse_the_parser() {
        let body = "a\r\n\r\nGET /evil HTTP/1.1\r\nHost: x\r\n\r\n";
        let req = format!(
            "POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut two = req.into_bytes();
        two.extend_from_slice(GET);
        let out = stamp_all(&two);
        // POST + the real GET = 2 stamps; the "request" inside the body is data.
        assert_eq!(count(&out, "X-Forwarded-Proto: https\r\n"), 2, "{out:?}");
        assert!(out.contains(body), "body bytes must be verbatim");
    }

    #[test]
    fn output_is_identical_however_the_input_is_chunked() {
        let mut req = b"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        req.extend_from_slice(GET);
        let whole = stamp_all(&req);

        // one byte at a time
        let mut s = ForwardedProtoStamper::new();
        let mut out = Vec::new();
        for b in &req {
            out.extend(s.feed(&[*b]));
        }
        out.extend(s.finish());
        assert_eq!(String::from_utf8(out).unwrap(), whole);

        // every possible 2-way split
        for cut in 1..req.len() {
            let mut s = ForwardedProtoStamper::new();
            let mut out = s.feed(&req[..cut]);
            out.extend(s.feed(&req[cut..]));
            out.extend(s.finish());
            assert_eq!(String::from_utf8(out).unwrap(), whole, "cut at {cut}");
        }
    }

    #[test]
    fn chunked_request_gets_a_stamped_head_then_passes_through() {
        let req = b"POST /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let out = stamp_all(req);
        assert_eq!(count(&out, "X-Forwarded-Proto: https\r\n"), 1, "{out:?}");
        assert!(out.ends_with("\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), "{out:?}");
        // a second request-looking blob after a chunked body must NOT be touched
        let mut s = ForwardedProtoStamper::new();
        let _ = s.feed(req);
        let later = s.feed(GET);
        assert_eq!(later, GET, "passthrough after a chunked request");
    }

    #[test]
    fn websocket_upgrade_head_is_stamped_then_the_stream_is_opaque() {
        let req =
            b"GET /cable HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let mut s = ForwardedProtoStamper::new();
        let head = String::from_utf8(s.feed(req)).unwrap();
        assert_eq!(count(&head, "X-Forwarded-Proto: https\r\n"), 1, "{head:?}");
        let frames = [
            0x81u8, 0x05, b'h', b'e', b'l', b'l', b'o', 0x0d, 0x0a, 0x0d, 0x0a,
        ];
        assert_eq!(s.feed(&frames), frames, "ws frames pass through verbatim");
    }

    #[test]
    fn non_http_bytes_pass_through_immediately_and_unchanged() {
        // SSH banner: completes its first line, which is not an HTTP request line.
        let mut s = ForwardedProtoStamper::new();
        assert_eq!(
            s.feed(b"SSH-2.0-OpenSSH_9.6\r\n"),
            b"SSH-2.0-OpenSSH_9.6\r\n"
        );
        assert_eq!(s.feed(b"\x00\x01\x02 binary"), b"\x00\x01\x02 binary");
        // binary that never contains a CRLF: still must not be held forever
        let mut s = ForwardedProtoStamper::new();
        let big = vec![0xffu8; MAX_HEAD + 10];
        let out = s.feed(&big);
        assert_eq!(
            out.len(),
            big.len(),
            "oversize non-HTTP head is flushed, not stalled"
        );
    }

    #[test]
    fn a_partial_head_is_held_then_flushed_at_eof_not_lost() {
        let mut s = ForwardedProtoStamper::new();
        assert!(
            s.feed(b"GET /up HTTP/1.1\r\nHost: a\r\n").is_empty(),
            "head not complete: hold"
        );
        assert_eq!(
            s.finish(),
            b"GET /up HTTP/1.1\r\nHost: a\r\n",
            "EOF flushes the held bytes verbatim"
        );
    }

    #[test]
    fn conflicting_or_invalid_content_length_stops_parsing_safely() {
        // an unparsable length: we cannot know where the body ends, so we must not
        // keep stamping (it could split the stream in the wrong place).
        let req = b"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: banana\r\n\r\nXXXX";
        let mut s = ForwardedProtoStamper::new();
        let first = String::from_utf8(s.feed(req)).unwrap();
        assert_eq!(count(&first, "X-Forwarded-Proto: https\r\n"), 1);
        assert_eq!(s.feed(GET), GET, "passthrough after unknowable framing");
    }

    // CodeRabbit (PR #119): MAX_HEAD was compared with the WHOLE buffer, so a
    // held partial head plus one big read (the pump reads up to 65 000 bytes)
    // could cross 64 KiB while the head itself was complete and small. The head
    // then went out unstamped and the connection fell into passthrough, so a
    // large https form POST got the Rails 422 this fix exists to prevent. The
    // cap is for a head that never ends, not for head + body.
    #[test]
    fn a_complete_head_is_stamped_even_when_the_buffer_passes_the_head_cap() {
        // A large-but-legal head: ~1 KiB of cookies, split across two reads.
        let cookie = format!("Cookie: {}\r\n", "c".repeat(1000));
        let head_a =
            format!("POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 65000\r\n{cookie}");
        let head_a = head_a.as_bytes();
        let head_b = b"Origin: https://a\r\n\r\n";
        let body = vec![b'x'; 65_000];
        let mut s = ForwardedProtoStamper::new();
        // 1st read: only part of the head (held)
        assert!(s.feed(head_a).is_empty());
        // 2nd read: rest of the head + a full-size body slice. head_a (~1.1 KB)
        // + this read (65 021) puts the buffer over MAX_HEAD (65 536).
        let mut second = head_b.to_vec();
        second.extend_from_slice(&body);
        assert!(
            head_a.len() + second.len() > MAX_HEAD,
            "sanity: the buffer must really cross the head cap for this test to mean anything"
        );
        let out = s.feed(&second);
        let text = String::from_utf8_lossy(&out);
        assert_eq!(
            text.matches("X-Forwarded-Proto: https\r\n").count(),
            1,
            "head must be stamped despite a large first body read"
        );
        assert_eq!(
            out.len(),
            head_a.len() + head_b.len() + FORWARDED_PROTO_HEADER.len() + 2 + 65_000,
            "head + added header + the full body, nothing lost"
        );
        // and the connection is NOT stuck in passthrough: the next request is stamped
        let next = s.feed(GET);
        assert_eq!(
            String::from_utf8_lossy(&next)
                .matches("X-Forwarded-Proto: https\r\n")
                .count(),
            1,
            "keep-alive request after a large POST must still be stamped"
        );
    }

    #[test]
    fn a_head_that_really_exceeds_the_cap_is_released_unchanged_not_held_forever() {
        let mut s = ForwardedProtoStamper::new();
        let mut junk = b"GET / HTTP/1.1\r\n".to_vec();
        junk.extend(std::iter::repeat_n(b'a', MAX_HEAD + 100)); // no blank line ever
        let out = s.feed(&junk);
        assert_eq!(
            out.len(),
            junk.len(),
            "an endless head is flushed, not stalled"
        );
        // and once released it stays out of the way
        assert_eq!(s.feed(GET), GET);
    }

    #[test]
    fn folded_continuation_of_a_dropped_header_is_dropped_too() {
        let req = b"GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-Proto: http\r\n \tcontinued\r\nAccept: */*\r\n\r\n";
        let out = stamp_all(req);
        assert!(!out.contains("continued"), "{out:?}");
        assert!(out.contains("Accept: */*\r\n"));
    }
}
