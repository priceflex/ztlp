use hmac::{Hmac, Mac};
use httparse;
use sha2::Sha256;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Resolved, NS-authoritative identity for one authenticated ZTLP tunnel.
///
/// Every field here MUST come from a lookup keyed by the tunnel's
/// cryptographically-verified peer pubkey (Noise handshake) — never from
/// anything the connecting agent self-reports. See `gateway_identity.rs`
/// for the resolution + caching logic. This struct is the thing that gets
/// signed and injected into every HTTP request on the tunnel.
#[derive(Debug, Clone, Default)]
pub struct IdentityBundle {
    /// Owning user, resolved via DEVICE record `owner` field.
    pub owner_email: String,
    /// DEVICE record name (ZTLP-NS reverse lookup by pubkey).
    pub device_name: String,
    /// ZTLP zone the device is enrolled in.
    pub zone: String,
    /// The specific `group:` policy rule that authorized this service
    /// (empty if the rule was a direct/exact match, not group-based).
    pub group: String,
    /// "hardware" | "software" | "unknown" — see agent/hardware_key.rs.
    /// NOT currently attested; treat as advisory until a real attestation
    /// path (TPM quote / secure-enclave cert) is added.
    pub assurance: String,
    /// Short hex fingerprint of the tunnel's authenticated static pubkey,
    /// for backend audit logs (not a secret, just an identifier).
    pub pubkey_fingerprint: String,
}

/// Inject a signed, audience-bound identity bundle into one HTTP request.
///
/// `audience` MUST be the target service name (e.g. the SVC/hostname the
/// tunnel resolved to). Binding the signature to the audience is what
/// prevents a signature minted for service A from verifying on service B
/// if they happen to share an HMAC secret.
pub fn inject_headers(
    raw_stream: &[u8],
    bundle: &IdentityBundle,
    audience: &str,
    timestamp: &str,
    hmac_key: &[u8],
) -> Result<Vec<u8>, String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let res = req
        .parse(raw_stream)
        .map_err(|e| format!("Failed to parse HTTP request: {}", e))?;

    if res.is_partial() {
        return Err("Partial HTTP request received, cannot inject headers safely".to_string());
    }

    let headers_len = res.unwrap();

    let method = req.method.ok_or("Missing method")?;
    let path = req.path.ok_or("Missing path")?;

    // We recreate the HTTP request
    // 1. Keep the same Method and Path and HTTP version (assume 1.1)
    let version = match req.version {
        Some(1) => "1.1",
        Some(0) => "1.0",
        _ => "1.1", // fallback
    };

    // 2. Filter out any existing x-ztlp-* headers, keep everything else
    let mut kept_headers = Vec::new();
    let mut canonical_headers: Vec<(String, String)> = Vec::new();

    for h in req.headers {
        let name_lower = h.name.to_lowercase();
        // Drop any faked ZTLP headers injected by malicious client
        if name_lower.starts_with("x-ztlp-") {
            continue;
        }

        let value_str = String::from_utf8_lossy(h.value).into_owned();
        kept_headers.push((h.name.to_string(), value_str));
    }

    // 3. Inject new ZTLP identity headers. Every field is NS-resolved
    // (see IdentityBundle doc comment) — none of it is agent-self-reported.
    let fields: [(&str, &str); 8] = [
        ("X-ZTLP-Authenticated", "1"),
        ("X-ZTLP-Admin-Email", &bundle.owner_email),
        ("X-ZTLP-Device-Name", &bundle.device_name),
        ("X-ZTLP-Zone", &bundle.zone),
        ("X-ZTLP-Group", &bundle.group),
        ("X-ZTLP-Assurance", &bundle.assurance),
        ("X-ZTLP-Audience", audience),
        ("X-ZTLP-Timestamp", timestamp),
    ];

    for (name, value) in fields {
        kept_headers.push((name.to_string(), value.to_string()));
        canonical_headers.push((name.to_lowercase(), value.to_string()));
    }

    // Compute HMAC over ALL signed fields, sorted for determinism.
    canonical_headers.sort_by(|a, b| a.0.cmp(&b.0));

    // Canonical format: lowercased "name:value" pairs joined by "\n" — NO
    // trailing newline. (Matches the Ruby/Elixir HeaderVerifier convention
    // for the original 3-field set; extended here to the full bundle.)
    let canonical_string = canonical_headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect::<Vec<_>>()
        .join("\n");

    let mut mac = HmacSha256::new_from_slice(hmac_key).map_err(|e| e.to_string())?;
    mac.update(canonical_string.as_bytes());
    let result = mac.finalize();
    let signature_hex = hex::encode(result.into_bytes());

    kept_headers.push(("X-ZTLP-Signature".to_string(), signature_hex));

    // Reconstruct the request byte stream
    let mut output = Vec::new();
    let req_line = format!("{} {} HTTP/{}\r\n", method, path, version);
    output.extend_from_slice(req_line.as_bytes());

    for (k, v) in kept_headers {
        let header_line = format!("{}: {}\r\n", k, v);
        output.extend_from_slice(header_line.as_bytes());
    }

    output.extend_from_slice(b"\r\n");

    // Append any body right after headers
    output.extend_from_slice(&raw_stream[headers_len..]);

    Ok(output)
}

/// Streaming per-request HTTP header injector.
///
/// Tracks HTTP/1.x request boundaries across an arbitrary sequence of byte
/// chunks (the client→backend pump) so that EVERY request on a keep-alive
/// connection gets fresh signed X-ZTLP-* identity headers — not just the
/// first frame of the stream. The tunnel is authenticated ONCE (Noise
/// handshake); this injector stamps that verified identity onto each
/// request without any per-request crypto beyond one HMAC.
///
/// State machine:
///   Headers  — buffering until "\r\n\r\n"; on completion, inject and emit,
///              then transition based on Content-Length (bodies are passed
///              through verbatim; chunked encoding and upgrades fall back
///              to passthrough for the rest of the connection).
///   Body(n)  — pass through n remaining body bytes, then back to Headers.
///   Passthrough — no more parsing (chunked/upgrade/parse-failure safety).
pub struct RequestInjector {
    bundle: IdentityBundle,
    audience: String,
    hmac_key: Vec<u8>,
    buf: Vec<u8>,
    state: InjectorState,
}

enum InjectorState {
    Headers,
    Body(usize),
    Passthrough,
}

/// Cap on buffered header bytes before we give up and pass through
/// (defends against a client that never sends "\r\n\r\n").
const MAX_HEADER_BUF: usize = 64 * 1024;

impl RequestInjector {
    /// `audience` is the resolved target service/hostname for this tunnel —
    /// baked in at construction (once per tunnel) so every request signs
    /// against the same audience the tunnel was actually authorized for.
    pub fn new(bundle: IdentityBundle, audience: &str, hmac_key: &[u8]) -> Self {
        RequestInjector {
            bundle,
            audience: audience.to_string(),
            hmac_key: hmac_key.to_vec(),
            buf: Vec::new(),
            state: InjectorState::Headers,
        }
    }

    /// Feed a chunk of client→backend bytes; returns the bytes to forward.
    /// May return an empty vec (headers still buffering) — callers must not
    /// treat that as EOF.
    pub fn feed(&mut self, chunk: &[u8], timestamp: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(chunk.len() + 256);
        let mut input = chunk;

        loop {
            match self.state {
                InjectorState::Passthrough => {
                    out.extend_from_slice(input);
                    return out;
                }
                InjectorState::Body(ref mut remaining) => {
                    if input.len() <= *remaining {
                        *remaining -= input.len();
                        out.extend_from_slice(input);
                        return out;
                    }
                    let (body, rest) = input.split_at(*remaining);
                    out.extend_from_slice(body);
                    self.state = InjectorState::Headers;
                    input = rest;
                }
                InjectorState::Headers => {
                    self.buf.extend_from_slice(input);
                    input = &[];

                    // Find end of headers in the buffer.
                    let hdr_end = find_subsequence(&self.buf, b"\r\n\r\n");
                    match hdr_end {
                        None => {
                            if self.buf.len() > MAX_HEADER_BUF {
                                // Not HTTP or hostile — flush and stop parsing.
                                out.append(&mut self.buf);
                                self.state = InjectorState::Passthrough;
                            }
                            return out;
                        }
                        Some(pos) => {
                            let split = pos + 4;
                            let request_head = self.buf[..split].to_vec();
                            let rest: Vec<u8> = self.buf[split..].to_vec();
                            self.buf.clear();

                            // Body length from Content-Length (chunked → passthrough).
                            let head_str = String::from_utf8_lossy(&request_head);
                            let head_lower = head_str.to_lowercase();
                            let is_chunked = head_lower.contains("transfer-encoding: chunked");
                            let is_upgrade = head_lower.contains("upgrade:");
                            let content_length = head_lower
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);

                            match inject_headers(
                                &request_head,
                                &self.bundle,
                                &self.audience,
                                timestamp,
                                &self.hmac_key,
                            ) {
                                Ok(injected) => out.extend_from_slice(&injected),
                                Err(_) => {
                                    // Not parseable as HTTP — forward untouched
                                    // and stop parsing this connection.
                                    out.extend_from_slice(&request_head);
                                    out.extend_from_slice(&rest);
                                    self.state = InjectorState::Passthrough;
                                    return out;
                                }
                            }

                            if is_chunked || is_upgrade {
                                out.extend_from_slice(&rest);
                                self.state = InjectorState::Passthrough;
                                return out;
                            }

                            self.state = InjectorState::Body(content_length);
                            if !rest.is_empty() {
                                // Re-run the loop over the leftover bytes.
                                // (They belong to the body and/or the next
                                // pipelined request.)
                                let leftover = rest;
                                let mut sub = self.feed_internal(&leftover, timestamp);
                                out.append(&mut sub);
                            }
                            return out;
                        }
                    }
                }
            }
        }
    }

    // Internal re-entry that avoids double-borrowing in the leftover path.
    fn feed_internal(&mut self, chunk: &[u8], timestamp: &str) -> Vec<u8> {
        self.feed(chunk, timestamp)
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bundle(email: &str) -> IdentityBundle {
        IdentityBundle {
            owner_email: email.to_string(),
            device_name: "steves-macbook.demo.ztlp".to_string(),
            zone: "demo.ztlp".to_string(),
            group: "techs@demo.ztlp".to_string(),
            assurance: "hardware".to_string(),
            pubkey_fingerprint: "deadbeef01".to_string(),
        }
    }

    #[test]
    fn test_inject_headers() {
        let raw_req = b"GET /admin HTTP/1.1\r\nHost: example.com\r\nX-ZTLP-Fake: 123\r\nbaz: qux\r\n\r\nBODYDATA";
        let bundle = test_bundle("admin@example.com");
        let audience = "web.demo.spongebob.ztlp";
        let timestamp = "2026-05-20T12:00:00Z";
        let hmac_key = b"supersecretkey";

        let modified = inject_headers(raw_req, &bundle, audience, timestamp, hmac_key).unwrap();
        let modified_str = String::from_utf8(modified.clone()).unwrap();

        // Check stripped header
        assert!(!modified_str.contains("X-ZTLP-Fake"));

        // Check basic header persistence
        assert!(modified_str.contains("Host: example.com"));
        assert!(modified_str.contains("baz: qux"));

        // Check injected headers (full bundle, not just email)
        assert!(modified_str.contains("X-ZTLP-Authenticated: 1"));
        assert!(modified_str.contains("X-ZTLP-Admin-Email: admin@example.com"));
        assert!(modified_str.contains("X-ZTLP-Device-Name: steves-macbook.demo.ztlp"));
        assert!(modified_str.contains("X-ZTLP-Zone: demo.ztlp"));
        assert!(modified_str.contains("X-ZTLP-Group: techs@demo.ztlp"));
        assert!(modified_str.contains("X-ZTLP-Assurance: hardware"));
        assert!(modified_str.contains("X-ZTLP-Audience: web.demo.spongebob.ztlp"));
        assert!(modified_str.contains("X-ZTLP-Timestamp: 2026-05-20T12:00:00Z"));
        assert!(modified_str.contains("X-ZTLP-Signature: "));

        // Verify body preservation
        assert!(modified_str.ends_with("\r\n\r\nBODYDATA"));
    }

    /// BDD: locks the canonical-string format byte-for-byte against the
    /// expanded 8-field bundle. If this test breaks, any downstream
    /// verifier (Ruby/Elixir/Python) needs its canonical-field list
    /// updated to match.
    ///
    /// Canonical rule (unchanged from the original 3-field contract, just
    /// extended to all 8 signed fields):
    ///   headers.map { |n,v| [n.downcase, v] }
    ///          .sort_by { |n,_| n }
    ///          .map { |n,v| "#{n}:#{v}" }
    ///          .join("\n")
    #[test]
    fn test_canonical_string_matches_ruby_contract() {
        // Empty body, multiple non-ztlp headers (must be excluded from MAC),
        // and a pre-existing forged x-ztlp-signature (must be excluded too).
        let raw_req = b"POST /api HTTP/1.1\r\n\
                        Host: bootstrap.example.ztlp\r\n\
                        Content-Length: 0\r\n\
                        X-ZTLP-Signature: forged-deadbeef\r\n\
                        X-Forwarded-For: 10.0.0.1\r\n\
                        \r\n";
        let bundle = test_bundle("ops@techrockstars.com");
        let audience = "bootstrap.example.ztlp";
        let timestamp = "2025-01-01T00:00:00Z";
        let hmac_key = b"shared-tenant-secret";

        // Expected canonical string: all EIGHT injected ZTLP headers,
        // lowercased, sorted, joined by '\n', NO trailing newline.
        let expected_canonical = "x-ztlp-admin-email:ops@techrockstars.com\n\
             x-ztlp-assurance:hardware\n\
             x-ztlp-audience:bootstrap.example.ztlp\n\
             x-ztlp-authenticated:1\n\
             x-ztlp-device-name:steves-macbook.demo.ztlp\n\
             x-ztlp-group:techs@demo.ztlp\n\
             x-ztlp-timestamp:2025-01-01T00:00:00Z\n\
             x-ztlp-zone:demo.ztlp";

        let mut mac = HmacSha256::new_from_slice(hmac_key).unwrap();
        mac.update(expected_canonical.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());

        let modified = inject_headers(raw_req, &bundle, audience, timestamp, hmac_key).unwrap();
        let s = String::from_utf8(modified).unwrap();

        // Forged signature must be stripped.
        assert!(!s.contains("forged-deadbeef"));
        // Non-ZTLP headers must be preserved verbatim (case + value).
        assert!(s.contains("Host: bootstrap.example.ztlp\r\n"));
        assert!(s.contains("X-Forwarded-For: 10.0.0.1\r\n"));
        // Trusted signature must match the canonicalization byte-for-byte.
        assert!(
            s.contains(&format!("X-ZTLP-Signature: {}\r\n", expected_sig)),
            "signature mismatch — canonical contract drift. Got body:\n{}",
            s
        );
    }

    /// BDD: a partial/streaming request (no \r\n\r\n boundary yet) MUST be
    /// rejected rather than signed, otherwise we'd be HMAC-signing an
    /// attacker-controlled prefix. Documents the safe-failure contract.
    ///
    /// **Stability contract for tunnel.rs**: the returned error string MUST
    /// start with "Partial HTTP request" — the tunnel.rs HTTP-injection
    /// hook pattern-matches on that prefix to distinguish "need more bytes"
    /// (keep buffering across decrypted chunks) from "non-recoverable
    /// parse error" (drop the connection). Changing this message will
    /// silently break multi-chunk HTTP injection — turbo.min.js requests
    /// and any other request that straddles a TCP frame will start
    /// failing again.
    #[test]
    fn test_partial_request_is_rejected() {
        let partial = b"GET / HTTP/1.1\r\nHost: example.com\r\n"; // no terminator
        let bundle = test_bundle("x@y.z");
        let result = inject_headers(partial, &bundle, "svc.ztlp", "2025-01-01T00:00:00Z", b"k");
        assert!(result.is_err(), "partial requests must not be signed");
        let err = result.unwrap_err();
        assert!(
            err.contains("Partial HTTP request"),
            "partial error message must start with 'Partial HTTP request' \
             (tunnel.rs pattern-matches on this prefix to keep buffering \
             across chunks) — got: {err}"
        );
    }

    /// BDD: when a complete request is reassembled from multiple chunks,
    /// the injector produces the same output as if the request had
    /// arrived in one piece. Locks the "buffer-and-retry" semantics that
    /// the tunnel.rs hook depends on for fragmented HTTP requests.
    #[test]
    fn test_inject_is_idempotent_across_reassembled_chunks() {
        let chunk_a = b"GET /assets/turbo.min.js HTTP/1.1\r\nHost: bootstrap.test.ztlp\r\nCookie: ";
        let chunk_b = b"big_cookie=";
        let chunk_c = &[b'x'; 600][..];
        let chunk_d = b"\r\n\r\n";

        let bundle = test_bundle("admin@example.com");
        let audience = "bootstrap.test.ztlp";
        let ts = "2026-05-20T12:00:00Z";
        let key = b"shared-tenant-secret";

        // Single-shot: the request arrives in one frame.
        let mut single = Vec::new();
        single.extend_from_slice(chunk_a);
        single.extend_from_slice(chunk_b);
        single.extend_from_slice(chunk_c);
        single.extend_from_slice(chunk_d);
        let single_out =
            inject_headers(&single, &bundle, audience, ts, key).expect("single-shot must inject");

        // Buffered: simulate the tunnel.rs accumulator — partial on each
        // chunk until the terminator arrives, then complete.
        let mut acc = Vec::new();
        acc.extend_from_slice(chunk_a);
        assert!(inject_headers(&acc, &bundle, audience, ts, key)
            .unwrap_err()
            .contains("Partial HTTP request"));
        acc.extend_from_slice(chunk_b);
        assert!(inject_headers(&acc, &bundle, audience, ts, key)
            .unwrap_err()
            .contains("Partial HTTP request"));
        acc.extend_from_slice(chunk_c);
        assert!(inject_headers(&acc, &bundle, audience, ts, key)
            .unwrap_err()
            .contains("Partial HTTP request"));
        acc.extend_from_slice(chunk_d);
        let buffered_out =
            inject_headers(&acc, &bundle, audience, ts, key).expect("complete must inject");

        // The two paths MUST produce byte-identical rewrites — the gateway
        // forwarding either one yields the same signed request upstream.
        assert_eq!(
            single_out, buffered_out,
            "reassembled-from-chunks output must match single-shot output"
        );
    }

    // ── RequestInjector (streaming, per-request keep-alive) ─────────────

    #[test]
    fn test_request_injector_multiple_requests_keepalive() {
        // Two GET requests arriving on the same connection (keep-alive):
        // BOTH must get injected headers.
        let key = b"supersecretkey";
        let mut inj = RequestInjector::new(test_bundle("admin@example.com"), "svc.ztlp", key);

        let req1 = b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req2 = b"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let out1 = inj.feed(req1, "2026-05-20T12:00:00Z");
        let s1 = String::from_utf8_lossy(&out1);
        assert!(s1.contains("GET /a HTTP/1.1"));
        assert!(s1.contains("X-ZTLP-Signature: "));

        let out2 = inj.feed(req2, "2026-05-20T12:00:01Z");
        let s2 = String::from_utf8_lossy(&out2);
        assert!(s2.contains("GET /b HTTP/1.1"));
        assert!(
            s2.contains("X-ZTLP-Signature: "),
            "second keep-alive request MUST also be injected, got: {}",
            s2
        );
        assert!(s2.contains("X-ZTLP-Timestamp: 2026-05-20T12:00:01Z"));
    }

    #[test]
    fn test_request_injector_split_across_chunks() {
        // A request head split across 3 chunks must still be injected once
        // complete, with nothing emitted early.
        let key = b"supersecretkey";
        let mut inj = RequestInjector::new(test_bundle("admin@example.com"), "svc.ztlp", key);

        let out = inj.feed(b"GET / HTT", "t");
        assert!(out.is_empty());
        let out = inj.feed(b"P/1.1\r\nHost: h\r\n", "t");
        assert!(out.is_empty());
        let out = inj.feed(b"\r\n", "t");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("X-ZTLP-Authenticated: 1"));
    }

    #[test]
    fn test_request_injector_body_passthrough_then_next_request() {
        // POST with a body, then a second request in the same chunk: body
        // bytes pass through untouched and the follow-up request is injected.
        let key = b"supersecretkey";
        let mut inj = RequestInjector::new(test_bundle("admin@example.com"), "svc.ztlp", key);

        let mut input = Vec::new();
        input.extend_from_slice(
            b"POST /submit HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nBODY",
        );
        input.extend_from_slice(b"GET /next HTTP/1.1\r\nHost: h\r\n\r\n");

        let out = inj.feed(&input, "t");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("POST /submit HTTP/1.1"));
        assert!(s.contains("BODY"));
        assert!(s.contains("GET /next HTTP/1.1"));
        // Both requests signed.
        assert_eq!(s.matches("X-ZTLP-Signature: ").count(), 2);
    }

    #[test]
    fn test_request_injector_non_http_passthrough() {
        // Binary/non-HTTP traffic: emitted untouched once the header cap
        // trips or parse fails; no data loss.
        let key = b"supersecretkey";
        let mut inj = RequestInjector::new(test_bundle("admin@example.com"), "svc.ztlp", key);

        // "\r\n\r\n" present but head unparseable as HTTP.
        let junk = b"\x00\x01\x02NOTHTTP\r\n\r\n\x03\x04";
        let out = inj.feed(junk, "t");
        assert_eq!(
            &out[..],
            &junk[..],
            "non-HTTP bytes must pass through unmodified"
        );
    }

    #[test]
    fn test_request_injector_strips_spoofed_headers_every_request() {
        // A client trying to spoof identity on the SECOND request must
        // still get its fake headers stripped.
        let key = b"supersecretkey";
        let mut inj = RequestInjector::new(test_bundle("real@example.com"), "svc.ztlp", key);

        let _ = inj.feed(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n", "t");
        let out = inj.feed(
            b"GET /b HTTP/1.1\r\nHost: h\r\nX-ZTLP-Admin-Email: fake@evil.com\r\n\r\n",
            "t",
        );
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("fake@evil.com"));
        assert!(s.contains("X-ZTLP-Admin-Email: real@example.com"));
    }

    #[test]
    fn test_audience_binding_prevents_cross_service_replay() {
        // Same bundle + timestamp + secret, different audience, MUST
        // produce different signatures — this is what stops a signature
        // minted for service A from verifying on service B.
        let bundle = test_bundle("admin@example.com");
        let ts = "2026-05-20T12:00:00Z";
        let key = b"shared-tenant-secret";
        let raw_req = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";

        let out_a = inject_headers(raw_req, &bundle, "service-a.ztlp", ts, key).unwrap();
        let out_b = inject_headers(raw_req, &bundle, "service-b.ztlp", ts, key).unwrap();

        let sig_a = extract_signature(&out_a);
        let sig_b = extract_signature(&out_b);
        assert_ne!(
            sig_a, sig_b,
            "signatures for different audiences must differ — cross-app replay \
             would otherwise be possible"
        );
    }

    fn extract_signature(raw: &[u8]) -> String {
        let s = String::from_utf8_lossy(raw);
        s.lines()
            .find_map(|l| l.strip_prefix("X-ZTLP-Signature: "))
            .unwrap_or("")
            .trim()
            .to_string()
    }
}
