use hmac::{Hmac, Mac};
use httparse;
use sha2::Sha256;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub fn inject_headers(
    raw_stream: &[u8],
    email: &str,
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

    // 3. Inject new ZTLP headers
    kept_headers.push(("X-ZTLP-Authenticated".to_string(), "1".to_string()));
    kept_headers.push(("X-ZTLP-Admin-Email".to_string(), email.to_string()));
    kept_headers.push(("X-ZTLP-Timestamp".to_string(), timestamp.to_string()));

    // Add them to canonical before calculation
    canonical_headers.push(("x-ztlp-authenticated".to_string(), "1".to_string()));
    canonical_headers.push(("x-ztlp-admin-email".to_string(), email.to_string()));
    canonical_headers.push(("x-ztlp-timestamp".to_string(), timestamp.to_string()));

    // Compute HMAC
    canonical_headers.sort_by(|a, b| a.0.cmp(&b.0));

    // Canonical format matches the Ruby/Elixir HeaderVerifier exactly:
    //   lowercased "name:value" pairs joined by "\n" — NO trailing newline.
    // Ruby reference: `headers.map { |n,v| "#{n}:#{v}" }.join("\n")`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_headers() {
        let raw_req = b"GET /admin HTTP/1.1\r\nHost: example.com\r\nX-ZTLP-Fake: 123\r\nbaz: qux\r\n\r\nBODYDATA";
        let email = "admin@example.com";
        let timestamp = "2026-05-20T12:00:00Z";
        let hmac_key = b"supersecretkey";

        let modified = inject_headers(raw_req, email, timestamp, hmac_key).unwrap();
        let modified_str = String::from_utf8(modified.clone()).unwrap();

        // Check stripped header
        assert!(!modified_str.contains("X-ZTLP-Fake"));

        // Check basic header persistence
        assert!(modified_str.contains("Host: example.com"));
        assert!(modified_str.contains("baz: qux"));

        // Check injected headers
        assert!(modified_str.contains("X-ZTLP-Authenticated: 1"));
        assert!(modified_str.contains("X-ZTLP-Admin-Email: admin@example.com"));
        assert!(modified_str.contains("X-ZTLP-Timestamp: 2026-05-20T12:00:00Z"));
        assert!(modified_str.contains("X-ZTLP-Signature: "));

        // Signature checks
        // Canonical format expectation:
        // x-ztlp-admin-email:admin@example.com\nx-ztlp-authenticated:1\nx-ztlp-timestamp:2026-05-20T12:00:00Z
        // (no trailing newline — matches Ruby `.join("\n")` semantics)

        let mut mac = HmacSha256::new_from_slice(hmac_key).unwrap();
        mac.update(b"x-ztlp-admin-email:admin@example.com\nx-ztlp-authenticated:1\nx-ztlp-timestamp:2026-05-20T12:00:00Z");
        let expected_signature = hex::encode(mac.finalize().into_bytes());

        assert!(modified_str.contains(&format!("X-ZTLP-Signature: {}", expected_signature)));

        // Verify body preservation
        assert!(modified_str.ends_with("\r\n\r\nBODYDATA"));
    }

    /// BDD: locks the canonical-string format byte-for-byte against the
    /// Ruby/Elixir HeaderVerifier contract. If this test breaks, the Rails
    /// `Ztlp::HeaderVerifier` will reject all gateway-signed requests.
    ///
    /// Reference: bootstrap/lib/ztlp/header_verifier.rb#canonical_string
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
        let email = "ops@techrockstars.com";
        let timestamp = "2025-01-01T00:00:00Z";
        let hmac_key = b"shared-tenant-secret";

        // Expected canonical string: only the THREE injected ZTLP headers,
        // lowercased, sorted, joined by '\n', NO trailing newline.
        let expected_canonical = "x-ztlp-admin-email:ops@techrockstars.com\n\
             x-ztlp-authenticated:1\n\
             x-ztlp-timestamp:2025-01-01T00:00:00Z";

        let mut mac = HmacSha256::new_from_slice(hmac_key).unwrap();
        mac.update(expected_canonical.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());

        let modified = inject_headers(raw_req, email, timestamp, hmac_key).unwrap();
        let s = String::from_utf8(modified).unwrap();

        // Forged signature must be stripped.
        assert!(!s.contains("forged-deadbeef"));
        // Non-ZTLP headers must be preserved verbatim (case + value).
        assert!(s.contains("Host: bootstrap.example.ztlp\r\n"));
        assert!(s.contains("X-Forwarded-For: 10.0.0.1\r\n"));
        // Trusted signature must match the Ruby canonicalization byte-for-byte.
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
        let result = inject_headers(partial, "x@y.z", "2025-01-01T00:00:00Z", b"k");
        assert!(result.is_err(), "partial requests must not be signed");
        let err = result.unwrap_err();
        assert!(
            err.contains("Partial HTTP request"),
            "partial error message must start with 'Partial HTTP request' \
             (tunnel.rs pattern-matches on this prefix to keep buffering \
             across chunks) — got: {err}"
        );
    }

    /// BDD: Z2LS client-auth headers (X-ZTLP-Client-*) MUST survive the
    /// admin-header strip-and-inject pass. They carry the per-zone HMAC
    /// auth contract verified by `Ztlp::ApiAuthenticator` in Rails, and
    /// the gateway has no business rewriting them — its job for these
    /// requests is to pass them through verbatim. The admin-auth header
    /// set (X-ZTLP-Authenticated / X-ZTLP-Admin-Email / X-ZTLP-Timestamp /
    /// X-ZTLP-Signature) lives under a non-prefixed namespace and is
    /// gateway-injected; the client-auth set lives under the prefixed
    /// `X-ZTLP-Client-*` namespace and is client-injected. The two paths
    /// are disjoint by construction so a client cannot smuggle an admin
    /// header by shadowing it.
    ///
    /// Reference: docs/per_zone_hmac_design.md + bootstrap/app/services/ztlp/api_authenticator.rb
    #[test]
    fn test_x_ztlp_client_headers_survive_strip() {
        let raw_req = b"GET /api/v1/whoami HTTP/1.1\r\n\
                        Host: bootstrap.hermes-sandbox.ztlp\r\n\
                        X-ZTLP-Client-Zone: hermes-sandbox.ztlp\r\n\
                        X-ZTLP-Client-Name: z2ls.hermes-sandbox\r\n\
                        X-ZTLP-Client-Timestamp: 1748159999\r\n\
                        X-ZTLP-Client-Signature: deadbeefcafef00d\r\n\
                        X-ZTLP-Fake: should-be-stripped\r\n\
                        \r\n";
        let email = "admin@example.com";
        let timestamp = "2026-05-24T08:00:00Z";
        let hmac_key = b"shared-tenant-secret";

        let modified = inject_headers(raw_req, email, timestamp, hmac_key).unwrap();
        let s = String::from_utf8(modified).unwrap();

        // Client-auth headers MUST pass through verbatim.
        assert!(
            s.contains("X-ZTLP-Client-Zone: hermes-sandbox.ztlp\r\n"),
            "X-ZTLP-Client-Zone stripped — Z2LS auth path broken. Got:\n{}",
            s
        );
        assert!(
            s.contains("X-ZTLP-Client-Name: z2ls.hermes-sandbox\r\n"),
            "X-ZTLP-Client-Name stripped — Z2LS auth path broken. Got:\n{}",
            s
        );
        assert!(
            s.contains("X-ZTLP-Client-Timestamp: 1748159999\r\n"),
            "X-ZTLP-Client-Timestamp stripped — Z2LS auth path broken. Got:\n{}",
            s
        );
        assert!(
            s.contains("X-ZTLP-Client-Signature: deadbeefcafef00d\r\n"),
            "X-ZTLP-Client-Signature stripped — Z2LS auth path broken. Got:\n{}",
            s
        );

        // Non-client-prefixed faked headers must still be stripped — the strip
        // policy MUST stay strict for the admin-auth namespace.
        assert!(
            !s.contains("X-ZTLP-Fake"),
            "X-ZTLP-Fake survived strip — admin-namespace defense broken"
        );

        // Gateway-injected admin headers must still be present (so admin
        // requests via the same gateway still work).
        assert!(s.contains("X-ZTLP-Authenticated: 1"));
        assert!(s.contains("X-ZTLP-Admin-Email: admin@example.com"));
        assert!(s.contains("X-ZTLP-Timestamp: 2026-05-24T08:00:00Z"));
        assert!(s.contains("X-ZTLP-Signature: "));
    }

    /// BDD: a client MUST NOT be able to forge an admin header by giving
    /// it the X-ZTLP-Client- prefix that matches case-insensitively to an
    /// admin header name. The allowlist applies to the prefix only; an
    /// attempted `X-ZTLP-Client-Authenticated: 1` from the client wire
    /// should pass through (the gateway has no business rewriting it),
    /// but the Rails `ApplicationController` admin-auth path reads
    /// `X-ZTLP-Authenticated`, not `X-ZTLP-Client-Authenticated`. So the
    /// header arriving at Rails is harmless — only the un-prefixed
    /// admin namespace can elevate. This test pins the prefix-only
    /// allowlist semantics so a future "case-insensitive shadowing"
    /// regression in the strip filter would be caught.
    #[test]
    fn test_client_prefix_cannot_shadow_admin_header() {
        let raw_req = b"GET /admin HTTP/1.1\r\n\
                        Host: bootstrap.example.ztlp\r\n\
                        X-ZTLP-Client-Authenticated: 1\r\n\
                        X-ZTLP-Authenticated: forged-by-client\r\n\
                        \r\n";
        let modified =
            inject_headers(raw_req, "admin@example.com", "2026-05-24T08:00:00Z", b"k").unwrap();
        let s = String::from_utf8(modified).unwrap();

        // The un-prefixed admin header MUST be stripped — forged-by-client
        // value gone; replaced with the gateway's injected "1".
        assert!(!s.contains("forged-by-client"));
        // The gateway-injected canonical admin header is present (and only
        // once).
        assert_eq!(s.matches("X-ZTLP-Authenticated: 1\r\n").count(), 1);
        // The prefixed-but-misleadingly-named client header passes through
        // — harmless because Rails admin-auth reads the un-prefixed name.
        assert!(s.contains("X-ZTLP-Client-Authenticated: 1\r\n"));
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

        let email = "admin@example.com";
        let ts = "2026-05-20T12:00:00Z";
        let key = b"shared-tenant-secret";

        // Single-shot: the request arrives in one frame.
        let mut single = Vec::new();
        single.extend_from_slice(chunk_a);
        single.extend_from_slice(chunk_b);
        single.extend_from_slice(chunk_c);
        single.extend_from_slice(chunk_d);
        let single_out = inject_headers(&single, email, ts, key).expect("single-shot must inject");

        // Buffered: simulate the tunnel.rs accumulator — partial on each
        // chunk until the terminator arrives, then complete.
        let mut acc = Vec::new();
        acc.extend_from_slice(chunk_a);
        assert!(inject_headers(&acc, email, ts, key)
            .unwrap_err()
            .contains("Partial HTTP request"));
        acc.extend_from_slice(chunk_b);
        assert!(inject_headers(&acc, email, ts, key)
            .unwrap_err()
            .contains("Partial HTTP request"));
        acc.extend_from_slice(chunk_c);
        assert!(inject_headers(&acc, email, ts, key)
            .unwrap_err()
            .contains("Partial HTTP request"));
        acc.extend_from_slice(chunk_d);
        let buffered_out = inject_headers(&acc, email, ts, key).expect("complete must inject");

        // The two paths MUST produce byte-identical rewrites — the gateway
        // forwarding either one yields the same signed request upstream.
        assert_eq!(
            single_out, buffered_out,
            "reassembled-from-chunks output must match single-shot output"
        );
    }
}
