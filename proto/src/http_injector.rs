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
    #[test]
    fn test_partial_request_is_rejected() {
        let partial = b"GET / HTTP/1.1\r\nHost: example.com\r\n"; // no terminator
        let result = inject_headers(partial, "x@y.z", "2025-01-01T00:00:00Z", b"k");
        assert!(result.is_err(), "partial requests must not be signed");
    }
}
