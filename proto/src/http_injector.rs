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
        canonical_headers.push((name_lower, value_str.clone()));

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

    let mut canonical_string = String::new();
    for (k, v) in canonical_headers {
        canonical_string.push_str(&k);
        canonical_string.push(':');
        canonical_string.push_str(&v);
        canonical_string.push('\n');
    }

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
        // baz:qux\nhost:example.com\nx-ztlp-admin-email:admin@example.com\nx-ztlp-authenticated:1\nx-ztlp-timestamp:2026-05-20T12:00:00Z\n

        let mut mac = HmacSha256::new_from_slice(hmac_key).unwrap();
        mac.update(b"baz:qux\nhost:example.com\nx-ztlp-admin-email:admin@example.com\nx-ztlp-authenticated:1\nx-ztlp-timestamp:2026-05-20T12:00:00Z\n");
        let expected_signature = hex::encode(mac.finalize().into_bytes());

        assert!(modified_str.contains(&format!("X-ZTLP-Signature: {}", expected_signature)));

        // Verify body preservation
        assert!(modified_str.ends_with("\r\n\r\nBODYDATA"));
    }
}
