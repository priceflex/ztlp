# Identity Headers Reference (v0.11.1)

The ZTLP gateway injects **13 cryptographically signed identity headers** into
HTTP requests forwarded to backend services. Headers are derived from the
client's X.509 certificate and ZTLP session state, providing rich identity
context without requiring backends to understand ZTLP directly.

## Header Reference

| Header | Description | Example |
|--------|------------|---------|
| `X-ZTLP-Node-ID` | 128-bit NodeID (hex) from cert SAN URI | `a1b2c3d4e5f67890a1b2c3d4e5f67890` |
| `X-ZTLP-Node-Name` | Node FQDN from cert CN | `laptop.office.ztlp` |
| `X-ZTLP-Zone` | Zone name from cert Organization | `office.ztlp` |
| `X-ZTLP-Authenticated` | Authentication status | `true` |
| `X-ZTLP-Assurance` | Key assurance level | `hardware` |
| `X-ZTLP-Key-Source` | Key storage backend | `yubikey` |
| `X-ZTLP-Key-Attestation` | Attestation status | `verified` |
| `X-ZTLP-Cert-Fingerprint` | SHA-256 fingerprint (hex) | `b94d27b9...e3b0c442` |
| `X-ZTLP-Cert-Serial` | X.509 serial number | `1234567890` |
| `X-ZTLP-Timestamp` | ISO 8601 timestamp of injection | `2026-03-23T21:15:00Z` |
| `X-ZTLP-Nonce` | 16 random bytes, hex-encoded (replay protection) | `3a7f9c2e1d4b8a6f...` |
| `X-ZTLP-Request-ID` | UUID v4 (audit trail) | `550e8400-e29b-41d4-a716-446655440000` |
| `X-ZTLP-Signature` | HMAC-SHA256 of all other X-ZTLP-* headers | `a1b2c3d4...` (64 hex) |

### Assurance Levels

| Level | Description | Key Sources |
|-------|------------|-------------|
| `hardware` | Key in tamper-resistant hardware | YubiKey, TPM 2.0, Secure Enclave |
| `device-bound` | Key bound to device, extractable with effort | Keychain, credential manager |
| `software` | Key stored in a file on disk | PEM file, JSON keyfile |
| `unknown` | Key source cannot be determined | — |

### Key Attestation

| Value | Meaning |
|-------|---------|
| `verified` | Hardware attestation certificate validated by the gateway |
| `unverified` | Key source is self-reported; no attestation available |

## Security Model

### Anti-Forgery: Strip → Inject → Sign

The gateway enforces a strict three-step pipeline:

1. **Strip** — all incoming `X-ZTLP-*` headers from the client are unconditionally removed
2. **Inject** — the gateway populates headers from the verified certificate and session state
3. **Sign** — an HMAC-SHA256 signature is computed over all injected headers

This ensures backends can trust that `X-ZTLP-*` headers were set exclusively
by the gateway.

### Auth Modes

| Mode | Headers Injected? | Certificate Required? | Use Case |
|------|:-:|:-:|----------|
| `passthrough` | No | No | Non-HTTP or binary protocols |
| `identity` | Yes (if cert present) | No | Enrich with identity when available |
| `enforce` | Yes | Yes (with `min_assurance`) | Require verified identity |

In `enforce` mode, the gateway rejects requests that don't meet the
configured minimum assurance level (e.g., `min_assurance: hardware`).

### HMAC Signature

The `X-ZTLP-Signature` header proves headers were injected by the gateway.

**Canonical signing format:**

1. Collect all `X-ZTLP-*` headers **except** `X-ZTLP-Signature`
2. Sort alphabetically by **lowercase header name**
3. Build a canonical string: each header as `name:value`, joined by newline (`\n`)
4. Compute `HMAC-SHA256(secret, canonical_string)`
5. Hex-encode the result → 64 character signature

**Example canonical string:**
```
x-ztlp-assurance:hardware
x-ztlp-authenticated:true
x-ztlp-cert-fingerprint:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
x-ztlp-cert-serial:1234567890
x-ztlp-key-attestation:verified
x-ztlp-key-source:yubikey
x-ztlp-node-id:a1b2c3d4e5f67890a1b2c3d4e5f67890
x-ztlp-node-name:laptop.office.ztlp
x-ztlp-nonce:3a7f9c2e1d4b8a6f0e5d7c9b2a4f8e1d
x-ztlp-request-id:550e8400-e29b-41d4-a716-446655440000
x-ztlp-timestamp:2026-03-23T21:15:00Z
x-ztlp-zone:office.ztlp
```

**Key:** The shared secret configured via `ZTLP_HEADER_HMAC_SECRET`
environment variable or the `header_signing.secret` config key.

### Timestamp Expiry

The `X-ZTLP-Timestamp` header contains an ISO 8601 timestamp of when the
headers were injected. Backends should reject requests where the timestamp
is more than 60 seconds old (configurable via
`header_signing.timestamp_window`).

### Nonce Replay Detection

The `X-ZTLP-Nonce` header contains 16 random bytes (32 hex characters),
unique per request. The gateway's `HeaderSigner.NonceCache` GenServer
maintains a sliding window of recently seen nonces. Duplicate nonces within
the timestamp window are rejected.

**⚠️ Backend-side nonce checking requires server-side state** — either an
in-memory set (with TTL-based expiry), a Redis sorted set, or equivalent.
This is optional but recommended for high-security deployments to prevent
replay attacks that bypass the gateway's cache (e.g., if the gateway restarts).

### Request-ID

`X-ZTLP-Request-ID` is a UUID v4 generated per request, providing an audit
trail correlation ID. Backends should log this value for distributed tracing.

## Verification Algorithm

```
1. Extract all X-ZTLP-* headers from the request
2. Check X-ZTLP-Timestamp is within the allowed window (ISO 8601 parse)
3. (Optional) Check X-ZTLP-Nonce hasn't been seen before
4. Collect all X-ZTLP-* headers except X-ZTLP-Signature
5. Sort by lowercase header name
6. Build canonical string: "name:value" joined by "\n"
7. Compute HMAC-SHA256(secret, canonical_string)
8. Compare computed HMAC with X-ZTLP-Signature (constant-time)
9. If match → headers are authentic; if not → reject
```

## Verification Examples

### Ruby / Rails

```ruby
require "openssl"
require "time"

def verify_ztlp_headers(request)
  sig = request.headers["X-ZTLP-Signature"]
  return false unless sig.present?

  # Collect X-ZTLP-* headers (excluding Signature)
  ztlp_headers = request.headers
    .select { |k, _| k.start_with?("X-ZTLP-") || k.start_with?("x-ztlp-") }
    .reject { |k, _| k.downcase == "x-ztlp-signature" }

  # Check timestamp
  ts = ztlp_headers.find { |k, _| k.downcase == "x-ztlp-timestamp" }&.last
  return false unless ts.present?
  return false if (Time.now.utc - Time.parse(ts)).abs > 60

  # Canonical string: sort by lowercase name, join as "name:value\n"
  canonical = ztlp_headers
    .sort_by { |k, _| k.downcase }
    .map { |k, v| "#{k.downcase}:#{v}" }
    .join("\n")

  expected = OpenSSL::HMAC.hexdigest(
    "SHA256",
    ENV.fetch("ZTLP_HEADER_HMAC_SECRET"),
    canonical
  )

  ActiveSupport::SecurityUtils.secure_compare(expected, sig)
end
```

### Python

```python
import hmac
import hashlib
import os
from datetime import datetime, timezone, timedelta

def verify_ztlp_headers(headers: dict) -> bool:
    sig = headers.get("X-ZTLP-Signature", "")
    if not sig:
        return False

    # Collect X-ZTLP-* headers (excluding Signature)
    ztlp_headers = {
        k: v for k, v in headers.items()
        if k.lower().startswith("x-ztlp-")
        and k.lower() != "x-ztlp-signature"
    }

    # Check timestamp
    ts_str = ztlp_headers.get("X-ZTLP-Timestamp") or ztlp_headers.get("x-ztlp-timestamp")
    if not ts_str:
        return False
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return False
    if abs((datetime.now(timezone.utc) - ts).total_seconds()) > 60:
        return False

    # Canonical string: sort by lowercase name, join as "name:value\n"
    canonical = "\n".join(
        f"{k.lower()}:{v}"
        for k, v in sorted(ztlp_headers.items(), key=lambda x: x[0].lower())
    )

    secret = os.environ["ZTLP_HEADER_HMAC_SECRET"]
    expected = hmac.new(
        secret.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, sig)
```

### Go

```go
package ztlp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func VerifyZTLPHeaders(r *http.Request) bool {
	sig := r.Header.Get("X-ZTLP-Signature")
	if sig == "" {
		return false
	}

	// Collect X-ZTLP-* headers (excluding Signature)
	var pairs []string
	ztlpHeaders := make(map[string]string)
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-ztlp-") && lower != "x-ztlp-signature" {
			ztlpHeaders[lower] = values[0]
		}
	}

	// Check timestamp
	tsStr, ok := ztlpHeaders["x-ztlp-timestamp"]
	if !ok {
		return false
	}
	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return false
	}
	if math.Abs(time.Since(ts).Seconds()) > 60 {
		return false
	}

	// Build canonical string: sort by lowercase name, join as "name:value\n"
	for k, v := range ztlpHeaders {
		pairs = append(pairs, fmt.Sprintf("%s:%s", k, v))
	}
	sort.Strings(pairs)
	canonical := strings.Join(pairs, "\n")

	// Compute HMAC-SHA256
	secret := os.Getenv("ZTLP_HEADER_HMAC_SECRET")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(sig))
}
```

## Configuration

### Gateway Elixir Config

```elixir
# config/config.exs
config :ztlp_gateway, :header_signing_enabled, true
config :ztlp_gateway, :header_signing_secret, System.get_env("ZTLP_HEADER_HMAC_SECRET")
config :ztlp_gateway, :header_signing_timestamp_window, 60
```

### Gateway YAML

```yaml
header_signing:
  enabled: true
  secret_env: ZTLP_HEADER_HMAC_SECRET   # read from environment variable
  timestamp_window: 60                    # seconds (default: 60)
```

### Per-Backend Auth Mode

```yaml
backends:
  - name: admin-panel
    host: 127.0.0.1
    port: 3000
    auth_mode: enforce              # require certificate + min assurance
    min_assurance: hardware         # reject software-only keys

  - name: public-api
    host: 127.0.0.1
    port: 8080
    auth_mode: identity             # inject headers if cert present

  - name: legacy-service
    host: 127.0.0.1
    port: 9090
    auth_mode: passthrough          # no headers injected
```

## When Headers Are Not Injected

- **passthrough mode** — no headers are injected
- **No client certificate** — in `identity` mode, headers are omitted if the
  client didn't present a certificate
- **Non-HTTP traffic** — binary protocols are forwarded as-is

## Security Recommendations

1. **Always verify the HMAC signature** in your backend before trusting
   the identity headers.
2. **Check the timestamp** — reject requests older than your configured window.
3. **Check the nonce** (optional but recommended) — maintain a seen-nonce set
   with TTL expiry. Use Redis sorted sets for distributed deployments.
4. **Use environment variables** for the HMAC secret — never hardcode it.
5. **Rotate the secret** periodically and redeploy gateway + backends together.
6. **Use constant-time comparison** for signature verification (all examples
   above use constant-time comparison).
7. **Firewall backends** — accept connections only from the gateway's IP.
   HMAC verification is defense-in-depth, not a substitute for network isolation.
8. **Set `auth_mode: enforce`** for sensitive services to require mTLS with
   a minimum assurance level.
9. **Log `X-ZTLP-Request-ID`** for audit trail and distributed tracing.
