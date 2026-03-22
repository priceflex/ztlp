# Identity Headers Reference

The ZTLP gateway injects verified identity headers into HTTP requests
forwarded to backend services. These headers are cryptographically signed
to prevent spoofing.

## Header Reference

| Header | Description | Example |
|--------|------------|---------|
| `X-ZTLP-Node-ID` | Unique node identifier (hex) | `a1b2c3d4e5f6` |
| `X-ZTLP-Node-Name` | Human-readable node name | `steves-macbook.corp.ztlp` |
| `X-ZTLP-User` | Authenticated user identity | `steve` |
| `X-ZTLP-Zone` | Network zone | `corp.ztlp` |
| `X-ZTLP-Assurance` | Authentication assurance level | `hardware` |
| `X-ZTLP-Groups` | Comma-separated group list | `admins,engineering` |
| `X-ZTLP-Timestamp` | Injection time (Unix seconds) | `1711065600` |
| `X-ZTLP-Signature` | HMAC-SHA256 of all above | `a1b2c3...` (64 hex chars) |

## Security Model

### Header Stripping

The gateway **strips all incoming `X-ZTLP-*` headers** before forwarding.
This prevents clients from spoofing identity headers by sending them
directly. Only the gateway can inject these headers.

### HMAC Signature

The `X-ZTLP-Signature` header contains an HMAC-SHA256 digest that proves
the headers were injected by the gateway:

**Signed payload:**
```
{Node-ID}|{Node-Name}|{User}|{Zone}|{Assurance}|{Groups}|{Timestamp}
```

**Key:** The shared secret configured via `ZTLP_HEADER_HMAC_SECRET`
environment variable or the `tls.header_signing.secret` config key.

### Timestamp Window

The `X-ZTLP-Timestamp` header contains the Unix timestamp when the headers
were injected. Backends should reject requests where the timestamp is
more than 60 seconds old (configurable via
`tls.header_signing.timestamp_window_seconds`).

This prevents replay attacks where an attacker captures and replays a
request with valid signed headers.

## Verification Algorithm

```
1. Extract all X-ZTLP-* headers from the request
2. Check X-ZTLP-Timestamp is within the allowed window
3. Construct the payload: join header values with "|"
4. Compute HMAC-SHA256(secret, payload)
5. Compare computed HMAC with X-ZTLP-Signature (constant-time)
6. If match → headers are authentic; if not → reject
```

## Verification Examples

### Ruby/Rails

```ruby
def verify_ztlp_headers(request)
  sig = request.headers["X-ZTLP-Signature"]
  ts  = request.headers["X-ZTLP-Timestamp"]

  return false unless sig.present? && ts.present?
  return false if (Time.now.to_i - ts.to_i).abs > 60

  payload = %w[
    X-ZTLP-Node-ID X-ZTLP-Node-Name X-ZTLP-User
    X-ZTLP-Zone X-ZTLP-Assurance X-ZTLP-Groups
  ].map { |h| request.headers[h] }.push(ts).join("|")

  expected = OpenSSL::HMAC.hexdigest(
    "SHA256",
    ENV.fetch("ZTLP_HEADER_HMAC_SECRET"),
    payload
  )

  ActiveSupport::SecurityUtils.secure_compare(expected, sig)
end
```

### Python

```python
import hmac, hashlib, time

def verify_ztlp_headers(headers):
    sig = headers.get("X-ZTLP-Signature", "")
    ts = headers.get("X-ZTLP-Timestamp", "0")

    if abs(time.time() - int(ts)) > 60:
        return False

    payload = "|".join([
        headers.get("X-ZTLP-Node-ID", ""),
        headers.get("X-ZTLP-Node-Name", ""),
        headers.get("X-ZTLP-User", ""),
        headers.get("X-ZTLP-Zone", ""),
        headers.get("X-ZTLP-Assurance", ""),
        headers.get("X-ZTLP-Groups", ""),
        ts,
    ])

    secret = os.environ["ZTLP_HEADER_HMAC_SECRET"]
    expected = hmac.new(
        secret.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, sig)
```

## Configuration

### Gateway YAML

```yaml
tls:
  header_signing:
    enabled: true
    secret: "your-secret-here"        # or use secret_env
    secret_env: ZTLP_HEADER_HMAC_SECRET
    timestamp_window_seconds: 60
```

### Per-Backend Signing

Each backend can optionally have its own signing secret:

```yaml
backends:
  - name: admin
    auth_mode: enforce
    # inherits global header_signing secret
  - name: partner-api
    auth_mode: identity
    # uses a per-backend secret if configured
```

## When Headers Are Not Injected

- **passthrough mode** — no headers are injected
- **No client certificate** — in `identity` mode, no headers if the client
  didn't present a certificate
- **Non-HTTP traffic** — binary protocols are forwarded as-is

## Security Recommendations

1. **Always verify the HMAC signature** in your backend before trusting
   the identity headers.
2. **Check the timestamp** to prevent replay attacks.
3. **Use environment variables** for the HMAC secret — never hardcode it.
4. **Rotate the secret** periodically and redeploy.
5. **Use constant-time comparison** for signature verification.
6. **Set `auth_mode: enforce`** for sensitive services to require mTLS.
