# Passwordless Authentication Guide

ZTLP enables passwordless authentication for backend services by extracting
identity from client TLS certificates and propagating it via signed HTTP
headers. Backends receive verified identity information without the user
ever entering a password.

## How It Works

```
User's Browser                ZTLP Gateway              Backend App
  │                               │                         │
  │  TLS + client cert ──────────▶│                         │
  │                               │ Extract identity        │
  │                               │ from X.509 cert         │
  │                               │                         │
  │                               │ HTTP + X-ZTLP-* ──────▶│
  │                               │  headers (HMAC signed)  │
  │                               │                         │
  │                               │◀─── Response ──────────│
  │◀────── Response ──────────────│                         │
```

1. The user's browser or app presents a client certificate during TLS handshake
2. The ZTLP gateway extracts identity from the certificate
3. The gateway injects signed `X-ZTLP-*` headers into the HTTP request
4. The backend reads the headers and trusts them (after HMAC verification)
5. No password prompt, no session cookie, no OAuth redirect

## Prerequisites

1. **ZTLP CA initialized** — `ztlp admin ca-init --zone corp.ztlp`
2. **Client certificate enrolled** — `ztlp setup` on the user's device
3. **Root cert trusted** — `ztlp admin ca-export-root | sudo tee /usr/local/share/ca-certificates/ztlp.crt`
4. **Gateway configured** — TLS enabled with `auth_mode: identity` or `auth_mode: enforce`

## Backend Integration Examples

### Rails

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  before_action :authenticate_via_ztlp

  private

  def authenticate_via_ztlp
    node_id = request.headers["X-ZTLP-Node-ID"]
    user = request.headers["X-ZTLP-User"]
    signature = request.headers["X-ZTLP-Signature"]
    timestamp = request.headers["X-ZTLP-Timestamp"]

    return unless node_id.present?

    # Verify HMAC signature
    unless verify_ztlp_signature(request.headers, signature, timestamp)
      render json: { error: "invalid_signature" }, status: :unauthorized
      return
    end

    # Find or create user
    @current_user = User.find_or_create_by(ztlp_node_id: node_id) do |u|
      u.name = request.headers["X-ZTLP-Node-Name"]
      u.email = "#{user}@#{request.headers['X-ZTLP-Zone']}"
    end
  end

  def verify_ztlp_signature(headers, signature, timestamp)
    return false if signature.blank? || timestamp.blank?

    # Check timestamp freshness (60-second window)
    ts = timestamp.to_i
    return false if (Time.now.to_i - ts).abs > 60

    # Reconstruct signed payload
    payload = [
      headers["X-ZTLP-Node-ID"],
      headers["X-ZTLP-Node-Name"],
      headers["X-ZTLP-User"],
      headers["X-ZTLP-Zone"],
      headers["X-ZTLP-Assurance"],
      headers["X-ZTLP-Groups"],
      timestamp
    ].join("|")

    secret = ENV.fetch("ZTLP_HEADER_HMAC_SECRET")
    expected = OpenSSL::HMAC.hexdigest("SHA256", secret, payload)
    ActiveSupport::SecurityUtils.secure_compare(expected, signature)
  end
end
```

### Express.js (Node.js)

```javascript
const crypto = require('crypto');

function ztlpAuth(req, res, next) {
  const nodeId = req.headers['x-ztlp-node-id'];
  const signature = req.headers['x-ztlp-signature'];
  const timestamp = req.headers['x-ztlp-timestamp'];

  if (!nodeId) return next(); // No ZTLP identity (passthrough mode)

  // Verify signature
  if (!verifySignature(req.headers, signature, timestamp)) {
    return res.status(401).json({ error: 'invalid_signature' });
  }

  // Attach identity to request
  req.ztlp = {
    nodeId,
    nodeName: req.headers['x-ztlp-node-name'],
    user: req.headers['x-ztlp-user'],
    zone: req.headers['x-ztlp-zone'],
    assurance: req.headers['x-ztlp-assurance'],
    groups: (req.headers['x-ztlp-groups'] || '').split(',').filter(Boolean),
  };

  next();
}

function verifySignature(headers, signature, timestamp) {
  if (!signature || !timestamp) return false;
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > 60) return false;

  const payload = [
    headers['x-ztlp-node-id'],
    headers['x-ztlp-node-name'],
    headers['x-ztlp-user'],
    headers['x-ztlp-zone'],
    headers['x-ztlp-assurance'],
    headers['x-ztlp-groups'],
    timestamp,
  ].join('|');

  const secret = process.env.ZTLP_HEADER_HMAC_SECRET;
  const expected = crypto.createHmac('sha256', secret)
    .update(payload).digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(expected), Buffer.from(signature)
  );
}

app.use(ztlpAuth);
```

### Go

```go
func ztlpAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        nodeID := r.Header.Get("X-ZTLP-Node-ID")
        if nodeID == "" {
            next.ServeHTTP(w, r)
            return
        }

        signature := r.Header.Get("X-ZTLP-Signature")
        timestamp := r.Header.Get("X-ZTLP-Timestamp")

        if !verifySignature(r.Header, signature, timestamp) {
            http.Error(w, `{"error":"invalid_signature"}`, 401)
            return
        }

        ctx := context.WithValue(r.Context(), "ztlp_node_id", nodeID)
        ctx = context.WithValue(ctx, "ztlp_user", r.Header.Get("X-ZTLP-User"))
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func verifySignature(h http.Header, sig, ts string) bool {
    if sig == "" || ts == "" { return false }

    t, _ := strconv.ParseInt(ts, 10, 64)
    if abs(time.Now().Unix()-t) > 60 { return false }

    payload := strings.Join([]string{
        h.Get("X-ZTLP-Node-ID"),
        h.Get("X-ZTLP-Node-Name"),
        h.Get("X-ZTLP-User"),
        h.Get("X-ZTLP-Zone"),
        h.Get("X-ZTLP-Assurance"),
        h.Get("X-ZTLP-Groups"),
        ts,
    }, "|")

    secret := os.Getenv("ZTLP_HEADER_HMAC_SECRET")
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(payload))
    expected := hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(sig))
}
```

## Assurance Levels

Backends can require specific authentication strength:

| Level | Description | Example |
|-------|------------|---------|
| `software` | Key stored on filesystem | `~/.ztlp/key` |
| `device-bound` | Key in TPM or OS Keychain | macOS Keychain, Windows TPM |
| `hardware` | Key on hardware security module | YubiKey, SmartCard |

Configure per-backend:

```yaml
backends:
  - name: admin
    auth_mode: enforce
    min_assurance: hardware   # Only YubiKey/SmartCard holders
```

Users who don't meet the assurance requirement receive a 403 with a
helpful error message directing them to re-enroll with a hardware key.

## Troubleshooting

### "Client certificate required"
The backend is in `enforce` mode but no client cert was presented.
Run `ztlp setup` to enroll the device and install a client certificate.

### "Insufficient assurance"
The backend requires a higher assurance level than your key provides.
Re-enroll with: `ztlp setup --hardware-key`

### Headers not appearing
1. Check `auth_mode` is `identity` or `enforce` (not `passthrough`)
2. Verify the client certificate is being presented (check browser settings)
3. Check the gateway audit log for TLS events
