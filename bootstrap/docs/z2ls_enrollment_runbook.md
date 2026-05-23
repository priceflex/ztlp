# Z2LS → ZTLP Bootstrap Enrollment Runbook

End-to-end guide for integrating a Z2LS (or any trusted system) with
ZTLP Bootstrap to mint single-use enrollment tokens for new devices.
This document walks through:

1. **Pre-reqs** — what has to be configured on both sides
2. **Provisioning a Z2LS client** — adding an `api_clients` row
3. **Signing a request** — the per-zone HMAC contract (with working
   Python and Ruby snippets)
4. **Minting a token** — `POST /api/v1/enrollment_tokens`
5. **Redeeming the token** — handing the URI to the enrolling device
6. **End-to-end smoke test** — a complete shell + python flow
7. **Troubleshooting** — every 401/422/503 failure mode and its fix

The runbook is the customer-facing companion to:

- `bootstrap/docs/api_v1_ztlp_secured.md` — formal API auth contract
- `bootstrap/docs/enrollment_token_lifecycle.md` — token state machine
- `bootstrap/docs/dashboard_bspr5.md` — admin UI for managing the
  allowlist (`api_clients`) and device-to-device grants

---

## 1. Pre-requisites

### On the ZTLP Bootstrap side

| Setting | Where | Value | Notes |
|---|---|---|---|
| Per-zone HMAC secret | env var on the bootstrap container | `ZTLP_HMAC_SECRET_<UPCASE_ZONE>=<hex-or-raw>` | Same secret the relay + gateway read. 64-char hex auto-decoded to 32 raw bytes. |
| Network row | DB | One row per zone (admin dashboard or BS-PR-4 auto-creation) | The Z2LS call mints a token for this network. |
| `api_clients` row | DB | One row per Z2LS instance (`/admin/api_clients`) | The allowlist entry — both `(zone, name)` are required. |

### On the Z2LS side

| Setting | Where | Value | Notes |
|---|---|---|---|
| Per-zone HMAC secret | Z2LS config / env | Same value as the bootstrap host | Treat as production secret. |
| Bootstrap URL | Z2LS config | e.g. `https://bootstrap.acme.ztlp` | Reachable from Z2LS. |
| Clock | host OS | NTP-synchronized | The bootstrap auth window is ±5 minutes; clock drift will silently kill all requests. |

### Why no API keys

Per Steve's brief: *"Do not use a traditional API key model. Instead,
use ZTLP-secured device-to-device communication so trusted systems
can talk to the ZTLP Bootstrap API."*

The per-zone HMAC secret IS the credential. The `api_clients` row is
an orthogonal allowlist on top of HMAC — both must pass for a
request to authenticate. Rotating the secret rotates the credential
for every consumer in that zone (Z2LS, the gateway, the relay) in
one operation; deactivating the `api_clients` row revokes ONE
consumer without touching the secret.

---

## 2. Provisioning a Z2LS client

A super-admin does this once per Z2LS instance.

1. Confirm the per-zone secret env var is set on the bootstrap
   container:
   ```bash
   ssh trs@10.69.95.12 'docker exec bootstrap_web_1 \
     bash -lc "test -n \"\${ZTLP_HMAC_SECRET_ACME_ZTLP}\" && echo set || echo MISSING"'
   ```
   If MISSING, set it before continuing (otherwise every
   authenticated request will fail with `no_zone_secret` server-side).

2. Sign into Bootstrap as super-admin, navigate to
   `🔑 API Clients` in the top nav.

3. Click `+ New API Client` and enter:
   - **Zone**: `acme.ztlp` (the zone the Z2LS will mint tokens for)
   - **Client name**: `z2ls.acme` (unique within the zone)
   - **Notes**: anything useful — e.g.
     `Z2LS production instance, owner: ops@techrockstars.com`

4. The audit log records `api_client.created` with your admin user id
   as the provenance.

5. Hand the per-zone HMAC secret to whoever operates the Z2LS host.

To revoke a client later: `/admin/api_clients` → `Deactivate`. To
permanently remove: `Delete`. See `dashboard_bspr5.md` § "API Clients"
for the kill-switch workflow.

---

## 3. Signing a request

Every request to `/api/v1/*` MUST carry four headers:

```
X-ZTLP-Zone:      <zone-id, matches your api_clients.zone>
X-ZTLP-Client:    <api_clients.name>
X-ZTLP-Timestamp: <unix seconds, integer>
X-ZTLP-Signature: <lower-case hex HMAC-SHA256 over the canonical message>
```

The canonical signed message is six lines joined with a single LF
(`\n`), no trailing newline:

```
<HTTP_METHOD, upper-cased>\n
<request path including query string>\n
<X-ZTLP-Zone>\n
<X-ZTLP-Client>\n
<X-ZTLP-Timestamp>\n
SHA256_HEX(<raw request body>)
```

### Reference: Python signer

```python
import hashlib
import hmac
import json
import time

import requests


def ztlp_sign(*, method, path, zone, client, timestamp, body, secret):
    """Return the hex HMAC-SHA256 for a ZTLP-secured Bootstrap request.

    secret may be raw bytes or a 64-char hex string; in the hex case
    we decode to 32 raw bytes (matching the gateway's decoding rule).
    """
    if isinstance(secret, str) and len(secret) == 64:
        try:
            secret = bytes.fromhex(secret)
        except ValueError:
            secret = secret.encode("utf-8")
    elif isinstance(secret, str):
        secret = secret.encode("utf-8")

    body_bytes = body.encode("utf-8") if isinstance(body, str) else (body or b"")
    body_digest = hashlib.sha256(body_bytes).hexdigest()

    message = "\n".join([
        method.upper(),
        path,
        zone,
        client,
        str(timestamp),
        body_digest,
    ]).encode("utf-8")

    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def request_enrollment_token(*, bootstrap_url, zone, client, secret, computer_name, metadata=None):
    """End-to-end: sign + POST + return the parsed JSON response."""
    path = "/api/v1/enrollment_tokens"
    payload = {"computer_name": computer_name}
    if metadata:
        payload["metadata"] = metadata

    body = json.dumps(payload, separators=(",", ":"))
    ts = int(time.time())
    sig = ztlp_sign(
        method="POST", path=path, zone=zone, client=client,
        timestamp=ts, body=body, secret=secret,
    )

    response = requests.post(
        f"{bootstrap_url}{path}",
        data=body,
        headers={
            "Content-Type":     "application/json",
            "X-ZTLP-Zone":      zone,
            "X-ZTLP-Client":    client,
            "X-ZTLP-Timestamp": str(ts),
            "X-ZTLP-Signature": sig,
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    import os
    result = request_enrollment_token(
        bootstrap_url="https://bootstrap.acme.ztlp",
        zone="acme.ztlp",
        client="z2ls.acme",
        secret=os.environ["ZTLP_HMAC_SECRET_ACME_ZTLP"],
        computer_name="alice-laptop",
        metadata={"os": "macOS 14.5", "owner": "alice@acme.com"},
    )
    print(result["enrollment_token"])
```

### Reference: Ruby signer

```ruby
require "digest"
require "json"
require "net/http"
require "openssl"
require "uri"

def ztlp_sign(method:, path:, zone:, client:, timestamp:, body:, secret:)
  # Match the gateway/Bootstrap's encoding rule: 64-char hex →
  # 32 raw bytes; anything else used as-is.
  if secret.is_a?(String) && secret.length == 64 && secret.match?(/\A[0-9a-fA-F]+\z/)
    secret = [secret].pack("H*")
  end

  body_str = body.is_a?(String) ? body : body.to_s
  body_digest = Digest::SHA256.hexdigest(body_str)

  message = [
    method.to_s.upcase,
    path,
    zone,
    client,
    timestamp.to_s,
    body_digest
  ].join("\n")

  OpenSSL::HMAC.hexdigest("SHA256", secret, message)
end

def request_enrollment_token(bootstrap_url:, zone:, client:, secret:, computer_name:, metadata: nil)
  path = "/api/v1/enrollment_tokens"
  payload = { computer_name: computer_name }
  payload[:metadata] = metadata if metadata
  body = payload.to_json

  ts = Time.now.to_i
  sig = ztlp_sign(
    method: "POST", path: path, zone: zone, client: client,
    timestamp: ts, body: body, secret: secret
  )

  uri = URI(bootstrap_url + path)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == "https")
  http.open_timeout = 5
  http.read_timeout = 10

  req = Net::HTTP::Post.new(uri.path)
  req["Content-Type"]     = "application/json"
  req["X-ZTLP-Zone"]      = zone
  req["X-ZTLP-Client"]    = client
  req["X-ZTLP-Timestamp"] = ts.to_s
  req["X-ZTLP-Signature"] = sig
  req.body = body

  resp = http.request(req)
  raise "Bootstrap returned #{resp.code}: #{resp.body}" unless resp.is_a?(Net::HTTPSuccess)

  JSON.parse(resp.body)
end

if __FILE__ == $PROGRAM_NAME
  result = request_enrollment_token(
    bootstrap_url: "https://bootstrap.acme.ztlp",
    zone:          "acme.ztlp",
    client:        "z2ls.acme",
    secret:        ENV.fetch("ZTLP_HMAC_SECRET_ACME_ZTLP"),
    computer_name: "alice-laptop",
    metadata:      { os: "macOS 14.5", owner: "alice@acme.com" }
  )
  puts result["enrollment_token"]
end
```

### Reference: curl one-liner (for smoke tests)

```bash
ZONE=acme.ztlp
CLIENT=z2ls.acme
SECRET=<the same value as ZTLP_HMAC_SECRET_ACME_ZTLP on the bootstrap host>
TS=$(date -u +%s)
METHOD=POST
PATH_=/api/v1/enrollment_tokens
BODY='{"computer_name":"alice-laptop"}'
BODY_DIGEST=$(printf '%s' "$BODY" | sha256sum | awk '{print $1}')
MSG=$(printf '%s\n%s\n%s\n%s\n%s\n%s' "$METHOD" "$PATH_" "$ZONE" "$CLIENT" "$TS" "$BODY_DIGEST")
SIG=$(printf '%s' "$MSG" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')

curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "X-ZTLP-Zone: $ZONE" \
  -H "X-ZTLP-Client: $CLIENT" \
  -H "X-ZTLP-Timestamp: $TS" \
  -H "X-ZTLP-Signature: $SIG" \
  --data "$BODY" \
  "https://bootstrap.acme.ztlp$PATH_"
```

**Gotcha:** if your `SECRET` is a 64-character hex string, the curl
snippet above will sign with the **hex string** as the HMAC key,
not the decoded raw bytes. The Bootstrap authenticator decodes the
env value when it's exactly 64 hex chars, so signatures won't match.

Workaround: pre-decode the hex secret to raw bytes and pass that
through openssl. The Python/Ruby snippets above handle this
automatically; bash needs an extra step:

```bash
# If SECRET is 64-hex-chars, decode first:
SECRET_BIN=$(printf '%s' "$SECRET" | xxd -r -p)
# Then sign using -macopt hexkey OR pipe to openssl with the binary:
SIG=$(printf '%s' "$MSG" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SECRET" -hex | awk '{print $2}')
```

---

## 4. Minting a token

Successful request:

```http
POST /api/v1/enrollment_tokens HTTP/1.1
Content-Type: application/json
X-ZTLP-Zone: acme.ztlp
X-ZTLP-Client: z2ls.acme
X-ZTLP-Timestamp: 1700000000
X-ZTLP-Signature: <hex>

{"computer_name": "alice-laptop", "metadata": {"os": "macOS 14.5"}}
```

Response (201 Created):

```json
{
  "enrollment_token": "ztlp://enroll/?zone=acme.ztlp&ns=...&token=ab12cd34ef567890&expires=1700086400",
  "token_id": "ab12cd34ef567890",
  "expiration_datetime": "2026-05-24T08:10:11Z",
  "token_lifetime_seconds": 86400,
  "status": "issued",
  "message": "Token issued; valid for 24h, single use."
}
```

**The full URI string** in `enrollment_token` is what you hand to the
device. The other fields are convenience metadata (display in UI,
log expiry, surface lifetime to the user).

### Payload

| Field | Required | Type | Notes |
|---|---|---|---|
| `computer_name` | ✅ | string | RFC1035 DNS-label shape. 1..253 bytes, lowercase alphanumeric + hyphens + dots. |
| `metadata` | ❌ | object | Opaque JSON. Stored as stringified blob in the token's `notes` column. Forward-compatible — future Bootstrap versions may interpret known keys; unknown keys are preserved. |

Adding new optional fields later doesn't require a Z2LS rev. The
controller validates the schema-of-record and ignores unknown
top-level keys (any future required field will land in a new
namespace like `/api/v2/...`).

---

## 5. Redeeming the token

The `enrollment_token` URI from step 4 is what the enrolling device
consumes. Three redemption paths:

### CLI (Linux/macOS/Windows)

```bash
ztlp setup --token "ztlp://enroll/?zone=acme.ztlp&ns=...&token=ab12cd34ef567890&expires=1700086400"
```

For unattended / SSH-batch use (no TTY):

```bash
ztlp setup --yes --name alice-laptop --token "ztlp://enroll/?..."
```

The `--name` and `--yes` flags are mandatory in non-TTY mode (the
CLI's `dialoguer` prompt would otherwise crash). See the
`ztlp-bootstrap-enrollment` skill for the full set of gotchas.

### macOS desktop app

1. Open the ZTLP macOS app
2. Enrollment screen → paste the URI → click `Submit`
3. Verify zone / NS / relay / expiry shown → click `Enroll Device`
4. Identity saved to `~/Library/Application Support/ZTLP/identity.json`

### iOS app

QR code scan OR paste — same URI format. Identity stored in the
App Group container.

### What happens at redemption

1. Device generates X25519 + Ed25519 keypair locally
2. Device sends `0x07 ENROLL` packet to the NS
3. NS verifies the token's URI is valid
4. NS auto-approves the device (within the 24h window, single use)
5. Device callbacks to `POST /api/enrollment/confirm` on Bootstrap
6. Bootstrap calls `token.use!` (atomic, see `enrollment_token_lifecycle.md`)
7. Token transitions `active → exhausted`. Subsequent redemptions
   of the same URI return 422.

---

## 6. End-to-end smoke test

A complete flow you can run against a non-production bootstrap to
verify your Z2LS implementation. Assumes:

- Bootstrap running at `https://bootstrap.staging.acme.ztlp`
- Per-zone secret set: `ZTLP_HMAC_SECRET_STAGING_ACME_ZTLP=<hex>`
- `api_clients` row exists: `(staging.acme.ztlp, z2ls.staging)`
- The CLI `ztlp` binary installed on a test box

```bash
# 1. Mint a token from your "Z2LS" (the python snippet above)
export ZTLP_HMAC_SECRET_STAGING_ACME_ZTLP=<the-secret>

URI=$(python3 z2ls_request.py 2>&1 | tail -1)
echo "Got URI: $URI"

# 2. Inspect the response: token_id, expiry, lifetime
# (the python snippet only prints the URI; modify to print the
# whole JSON if you want to verify expiration_datetime etc.)

# 3. Redeem on the test box
ztlp setup --yes --name "smoke-$(date +%s)" --token "$URI"

# 4. Confirm the token is now exhausted
ssh trs@<bootstrap_host> 'docker exec bootstrap_web_1 bash -lc \
  "cd /rails && bin/rails runner \"
    t = EnrollmentToken.find_by(token_id: '\\''$(echo $URI | sed -n '\''s/.*token=\\([a-f0-9]*\\).*/\\1/p'\'')'\\'')
    puts [t.status, t.current_uses, t.max_uses].join('\\'' | '\\'')
  \""'
# Expect: exhausted | 1 | 1

# 5. Confirm second redemption fails
ztlp setup --yes --name "should-fail" --token "$URI"
# Expect: error from NS or 422 from Bootstrap during confirm
```

---

## 7. Troubleshooting

### 401 Unauthorized

The response body is always `{"error": "unauthorized"}` — the
specific reason is **only** in the server-side log + audit trail
(deliberate: don't help attackers iterate). Grep the bootstrap
logs:

```bash
ssh trs@10.69.95.12 'docker logs bootstrap_web_1 2>&1 | \
  grep -E "Api::V1.*auth rejected" | tail -10'
```

Reason codes:

| Code | Meaning | Fix |
|---|---|---|
| `missing_header` | One of the 4 headers is absent | Set every header on the request |
| `bad_timestamp` | `X-ZTLP-Timestamp` is not a valid integer | Send unix seconds, not ms or ISO8601 |
| `expired_timestamp` | Outside ±5 min window | Check your NTP — clock drift kills auth silently |
| `unknown_client` | `(zone, name)` not in `api_clients` OR `active=false` | Add the row at `/admin/api_clients`, or reactivate |
| `no_zone_secret` | `ZTLP_HMAC_SECRET_<UPCASE_ZONE>` not set on bootstrap | Set the env var; restart bootstrap if not already loaded |
| `bad_signature` | HMAC mismatch | See "Signing pitfalls" below |

### Signing pitfalls (the most common failures)

1. **Hex secret used as raw bytes (or vice versa).** Bootstrap
   auto-decodes 64-char hex env values. If your client sends raw
   hex as the HMAC key, signatures won't match. **Symptom:**
   `bad_signature` in logs even though everything else looks right.
   **Fix:** decode hex to bytes on the client side BEFORE signing.

2. **Wrong canonical message.** The 6-line order is fixed:
   `METHOD / PATH / ZONE / CLIENT / TIMESTAMP / SHA256_HEX(body)`.
   Common errors: missing the trailing body digest line, including
   a trailing newline, signing the body twice (raw + digest), or
   using request path WITHOUT query string. Bootstrap uses
   `request.fullpath` (path + query) — match that.

3. **Body mismatch.** Make sure the body bytes you sign are
   byte-identical to what you actually send. JSON serializers can
   add/remove whitespace inconsistently. Always serialize once,
   then sign + send the same bytes.

4. **Method case mismatch.** Sign over `"POST"` (upper-cased), not
   `"post"`. Bootstrap upper-cases server-side.

5. **Timezone confusion.** `X-ZTLP-Timestamp` is unix seconds (UTC,
   integer). Not ISO8601, not RFC3339, not local time.

6. **Trailing whitespace in env vars.** If the env value has a
   trailing newline (common when piping from a file), the HMAC will
   differ from what the test snippets compute. `printf '%s' "$VAL"`
   never adds a trailing newline; `echo "$VAL"` does.

### 422 Unprocessable Entity

The response body explains:

```json
{"status": "error", "message": "computer_name must be a valid DNS label..."}
```

| Message | Fix |
|---|---|
| `computer_name is required` | Include `computer_name` in the body |
| `computer_name exceeds RFC1035 length limit` | Trim to ≤253 bytes |
| `computer_name must be a valid DNS label` | Lowercase alphanumeric + hyphens + dots; no spaces, no underscores, no punctuation |

### 503 Service Unavailable

```json
{"status": "error", "message": "no network configured for zone=acme.ztlp; create one via the admin dashboard first"}
```

The `api_clients` row exists but no `Network` row matches. Create
the network in the admin dashboard (BS-PR-4 will automate this
during ztlp.net onboarding once it lands).

### Token is rejected by the enrolling device

| Symptom | Cause | Fix |
|---|---|---|
| `ztlp setup` reports "expired" immediately | Device clock is behind / URI's `expires` epoch is wrong | Generate the URI using the **device's** clock if you're scripting; verify with `date +%s` on the device |
| NS rejects with `<<0x08, 0x06>>` | NS-side enrollment secret mismatch | See the `ztlp-bootstrap-deploy` skill — most common cause is lowercase hex (NS requires uppercase) |
| `ztlp enroll` / `ztlp claim` not recognized | Deprecated CLI verbs | Use `ztlp setup --token` instead (v0.5+ removed the old verbs) |

### Audit trail forensics

Every successful issuance writes an `api.v1.enrollment_token.issued`
audit log row. Find tokens issued today:

```bash
ssh trs@10.69.95.12 'docker exec bootstrap_web_1 bash -lc \
  "cd /rails && bin/rails runner \"
    AuditLog.where(action: '\\''api.v1.enrollment_token.issued'\\'')
            .where('\\''created_at > ?'\\'', 24.hours.ago)
            .each do |a|
      d = JSON.parse(a.details || '\\''{}'\\'')
      puts [a.created_at.iso8601, d['\\''issued_by_api_client'\\''], d['\\''computer_name'\\''], d['\\''token_id'\\'']].join('\\'' | '\\'')
    end
  \""'
```

Every revocation / exhaustion / expiry writes its own audit row —
see `enrollment_token_lifecycle.md` § "Auditing" for the full table.

---

## Related documents

- `bootstrap/docs/api_v1_ztlp_secured.md` — formal API auth contract,
  failure response policy, future variants
- `bootstrap/docs/enrollment_token_lifecycle.md` — token state machine,
  atomicity, sweeper cron
- `bootstrap/docs/dashboard_bspr5.md` — admin UI for `api_clients`
  and device communication grants
- `~/.hermes/skills/devops/ztlp-bootstrap-enrollment/SKILL.md` —
  CLI / iOS / macOS redemption details
- `~/.hermes/skills/devops/ztlp-saas-orchestration/SKILL.md` —
  tenant provisioning flow (BS-PR-4 will hook into this)

## Versioning

This runbook describes API v1. Breaking changes go to `/api/v2/...`;
v1 continues to honor the contract above indefinitely.

Last updated: 2026-05-23 — BS-PR-6.
