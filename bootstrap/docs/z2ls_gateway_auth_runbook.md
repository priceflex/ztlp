# Z2LS → ZTLP Bootstrap Enrollment Runbook (gateway-auth / Option C)

End-to-end guide for integrating a Z2LS host with ZTLP Bootstrap to
mint single-use enrollment tokens **without HMAC signing and without
shared API secrets on the Z2LS host**. The trust boundary is the ZTLP
device identity itself: Z2LS becomes "an admin-equivalent client over
ZTLP."

This runbook supersedes `z2ls_enrollment_runbook.md` (HMAC path) for
new integrations on Launch-provisioned topology. See
[§ Why this exists](#why-this-exists) for the header-collision
backstory.

The companion docs are:

- `bootstrap/docs/api_v1_ztlp_secured.md` — HMAC v1 contract (kept as
  historical/secondary)
- `bootstrap/docs/enrollment_token_lifecycle.md` — EnrollmentToken
  state machine (shared between v1 and admin paths)
- `bootstrap/docs/dashboard_bspr5.md` — admin UI for managing the
  ZTLP-enrolled admin devices that can drive this API

---

## Why this exists

The HMAC API at `POST /api/v1/enrollment_tokens` is unusable in
Launch-provisioned topology because the per-tenant ZTLP gateway is
started with `--http-inject-headers`, which **strips ALL inbound
`X-ZTLP-*` headers** as a defense against admin-auth spoofing. The
HMAC API headers (`X-ZTLP-Zone`, `X-ZTLP-Client`, `X-ZTLP-Timestamp`,
`X-ZTLP-Signature`) share that prefix, so they get nuked before
reaching Rails. (Diagnosis lives in the unreleased
`docs/findings/2026-05-23-v1-api-header-collision.md` note.)

Steve's direction: skip the HMAC path entirely and reuse the same
gateway-auth path the Bootstrap UI uses. The gateway already injects
authoritative admin-identity headers and HMAC-signs them with
`ZTLP_GATEWAY_HEADER_SECRET`; Bootstrap verifies via
`Ztlp::HeaderVerifier`. The trust boundary becomes the ZTLP device
identity, not a separate per-zone API secret. Rotating a Z2LS host's
access means unbinding its pubkey from the admin allowlist, not
rotating an HMAC secret.

---

## 1. Architecture

```
Z2LS host (ZTLP-enrolled admin device for zone "acme.ztlp")
      │
      │   ztlp connect bootstrap.acme.ztlp --local 127.0.0.1:8000
      │   (tunnel terminates locally on the Z2LS host)
      ▼
127.0.0.1:8000 ───────► ZTLP gateway in the tenant container
                              │
                              │ injects, on every forwarded request:
                              │   X-ZTLP-Authenticated: 1
                              │   X-ZTLP-Admin-Email:   z2ls@acme.com
                              │   X-ZTLP-Timestamp:     <iso8601>
                              │   X-ZTLP-Signature:     <hex hmac>
                              ▼
                         Rails container
                              │
                              ▼
                     POST /api/admin/enrollment_tokens
                       ApplicationController
                          └─ trusted_gateway_admin
                                └─ Ztlp::HeaderVerifier.verify_request
                                      └─ HMAC OK + age < 60s
                                            └─ AdminUser found, session set
                       Api::Admin::EnrollmentTokensController#create
                          └─ TokenGenerator#generate!
                          └─ render 201 { enrollment_token: "ztlp://enroll/?..." }
```

The Z2LS host carries **no shared secrets** in the API call. The
HMAC over identity headers happens inside the gateway, signed with a
gateway-only secret Z2LS never sees.

---

## 2. Setup

### Prerequisites on the Bootstrap side

| Setting | Where | Value |
|---|---|---|
| Gateway-auth enabled | env var on the bootstrap container | `ZTLP_TRUST_GATEWAY_AUTH=true` |
| Gateway HMAC secret | env var on the bootstrap container | `ZTLP_GATEWAY_HEADER_SECRET=<shared with the tenant gateway>` |
| Network row | DB | One row per zone (admin dashboard) |
| AdminUser row | DB | `admin_users.email` matching the value the gateway will inject |

Both env vars are required. If `ZTLP_GATEWAY_HEADER_SECRET` is unset,
`trusted_gateway_admin` logs a warning and refuses to authenticate
gateway requests — the endpoint will then always 401.

### Prerequisites on the Z2LS side

1. Z2LS host must be a ZTLP-enrolled admin device for the customer
   zone. Run `ztlp setup` once with an admin-class enrollment token
   issued through the Bootstrap UI.
2. The Z2LS host's ZTLP pubkey must be bound to an AdminUser email
   in the customer's Bootstrap (this is what the gateway will inject
   as `X-ZTLP-Admin-Email`).
3. Open the tunnel before invoking the API:
   ```bash
   ztlp connect bootstrap.acme.ztlp --local 127.0.0.1:8000
   ```
   Leave this running in the background.

There is **no per-zone HMAC secret on the Z2LS host**. There is **no
api_clients allowlist row** for this path — admin-device identity IS
the allowlist.

---

## 3. API contract

### Request

```http
POST /api/admin/enrollment_tokens HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/json

{
  "computer_name": "alice-laptop",
  "metadata":      { "os": "macOS 14.5", "owner": "alice@acme.com" },
  "max_uses":      1,
  "expires_in":    "24h",
  "zone":          "acme.ztlp"
}
```

| Field | Required | Type | Notes |
|---|---|---|---|
| `computer_name` | ✅ | string | RFC1035 DNS-label shape. 1..253 bytes, lowercase alphanumeric + hyphens + dots. |
| `metadata` | ❌ | object | Opaque JSON stored stringified in `notes`. Forward-compatible — add fields without a schema change. |
| `max_uses` | ❌ | int | Defaults to `1`. |
| `expires_in` | ❌ | string | One of `1h`, `6h`, `12h`, `24h`, `1d`, `3d`, `7d`, `1w`. Defaults to `24h`. Unknown values silently fall back to the 24h model default. |
| `zone` | ❌ | string | Only needed when the Bootstrap host serves more than one Network row. Launch containers are single-zone, so this is usually omitted. |

### Response — 201 Created

```json
{
  "enrollment_token":       "ztlp://enroll/?zone=acme.ztlp&ns=...&token=ab12cd34&expires=1700086400",
  "token_id":               "ab12cd34ef567890",
  "expiration_datetime":    "2026-05-24T08:10:11Z",
  "token_lifetime_seconds": 86400,
  "status":                 "issued",
  "message":                "Token issued; valid for 24h, single use."
}
```

The full `enrollment_token` URI is what you hand to the device
that's enrolling (CLI `ztlp setup --token "<uri>"`, macOS app,
iOS app, etc.). The other fields are convenience metadata.

### Failure responses

| Status | Body | Cause |
|---|---|---|
| 401 | `{"error":"unauthorized"}` | Tunnel down, gateway headers missing/expired/forged, admin pubkey not bound to a Bootstrap AdminUser row, OR cookie-session admin (this endpoint is gateway-auth-only). |
| 422 | `{"error":"validation_failed","message":"..."}` | Bad/missing `computer_name`, or zone ambiguous when >1 Network row exists. |
| 503 | `{"error":"service_unavailable","message":"..."}` | The resolved Network has no NS machine yet — operator must provision it before pointing Z2LS at it. |

The 401 response is deliberately opaque (matches the HMAC v1
controller's behavior) — don't help an attacker enumerate failure
modes. Server-side logs carry the specific reason. Grep with:

```bash
ssh trs@<bootstrap_host> 'docker logs bootstrap_web_1 2>&1 | \
  grep -E "gateway-auth.*rejected" | tail -10'
```

---

## 4. Smoke test — curl

Because there's no signing dance, the curl one-liner is short.
Assumes the ZTLP tunnel is up and forwarding `127.0.0.1:8000` to
`bootstrap.acme.ztlp`:

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -d '{"computer_name":"alice-laptop","metadata":{"os":"macOS"}}' \
  http://127.0.0.1:8000/api/admin/enrollment_tokens
```

You should get back a `201` with the response shape from § 3. If you
get a `401`, the tunnel is down or your admin pubkey isn't bound;
see [§ Troubleshooting](#7-troubleshooting).

---

## 5. Ruby reference client

The reference implementation lives at
`bootstrap/script/z2ls_gateway_auth_token_request.rb` and uses only
the Ruby stdlib (`net/http`, `json`, `uri`). Excerpt:

```ruby
require "json"
require "net/http"
require "uri"

def request_enrollment_token(bootstrap_url:, computer_name:, metadata: nil)
  uri = URI(bootstrap_url.chomp("/") + "/api/admin/enrollment_tokens")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == "https")

  req = Net::HTTP::Post.new(uri.path)
  req["Content-Type"] = "application/json"
  payload = { computer_name: computer_name }
  payload[:metadata] = metadata if metadata && !metadata.empty?
  req.body = payload.to_json

  resp = http.request(req)
  raise "Bootstrap returned #{resp.code}: #{resp.body}" unless resp.is_a?(Net::HTTPSuccess)
  JSON.parse(resp.body)
end

result = request_enrollment_token(
  bootstrap_url: "http://127.0.0.1:8000",
  computer_name: "alice-laptop",
  metadata:      { os: "macOS 14.5", owner: "alice@acme.com" }
)
puts result["enrollment_token"]
```

CLI invocation:

```bash
ztlp connect bootstrap.acme.ztlp --local 127.0.0.1:8000 &
ruby bootstrap/script/z2ls_gateway_auth_token_request.rb \
  alice-laptop os=macOS owner=alice@acme.com
```

---

## 6. Redeeming the token

Identical to the HMAC path — same `EnrollmentToken` model, same NS
behavior, same callback to `POST /api/enrollment/confirm`. See
`z2ls_enrollment_runbook.md` § 5 ("Redeeming the token") for the
device-side flow. The URI is opaque from the redemption side; how it
was minted (HMAC v1 or gateway-auth) doesn't matter.

---

## 7. Troubleshooting

### 401 Unauthorized

The endpoint returns the same opaque `{"error":"unauthorized"}` for
every auth failure. Possible causes, in rough order of probability:

| Cause | How to confirm | Fix |
|---|---|---|
| Tunnel isn't up | `curl -sv http://127.0.0.1:8000/up` from the Z2LS host hangs or refuses | `ztlp connect bootstrap.<zone> --local 127.0.0.1:8000` |
| Z2LS admin pubkey not bound to a Bootstrap AdminUser | `grep "gateway-auth.*rejected" bootstrap_web.log` shows the verifier's reason | Bind the pubkey via the Bootstrap admin pages, or create the AdminUser row with the email the gateway is injecting |
| Gateway not injecting headers (bad gateway config) | `grep "X-ZTLP-Admin-Email" bootstrap_web.log` shows nothing for the request | Verify the gateway is running with the `--http-inject-headers` profile and pointed at this Bootstrap |
| `ZTLP_TRUST_GATEWAY_AUTH` unset on Bootstrap | `docker exec bootstrap_web_1 env \| grep ZTLP_TRUST` shows nothing | `ZTLP_TRUST_GATEWAY_AUTH=true` in the container env |
| `ZTLP_GATEWAY_HEADER_SECRET` unset OR mismatched | server log: `gateway-auth disabled: ZTLP_GATEWAY_HEADER_SECRET not set` or `rejected gateway header set: :invalid_signature` | Set the same secret on both gateway and Bootstrap |
| Timestamp drift > 60s | server log: `rejected gateway header set: :expired` | NTP-sync both hosts |
| You're trying to use a cookie session (UI login) | The request has a session cookie but no gateway headers | This endpoint is gateway-auth-only by design. Use the tunnel. |

### 422 validation_failed

The message field explains it:

- `computer_name is required` — payload missing the field
- `computer_name exceeds RFC1035 length limit (253)` — shorten the name
- `computer_name must be a valid DNS label (...)` — fix character set
- `could not resolve a Network for this request — pass \`zone\` in the body, or ensure exactly one Network row exists for this tenant` — set `zone` in the body (multi-zone Bootstrap) or remove extra Network rows

### 503 service_unavailable

```json
{"error":"service_unavailable","message":"Network must have at least one NS machine"}
```

The Network row exists but has no NS machine provisioned. Provision
one in the admin dashboard before retrying.

---

## 8. Differences from the HMAC v1 contract

| Concern | HMAC v1 (`/api/v1/`) | Gateway-auth (`/api/admin/`) |
|---|---|---|
| Auth credential | Per-zone HMAC secret (`ZTLP_HMAC_SECRET_<UPCASE_ZONE>`) shared with Z2LS | Z2LS's ZTLP device identity — no shared secret on the Z2LS host |
| Allowlist | `api_clients` table row | `admin_users` table row + ZTLP pubkey binding |
| Signing | Z2LS computes HMAC over a 6-line canonical message and sets 4 `X-ZTLP-*` headers | None — the tunnel handles identity. Just plain HTTP. |
| CSRF | N/A (API namespace) | Skipped — gateway-auth is strictly stronger than CSRF |
| Works with `--http-inject-headers` gateway | ❌ No — header collision strips the signing headers | ✅ Yes — the gateway IS injecting the headers |
| Rotation | Rotate the per-zone secret on all consumers | Unbind the Z2LS pubkey from the admin allowlist |
| Audit row | `api.v1.enrollment_token.issued` (records `issued_by_api_client`) | `api.admin.enrollment_token.issued` (records `admin_email`) |

The minted token itself is identical (same `EnrollmentToken` row,
same URI shape, same NS behavior). The difference is purely in how
the *request* is authenticated.
