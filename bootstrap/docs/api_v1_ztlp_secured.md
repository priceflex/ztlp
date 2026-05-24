# Bootstrap API — v1 (ZTLP-secured)

> **⚠️ Preferred path: gateway-auth (`/api/admin/`).** In
> Launch-provisioned topology the per-tenant ZTLP gateway runs with
> `--http-inject-headers`, which strips all inbound `X-ZTLP-*`
> headers — including this API's signing headers — before they
> reach Rails. New Z2LS↔ZTLP integrations should use the gateway-auth
> contract documented in
> [`z2ls_gateway_auth_runbook.md`](./z2ls_gateway_auth_runbook.md)
> (`POST /api/admin/enrollment_tokens`). That path is no-HMAC,
> no-CSRF, and authenticated by the ZTLP device identity itself.
>
> This document remains the contract of record for the HMAC v1 API.
> The HMAC controller is still wired up and works in test, dev, and
> any deployment that does NOT sit behind a header-injecting gateway.

This document is the contract for callers of the ZTLP Bootstrap
`Api::V1` namespace. Every endpoint under `/api/v1/...` requires the
ZTLP-secured headers described below — there are **no API keys**.

If you're integrating Z2LS (or any other trusted system) with
Bootstrap, this is the document to follow.

## Why no API keys

Per Steve's 2026-05-23 brief:

> Do not use a traditional API key model. Instead, use ZTLP-secured
> device-to-device communication so trusted systems can talk to the
> ZTLP Bootstrap API.

We already have a working per-zone HMAC secret distribution
(`ZTLP_HMAC_SECRET_<UPCASE_ZONE>`) shared by the relay, the gateway,
and now Bootstrap. Using it as the API credential keeps the secret
inventory small — one secret per zone, used by every ZTLP component
in that zone.

## Request signing — v1

Every request must include four headers:

| Header              | Meaning                                                |
|---------------------|--------------------------------------------------------|
| `X-ZTLP-Zone`       | Zone-id the caller is signing for                      |
| `X-ZTLP-Client`     | `api_clients.name` — the allowlisted client identifier |
| `X-ZTLP-Timestamp`  | Unix seconds, integer (must be within ±5 minutes of "now") |
| `X-ZTLP-Signature`  | Lower-case hex HMAC-SHA256 over the canonical message  |

The canonical signed message is six lines, joined with a single LF
(`\n`) — no trailing newline:

```
<HTTP_METHOD, upper-cased>\n
<request.fullpath, including query string>\n
<X-ZTLP-Zone>\n
<X-ZTLP-Client>\n
<X-ZTLP-Timestamp>\n
SHA256_HEX(<raw request body>)
```

The HMAC key is the **primary** per-zone secret — the first
comma-separated entry of `ZTLP_HMAC_SECRET_<UPCASE_ZONE>`. A
64-character hex value is auto-decoded to 32 raw bytes (matching the
gateway's decoding rule); anything else is used as-is.

### Reference signing helpers

#### Ruby (for Z2LS / scripts)

```ruby
require "openssl"
require "digest"

def ztlp_sign(method:, path:, zone:, client:, timestamp:, body:, secret:)
  msg = [
    method.upcase, path, zone, client, timestamp.to_s,
    Digest::SHA256.hexdigest(body.to_s)
  ].join("\n")
  OpenSSL::HMAC.hexdigest("SHA256", secret, msg)
end
```

#### curl one-liner (smoke test)

```bash
ZONE=acme.ztlp
CLIENT=z2ls.acme
SECRET="<the same value as ZTLP_HMAC_SECRET_ACME_ZTLP on the bootstrap host>"
TS=$(date +%s)
METHOD=GET
PATH_=/api/v1/health
BODY=""
BODY_DIGEST=$(printf '%s' "$BODY" | sha256sum | awk '{print $1}')
MSG=$(printf '%s\n%s\n%s\n%s\n%s\n%s' "$METHOD" "$PATH_" "$ZONE" "$CLIENT" "$TS" "$BODY_DIGEST")
SIG=$(printf '%s' "$MSG" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')

curl -s -H "X-ZTLP-Zone: $ZONE" \
        -H "X-ZTLP-Client: $CLIENT" \
        -H "X-ZTLP-Timestamp: $TS" \
        -H "X-ZTLP-Signature: $SIG" \
        "https://bootstrap.example/api/v1/health"
```

Expected response:

```json
{
  "ok": true,
  "client": "z2ls.acme",
  "zone": "acme.ztlp",
  "server_time": "2026-05-23T06:55:00Z"
}
```

## The `api_clients` allowlist

Mathematically the HMAC alone is sufficient — anyone who holds the
per-zone secret can sign a valid request. The `api_clients` row is
the orthogonal **authorization** check: it says "we permit this
named caller in this zone to use the API at all."

Two reasons:

1. **Kill switch.** Setting `active: false` immediately revokes a
   caller without needing to rotate the per-zone secret (which would
   take down every other consumer of the secret too).

2. **Audit attribution.** Every authenticated request logs the
   `api_client.name`, so dashboards can show "who minted this
   enrollment token?" without grepping by IP.

## Allowlist management

```ruby
# Create a Z2LS allowlist row from the Rails console
ApiClient.create!(
  name: "z2ls.acme",
  zone: "acme.ztlp",
  notes: "Acme Corp's Z2LS instance, deployed 2026-05-23",
  created_by_admin_user_id: AdminUser.find_by(email: "ops@techrockstars.com").id
)

# Revoke (soft-disable)
ApiClient.find_by(zone: "acme.ztlp", name: "z2ls.acme").update!(active: false)

# Re-enable
ApiClient.find_by(zone: "acme.ztlp", name: "z2ls.acme").update!(active: true)
```

A dashboard UI for managing api_clients will land in BS-PR-5
(Dashboard UX pass).

## Failure responses

Every failure returns HTTP 401 with the same response body:

```json
{"error": "unauthorized"}
```

The reason code is **logged server-side** (search Rails logs for
`[Api::V1] auth rejected reason=<code>`) and recorded in the
`audit_logs` table under the action `api.v1.auth.failure`, but it
is **never** sent back to the caller. This is deliberate — an
attacker who can enumerate failure reasons can iterate toward a
successful forgery faster than one who only sees a flat 401.

Common reasons (server log only):

- `missing_header` — at least one of the four required headers is absent
- `bad_timestamp` — `X-ZTLP-Timestamp` is not a valid integer
- `expired_timestamp` — outside the ±5 minute window
- `unknown_client` — no `(zone, name)` row matched OR the row is inactive
- `no_zone_secret` — `ZTLP_HMAC_SECRET_<UPCASE_ZONE>` is not set on the bootstrap host
- `bad_signature` — HMAC mismatch (the most common forgery class)

### `POST /api/v1/enrollment_tokens` — Z2LS enrollment endpoint (BS-PR-3)

Mint a single-use enrollment token for a new device. The token is
valid for 24 hours, can be redeemed exactly once, and is bound to
the authenticated client's zone.

**Request:**

```http
POST /api/v1/enrollment_tokens HTTP/1.1
Content-Type: application/json
X-ZTLP-Zone: office.acme.ztlp
X-ZTLP-Client: z2ls.office
X-ZTLP-Timestamp: 1700000000
X-ZTLP-Signature: <hex>

{
  "computer_name": "alice-laptop",
  "metadata": { "os": "macOS 14.5", "user": "alice" }
}
```

- `computer_name` (string, required) — RFC1035-shape DNS label.
  Accepts a hostname (`alice-laptop`) or a fully-qualified
  `hostname.zone` form. Lower-case alphanumeric plus hyphens, with
  optional dotted segments. Max 253 bytes.
- `metadata` (object, optional) — opaque JSON. Stored on the
  EnrollmentToken's `notes` field as a stringified blob so future
  payload fields don't require schema changes.

**Success (201 Created):**

```json
{
  "enrollment_token":       "ztlp://enroll/?zone=office.acme.ztlp&ns=10.0.1.10:23096&token=ab12cd34ef567890&expires=1700086400",
  "token_id":               "ab12cd34ef567890",
  "expiration_datetime":    "2026-05-24T07:18:54Z",
  "token_lifetime_seconds": 86400,
  "status":                 "issued",
  "message":                "Token issued; valid for 24h, single use."
}
```

The caller hands `enrollment_token` to the device that's enrolling.
The device passes it to `ztlp setup --token "<uri>"`. After
successful enrollment the token transitions `active → exhausted`
(see `bootstrap/docs/enrollment_token_lifecycle.md`); the same
URI cannot be used to enroll a second device.

**Failure responses:**

| Status | When                                                              |
|--------|-------------------------------------------------------------------|
| 401    | Auth headers missing / bad / expired (see auth contract above)    |
| 422    | `computer_name` missing, empty, malformed, or > 253 bytes         |
| 503    | The auth'd client's zone has no Network row provisioned yet       |

The 422 response body is `{"status":"error","message":"<reason>"}`.

**Cross-tenant safety:** the controller looks up the Network row by
`current_api_client.zone` — there's no way for a Z2LS authenticated
as zone A to put `"zone": "B"` in the body and mint a token for B.
The authenticated client's zone is the only thing that matters.

**Audit:** every issuance writes an `api.v1.enrollment_token.issued`
audit log row with the api_client name, computer_name, token_id, and
zone. Useful for "who issued this token?" forensics.

## Endpoints

### `GET /api/v1/health`

Smoke endpoint. Returns 200 with the authenticated client echoed
back. No side effects. Useful for debugging your signing
implementation before moving on to mutating endpoints.

### `POST /api/v1/enrollment_tokens` (BS-PR-3, queued)

The Z2LS endpoint — request an enrollment token for a new device.
Will accept `{computer_name, metadata?}` and return the
`ztlp://enroll/?...` URI plus expiry metadata. **Not yet
implemented.** See `~/hermes_session_handoff.md` § BS-PR-3.

## Operational notes

- **Clock skew.** The 5-minute window is generous but not unlimited.
  If your caller's host clock drifts, signing will start failing.
  NTP is mandatory for Z2LS hosts.
- **Replay protection.** A signed request is single-use only within
  the 5-minute window — but Bootstrap doesn't track seen nonces, so
  technically the same `(timestamp, signature)` pair *can* be
  replayed within the window. If you need strict at-most-once
  semantics, prepend a nonce to the body and have the endpoint
  reject duplicates (`POST /api/v1/enrollment_tokens` will do this
  in BS-PR-3 by using `computer_name` uniqueness as the
  de-duplication key).
- **Rotating a per-zone secret.** The `ZTLP_HMAC_SECRET_<ZONE>` env
  supports comma-separated rotation lists (`new,old`) on the relay
  and gateway, but the Bootstrap authenticator currently only reads
  the primary (first) entry. Operators rotating a secret should
  update Bootstrap **last**, after every Z2LS instance has been
  cut over to the new primary.

## Future variants (not in v1)

- **Ed25519 signatures.** The `api_clients.ed25519_pubkey` column is
  reserved for a future BS-PR-7+ variant that lets clients hold an
  asymmetric key instead of sharing the per-zone secret. Useful for
  callers who can't be trusted with the zone secret (e.g., a
  third-party SaaS integration). HMAC stays as the v1 default.
- **mTLS.** Out of scope for v1. The HMAC is the only credential
  today; mTLS would be a defence-in-depth layer if the deployment
  ever exposes `/api/v1/...` to the public internet.

## References

- Authenticator: `app/services/ztlp/api_authenticator.rb`
- Base controller: `app/controllers/api/v1/base_controller.rb`
- Allowlist model: `app/models/api_client.rb`
- Tests: `test/services/ztlp/api_authenticator_test.rb`,
  `test/models/api_client_test.rb`,
  `test/controllers/api/v1/health_controller_test.rb`
- Per-zone HMAC design (covers the secret store both Bootstrap and
  the gateway/relay read from): `docs/per_zone_hmac_design.md` in
  the ZTLP repo
