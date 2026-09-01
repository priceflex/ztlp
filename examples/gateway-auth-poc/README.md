# ZTLP Gateway-Auth PoC

The "dashboard access" proof for the ZTLP gateway-auth path: a tiny webpage
reachable **only** through a ZTLP tunnel. The gateway
(`ztlp listen --http-inject-headers`) rewrites **every** HTTP request on the
tunnel — keep-alive included — injecting signed `X-ZTLP-*` identity headers;
this page renders them and independently re-checks the HMAC-SHA256 signature,
the audience binding, and the timestamp freshness.

This directory is the **source of truth** for the PoC backend
(`ztlp-poc:latest` image). Before this, the deployed `/app/app.py` was
hot-patched into the running container with `docker cp`, so a container
recreate silently reverted it (open item #5 in
`~/ztlp-gateway-auth-next-steps.md`). Build from here instead.

## Headers the gateway injects

`proto/src/http_injector.rs::inject_headers` / `RequestInjector` stamp these
onto every request (one Noise handshake per tunnel; the bundle is resolved
once at the handshake and cached — NOT re-queried per request):

| Header | Value |
|---|---|
| `X-ZTLP-Authenticated` | `1` |
| `X-ZTLP-Admin-Email` | owner email — NS-resolved by the tunnel's authenticated Noise pubkey (falls back to the gateway's static `--admin-map` when no `--ns-server` is configured) |
| `X-ZTLP-Device-Name` | NS DEVICE record name (empty without `--ns-server` / enrollment) |
| `X-ZTLP-Zone` | ZTLP zone (same caveat) |
| `X-ZTLP-Group` | the `group:` policy rule that authorized this request (same caveat) |
| `X-ZTLP-Assurance` | hardware / software / unknown (same caveat; self-reported until attestation lands) |
| `X-ZTLP-Audience` | target service name — binds the signature to THIS service, so a signature minted for service A can't replay against service B |
| `X-ZTLP-Timestamp` | UTC timestamp — freshness-bounded (the page rejects signatures older than `ZTLP_MAX_TIMESTAMP_AGE`, default 30s) |
| `X-ZTLP-Signature` | HMAC-SHA256 over the sorted, lowercased `name:value` pairs of the eight signed fields, joined by `\n` (no trailing newline), keyed with `--header-hmac-secret` |

## Build & run

```bash
cd examples/gateway-auth-poc
docker build -t ztlp-poc .
docker run -d --name ztlp-poc -p 18080:8080 \
  -e ZTLP_HEADER_HMAC_SECRET=<gateway --header-hmac-secret> \
  -e ZTLP_EXPECTED_AUDIENCE=web \
  ztlp-poc
```

Or via compose (fill in the real HMAC secret first):

```bash
docker compose -f examples/gateway-auth-poc/docker-compose.yml up -d --build
```

The two `ZTLP_*` env vars must match the gateway's launch args exactly, or
every request is rejected with 401/403 (by design).

## Verifying end-to-end (from a ZTLP-enrolled client)

```bash
# 1. Trigger the VIP (lazy bind on first DNS query)
nslookup web.demo.spongebob.ztlp 127.0.0.53 | findstr 100

# 2. curl through the tunnel
curl.exe -s -m 20 -o body.html -w "HTTP %{http_code} t=%{time_total}s" \
  "http://web.demo.spongebob.ztlp/"
```

Expect `HTTP 200`, and in `body.html`:
- `GATEWAY-AUTHENTICATED` (not `NOT VERIFIED`)
- `✓ signature VALID` with `expected=` == `provided=`
- `age=` well under the 30s max

Two sequential keep-alive requests 3s apart get independently fresh
`X-ZTLP-Timestamp` + `X-ZTLP-Signature` (two requests <1s apart share a
timestamp — 1s resolution, not a bug).

## Verification scenarios (direct, no tunnel)

Against the running container (bypassing the tunnel, forging headers):

1. **Valid + fresh** — correct HMAC, correct audience, current timestamp → 200
2. **Cross-audience replay** — valid signature for a different `X-ZTLP-Audience` → reject
3. **Stale replay** — valid signature, old timestamp → reject
4. **Forged secret** — wrong HMAC key → reject

## Notes

- Stdlib-only Python (no pip deps).
- The signature is **not** a bearer token: it's a per-request freshness
  marker bound to one service. Treat it as a demo/PoC primitive until
  per-service secrets / attestation land (see
  `~/ztlp-gateway-auth-next-steps.md` items 1–3, 7).
