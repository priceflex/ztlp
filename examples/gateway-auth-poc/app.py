#!/usr/bin/env python3
"""
ZTLP Gateway-Auth Proof-of-Concept dashboard.

A deliberately tiny webpage that renders the X-ZTLP-* headers the ZTLP gateway
injects (via `ztlp listen --http-inject-headers`), and verifies the
X-ZTLP-Signature HMAC-SHA256 to prove the headers came from the real gateway
(and not a faked request). This is the "dashboard access" proof: spongebob's
ztlp connect tunnel lands here, the gateway signs the identity headers, and
this page shows them + the signature check result.

The ZTLP gateway (proto/src/http_injector.rs::inject_headers) injects, on
EVERY HTTP request on the tunnel (not just the first — see RequestInjector):
    X-ZTLP-Authenticated: 1
    X-ZTLP-Admin-Email:   <owner email, NS-resolved by tunnel pubkey>
    X-ZTLP-Device-Name:   <NS DEVICE record name>
    X-ZTLP-Zone:          <ZTLP zone>
    X-ZTLP-Group:         <policy group: rule that authorized this request>
    X-ZTLP-Assurance:     hardware | software | unknown
    X-ZTLP-Audience:      <target service name — binds sig to THIS service>
    X-ZTLP-Timestamp:     <iso8601, UTC, refreshed every request>
    X-ZTLP-Signature:     <hex hmac-sha256>

Signature scheme (must match the gateway + the shared --header-hmac-secret):
    canonical = sorted lowercased "name:value" pairs of the EIGHT signed
                fields above, joined by "\n", NO trailing newline
    signature = hex( HMAC-SHA256( secret, canonical ) )

Replay protections (both enforced here, not just by the gateway):
  - Audience binding: a signature only verifies if X-ZTLP-Audience matches
    what THIS app expects — a signature minted for another service can't be
    replayed here even with a shared secret.
  - Timestamp freshness: a signature older than MAX_TIMESTAMP_AGE_SECONDS is
    rejected even if the HMAC is otherwise valid — bounds how long a
    captured header set stays replayable.

Run:  python3 app.py        (listens on 0.0.0.0:$PORT, default 8080)
Env:  PORT (default 8080), ZTLP_HEADER_HMAC_SECRET (shared HMAC secret),
      ZTLP_EXPECTED_AUDIENCE (this service's name as the gateway sees it;
      defaults to unset = audience check skipped, for local testing),
      ZTLP_MAX_TIMESTAMP_AGE (seconds, default 30)
"""
import hashlib
import hmac
import os
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
# Shared HMAC secret the gateway signs with. Empty = verification disabled
# (headers shown but signature check reported as "no secret configured").
HMAC_SECRET = os.environ.get("ZTLP_HEADER_HMAC_SECRET", "").encode("utf-8")
# The audience this deployment expects to see in X-ZTLP-Audience. Empty
# string means "don't check" (useful for ad-hoc local testing only — a
# production deployment should always set this).
EXPECTED_AUDIENCE = os.environ.get("ZTLP_EXPECTED_AUDIENCE", "")
MAX_TIMESTAMP_AGE_SECONDS = int(os.environ.get("ZTLP_MAX_TIMESTAMP_AGE", "30"))

# The headers the gateway signs (lowercased, sorted, per http_injector.rs
# IdentityBundle — 8 fields total).
SIGNED_FIELDS = [
    "x-ztlp-authenticated",
    "x-ztlp-admin-email",
    "x-ztlp-device-name",
    "x-ztlp-zone",
    "x-ztlp-group",
    "x-ztlp-assurance",
    "x-ztlp-audience",
    "x-ztlp-timestamp",
]


def _parse_iso8601_utc(ts):
    """Parse the gateway's '%Y-%m-%dT%H:%M:%SZ' timestamp to a UTC epoch."""
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    ).timestamp()


def verify_signature(headers):
    """Recompute the HMAC-SHA256 the way the gateway does + compare, with
    audience-binding and timestamp-freshness checks on top of the raw HMAC.

    Returns (ok: bool, detail: str). `detail` always explains WHY, so a
    failed check is debuggable without extra tooling.
    """
    if not HMAC_SECRET:
        return False, "no HMAC secret configured (set ZTLP_HEADER_HMAC_SECRET)"
    provided = headers.get("X-ZTLP-Signature", "")
    if not provided:
        return False, "missing X-ZTLP-Signature header"

    pairs = []
    for name in SIGNED_FIELDS:
        val = ""
        for k, v in headers.items():
            if k.lower() == name:
                val = v
                break
        pairs.append(f"{name}:{val}")
    pairs.sort()
    canonical = "\n".join(pairs)
    expected = hmac.new(HMAC_SECRET, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    hmac_ok = hmac.compare_digest(expected.lower(), provided.lower())

    if not hmac_ok:
        return False, f"HMAC mismatch — signature does not match canonical headers\nexpected={expected}\nprovided={provided}"

    # Audience binding: even with a valid HMAC, reject if this request's
    # signed audience doesn't match what THIS deployment expects. This is
    # what stops a signature minted for a different service (sharing the
    # same --header-hmac-secret) from being replayed here.
    if EXPECTED_AUDIENCE:
        audience = headers.get("X-ZTLP-Audience", "")
        if audience != EXPECTED_AUDIENCE:
            return False, (
                f"audience mismatch — signed for '{audience}', "
                f"this deployment expects '{EXPECTED_AUDIENCE}' "
                f"(cross-service replay rejected)"
            )

    # Timestamp freshness: reject a signature (even a valid one) if it's
    # older than the allowed window. Bounds how long a captured header set
    # is replayable, independent of the gateway's own tunnel lifetime.
    ts_raw = headers.get("X-ZTLP-Timestamp", "")
    try:
        ts_epoch = _parse_iso8601_utc(ts_raw)
    except (ValueError, TypeError):
        return False, f"unparseable X-ZTLP-Timestamp: '{ts_raw}'"
    age = time.time() - ts_epoch
    if age > MAX_TIMESTAMP_AGE_SECONDS:
        return False, (
            f"stale timestamp — signed {age:.1f}s ago, "
            f"max allowed is {MAX_TIMESTAMP_AGE_SECONDS}s (replay rejected)"
        )
    if age < -5:
        # Small negative slack for clock skew between gateway and backend;
        # anything further in the future is suspicious.
        return False, f"timestamp is {(-age):.1f}s in the future — clock skew or forged"

    return True, f"expected={expected}\nprovided={provided}\nage={age:.2f}s (max {MAX_TIMESTAMP_AGE_SECONDS}s)"


def render(headers):
    sig_ok, sig_detail = verify_signature(headers)
    status_color = "#0f0" if sig_ok else "#f44"
    status_text = "GATEWAY-AUTHENTICATED" if sig_ok else "NOT VERIFIED"

    def h(name):
        name_l = name.lower()
        for k, v in headers.items():
            if k.lower() == name_l:
                return v
        return "(absent)"

    # Build the human-readable header table
    rows = []
    interesting = [
        "X-ZTLP-Authenticated",
        "X-ZTLP-Admin-Email",
        "X-ZTLP-Device-Name",
        "X-ZTLP-Zone",
        "X-ZTLP-Group",
        "X-ZTLP-Assurance",
        "X-ZTLP-Audience",
        "X-ZTLP-Timestamp",
        "X-ZTLP-Signature",
        "Host",
        "User-Agent",
        "X-Forwarded-For",
    ]
    for name in interesting:
        rows.append(f"<tr><td class='k'>{name}</td><td class='v'>{h(name)}</td></tr>")

    detail_escaped = sig_detail.replace("\n", "<br>")

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZTLP Gateway-Auth PoC</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 32px; background: #0d1117; color: #e6edf3;
    font-family: -apple-system, "Segoe UI", Roboto, monospace, sans-serif;
  }}
  .wrap {{ max-width: 780px; margin: 0 auto; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .sub {{ color: #8b949e; font-size: 13px; margin-bottom: 24px; }}
  .banner {{
    border: 2px solid {status_color}; border-radius: 10px; padding: 18px 22px;
    margin-bottom: 24px; background: #161b22;
  }}
  .banner .status {{ font-size: 18px; font-weight: 700; color: {status_color}; letter-spacing: .5px; }}
  .banner .who {{ margin-top: 6px; color: #e6edf3; font-size: 15px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 16px 18px; margin-bottom: 18px; }}
  .card h2 {{ font-size: 14px; text-transform: uppercase; letter-spacing: 1px; color: #8b949e; margin: 0 0 12px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  td.k {{ color: #8b949e; padding: 5px 10px 5px 0; white-space: nowrap; vertical-align: top; width: 220px; }}
  td.v {{ color: #e6edf3; padding: 5px 0; word-break: break-all; font-family: ui-monospace, monospace; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #c9d1d9; }}
  .ok {{ color: #3fb950; }} .bad {{ color: #f85149; }}
  .foot {{ color: #6e7681; font-size: 12px; margin-top: 24px; line-height: 1.6; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>ZTLP Gateway-Auth &mdash; Proof of Concept</h1>
  <div class="sub">This page is reachable only through a ZTLP tunnel. The gateway
  rewrites EVERY HTTP request on the connection (keep-alive included) to inject
  signed <code>X-ZTLP-*</code> identity headers, NS-resolved from the tunnel's
  authenticated pubkey; this page renders them and re-checks the HMAC signature,
  audience binding, and timestamp freshness.</div>

  <div class="banner">
    <div class="status">{status_text}</div>
    <div class="who">Authenticated as <b>{h('X-ZTLP-Admin-Email')}</b>
      &middot; device: <b>{h('X-ZTLP-Device-Name')}</b>
      &middot; zone: <b>{h('X-ZTLP-Zone')}</b>
      &middot; group: <b>{h('X-ZTLP-Group')}</b>
      &middot; assurance: <b>{h('X-ZTLP-Assurance')}</b></div>
  </div>

  <div class="card">
    <h2>Injected ZTLP headers</h2>
    <table>{''.join(rows)}</table>
  </div>

  <div class="card">
    <h2>Signature verification</h2>
    <div class="{'ok' if sig_ok else 'bad'}">{'&check; signature VALID' if sig_ok else '&times; signature INVALID'}</div>
    <pre class="mono" style="margin-top:10px">{detail_escaped}</pre>
  </div>

  <div class="foot">
    Scheme: <span class="mono">HMAC-SHA256</span> over the sorted, lowercased
    <span class="mono">name:value</span> pairs of the eight signed fields, joined by
    <span class="mono">\\n</span> (no trailing newline), keyed with the shared
    <span class="mono">--header-hmac-secret</span>. Matches
    <span class="mono">proto/src/http_injector.rs::inject_headers</span>.
    Audience-bound (rejects cross-service replay) and timestamp-bounded
    (max age {MAX_TIMESTAMP_AGE_SECONDS}s, rejects stale replay).
    <br><br>
    Flow: <span class="mono">spongebob (AI computer) &rarr; ztlp connect &rarr; [NS + relay] &rarr;
    ztlp listen (gateway, per-request header injection via RequestInjector) &rarr; this page</span>.
  </div>
</div>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive; the gateway now signs EVERY
                                   # request on the tunnel (RequestInjector),
                                   # so keep-alive works normally again — no
                                   # need to force "Connection: close".

    def log_message(self, fmt, *args):
        # Compact stderr log (one line per request) — useful for the PoC.
        print(f"[ztlp-poc] {self.client_address[0]} {fmt % args}", flush=True)

    def _respond(self, status, body, content_type="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-ZTLP-PoC", "gateway-auth")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        # Strip the path — the PoC is a single page.
        headers = {k: v for k, v in self.headers.items()}
        if self.path.rstrip("/") in ("", "/"):
            self._respond(200, render(headers))
        elif self.path.rstrip("/") == "/up":
            # Health endpoint (plain text, no ZTLP required).
            self._respond(200, "ok\n", "text/plain")
        else:
            # Any other path: still render the auth page (so tunnel probes work).
            self._respond(200, render(headers))

    do_HEAD = do_GET  # keep it simple


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[ztlp-poc] ZTLP gateway-auth PoC listening on 0.0.0.0:{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
