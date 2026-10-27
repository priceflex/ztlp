#!/usr/bin/env python3
"""ztlp-whoami: show the identity a ZTLP gateway signed for this request.

Sits behind a Rust `ztlp listen --gateway --http-inject-headers` gateway and verifies the 8 signed
X-ZTLP-* headers (proto/src/http_injector.rs): canonical string = lowercased `x-ztlp-<field>:<value>`
for all 8 fields, sorted, joined by LF; HMAC-SHA256 hex with the raw secret bytes as the key.

Configured with exactly what the admin panel hands out for a service ("App settings"):
  ZTLP_GATEWAY_HEADER_SECRET  the gateway's --header-hmac-secret
  ZTLP_GATEWAY_AUDIENCE       the gateway's service name (signatures are bound to it)
Optional: ZTLP_MAX_AGE (seconds, default 30), PORT (default 8080), BIND (default 0.0.0.0).

Pages: /  (HTML), /who.json, /up. Standard library only.
"""

import hashlib
import hmac
import html
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIGNED = ["authenticated", "admin-email", "device-name", "zone", "group", "assurance", "audience", "timestamp"]
SECRET = os.environ.get("ZTLP_GATEWAY_HEADER_SECRET", "")
AUDIENCE = os.environ.get("ZTLP_GATEWAY_AUDIENCE", "")
MAX_AGE = int(os.environ.get("ZTLP_MAX_AGE", "30"))
VERSION = "0.1.0"


def canonical(fields):
    return "\n".join(sorted(f"x-ztlp-{k}:{v}" for k, v in fields.items()))


def parse_ts(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def verify(headers, now=None):
    """Return a dict describing the request's identity and every check, never raising."""
    now = now or datetime.now(timezone.utc)
    fields = {k: headers.get(f"X-ZTLP-{k}", "") or "" for k in SIGNED}
    signature = headers.get("X-ZTLP-Signature", "") or ""
    present = any(headers.get(f"X-ZTLP-{k}") is not None for k in SIGNED) or bool(signature)
    out = {
        "via_ztlp": present,
        "verified": False,
        "reason": "",
        "person": fields["admin-email"],
        "device": fields["device-name"],
        "zone": fields["zone"],
        "group": fields["group"],
        "assurance": fields["assurance"],
        "audience": fields["audience"],
        "timestamp": fields["timestamp"],
        "age_seconds": None,
        "checks": {},
        "canonical": canonical(fields) if present else "",
    }
    if not present:
        out["reason"] = "no ZTLP headers: this request did not come through a ZTLP gateway"
        return out
    if not SECRET:
        out["reason"] = "ZTLP_GATEWAY_HEADER_SECRET is not set on the app, so nothing can be verified"
        return out

    expected = hmac.new(SECRET.encode(), out["canonical"].encode(), hashlib.sha256).hexdigest()
    ts = parse_ts(fields["timestamp"])
    age = (now - ts).total_seconds() if ts else None
    out["age_seconds"] = round(age, 1) if age is not None else None
    checks = {
        "signature": hmac.compare_digest(expected, signature.lower()),
        "authenticated": fields["authenticated"] in ("1", "true"),
        "audience": bool(AUDIENCE) and fields["audience"] == AUDIENCE,
        "fresh": age is not None and -5 <= age <= MAX_AGE,
    }
    out["checks"] = checks
    failed = [k for k, ok in checks.items() if not ok]
    out["verified"] = not failed
    if failed:
        why = {
            "signature": "the signature does not match (wrong header secret on the app or the gateway?)",
            "authenticated": "the gateway did not mark the request authenticated",
            "audience": f"signed for audience '{fields['audience']}', this app is '{AUDIENCE or '(unset)'}'",
            "fresh": f"timestamp is {out['age_seconds']}s old (limit {MAX_AGE}s)",
        }
        out["reason"] = "; ".join(why[k] for k in failed)
    else:
        out["reason"] = "signed by the gateway and verified"
    return out


def row(label, value, hint=""):
    shown = html.escape(value) if value else '<span class="empty">(empty)</span>'
    tip = f'<div class="hint">{html.escape(hint)}</div>' if hint else ""
    return f"<tr><th>{html.escape(label)}</th><td class=\"mono\">{shown}{tip}</td></tr>"


def page(who):
    if who["verified"]:
        banner, cls = "Verified ZTLP identity", "ok"
    elif who["via_ztlp"]:
        banner, cls = "Not verified", "bad"
    else:
        banner, cls = "Not via ZTLP", "warn"
    checks = "".join(
        f'<li class="{"ok" if ok else "bad"}">{"✓" if ok else "✗"} {html.escape(k)}</li>' for k, ok in who["checks"].items()
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>ZTLP whoami</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{{font-family:system-ui,sans-serif;background:#0f1419;color:#e6e6e6;margin:0;padding:2rem;}}
main{{max-width:52rem;margin:auto}} h1{{font-size:1.4rem;margin:0 0 1rem}}
.banner{{padding:1rem 1.2rem;border-radius:.5rem;font-size:1.3rem;font-weight:600;margin-bottom:.5rem}}
.banner.ok{{background:#12391f;color:#7ee2a0}} .banner.bad{{background:#3d1416;color:#ff9c9c}} .banner.warn{{background:#3a3112;color:#ffd77a}}
.reason{{color:#b8b8b8;margin-bottom:1.5rem}}
table{{width:100%;border-collapse:collapse;margin-bottom:1.5rem}} th,td{{text-align:left;padding:.5rem .6rem;border-bottom:1px solid #263040;vertical-align:top}}
th{{width:11rem;color:#9fb0c8;font-weight:500}} .mono{{font-family:ui-monospace,Menlo,monospace}} .empty{{color:#6b7685}}
.hint{{color:#6b7685;font-family:system-ui;font-size:.85rem;margin-top:.2rem}}
ul.checks{{list-style:none;padding:0;display:flex;gap:1rem;flex-wrap:wrap}} li.ok{{color:#7ee2a0}} li.bad{{color:#ff9c9c}}
pre{{background:#161d26;padding:.8rem;border-radius:.4rem;overflow:auto;font-size:.85rem}}
footer{{color:#6b7685;font-size:.85rem}}
</style></head><body><main>
<h1>ZTLP whoami</h1>
<div class="banner {cls}">{banner}</div>
<div class="reason">{html.escape(who["reason"])}</div>
<table>
{row("Person", who["person"], "Owner of the device in the name server (empty = device not linked to a user).")}
{row("Device", who["device"], "Resolved by the gateway from the tunnel key; the device cannot choose it.")}
{row("Zone", who["zone"])}
{row("Group", who["group"], "The group rule that let this device in (empty = no group rule matched).")}
{row("Assurance", who["assurance"], "Advisory: reported by the device, not attested.")}
{row("Audience", who["audience"], "The service this signature is bound to.")}
{row("Signed at", who["timestamp"] + (f"  ({who['age_seconds']}s ago)" if who["age_seconds"] is not None else ""))}
</table>
<ul class="checks">{checks}</ul>
<details><summary>Signed string</summary><pre>{html.escape(who["canonical"]) or "(none)"}</pre></details>
<footer>ztlp-whoami {VERSION} · audience {html.escape(AUDIENCE or "(unset)")} · <a href="/who.json" style="color:#9fb0c8">who.json</a></footer>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ztlp-whoami/" + VERSION

    def _send(self, code, ctype, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/up":
            return self._send(200, "text/plain", "ok\n")
        who = verify(self.headers)
        sys.stderr.write(
            f"[whoami] {path} via_ztlp={who['via_ztlp']} verified={who['verified']} "
            f"person={who['person']!r} device={who['device']!r} reason={who['reason']!r}\n"
        )
        if path == "/who.json":
            return self._send(200, "application/json", json.dumps(who, indent=2) + "\n")
        if path == "/":
            return self._send(200, "text/html; charset=utf-8", page(who))
        return self._send(404, "text/plain", "not found\n")

    def log_message(self, format, *args):  # noqa: A002 (base class name)  # the [whoami] line above is the access log
        pass


if __name__ == "__main__":
    bind, port = os.environ.get("BIND", "0.0.0.0"), int(os.environ.get("PORT", "8080"))
    sys.stderr.write(f"ztlp-whoami {VERSION} on {bind}:{port}, audience={AUDIENCE or '(unset)'}, "
                     f"secret={'set' if SECRET else 'NOT SET'}\n")
    ThreadingHTTPServer((bind, port), Handler).serve_forever()
