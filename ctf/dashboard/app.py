#!/usr/bin/env python3
"""ZTLP CTF Dashboard - DEF CON 34

The flag is released ONLY when the request carries identity headers that
are cryptographically verified:

  1. X-ZTLP-Signature must be a valid HMAC-SHA256 over the canonical
     string of every other X-ZTLP-* header, keyed with the shared secret
     the gateway was configured with.
  2. X-ZTLP-Timestamp must be recent (replay window), and
  3. X-ZTLP-Nonce must not have been seen before (replay defence).

Presence of a header proves nothing -- anyone can `curl -H`. Only the
signature proves the request actually traversed the ZTLP gateway, because
only the gateway holds the signing secret.

Canonical string format (must match gateway/lib/ztlp_gateway/header_signer.ex
exactly): all x-ztlp-* headers EXCEPT x-ztlp-signature, lowercased name,
sorted by name, rendered "name:value", joined by "\n", no trailing newline.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, datetime, html, os, socket, hashlib, hmac

HISTORY = []
MAX_HISTORY = 50

# Replay defence: remember nonces we've already honoured.
SEEN_NONCES = set()
MAX_NONCES = 5000

# How much clock skew / travel time we tolerate on X-ZTLP-Timestamp.
MAX_AGE_SECONDS = 300


def get_flag():
    hostname = socket.gethostname()
    d = datetime.date.today().isoformat()
    seed = f"ztlp_ctf_{hostname}_{d}"
    return hashlib.sha256(seed.encode()).hexdigest()[:32]


# NOTE: an empty/absent CTF_FLAG must fall back to the computed flag.
# `os.environ.get("CTF_FLAG", default)` returns "" when the var is set but
# empty, which previously rendered a hollow "FLAG{}".
FLAG = os.environ.get("CTF_FLAG") or get_flag()

SIGNING_SECRET = os.environ.get("ZTLP_HEADER_HMAC_SECRET", "")


def canonical_string(ztlp_headers):
    """Rebuild the gateway's canonical signing string.

    Mirrors ZtlpGateway.HeaderSigner.canonical_string/1.
    """
    items = [
        (k.lower(), v)
        for k, v in ztlp_headers.items()
        if k.lower().startswith("x-ztlp-") and k.lower() != "x-ztlp-signature"
    ]
    items.sort(key=lambda kv: kv[0])
    return "\n".join(f"{k}:{v}" for k, v in items)


def verify_identity(ztlp_headers):
    """Return (verified: bool, reason: str).

    Fails closed: any missing piece, bad signature, stale timestamp or
    replayed nonce denies the flag.
    """
    if not SIGNING_SECRET:
        return False, "Dashboard has no signing secret configured"

    signature = None
    for k, v in ztlp_headers.items():
        if k.lower() == "x-ztlp-signature":
            signature = v
            break

    if not signature:
        return False, "No X-ZTLP-Signature header (headers alone prove nothing)"

    expected = hmac.new(
        SIGNING_SECRET.encode(),
        canonical_string(ztlp_headers).encode(),
        hashlib.sha256,
    ).hexdigest()

    # Constant-time compare to avoid leaking the signature byte-by-byte.
    if not hmac.compare_digest(expected, signature.strip().lower()):
        return False, "Invalid HMAC signature - forged or tampered headers"

    # Signature is good; now enforce freshness so a captured-but-valid
    # request can't be replayed forever.
    ts = None
    nonce = None
    for k, v in ztlp_headers.items():
        if k.lower() == "x-ztlp-timestamp":
            ts = v
        elif k.lower() == "x-ztlp-nonce":
            nonce = v

    if not ts:
        return False, "Signature valid but no X-ZTLP-Timestamp"

    try:
        # Gateway emits ISO8601 via DateTime.to_iso8601/1.
        parsed = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        age = (datetime.datetime.now(datetime.timezone.utc) - parsed).total_seconds()
    except ValueError:
        return False, "Signature valid but timestamp is unparseable"

    if age > MAX_AGE_SECONDS:
        return False, f"Signature valid but expired ({int(age)}s old)"
    if age < -MAX_AGE_SECONDS:
        return False, "Signature valid but timestamp is in the future"

    if nonce:
        if nonce in SEEN_NONCES:
            return False, "Replayed nonce - this exact request was already used"
        if len(SEEN_NONCES) >= MAX_NONCES:
            SEEN_NONCES.clear()
        SEEN_NONCES.add(nonce)

    return True, "HMAC-SHA256 verified - request provably traversed the ZTLP gateway"


class Handler(BaseHTTPRequestHandler):
    def record_event(self, verified, reason):
        entry = {
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "ip": self.client_address[0],
            "verified": verified,
            "reason": reason,
            "headers": {k: v for k, v in self.headers.items() if k.startswith("X-ZTLP-")},
        }
        HISTORY.append(entry)
        if len(HISTORY) > MAX_HISTORY:
            HISTORY.pop(0)

    def do_GET(self):
        if self.path == "/":
            self.serve_dashboard()
        elif self.path == "/api/history":
            self.serve_history()
        elif self.path == "/api/reset":
            global HISTORY
            HISTORY.clear()
            SEEN_NONCES.clear()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "reset"}).encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def serve_history(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(HISTORY, indent=2).encode())

    def serve_dashboard(self):
        ztlp_headers = {k: v for k, v in self.headers.items() if k.startswith("X-ZTLP-")}
        verified, reason = verify_identity(ztlp_headers)
        self.record_event(verified, reason)

        status = "VERIFIED" if verified else "DENIED"

        flag_display = ""
        if verified:
            flag_display = "\n".join([
                '<div class="flag">',
                'FLAG{' + FLAG + '}',
                '</div>',
            ])

        h = '<!DOCTYPE html>\n<html><head><meta charset="UTF-8">\n'
        h += '<title>ZTLP CTF - DEF CON 34</title>\n'
        h += '<style>\n'
        h += '*{margin:0;padding:0;box-sizing:border-box}\n'
        h += 'body{font-family:"Courier New",monospace;background:#0a0a0a;color:#00ff41;padding:20px}\n'
        h += '.header{text-align:center;padding:20px;border-bottom:1px solid #00ff41;margin-bottom:20px}\n'
        h += '.header h1{font-size:2em;text-shadow:0 0 10px #00ff41}\n'
        h += '.status{text-align:center;padding:15px;margin:20px 0;border:2px solid;font-size:1.3em}\n'
        h += '.status.denied{color:#ff4444;border-color:#ff4444;background:#1a0000}\n'
        h += '.status.verified{color:#00ff41;border-color:#00ff41;background:#001a00}\n'
        h += '.flag{text-align:center;padding:30px;margin:20px 0;font-size:2em;border:3px dashed #ffdd00;background:#1a1a00;color:#ffdd00}\n'
        h += '.info table{width:100%;border-collapse:collapse;margin:10px 0}\n'
        h += '.info td{padding:8px 12px;border:1px solid #1a3a1a;word-break:break-all}\n'
        h += '.info td:first-child{color:#00aa2a;width:230px;font-weight:bold}\n'
        h += '.challenge{background:#0a1a0a;border:1px solid #00aa2a;padding:15px;margin:20px 0}\n'
        h += '.hint{background:#1a1a0a;border:1px solid #333300;padding:10px;margin:15px 0;color:#aa8800}\n'
        h += '</style></head><body>\n'
        h += '<div class="header"><h1>ZTLP CTF</h1><h2>DEF CON 34</h2></div>\n'
        h += '<div class="challenge">\n'
        h += '<h3 style="color:#ffdd00">&gt; THE CHALLENGE</h3>\n'
        h += '<p>This dashboard is behind ZTLP zero-trust authentication.</p>\n'
        h += '<p>The Name Server (UDP 23096) is in <strong>PRODUCTION AUTHENTICATED MODE</strong>.</p>\n'
        h += '<p>Only entities signed by the zone authority key can register records.</p>\n'
        h += '<p>Identity headers are <strong>HMAC-SHA256 signed by the gateway</strong> — '
        h += 'sending your own <code>X-ZTLP-*</code> headers will NOT work.</p>\n'
        h += '<p><strong>Get a verified identity through the tunnel to reveal the flag.</strong></p>\n'
        h += '</div>\n'
        h += '<div class="status ' + status.lower() + '">' + status + ' - ' + html.escape(reason) + '</div>\n'

        if verified:
            h += flag_display + '\n'

        if ztlp_headers:
            h += '<div class="info"><table>\n'
            for k, v in sorted(ztlp_headers.items()):
                h += '<tr><td>' + html.escape(k) + '</td><td>' + html.escape(v) + '</td></tr>\n'
            h += '</table></div>\n'
        else:
            h += '<div class="hint">No ZTLP identity headers present — '
            h += 'you are talking to the backend directly, not through the gateway.</div>\n'

        h += '<div class="hint">\n'
        h += '<strong>NS:</strong> UDP 23096 | <strong>Relay:</strong> UDP 23095 | <strong>Gateway:</strong> UDP 23097\n'
        h += '| <strong>Auth:</strong> Production (zone signing required) + HMAC header verification\n'
        h += '</div></body></html>'

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(h.encode())

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8420"))
    mode = "HMAC-VERIFIED" if SIGNING_SECRET else "UNVERIFIED (no secret!)"
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"CTF Dashboard on 0.0.0.0:{port} [{mode}]", flush=True)
    server.serve_forever()
