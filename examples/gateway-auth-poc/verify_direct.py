#!/usr/bin/env python3
"""Forge ZTLP headers, hit the local PoC container directly, report outcomes.

Scenarios:
  1. valid-fresh        -> expect 200 GATEWAY-AUTHENTICATED + signature VALID
  2. cross-audience     -> expect rejection (not GATEWAY-AUTHENTICATED)
  3. stale-timestamp    -> expect rejection
  4. forged-secret      -> expect rejection
"""
import hmac, hashlib, time, urllib.request, sys, re

SECRET = "995908ad45fb48ea7f30da7ef7f34a81c55a19612e0373f8f398b8c89cab4b6f"
PORT = "18099"

def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

def sign(fields, secret):
    # canonical: sorted "name:value" lines, names lowercased, VALUES VERBATIM
    # (the gateway signs the raw timestamp — lowercasing it breaks the HMAC),
    # \n-joined, no trailing \n.
    lines = sorted(f"{k.lower()}:{v}" for k, v in fields.items())
    msg = "\n".join(lines)
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

BASE = {
    "X-ZTLP-Authenticated": "1",
    "X-ZTLP-Admin-Email": "spongebob@demo.spongebob.ztlp",
    "X-ZTLP-Device-Name": "",
    "X-ZTLP-Zone": "",
    "X-ZTLP-Group": "",
    "X-ZTLP-Assurance": "",
    "X-ZTLP-Audience": "web",
    "X-ZTLP-Timestamp": "",
}

def forge(secret, audience, ts, sig=None):
    h = dict(BASE)
    h["X-ZTLP-Audience"] = audience
    h["X-ZTLP-Timestamp"] = ts
    computed = sign(h, secret)
    h["X-ZTLP-Signature"] = sig if sig else computed
    return h

def hit(raw_headers, label, expect_auth):
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
        s.sendall(raw_headers.encode())
        time.sleep(0.3)
        s.settimeout(5)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        body = data.decode(errors="replace")
        code = "200"
    except Exception as e:
        body = str(e)
        code = "?"
    authed = "GATEWAY-AUTHENTICATED" in body
    valid = "signature VALID" in body
    ok = authed == expect_auth
    mark = "PASS" if ok else "FAIL"
    detail = f"auth={authed} valid={valid}"
    if not expect_auth:
        for reason in ("audience", "stale", "HMAC mismatch", "unparseable"):
            if reason.lower() in body.lower():
                detail += f" reason~{reason}"
                break
    print(f"[{mark}] {label}: HTTP {code} {detail}")
    return ok

def make_headers(secret, audience, ts, sig_override=None):
    fields = {
        "X-ZTLP-Authenticated": "1",
        "X-ZTLP-Admin-Email": "spongebob@demo.spongebob.ztlp",
        "X-ZTLP-Device-Name": "",
        "X-ZTLP-Zone": "",
        "X-ZTLP-Group": "",
        "X-ZTLP-Assurance": "",
        "X-ZTLP-Audience": audience,
        "X-ZTLP-Timestamp": ts,
    }
    computed = sign(fields, secret)
    sig = sig_override or computed
    lines = [f"{k}: {v}" for k, v in fields.items()]
    lines.append(f"X-ZTLP-Signature: {sig}")
    return "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n" + "\r\n".join(lines) + "\r\nConnection: close\r\n\r\n"

now = int(time.time())
ts = iso(now)

results = [
    hit(make_headers(SECRET, "web", ts), "1. valid-fresh", True),
    hit(make_headers(SECRET, "other-service", ts), "2. cross-audience", False),
    hit(make_headers(SECRET, "web", iso(now - 300)), "3. stale-timestamp(-300s)", False),
    hit(make_headers("0" * 64, "web", ts), "4. forged-secret", False),
]
print(f"\n{sum(results)}/{len(results)} scenarios passed")
sys.exit(0 if all(results) else 1)
