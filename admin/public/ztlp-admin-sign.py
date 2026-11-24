#!/usr/bin/env python3
"""ztlp-admin-sign.py - sign ZTLP Admin claim / login messages with your ZTLP identity.

Stop-gap until `ztlp admin claim` / `ztlp admin login` ship in the CLI. Reads the
Ed25519 seed from ~/.ztlp/identity.json (field `signing_key_seed`, hex). Nothing
leaves this machine; it prints values for you to paste into the web form.

  python3 ztlp-admin-sign.py pubkey
  python3 ztlp-admin-sign.py claim --code CODE --username U --display-name "Name" [--email E]
  python3 ztlp-admin-sign.py login --host admin.trs.ztlp --nonce NONCE

Uses the `cryptography` package when available, otherwise a pure-Python Ed25519
(RFC 8032 reference implementation; slow but dependency-free).
"""
import argparse, hashlib, json, os, sys, time

# ---------- pure-python Ed25519 (RFC 8032 §6) ----------
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493
def _inv(x): return pow(x, _q - 2, _q)
_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)
def _xrec(y):
    xx = (y*y - 1) * _inv(_d*y*y + 1); x = pow(xx, (_q + 3) // 8, _q)
    if (x*x - xx) % _q: x = (x * _I) % _q
    return x if x % 2 == 0 else _q - x
_By = (4 * _inv(5)) % _q; _B = (_xrec(_By), _By)
def _add(P, Q):
    x1, y1 = P; x2, y2 = Q
    x3 = (x1*y2 + x2*y1) * _inv(1 + _d*x1*x2*y1*y2); y3 = (y1*y2 + x1*x2) * _inv(1 - _d*x1*x2*y1*y2)
    return (x3 % _q, y3 % _q)
def _mul(P, e):
    Q = (0, 1)
    while e:
        if e & 1: Q = _add(Q, P)
        P = _add(P, P); e >>= 1
    return Q
def _enc(P):
    x, y = P; return (y | ((x & 1) << 255)).to_bytes(32, "little")
def _clamp(h):
    a = int.from_bytes(h[:32], "little"); return (a & ~(7) & ((1 << 254) - 1)) | (1 << 254)
def _py_pub(seed):
    return _enc(_mul(_B, _clamp(hashlib.sha512(seed).digest())))
def _py_sign(seed, msg):
    h = hashlib.sha512(seed).digest(); a = _clamp(h); A = _py_pub(seed)
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % _l
    R = _enc(_mul(_B, r))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % _l
    return R + ((r + k * a) % _l).to_bytes(32, "little")

def _backend():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        def pub(seed):
            k = Ed25519PrivateKey.from_private_bytes(seed)
            return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        def sign(seed, msg): return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
        return pub, sign
    except Exception:
        return _py_pub, _py_sign

SEED_FIELDS = ("signing_key_seed", "ed25519_seed")

def load_seed(path):
    with open(os.path.expanduser(path)) as f:
        d = json.load(f)
    # `ztlp keygen` writes `ed25519_seed`; the daemon (`NodeIdentity::save`)
    # writes `signing_key_seed`. Both are the same Ed25519 seed, and a file
    # that carries one is never rewritten by the daemon, so accept either.
    found = {k: d.get(k) for k in SEED_FIELDS if d.get(k)}
    if not found:
        sys.exit("identity.json has no %s (run `ztlp keygen` with a current ztlp first)"
                 % " or ".join(SEED_FIELDS))
    values = {v.lower() if isinstance(v, str) else v for v in found.values()}
    if len(values) > 1:
        sys.exit("identity.json has conflicting seeds under %s; refusing to guess"
                 % ", ".join(sorted(found)))
    s = next(iter(found.values()))
    return bytes.fromhex(s) if isinstance(s, str) else bytes(s)

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def claim_submit(url, body, sig):
    """GET /claim for the session cookie + CSRF token, then POST the signed claim.
    The panel only answers through its ZTLP gateway, so run this with the ZTLP agent up."""
    import http.cookiejar, re, urllib.error, urllib.parse, urllib.request
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    url = url.rstrip("/")
    try:
        page = opener.open(url + "/claim", timeout=30).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code == 403:
            sys.exit("403 from the panel: the request did not come through ZTLP (is the agent running?)")
        sys.exit("GET %s/claim failed: HTTP %s" % (url, e.code))
    except Exception as e:
        sys.exit("cannot reach %s/claim: %s (is the ZTLP agent running?)" % (url, e))
    m = re.search(r'name="authenticity_token" value="([^"]+)"', page)
    if not m:
        sys.exit("no claim form at %s/claim (already claimed? open %s in a browser)" % (url, url))
    form = {"authenticity_token": m.group(1), "claim[signature]": sig}
    form.update({"claim[%s]" % k: str(v) for k, v in body.items()})
    req = urllib.request.Request(url + "/claim", data=urllib.parse.urlencode(form).encode(), method="POST")
    try:
        resp = opener.open(req, timeout=30)
        text = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        alert = re.search(r'class="[^"]*(?:alert|flash)[^"]*"[^>]*>\s*([^<]+)', text)
        sys.exit("claim refused (HTTP %s): %s" % (e.code, alert.group(1).strip() if alert else "open the panel to see why"))
    if "Welcome" in text or not resp.geturl().rstrip("/").endswith("/claim"):
        print("Claimed: %s is now the first administrator. Open %s in your browser." % (body["username"], url))
    else:
        sys.exit("the claim did not complete; open %s/claim in a browser to see why" % url)

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--identity", default="~/.ztlp/identity.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pubkey")
    sub.add_parser("device-key", help="print static_public_key (for ztlp-bootstrap --admin-device)")
    c = sub.add_parser("claim"); c.add_argument("--code", required=True); c.add_argument("--username", required=True)
    c.add_argument("--display-name", required=True); c.add_argument("--email", default="")
    cs = sub.add_parser("claim-submit", help="sign AND submit the claim to the panel (needs the ZTLP agent)")
    cs.add_argument("--url", required=True, help="e.g. http://admin.example.ztlp")
    cs.add_argument("--code", required=True); cs.add_argument("--username", required=True)
    cs.add_argument("--display-name", required=True); cs.add_argument("--email", default="")
    lg = sub.add_parser("login"); lg.add_argument("--host", required=True); lg.add_argument("--nonce", required=True)
    a = ap.parse_args()
    if a.cmd == "device-key":
        with open(os.path.expanduser(a.identity)) as f:
            k = json.load(f).get("static_public_key")
        if not k:
            sys.exit("identity.json has no static_public_key")
        print(k if isinstance(k, str) else bytes(k).hex()); return
    pub, sign = _backend()
    seed = load_seed(a.identity)
    pk = pub(seed).hex()
    if a.cmd == "pubkey":
        print(pk); return
    if a.cmd in ("claim", "claim-submit"):
        ts = int(time.time())
        body = {"claim_code": a.code, "username": a.username, "display_name": a.display_name,
                "email": a.email, "pubkey_hex": pk, "timestamp": ts}
        sig = sign(seed, hashlib.sha256(canonical(body)).digest()).hex()
        if a.cmd == "claim-submit":
            claim_submit(a.url, body, sig); return
        print(f"pubkey_hex: {pk}\ntimestamp:  {ts}\nsignature:  {sig}"); return
    if a.cmd == "login":
        msg = f"ztlp-admin-login\n{a.host}\n{a.nonce}".encode()
        print(f"pubkey_hex: {pk}\nsignature:  {sign(seed, msg).hex()}")

if __name__ == "__main__":
    main()
