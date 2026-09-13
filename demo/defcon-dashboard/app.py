# Minimal ZTLP demo dashboard for the DEF CON-style laptop demo.
# Shows the ZTLP headers the gateway injects (identity, role, HMAC-signed
# headers), plus a simple live counter. No external deps beyond Flask.

import os
import time
import hashlib
import hmac
import json

from flask import Flask, jsonify, request

app = Flask(__name__)

HMAC_KEY = os.environ.get("ZTLP_DEMO_HMAC_KEY", "supersecretkey").encode()
START_TIME = time.time()


def canonical_string(headers):
    """Mirror ZtlpGateway.HeaderSigner.canonical_string/1:
    all X-ZTLP-* headers except X-ZTLP-Signature, sorted by lowercase name,
    each as "name:value" (name lowercased), joined with "\\n"."""
    pairs = [
        (name.lower(), value)
        for name, value in headers
        if name.lower().startswith("x-ztlp-") and name.lower() != "x-ztlp-signature"
    ]
    pairs.sort(key=lambda kv: kv[0])
    return "\n".join(f"{n}:{v}" for n, v in pairs)


def verify_signature(headers, key):
    """Verify the gateway's X-ZTLP-Signature (HMAC-SHA256 hex over the
    canonical string). Returns (True|False|None, detail)."""
    sig = next((v for n, v in headers if n.lower() == "x-ztlp-signature"), "")
    if not sig:
        return None, "no signature header"
    expected = hmac.new(key, canonical_string(headers).encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, sig.lower()):
        return True, "signature matches"
    return False, "signature mismatch"


def verify_hmac():
    """Verify the gateway's HMAC signature over the injected identity headers."""
    return verify_signature(list(request.headers.items()), HMAC_KEY)


ZTLP_HEADERS = [
    ("X-ZTLP-Node-Name", "node name"),
    ("X-ZTLP-Node-Id", "node id"),
    ("X-ZTLP-Zone", "zone"),
    ("X-ZTLP-Authenticated", "authenticated"),
    ("X-ZTLP-Assurance", "assurance level"),
    ("X-ZTLP-Key-Source", "key source"),
    ("X-ZTLP-Key-Attestation", "key attestation"),
    ("X-ZTLP-Timestamp", "timestamp"),
    ("X-ZTLP-Nonce", "nonce"),
    ("X-ZTLP-Request-Id", "request id"),
    ("X-ZTLP-Signature", "HMAC signature"),
]


@app.route("/")
def index():
    headers = {label: request.headers.get(name, "—") for name, label in ZTLP_HEADERS}
    hmac_ok, hmac_detail = verify_hmac()
    return jsonify(
        {
            "title": "ZTLP Demo Dashboard",
            "subtitle": "You reached this page through the ZTLP tunnel + gateway.",
            "uptime_seconds": round(time.time() - START_TIME, 1),
            "ztlp_headers": headers,
            "hmac_verified": hmac_ok,
            "hmac_detail": hmac_detail,
        }
    )


@app.route("/api/headers")
def api_headers():
    return jsonify({name: request.headers.get(name) for name, _ in ZTLP_HEADERS})


@app.route("/api/health")
def health():
    return jsonify(status="ok")


@app.route("/api/reset")
def reset():
    global START_TIME
    START_TIME = time.time()
    return jsonify(reset=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8420)
