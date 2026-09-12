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


def verify_hmac():
    """Verify the gateway's HMAC header over the identity headers, if present."""
    sig = request.headers.get("X-ZTLP-HEADER-SIG", "")
    if not sig:
        return None, "no signature header"
    body = request.headers.get("X-ZTLP-HEADER-BODY", "")
    if not body:
        return None, "no header body"
    expected = hmac.new(HMAC_KEY, body.encode(), hashlib.sha256).hexdigest()
    return (hmac.compare_digest(expected, sig), "signature matches") if expected == sig else (False, "signature mismatch")


ZTLP_HEADERS = [
    ("X-ZTLP-Node-Name", "node name"),
    ("X-ZTLP-Node-Id", "node id"),
    ("X-ZTLP-Zone", "zone"),
    ("X-ZTLP-Role", "role"),
    ("X-ZTLP-Assurance", "assurance level"),
    ("X-ZTLP-Device", "device"),
    ("X-ZTLP-Owner", "owning user"),
    ("X-ZTLP-Session-Id", "session id"),
    ("X-ZTLP-HEADER-BODY", "signed header body"),
    ("X-ZTLP-HEADER-SIG", "HMAC signature"),
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
