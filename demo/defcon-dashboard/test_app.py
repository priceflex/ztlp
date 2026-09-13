"""Tests for the demo dashboard's X-ZTLP-Signature verification.

The gateway (gateway/lib/ztlp_gateway/header_signer.ex) signs headers as:
  canonical = "\n".join(f"{name.lower()}:{value}" for all X-ZTLP-* headers
              except X-ZTLP-Signature, sorted by lowercase name)
  X-ZTLP-Signature = hex(HMAC-SHA256(secret, canonical))
The dashboard must recompute exactly that.
"""
import hashlib
import hmac

import app as dashboard

KEY = b"supersecretkey"


def _sign(headers, key=KEY):
    canon = "\n".join(
        f"{n.lower()}:{v}"
        for n, v in sorted(
            ((n, v) for n, v in headers if n.lower().startswith("x-ztlp-") and n.lower() != "x-ztlp-signature"),
            key=lambda kv: kv[0].lower(),
        )
    )
    return hmac.new(key, canon.encode(), hashlib.sha256).hexdigest()


GATEWAY_HEADERS = [
    ("X-ZTLP-Node-ID", "4ea4bbd82796ff262a884adc750ad22bf2ad74ca7d1d0304bd952f2deb52ea6a"),
    ("X-ZTLP-Node-Name", "unknown:4ea4bbd82796ff262a884adc750ad22bf2ad74ca7d1d0304bd952f2deb52ea6a"),
    ("X-ZTLP-Zone", ""),
    ("X-ZTLP-Authenticated", "true"),
    ("X-ZTLP-Assurance", "device-bound"),
    ("X-ZTLP-Key-Source", "ztlp-noise"),
    ("X-ZTLP-Key-Attestation", "unverified"),
    ("X-ZTLP-Cert-Fingerprint", ""),
    ("X-ZTLP-Cert-Serial", ""),
    ("X-ZTLP-Timestamp", "2026-09-13T00:17:09.000000Z"),
    ("X-ZTLP-Nonce", "0123456789abcdef0123456789abcdef"),
    ("X-ZTLP-Request-ID", "12345678-1234-4123-8123-123456789abc"),
    ("Host", "demo-dashboard.defcon.ztlp"),  # non-ZTLP header, must be ignored
    ("X-Forwarded-Proto", "https"),           # non-ZTLP header, must be ignored
]


def test_canonical_string_matches_gateway_scheme():
    canon = dashboard.canonical_string(GATEWAY_HEADERS)
    lines = canon.split("\n")
    assert lines == sorted(lines)
    assert all(l.startswith("x-ztlp-") for l in lines)
    assert not any(l.startswith("x-ztlp-signature") for l in lines)
    assert "x-ztlp-node-id:4ea4bbd8" in canon
    assert "host:" not in canon and "x-forwarded" not in canon


def test_valid_signature_verifies():
    sig = _sign(GATEWAY_HEADERS)
    headers = GATEWAY_HEADERS + [("X-ZTLP-Signature", sig)]
    ok, detail = dashboard.verify_signature(headers, KEY)
    assert ok is True, detail


def test_tampered_header_fails():
    sig = _sign(GATEWAY_HEADERS)
    tampered = [(n, ("admin" if n == "X-ZTLP-Node-Name" else v)) for n, v in GATEWAY_HEADERS]
    ok, detail = dashboard.verify_signature(tampered + [("X-ZTLP-Signature", sig)], KEY)
    assert ok is False
    assert detail == "signature mismatch"


def test_wrong_key_fails():
    sig = _sign(GATEWAY_HEADERS, b"otherkey")
    ok, _ = dashboard.verify_signature(GATEWAY_HEADERS + [("X-ZTLP-Signature", sig)], KEY)
    assert ok is False


def test_missing_signature_is_none():
    ok, detail = dashboard.verify_signature(GATEWAY_HEADERS, KEY)
    assert ok is None
    assert detail == "no signature header"


def test_index_route_reports_verified(monkeypatch):
    sig = _sign(GATEWAY_HEADERS)
    client = dashboard.app.test_client()
    resp = client.get("/", headers=GATEWAY_HEADERS + [("X-ZTLP-Signature", sig)])
    body = resp.get_json()
    assert body["hmac_verified"] is True
    assert body["ztlp_headers"]["HMAC signature"] == sig
