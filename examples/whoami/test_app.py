"""Tests for ztlp-whoami's verifier. Run: python3 -m unittest test_app.py (from examples/whoami)."""

import hashlib
import hmac
import importlib
import os
import unittest
from email.message import Message
from datetime import datetime, timedelta, timezone

os.environ["ZTLP_GATEWAY_HEADER_SECRET"] = "test-header-secret"
os.environ["ZTLP_GATEWAY_AUDIENCE"] = "whoami"
app = importlib.import_module("app")

NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)


def signed(secret="test-header-secret", **over):
    fields = {
        "authenticated": "1", "admin-email": "steve@trs.ztlp", "device-name": "stevens-mac-studio.trs.ztlp",
        "zone": "trs.ztlp", "group": "", "assurance": "software", "audience": "whoami",
        "timestamp": (NOW - timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    fields.update(over)
    canon = "\n".join(sorted(f"x-ztlp-{k}:{v}" for k, v in fields.items()))
    return as_http({**{f"X-ZTLP-{k}": v for k, v in fields.items()},
                    "X-ZTLP-Signature": hmac.new(secret.encode(), canon.encode(), hashlib.sha256).hexdigest()})


def as_http(d):
    """Case-insensitive headers, like BaseHTTPRequestHandler.headers."""
    m = Message()
    for k, v in d.items():
        m[k] = v
    return m


class VerifyTest(unittest.TestCase):
    def test_golden_vector_matches_the_rust_injector_canonical_form(self):
        h = signed()
        self.assertEqual(
            app.verify(h, NOW)["canonical"],
            "x-ztlp-admin-email:steve@trs.ztlp\nx-ztlp-assurance:software\nx-ztlp-audience:whoami\n"
            "x-ztlp-authenticated:1\nx-ztlp-device-name:stevens-mac-studio.trs.ztlp\nx-ztlp-group:\n"
            "x-ztlp-timestamp:2026-10-27T11:59:58Z\nx-ztlp-zone:trs.ztlp",
        )

    def test_the_rust_injector_test_vector_canonicalises_identically(self):
        # proto/src/http_injector.rs test_canonical_string_matches_ruby_contract
        h = as_http({"X-ZTLP-Authenticated": "1", "X-ZTLP-Admin-Email": "ops@techrockstars.com",
                     "X-ZTLP-Device-Name": "steves-macbook.demo.ztlp", "X-ZTLP-Zone": "demo.ztlp",
                     "X-ZTLP-Group": "techs@demo.ztlp", "X-ZTLP-Assurance": "hardware",
                     "X-ZTLP-Audience": "bootstrap.example.ztlp", "X-ZTLP-Timestamp": "2025-01-01T00:00:00Z"})
        self.assertEqual(
            app.verify(h, NOW)["canonical"],
            "x-ztlp-admin-email:ops@techrockstars.com\nx-ztlp-assurance:hardware\nx-ztlp-audience:bootstrap.example.ztlp\n"
            "x-ztlp-authenticated:1\nx-ztlp-device-name:steves-macbook.demo.ztlp\nx-ztlp-group:techs@demo.ztlp\n"
            "x-ztlp-timestamp:2025-01-01T00:00:00Z\nx-ztlp-zone:demo.ztlp",
        )

    def test_a_correctly_signed_request_is_verified_and_shows_the_identity(self):
        who = app.verify(signed(), NOW)
        self.assertTrue(who["verified"], who["reason"])
        self.assertEqual("steve@trs.ztlp", who["person"])
        self.assertEqual("stevens-mac-studio.trs.ztlp", who["device"])

    def test_no_headers_means_not_via_ztlp(self):
        who = app.verify({}, NOW)
        self.assertFalse(who["via_ztlp"])
        self.assertFalse(who["verified"])

    def test_wrong_secret_fails_the_signature_check(self):
        who = app.verify(signed(secret="another-secret"), NOW)
        self.assertFalse(who["verified"])
        self.assertFalse(who["checks"]["signature"])

    def test_a_tampered_field_fails(self):
        h = signed()
        h.replace_header("X-ZTLP-Admin-Email", "mallory@trs.ztlp")
        self.assertFalse(app.verify(h, NOW)["checks"]["signature"])

    def test_a_signature_for_another_service_is_refused(self):
        who = app.verify(signed(audience="admin"), NOW)
        self.assertTrue(who["checks"]["signature"])
        self.assertFalse(who["checks"]["audience"])
        self.assertFalse(who["verified"])

    def test_a_stale_signature_is_refused(self):
        old = (NOW - timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertFalse(app.verify(signed(timestamp=old), NOW)["checks"]["fresh"])

    def test_page_escapes_header_values(self):
        h = signed(**{"admin-email": "<script>x</script>"})
        self.assertNotIn("<script>x", app.page(app.verify(h, NOW)))


if __name__ == "__main__":
    unittest.main()
