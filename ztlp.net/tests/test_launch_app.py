import datetime as dt
import io
import json
import os
import sqlite3
import tempfile
import unittest
from http import HTTPStatus
from urllib.parse import parse_qs, urlencode, urlparse

from launch_app.app import LaunchApp, validate_zone


class LaunchAppTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "launch.sqlite3")
        # Isolate provisioning side-effects: pin LAUNCH_INSTANCE_ROOT into a
        # temp dir and stub subprocess.run so /claim/launch never invokes the
        # real `docker compose up -d`.
        self.instance_root = tempfile.TemporaryDirectory()
        self._orig_instance_root = os.environ.get("LAUNCH_INSTANCE_ROOT")
        os.environ["LAUNCH_INSTANCE_ROOT"] = self.instance_root.name
        import subprocess as _subprocess
        self._subprocess = _subprocess
        self._real_subprocess_run = _subprocess.run
        self._subprocess_calls = []

        def _fake_run(cmd, *args, **kwargs):
            self._subprocess_calls.append({"cmd": cmd, "cwd": kwargs.get("cwd")})
            return _subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        _subprocess.run = _fake_run
        self.app = LaunchApp(
            db_path=self.db_path,
            token_secret="test-secret",
            now=lambda: dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc),
            require_pow=False,
            # Tests pre-date the required-referral gate. Keep the gate off by
            # default so existing POW / rate-limit / claim tests still drive
            # the flow without supplying a code. The dedicated
            # ReferralCodeTest class exercises the gate explicitly.
            referrals_required=False,
        )

    def tearDown(self):
        self._subprocess.run = self._real_subprocess_run
        if self._orig_instance_root is None:
            os.environ.pop("LAUNCH_INSTANCE_ROOT", None)
        else:
            os.environ["LAUNCH_INSTANCE_ROOT"] = self._orig_instance_root
        self.instance_root.cleanup()
        self.tmpdir.cleanup()

    def request(self, method, path, body="", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path.split("?", 1)[0],
            "QUERY_STRING": path.split("?", 1)[1] if "?" in path else "",
            "SERVER_NAME": "testserver",
            "SERVER_PORT": "80",
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO(body),
            "wsgi.errors": io.StringIO(),
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "CONTENT_LENGTH": str(len(body)),
        }
        for key, value in (headers or {}).items():
            environ[key] = value
        captured = {}

        def start_response(status, response_headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = dict(response_headers)

        response_body = b"".join(self.app(environ, start_response)).decode("utf-8")
        status_code = int(captured["status"].split()[0])
        return status_code, captured["headers"], response_body

    def post_form(self, path, data):
        return self.request(
            "POST",
            path,
            urlencode(data),
            {"CONTENT_TYPE": "application/x-www-form-urlencoded"},
        )

    def test_public_routes_render_without_private_admin_exposure(self):
        for path, expected in [
            ("/", "ZTLP Launch"),
            ("/start", "Request onboarding"),
            ("/downloads", "Download ZTLP"),
        ]:
            with self.subTest(path=path):
                status, _headers, body = self.request("GET", path)
                self.assertEqual(HTTPStatus.OK, status)
                self.assertIn(expected, body)
                self.assertNotIn("http://127.0.0.1", body)
                self.assertNotIn("/login", body)

    def test_health_check(self):
        status, headers, body = self.request("GET", "/health")
        self.assertEqual(HTTPStatus.OK, status)
        self.assertEqual("text/plain; charset=utf-8", headers["Content-Type"])
        self.assertEqual("ok\n", body)

    def test_start_creates_request_shows_token_once_and_stores_only_digest(self):
        status, _headers, body = self.post_form(
            "/start",
            {
                "organization_name": "Acme Corp",
                "admin_name": "Ada Admin",
                "admin_email": "ada@example.com",
                "zone": "acme.ztlp",
            },
        )
        self.assertEqual(HTTPStatus.CREATED, status)
        self.assertIn("Claim link", body)
        parsed = urlparse(self.extract_claim_link(body))
        token = parse_qs(parsed.query)["token"][0]
        self.assertGreaterEqual(len(token), 30)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT organization_name, admin_name, admin_email, zone, status, claim_token_digest, claim_expires_at, claimed_at FROM onboarding_requests"
        ).fetchone()
        conn.close()

        self.assertEqual("Acme Corp", row[0])
        self.assertEqual("Ada Admin", row[1])
        self.assertEqual("ada@example.com", row[2])
        self.assertEqual("acme.ztlp", row[3])
        self.assertEqual("requested", row[4])
        self.assertNotEqual(token, row[5])
        with open(self.db_path, "rb") as db_file:
            self.assertNotIn(token, db_file.read().decode("latin1", errors="ignore"))
        self.assertEqual("2026-01-09T03:04:05+00:00", row[6])
        self.assertIsNone(row[7])

    def test_claim_marks_request_claimed_and_shows_safe_service_name(self):
        _status, _headers, body = self.post_form(
            "/start",
            {
                "organization_name": "Example Org",
                "admin_name": "Eve Example",
                "admin_email": "eve@example.com",
                "zone": "example.ztlp",
            },
        )
        token = parse_qs(urlparse(self.extract_claim_link(body)).query)["token"][0]

        # New flow: GET /claim on an unclaimed token returns the confirm form
        # (no provisioning, no "Status: claimed"). The user must POST
        # /claim/launch (optionally with a pubkey) to actually claim + provision.
        status, _headers, claim_body = self.post_form("/claim/launch", {"token": token, "pubkey_hex": ""})
        self.assertEqual(HTTPStatus.OK, status)
        self.assertIn("Status:", claim_body)
        self.assertIn("bootstrap.example.ztlp", claim_body)
        # v0.29.1: the Setup command (ztlp setup --token ztlp://enroll/...) was
        # moved off the claim status page (it was shown on the prior enrollment
        # page already). The enrollment_token_uri is still stored in the DB —
        # asserted on `row[2]` below — it's just not displayed twice.
        self.assertNotIn("ztlp setup --token", claim_body)
        self.assertNotIn("ztlp://enroll/", claim_body)
        self.assertIn("44.230.7.100:23096", claim_body)
        # v0.30.5: connect command uses the V2 routing key `gw:<zone>` so the
        # relay routes by zone (collision-safe) instead of by V1 truncated org
        # slug. See docs/plans/2026-05-24-zone-keyed-gateway-register-IMPL.md.
        self.assertIn("ztlp connect bootstrap.example.ztlp --ns-server 44.230.7.100:23096 --multi-candidate --service gw:example.ztlp", claim_body)
        self.assertIn("Download ZTLP", claim_body)
        self.assertNotIn("http://127.0.0.1", claim_body)
        self.assertNotIn("/login", claim_body)
        # Note: render_claim_page now embeds the claim token in a hidden form
        # field so the admin can re-bind a device pubkey from the same page,
        # so we intentionally do NOT assert the token is absent here — the
        # security invariant being protected is "no admin URL / login path
        # is exposed", which is checked above.

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, claimed_at, enrollment_token_uri, bootstrap_service_name, ns_server FROM onboarding_requests").fetchone()
        conn.close()
        # POST /claim/launch transitions the row to launch_requested in one
        # shot (claim + provision happen together in the new flow).
        self.assertEqual("launch_requested", row[0])
        self.assertEqual("2026-01-02T03:04:05+00:00", row[1])
        self.assertTrue(row[2].startswith("ztlp://enroll/"))
        self.assertNotEqual(token, row[2])
        self.assertEqual("bootstrap.example.ztlp", row[3])
        self.assertEqual("44.230.7.100:23096", row[4])

    def test_claim_launch_requires_claim_token_and_updates_status_without_exposing_admin_url(self):
        _status, _headers, body = self.post_form(
            "/start",
            {
                "organization_name": "Launch Co",
                "admin_name": "Lee Launch",
                "admin_email": "lee@example.com",
                "zone": "launch.ztlp",
            },
        )
        token = parse_qs(urlparse(self.extract_claim_link(body)).query)["token"][0]

        # New flow: POST /claim/launch is the single endpoint that claims +
        # provisions in one shot. No prior /claim GET is required. The
        # response must never expose the bootstrap admin URL or login path
        # (the original security concern of this test).
        status, _headers, launch_body = self.post_form("/claim/launch", {"token": token, "pubkey_hex": ""})
        self.assertEqual(HTTPStatus.OK, status)
        self.assertIn("Status: launch_requested", launch_body)
        self.assertIn("bootstrap.launch.ztlp", launch_body)
        # v0.29.1: setup command moved off the claim status page; the
        # enrollment_token_uri must still be persisted in the DB (asserted
        # below via the SQL row) but should not be displayed here.
        self.assertNotIn("ztlp://enroll/", launch_body)
        # v0.30.5: connect command uses the V2 routing key `gw:<zone>`
        # so the relay routes by zone (collision-safe). Tenant "Launch Co"
        # has zone "launch.ztlp" so the gateway service is "gw:launch.ztlp".
        self.assertIn("ztlp connect bootstrap.launch.ztlp --ns-server 44.230.7.100:23096 --multi-candidate --service gw:launch.ztlp", launch_body)
        self.assertNotIn("http://127.0.0.1", launch_body)
        self.assertNotIn("/login", launch_body)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, bootstrap_service_name, ns_server, bootstrap_listener_addr FROM onboarding_requests").fetchone()
        conn.close()
        self.assertEqual("launch_requested", row[0])
        self.assertEqual("bootstrap.launch.ztlp", row[1])
        self.assertEqual("44.230.7.100:23096", row[2])
        self.assertEqual("34.218.240.106:23095", row[3])

    def test_invalid_or_missing_token_is_not_found(self):
        for method, path, data in [
            ("GET", "/claim", None),
            ("GET", "/claim?token=bogus", None),
            ("POST", "/claim/launch", {"token": "bogus"}),
        ]:
            with self.subTest(method=method, path=path):
                if method == "POST":
                    status, _headers, body = self.post_form(path, data)
                else:
                    status, _headers, body = self.request(method, path)
                self.assertEqual(HTTPStatus.NOT_FOUND, status)
                self.assertIn("claim token was not found", body)


    def test_start_rejects_oversized_request_body(self):
        huge_body = "organization_name=" + "A" * (70 * 1024)
        status, _headers, body = self.request(
            "POST",
            "/start",
            huge_body,
            {"CONTENT_TYPE": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, status)
        self.assertIn("request body is too large", body)

    def test_start_escapes_user_values(self):
        status, _headers, body = self.post_form(
            "/start",
            {
                "organization_name": "<script>alert(1)</script>",
                "admin_name": "Alice <Admin>",
                "admin_email": "alice@example.com",
                "zone": "safe.ztlp",
            },
        )
        self.assertEqual(HTTPStatus.CREATED, status)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body)

    def test_expired_claim_token_is_rejected(self):
        _status, _headers, body = self.post_form(
            "/start",
            {
                "organization_name": "Expired Org",
                "admin_name": "Eve Expired",
                "admin_email": "eve@example.com",
                "zone": "expired.ztlp",
            },
        )
        token = parse_qs(urlparse(self.extract_claim_link(body)).query)["token"][0]
        self.app.now = lambda: dt.datetime(2026, 1, 20, 3, 4, 5, tzinfo=dt.timezone.utc)
        status, _headers, expired_body = self.request("GET", f"/claim?token={token}")
        self.assertEqual(HTTPStatus.NOT_FOUND, status)
        self.assertIn("expired or was revoked", expired_body)

    def test_default_secret_is_rejected_outside_development(self):
        with self.assertRaises(ValueError):
            LaunchApp(db_path=os.path.join(self.tmpdir.name, "prod.sqlite3"), token_secret="ztlp-launch-dev-secret-change-me", environment="production")



    def test_download_page_links_to_release_assets_without_private_admin_exposure(self):
        status, _headers, body = self.request("GET", "/downloads")
        self.assertEqual(HTTPStatus.OK, status)
        self.assertIn("Windows ZIP", body)
        self.assertIn("Microsoft Visual C++ Redistributable x64", body)
        self.assertIn("ztlp-v-before-nebula-collapse-x86_64-pc-windows-msvc.zip", body)
        self.assertIn("ztlp-v-before-nebula-collapse-x86_64-unknown-linux-gnu.tar.gz", body)
        self.assertIn("ztlp-v-before-nebula-collapse-aarch64-apple-darwin.tar.gz", body)
        self.assertIn("/downloads/manifest.json", body)
        self.assertNotIn("http://127.0.0.1", body)
        self.assertNotIn("/login", body)

    def test_download_redirects_to_github_release_assets(self):
        for key, expected in [
            ("windows", "ztlp-v-before-nebula-collapse-x86_64-pc-windows-msvc.zip"),
            ("linux", "ztlp-v-before-nebula-collapse-x86_64-unknown-linux-gnu.tar.gz"),
            ("macos-apple-silicon", "ztlp-v-before-nebula-collapse-aarch64-apple-darwin.tar.gz"),
            ("macos-intel", "ztlp-v-before-nebula-collapse-x86_64-apple-darwin.tar.gz"),
            ("checksums", "SHA256SUMS.txt"),
        ]:
            with self.subTest(key=key):
                status, headers, body = self.request("GET", f"/downloads/{key}")
                self.assertEqual(HTTPStatus.FOUND, status)
                self.assertIn(expected, headers["Location"])
                self.assertIn("github.com/priceflex/ztlp/releases/download/v-before-nebula-collapse", headers["Location"])
                self.assertIn(expected, body)

    def test_download_manifest_json_lists_launch_and_github_urls(self):
        status, headers, body = self.request("GET", "/downloads/manifest.json")
        self.assertEqual(HTTPStatus.OK, status)
        self.assertEqual("application/json; charset=utf-8", headers["Content-Type"])
        self.assertIn('"release": "v-before-nebula-collapse"', body)
        self.assertIn('"key": "windows"', body)
        self.assertIn('"launch_url": "http://testserver/downloads/windows"', body)
        self.assertIn('"url": "https://github.com/priceflex/ztlp/releases/download/v-before-nebula-collapse/ztlp-v-before-nebula-collapse-x86_64-pc-windows-msvc.zip"', body)

    def test_zone_accepts_long_dns_name(self):
        # Construct a 200-char DNS-valid name made of multiple labels.
        # label1 = 63 'a', label2 = 63 'b', label3 = 63 'c', plus ".ztlp" suffix = 63+1+63+1+63+5 = 196 — pad to 200.
        long_zone = ("a" * 63) + "." + ("b" * 63) + "." + ("c" * 63) + ".ztlp"
        self.assertEqual(len(long_zone), 196)
        # extend with extra label to reach exactly 200
        long_zone = ("a" * 63) + "." + ("b" * 63) + "." + ("c" * 63) + ".example.ztlp"
        self.assertEqual(len(long_zone), 204)
        # Use one that is <=253 — 204 is fine.
        self.assertEqual([], validate_zone(long_zone))

    def test_zone_rejects_overlong_total(self):
        zone = ("a" * 63) + "." + ("b" * 63) + "." + ("c" * 63) + "." + ("d" * 63)
        # 63*4 + 3 = 255 — should be rejected
        self.assertGreater(len(zone), 253)
        errors = validate_zone(zone)
        self.assertTrue(errors, "expected validation errors for overlong zone")
        self.assertTrue(any("253" in e or "long" in e.lower() for e in errors), errors)

    def test_zone_rejects_overlong_label(self):
        zone = ("a" * 64) + ".ztlp"
        errors = validate_zone(zone)
        self.assertTrue(errors)
        self.assertTrue(any("63" in e or "label" in e.lower() for e in errors), errors)

    def test_zone_rejects_leading_hyphen_label(self):
        self.assertTrue(validate_zone("-bad.ztlp"))
        self.assertTrue(validate_zone("bad-.ztlp"))

    def test_zone_rejects_uppercase_then_normalized(self):
        # validate_zone receives an already-normalized (lowercased) value in the app pipeline,
        # so feeding "ACME.ZTLP" directly should fail; but a /start POST with "ACME.ZTLP"
        # must succeed via normalize_zone + validate.
        self.assertTrue(validate_zone("ACME.ZTLP"))
        status, _headers, body = self.post_form(
            "/start",
            {
                "organization_name": "Upper Org",
                "admin_name": "Upper Admin",
                "admin_email": "u@example.com",
                "zone": "ACME.ZTLP",
            },
        )
        self.assertEqual(HTTPStatus.CREATED, status)
        conn = sqlite3.connect(self.db_path)
        zone = conn.execute("SELECT zone FROM onboarding_requests").fetchone()[0]
        conn.close()
        self.assertEqual("acme.ztlp", zone)

    def test_zone_rejects_underscore(self):
        self.assertTrue(validate_zone("bad_zone.ztlp"))

    def test_zone_rejects_empty_label(self):
        self.assertTrue(validate_zone("acme..ztlp"))
        self.assertTrue(validate_zone(".acme.ztlp"))

    def test_zone_available_for_unused_name(self):
        status, headers, body = self.request("GET", "/api/zone-available?zone=fresh.ztlp")
        self.assertEqual(HTTPStatus.OK, status)
        self.assertEqual("application/json; charset=utf-8", headers["Content-Type"])
        import json as _json
        payload = _json.loads(body)
        self.assertEqual("fresh.ztlp", payload["zone"])
        self.assertTrue(payload["available"])
        self.assertEqual("ok", payload["reason"])

    def test_zone_available_returns_taken_after_start_post(self):
        self.post_form(
            "/start",
            {
                "organization_name": "Taken Org",
                "admin_name": "Tina Taken",
                "admin_email": "tina@example.com",
                "zone": "taken.ztlp",
            },
        )
        status, headers, body = self.request("GET", "/api/zone-available?zone=taken.ztlp")
        self.assertEqual(HTTPStatus.OK, status)
        self.assertEqual("application/json; charset=utf-8", headers["Content-Type"])
        import json as _json
        payload = _json.loads(body)
        self.assertFalse(payload["available"])
        self.assertEqual("taken_locally", payload["reason"])

    def test_zone_available_for_invalid_name_returns_invalid_reason(self):
        status, headers, body = self.request("GET", "/api/zone-available?zone=BAD__zone")
        self.assertEqual(HTTPStatus.OK, status)
        self.assertEqual("application/json; charset=utf-8", headers["Content-Type"])
        import json as _json
        payload = _json.loads(body)
        self.assertFalse(payload["available"])
        self.assertEqual("invalid", payload["reason"])

    def _start_form(self, email="rl@example.com", zone_suffix="a", ip=None):
        data = {
            "organization_name": "Rate Org",
            "admin_name": "Rate Limiter",
            "admin_email": email,
            "zone": f"rl-{zone_suffix}.ztlp",
        }
        headers = {"CONTENT_TYPE": "application/x-www-form-urlencoded"}
        if ip is not None:
            headers["REMOTE_ADDR"] = ip
        return self.request("POST", "/start", urlencode(data), headers)

    def test_rate_limit_blocks_after_email_threshold(self):
        app = LaunchApp(
            db_path=self.db_path,
            token_secret="test-secret",
            now=lambda: dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc),
            email_rate_limit_per_hour=5,
            ip_rate_limit_per_hour=10_000,
            require_pow=False,
            referrals_required=False,
        )
        self.app = app
        for i in range(5):
            status, _h, _b = self._start_form(email="floody@example.com", zone_suffix=f"e{i}", ip=f"10.0.0.{i+1}")
            self.assertEqual(HTTPStatus.CREATED, status, f"attempt {i+1} should be CREATED")
        status, _h, body = self._start_form(email="floody@example.com", zone_suffix="e9", ip="10.0.0.99")
        self.assertEqual(HTTPStatus.TOO_MANY_REQUESTS, status)
        self.assertIn("rate", body.lower())

    def test_rate_limit_blocks_after_ip_threshold(self):
        app = LaunchApp(
            db_path=self.db_path,
            token_secret="test-secret",
            now=lambda: dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc),
            email_rate_limit_per_hour=10_000,
            ip_rate_limit_per_hour=20,
            require_pow=False,
            referrals_required=False,
        )
        self.app = app
        for i in range(20):
            status, _h, _b = self._start_form(email=f"u{i}@example.com", zone_suffix=f"i{i}", ip="192.0.2.7")
            self.assertEqual(HTTPStatus.CREATED, status, f"attempt {i+1} should be CREATED, got {status}")
        status, _h, body = self._start_form(email="u20@example.com", zone_suffix="i20", ip="192.0.2.7")
        self.assertEqual(HTTPStatus.TOO_MANY_REQUESTS, status)
        self.assertIn("rate", body.lower())

    def test_rate_limit_window_resets_after_an_hour(self):
        clock = [dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)]
        app = LaunchApp(
            db_path=self.db_path,
            token_secret="test-secret",
            now=lambda: clock[0],
            email_rate_limit_per_hour=2,
            ip_rate_limit_per_hour=10_000,
            require_pow=False,
            referrals_required=False,
        )
        self.app = app
        for i in range(2):
            status, _h, _b = self._start_form(email="reset@example.com", zone_suffix=f"r{i}", ip=f"10.0.1.{i+1}")
            self.assertEqual(HTTPStatus.CREATED, status)
        # third one in the same window is blocked
        status, _h, _b = self._start_form(email="reset@example.com", zone_suffix="r2", ip="10.0.1.50")
        self.assertEqual(HTTPStatus.TOO_MANY_REQUESTS, status)
        # advance 65 minutes — window resets
        clock[0] = clock[0] + dt.timedelta(minutes=65)
        status, _h, _b = self._start_form(email="reset@example.com", zone_suffix="r3", ip="10.0.1.51")
        self.assertEqual(HTTPStatus.CREATED, status)

    def test_rate_limit_uses_x_forwarded_for_when_remote_addr_is_proxy(self):
        app = LaunchApp(
            db_path=self.db_path,
            token_secret="test-secret",
            now=lambda: dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc),
            email_rate_limit_per_hour=10_000,
            ip_rate_limit_per_hour=2,
            require_pow=False,
            referrals_required=False,
        )
        self.app = app
        headers_base = {
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            # No REMOTE_ADDR — simulate reverse proxy stripping it
            "HTTP_X_FORWARDED_FOR": "203.0.113.45, 10.0.0.1",
        }
        for i in range(2):
            data = {
                "organization_name": "Xff Org",
                "admin_name": "Xff User",
                "admin_email": f"x{i}@example.com",
                "zone": f"xff-{i}.ztlp",
            }
            status, _h, _b = self.request("POST", "/start", urlencode(data), headers_base)
            self.assertEqual(HTTPStatus.CREATED, status)
        data = {
            "organization_name": "Xff Org",
            "admin_name": "Xff User",
            "admin_email": "x3@example.com",
            "zone": "xff-3.ztlp",
        }
        status, _h, _b = self.request("POST", "/start", urlencode(data), headers_base)
        self.assertEqual(HTTPStatus.TOO_MANY_REQUESTS, status)

    # ---- Proof-of-work CAPTCHA -------------------------------------------------

    def _compute_pow_nonce(self, challenge_hex: str, difficulty_bits: int) -> str:
        import hashlib as _hl
        prefix_bytes = difficulty_bits // 8
        remainder_bits = difficulty_bits % 8
        n = 0
        challenge_bytes = bytes.fromhex(challenge_hex)
        while True:
            nonce = f"{n:x}"
            digest = _hl.sha256(challenge_bytes + nonce.encode("ascii")).digest()
            if digest[:prefix_bytes] == b"\x00" * prefix_bytes:
                if remainder_bits == 0 or (digest[prefix_bytes] >> (8 - remainder_bits)) == 0:
                    return nonce
            n += 1

    def _fresh_pow_app(self, difficulty_bits=8, pow_ttl_seconds=600, now=None):
        if now is None:
            now = lambda: dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
        return LaunchApp(
            db_path=self.db_path,
            token_secret="test-secret",
            now=now,
            pow_difficulty_bits=difficulty_bits,
            pow_ttl_seconds=pow_ttl_seconds,
            require_pow=True,
            referrals_required=False,
        )

    def _extract_pow_fields(self, body):
        import re as _re
        fields = {}
        for name in ("pow_challenge", "pow_difficulty", "pow_issued_at", "pow_signature"):
            m = _re.search(rf'name="{name}"\s+value="([^"]*)"', body)
            self.assertIsNotNone(m, f"missing PoW field {name} in form body")
            fields[name] = m.group(1)
        return fields

    def test_post_start_rejects_missing_pow(self):
        self.app = self._fresh_pow_app(difficulty_bits=8)
        status, _h, body = self.post_form(
            "/start",
            {
                "organization_name": "PoW Org",
                "admin_name": "Pow Admin",
                "admin_email": "pow@example.com",
                "zone": "pow.ztlp",
            },
        )
        self.assertEqual(HTTPStatus.BAD_REQUEST, status)
        self.assertIn("verification", body.lower())
        # And the re-rendered form should contain a fresh challenge
        fields = self._extract_pow_fields(body)
        self.assertEqual(32, len(fields["pow_challenge"]))  # 16 bytes hex = 32 chars

    def test_post_start_accepts_valid_pow(self):
        self.app = self._fresh_pow_app(difficulty_bits=8)
        # GET the form to get a fresh challenge
        status, _h, form_body = self.request("GET", "/start")
        self.assertEqual(HTTPStatus.OK, status)
        fields = self._extract_pow_fields(form_body)
        nonce = self._compute_pow_nonce(fields["pow_challenge"], int(fields["pow_difficulty"]))
        post_data = {
            "organization_name": "PoW Org",
            "admin_name": "Pow Admin",
            "admin_email": "pow@example.com",
            "zone": "pow.ztlp",
            "pow_challenge": fields["pow_challenge"],
            "pow_difficulty": fields["pow_difficulty"],
            "pow_issued_at": fields["pow_issued_at"],
            "pow_signature": fields["pow_signature"],
            "pow_nonce": nonce,
        }
        status, _h, body = self.post_form("/start", post_data)
        self.assertEqual(HTTPStatus.CREATED, status, body[:400])
        self.assertIn("Claim link", body)

    def test_post_start_rejects_stale_pow_signature(self):
        clock = [dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)]
        self.app = self._fresh_pow_app(difficulty_bits=8, pow_ttl_seconds=600, now=lambda: clock[0])
        status, _h, form_body = self.request("GET", "/start")
        self.assertEqual(HTTPStatus.OK, status)
        fields = self._extract_pow_fields(form_body)
        nonce = self._compute_pow_nonce(fields["pow_challenge"], int(fields["pow_difficulty"]))
        # advance the clock past the TTL
        clock[0] = clock[0] + dt.timedelta(seconds=601)
        post_data = {
            "organization_name": "PoW Org",
            "admin_name": "Pow Admin",
            "admin_email": "pow@example.com",
            "zone": "pow.ztlp",
            "pow_challenge": fields["pow_challenge"],
            "pow_difficulty": fields["pow_difficulty"],
            "pow_issued_at": fields["pow_issued_at"],
            "pow_signature": fields["pow_signature"],
            "pow_nonce": nonce,
        }
        status, _h, body = self.post_form("/start", post_data)
        self.assertEqual(HTTPStatus.BAD_REQUEST, status)
        self.assertIn("verification", body.lower())

    def test_post_start_rejects_tampered_pow_signature(self):
        self.app = self._fresh_pow_app(difficulty_bits=8)
        status, _h, form_body = self.request("GET", "/start")
        fields = self._extract_pow_fields(form_body)
        nonce = self._compute_pow_nonce(fields["pow_challenge"], int(fields["pow_difficulty"]))
        post_data = {
            "organization_name": "PoW Org",
            "admin_name": "Pow Admin",
            "admin_email": "pow@example.com",
            "zone": "pow.ztlp",
            "pow_challenge": fields["pow_challenge"],
            "pow_difficulty": "4",  # tamper — must invalidate signature
            "pow_issued_at": fields["pow_issued_at"],
            "pow_signature": fields["pow_signature"],
            "pow_nonce": nonce,
        }
        status, _h, body = self.post_form("/start", post_data)
        self.assertEqual(HTTPStatus.BAD_REQUEST, status)
        self.assertIn("verification", body.lower())

    def test_two_separate_onboardings_get_distinct_metadata_and_third_collision_is_detected(self):
        """Full end-to-end multi-zone flow:

        1) Two distinct onboarding requests (acme.ztlp + bravo.ztlp) each go
           through /start -> /claim -> /claim/launch.
        2) Each gets its own bootstrap_service_name, enrollment token URI, and
           the bootstrap.<zone> service name is zone-specific.
        3) A third /api/zone-available?zone=acme.ztlp call reports the zone
           as taken_locally.
        """
        zones = ["acme.ztlp", "bravo.ztlp"]
        captured = []
        for zone in zones:
            status, _h, body = self.post_form(
                "/start",
                {
                    "organization_name": f"Org {zone}",
                    "admin_name": f"Admin {zone}",
                    "admin_email": f"admin-{zone.replace('.', '-')}@example.com",
                    "zone": zone,
                },
            )
            self.assertEqual(HTTPStatus.CREATED, status, body[:200])
            token = parse_qs(urlparse(self.extract_claim_link(body)).query)["token"][0]

            status, _h, claim_body = self.request("GET", f"/claim?token={token}")
            self.assertEqual(HTTPStatus.OK, status)
            # First GET shows the confirm form (no service name yet);
            # actual provisioning happens on POST /claim/launch below.
            self.assertIn("Confirm your claim", claim_body)

            status, _h, launch_body = self.post_form("/claim/launch", {"token": token, "pubkey_hex": ""})
            self.assertEqual(HTTPStatus.OK, status)
            self.assertIn("Status: launch_requested", launch_body)
            self.assertIn(f"bootstrap.{zone}", launch_body)
            captured.append((zone, token))

        # Pull metadata for both rows and verify they are distinct.
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT zone, bootstrap_service_name, enrollment_token_uri FROM onboarding_requests ORDER BY id"
        ).fetchall()
        conn.close()
        self.assertEqual(2, len(rows))
        zones_seen = {r[0] for r in rows}
        services_seen = {r[1] for r in rows}
        tokens_seen = {r[2] for r in rows}
        self.assertEqual({"acme.ztlp", "bravo.ztlp"}, zones_seen)
        self.assertEqual({"bootstrap.acme.ztlp", "bootstrap.bravo.ztlp"}, services_seen)
        self.assertEqual(2, len(tokens_seen), "each onboarding must mint its own enrollment token URI")

        # Third request with acme.ztlp must report taken_locally.
        status, headers, body = self.request("GET", "/api/zone-available?zone=acme.ztlp")
        self.assertEqual(HTTPStatus.OK, status)
        self.assertEqual("application/json; charset=utf-8", headers["Content-Type"])
        import json as _json
        payload = _json.loads(body)
        self.assertFalse(payload["available"])
        self.assertEqual("taken_locally", payload["reason"])

    # ── /api/admin-pubkey ────────────────────────────────────────────

    def _claim_token_for(self, org_name, zone):
        """Provision a tenant via /start + /claim/launch and return the claim token.

        In the new claim-confirm-then-provision flow, GET /claim only renders
        the confirmation form; the actual provisioning (instance dir +
        instance.env + docker compose up) happens on POST /claim/launch.
        All `docker compose` invocations run through the fake subprocess.run
        installed in setUp, so this is pure Python + a populated instance dir
        on disk.
        """
        _status, _headers, body = self.post_form(
            "/start",
            {
                "organization_name": org_name,
                "admin_name": "Pubkey Admin",
                "admin_email": "pubkey@example.com",
                "zone": zone,
            },
        )
        token = parse_qs(urlparse(self.extract_claim_link(body)).query)["token"][0]
        # POST /claim/launch with an empty pubkey to claim + provision the
        # instance dir + instance.env in one shot.
        self.post_form("/claim/launch", {"token": token, "pubkey_hex": ""})
        return token

    def test_admin_pubkey_rejects_missing_token(self):
        status, _headers, body = self.post_form(
            "/api/admin-pubkey",
            {"pubkey_hex": "a" * 64},
        )
        self.assertEqual(HTTPStatus.UNAUTHORIZED, status)
        self.assertIn("invalid", body.lower())

    def test_admin_pubkey_rejects_invalid_token(self):
        status, _headers, body = self.post_form(
            "/api/admin-pubkey",
            {"token": "not-a-real-token", "pubkey_hex": "a" * 64},
        )
        self.assertEqual(HTTPStatus.UNAUTHORIZED, status)
        self.assertIn("invalid", body.lower())

    def test_admin_pubkey_rejects_bad_hex(self):
        token = self._claim_token_for("Pubkey BadHex Co", "pubkey-badhex.ztlp")
        for bad in [
            "",
            "short",
            "G" * 64,  # non-hex char (uppercase G)
            "a" * 63,  # off by one
            "a" * 65,  # off by one
        ]:
            with self.subTest(bad=bad):
                status, _headers, body = self.post_form(
                    "/api/admin-pubkey",
                    {"token": token, "pubkey_hex": bad},
                )
                self.assertEqual(HTTPStatus.BAD_REQUEST, status)
                self.assertIn("64 lowercase hex", body)

    def test_admin_pubkey_accepts_uppercase_hex_by_normalizing(self):
        token = self._claim_token_for("Pubkey Upper Co", "pubkey-upper.ztlp")
        valid_upper = "AB" * 32  # 64 chars, uppercase hex, lowercases to a valid 32-byte key
        status, _headers, body = self.post_form(
            "/api/admin-pubkey",
            {"token": token, "pubkey_hex": valid_upper},
        )
        self.assertEqual(HTTPStatus.OK, status, msg=body)
        # Verify the file was written with the lowercased value.
        instance_env = os.path.join(
            self.instance_root.name, "pubkey-upper-co", "instance.env"
        )
        with open(instance_env, "r", encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(f"ZTLP_ADMIN_PUBKEY_HEX={'ab' * 32}", text)

    def test_admin_pubkey_writes_env_and_recreates_gateway(self):
        token = self._claim_token_for("Pubkey Demo Co", "pubkey-demo.ztlp")
        # Clear the call log so we only see the docker recreate invocation.
        self._subprocess_calls.clear()

        pubkey = "0123456789abcdef" * 4  # 64 hex chars
        status, headers, body = self.post_form(
            "/api/admin-pubkey",
            {"token": token, "pubkey_hex": pubkey},
        )
        self.assertEqual(HTTPStatus.OK, status, msg=body)
        self.assertEqual("application/json; charset=utf-8", headers["Content-Type"])
        import json as _json
        payload = _json.loads(body)
        self.assertTrue(payload["applied"])
        self.assertEqual("pubkey-demo-co", payload["slug"])

        # instance.env now contains the new pubkey.
        instance_dir = os.path.join(self.instance_root.name, "pubkey-demo-co")
        with open(os.path.join(instance_dir, "instance.env"), "r", encoding="utf-8") as fh:
            env_text = fh.read()
        self.assertIn(f"ZTLP_ADMIN_PUBKEY_HEX={pubkey}", env_text)
        # The empty default line was REPLACED, not appended — assert only one
        # occurrence of the key.
        self.assertEqual(1, env_text.count("ZTLP_ADMIN_PUBKEY_HEX="))

        # And we invoked `docker compose up -d --force-recreate gateway` in the
        # instance dir. Without --force-recreate the running container would
        # keep the old (empty) env value.
        recreate_calls = [
            c for c in self._subprocess_calls
            if c["cmd"][:1] == ["docker"] and "--force-recreate" in c["cmd"]
        ]
        self.assertEqual(1, len(recreate_calls), msg=str(self._subprocess_calls))
        self.assertEqual(instance_dir, recreate_calls[0]["cwd"])
        self.assertIn("gateway", recreate_calls[0]["cmd"])

    def test_admin_pubkey_rebind_overwrites_previous_value(self):
        token = self._claim_token_for("Pubkey Rebind Co", "pubkey-rebind.ztlp")
        first = "11" * 32
        second = "22" * 32

        status1, _h1, _b1 = self.post_form(
            "/api/admin-pubkey", {"token": token, "pubkey_hex": first},
        )
        self.assertEqual(HTTPStatus.OK, status1)
        status2, _h2, _b2 = self.post_form(
            "/api/admin-pubkey", {"token": token, "pubkey_hex": second},
        )
        self.assertEqual(HTTPStatus.OK, status2)

        instance_env = os.path.join(self.instance_root.name, "pubkey-rebind-co", "instance.env")
        with open(instance_env, "r", encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(f"ZTLP_ADMIN_PUBKEY_HEX={second}", text)
        self.assertNotIn(f"ZTLP_ADMIN_PUBKEY_HEX={first}", text)
        # Still exactly one occurrence of the key.
        self.assertEqual(1, text.count("ZTLP_ADMIN_PUBKEY_HEX="))

    def test_admin_pubkey_returns_404_when_instance_not_provisioned(self):
        # /start creates the request row but does NOT provision the instance —
        # provisioning happens on POST /claim/launch (the confirm-then-provision
        # step). If the admin POSTs to /api/admin-pubkey BEFORE completing
        # the claim flow, there is no instance.env to write into.
        _status, _headers, body = self.post_form(
            "/start",
            {
                "organization_name": "Pubkey 404 Co",
                "admin_name": "Pubkey Admin",
                "admin_email": "pubkey@example.com",
                "zone": "pubkey-404.ztlp",
            },
        )
        token = parse_qs(urlparse(self.extract_claim_link(body)).query)["token"][0]
        # Skip the /claim hit — instance.env does not exist yet.

        status, _h, body = self.post_form(
            "/api/admin-pubkey",
            {"token": token, "pubkey_hex": "a" * 64},
        )
        self.assertEqual(HTTPStatus.NOT_FOUND, status)
        self.assertIn("not provisioned", body)

    def test_admin_pubkey_rejects_claimed_then_expired_token(self):
        """Regression: CLAIMED+EXPIRED tokens must be rejected, not only unclaimed.

        A stolen claim token should not allow indefinite pubkey rebinding once
        the token's expiration window has passed (CWE-287).
        """
        token = self._claim_token_for("Expired Pubkey Co", "expired-pubkey.ztlp")
        # Fast-forward past the default 1h claim_expires_at window
        self.app.now = lambda: dt.datetime(2026, 12, 31, tzinfo=dt.timezone.utc)

        status, _headers, body = self.post_form(
            "/api/admin-pubkey",
            {"token": token, "pubkey_hex": "ab" * 32},
        )
        self.assertEqual(HTTPStatus.UNAUTHORIZED, status)
        self.assertIn("invalid", body.lower())

    # ── New claim-confirm-then-provision flow ─────────────────────────

    def _start_and_get_token(self, *, org="Confirm Co", zone="confirm.ztlp", email="confirm@example.com"):
        """POST /start with the given fields and return the minted claim token."""
        _status, _headers, body = self.post_form(
            "/start",
            {
                "organization_name": org,
                "admin_name": "Confirm Admin",
                "admin_email": email,
                "zone": zone,
            },
        )
        return parse_qs(urlparse(self.extract_claim_link(body)).query)["token"][0]

    def test_claim_first_visit_shows_confirm_form_not_status_page(self):
        token = self._start_and_get_token(org="Confirm Co", zone="confirm.ztlp", email="c1@example.com")

        status, _headers, body = self.request("GET", f"/claim?token={token}")
        self.assertEqual(HTTPStatus.OK, status)
        # The confirm form must be the body (NOT the status page).
        self.assertIn("Confirm your claim", body)
        self.assertIn('name="pubkey_hex"', body)
        # And we must NOT have transitioned the row to claimed/provisioned.
        self.assertNotIn("Status: claimed", body)
        self.assertNotIn("Status: launch_requested", body)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT status, claimed_at FROM onboarding_requests"
        ).fetchone()
        conn.close()
        self.assertEqual("requested", row[0])
        self.assertIsNone(row[1])

    def test_claim_launch_with_valid_pubkey_writes_admin_pubkey_to_instance_env(self):
        token = self._start_and_get_token(org="Pubkey Bake Co", zone="pubkey-bake.ztlp", email="bake@example.com")
        good_pubkey = "ab" * 32  # 64 lowercase hex chars

        status, _headers, body = self.post_form(
            "/claim/launch", {"token": token, "pubkey_hex": good_pubkey}
        )
        self.assertEqual(HTTPStatus.OK, status, msg=body[:400])
        self.assertIn("Status: launch_requested", body)

        # The pubkey must have been baked into the freshly-provisioned
        # instance.env (no post-provision force-recreate dance required).
        instance_env = os.path.join(
            self.instance_root.name, "pubkey-bake-co", "instance.env"
        )
        self.assertTrue(
            os.path.isfile(instance_env),
            f"instance.env not created at {instance_env}",
        )
        with open(instance_env, "r", encoding="utf-8") as fh:
            env_text = fh.read()
        self.assertIn(f"ZTLP_ADMIN_PUBKEY_HEX={good_pubkey}", env_text)
        # Only one ZTLP_ADMIN_PUBKEY_HEX line should be present.
        self.assertEqual(1, env_text.count("ZTLP_ADMIN_PUBKEY_HEX="))

    def test_claim_launch_with_bad_pubkey_returns_400_and_does_not_provision(self):
        token = self._start_and_get_token(org="Bad Pubkey Co", zone="bad-pubkey.ztlp", email="bad@example.com")

        status, _headers, body = self.post_form(
            "/claim/launch", {"token": token, "pubkey_hex": "notvalidhex"}
        )
        self.assertEqual(HTTPStatus.BAD_REQUEST, status)
        self.assertIn("64 lowercase hex", body)
        # The confirm form should be re-rendered so the admin can correct
        # their paste.
        self.assertIn("Confirm your claim", body)

        # No instance dir should have been created — provisioning is gated
        # behind a valid (or empty) pubkey.
        instance_dir = os.path.join(self.instance_root.name, "bad-pubkey-co")
        self.assertFalse(
            os.path.isdir(instance_dir),
            f"instance dir {instance_dir} should not exist after a 400",
        )

        # And the DB row must still be in 'requested' state.
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT status, claimed_at FROM onboarding_requests"
        ).fetchone()
        conn.close()
        self.assertEqual("requested", row[0])
        self.assertIsNone(row[1])

    def extract_claim_link(self, body):
        marker = "http://testserver/claim?token="
        start = body.index(marker)
        end = body.index('"', start)
        return body[start:end].replace("&amp;", "&")


class ProvisionZoneDockersTest(unittest.TestCase):
    """Exercise LaunchApp._provision_zone_dockers in pure-Python (no docker)."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.instance_root = tempfile.TemporaryDirectory()
        self._orig_instance_root = os.environ.get("LAUNCH_INSTANCE_ROOT")
        os.environ["LAUNCH_INSTANCE_ROOT"] = self.instance_root.name
        self.db_path = os.path.join(self.tmpdir.name, "launch.sqlite3")
        self.app = LaunchApp(
            db_path=self.db_path,
            token_secret="test-secret",
            now=lambda: dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc),
            require_pow=False,
            # Tests pre-date the required-referral gate. Keep the gate off by
            # default so existing POW / rate-limit / claim tests still drive
            # the flow without supplying a code. The dedicated
            # ReferralCodeTest class exercises the gate explicitly.
            referrals_required=False,
        )
        # Save and stub subprocess.run inside launch_app.app.
        import launch_app.app as launch_module
        import subprocess as _subprocess
        self._launch_module = launch_module
        self._real_subprocess_run = _subprocess.run
        self._calls = []

        def fake_run(cmd, *args, **kwargs):
            self._calls.append({"cmd": cmd, "cwd": kwargs.get("cwd")})
            return _subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        _subprocess.run = fake_run
        self._subprocess = _subprocess

    def tearDown(self):
        self._subprocess.run = self._real_subprocess_run
        if self._orig_instance_root is None:
            os.environ.pop("LAUNCH_INSTANCE_ROOT", None)
        else:
            os.environ["LAUNCH_INSTANCE_ROOT"] = self._orig_instance_root
        self.instance_root.cleanup()
        self.tmpdir.cleanup()

    def _create_row(self, org="Acme Corp", zone="acme.ztlp", email="admin@example.com"):
        # Use the real /start flow so we get a real sqlite3.Row out of the DB.
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/start",
            "QUERY_STRING": "",
            "SERVER_NAME": "testserver",
            "SERVER_PORT": "80",
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO(urlencode({
                "organization_name": org,
                "admin_name": "Ada Admin",
                "admin_email": email,
                "zone": zone,
            }).encode("utf-8")),
            "wsgi.errors": io.StringIO(),
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": "0",
        }
        body = urlencode({
            "organization_name": org,
            "admin_name": "Ada Admin",
            "admin_email": email,
            "zone": zone,
        }).encode("utf-8")
        environ["wsgi.input"] = io.BytesIO(body)
        environ["CONTENT_LENGTH"] = str(len(body))
        self.app(environ, lambda status, headers, exc_info=None: None)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM onboarding_requests").fetchone()
        conn.close()
        return row

    def test_provision_creates_instance_dir_and_files(self):
        row = self._create_row(org="Acme Corp", zone="acme.ztlp")
        result = self.app._provision_zone_dockers(row)
        self.assertIsNotNone(result)
        self.assertEqual("acme-corp", result["slug"])
        self.assertTrue(39000 <= result["port"] < 39900, result["port"])
        instance_dir = result["instance_dir"]
        self.assertTrue(os.path.isdir(instance_dir))
        env_path = os.path.join(instance_dir, "instance.env")
        compose_path = os.path.join(instance_dir, "docker-compose.yml")
        self.assertTrue(os.path.isfile(env_path))
        self.assertTrue(os.path.isfile(compose_path))
        with open(env_path) as fh:
            env_text = fh.read()
        self.assertIn("ZTLP_INSTANCE_SLUG=acme-corp", env_text)
        self.assertIn("ZTLP_ORG_NAME=Acme Corp", env_text)
        self.assertIn("ZTLP_ZONE=acme.ztlp", env_text)
        self.assertIn(f"ZTLP_PRIVATE_PORT={result['port']}", env_text)
        with open(compose_path) as fh:
            compose_text = fh.read()
        self.assertIn("priceflex/ztlp-bootstrap:latest", compose_text)
        self.assertIn("ztlp-bootstrap-acme-corp", compose_text)
        self.assertIn(f"127.0.0.1:{result['port']}:3000", compose_text)
        # Regression: the gateway sidecar must use the v0.26 CLI shape.
        # `ztlp listen` removed `--service` in favor of `--service-name`, and
        # the value must stay under 16 bytes (relay-side padding). The NS
        # SVC record (long FQDN) is registered separately via `ns register`.
        self.assertIn("--service-name gw-acme-corp", compose_text)
        self.assertNotIn("--service bootstrap", compose_text)
        # v0.30.5: gateway also emits V2 (0x0E) GATEWAY_REGISTER frames
        # carrying the explicit zone, so the relay routes by `gw:<zone>`
        # instead of the V1 truncated slug. See
        # docs/plans/2026-05-24-zone-keyed-gateway-register-IMPL.md.
        self.assertIn("--zone acme.ztlp", compose_text)
        # Regression: `ztlp keygen` v0.26 does NOT accept -y (no interactive
        # prompt exists for keygen). Earlier compose generation copy-pasted
        # `-y` from `ztlp setup` and the gateway sidecar crash-looped.
        self.assertNotIn("ztlp keygen --output /data/keys/identity.json -y", compose_text)
        self.assertIn("ztlp keygen --output /data/keys/identity.json", compose_text)
        # v0.35.1: the standalone `register_ns` sidecar (which ran the v1
        # unauthenticated `ztlp ns register`) was removed — NS now requires
        # authenticated registration so the gateway self-publishes its
        # KEY+SVC records via `--ns-register-name <fqdn>` on the listen
        # command instead. Assert the gateway carries it and the old sidecar
        # command is gone.
        self.assertIn("--ns-register-name bootstrap.acme.ztlp", compose_text)
        self.assertNotIn("ns register --name", compose_text)
        self.assertNotIn("ztlp-ns-reg-", compose_text)
        self.assertNotIn("--type svc", compose_text)
        # Regression (PR #5 / #6 / #8): env-file-sourced vars referenced in
        # the gateway `command:` MUST be written as `$$VAR` (escaped) so
        # docker-compose passes them through verbatim and the in-container
        # `sh -c` expands them from env_file at run time. A single `$VAR`
        # makes compose-cli substitute from the HOST process env at parse
        # time — usually empty — yielding `--header-hmac-secret ""` and a
        # crash-loop. Live triage 2026-05-20 cost ~2h. See
        # ztlp-net-launch SKILL pitfall #17.
        self.assertIn("--header-hmac-secret \\\"$$ZTLP_GATEWAY_HEADER_SECRET\\\"", compose_text)
        self.assertNotIn("--header-hmac-secret \\\"$ZTLP_GATEWAY_HEADER_SECRET\\\"", compose_text)
        self.assertIn("$$ZTLP_ADMIN_PUBKEY_HEX", compose_text)
        self.assertIn("$$ZTLP_ADMIN_EMAIL", compose_text)
        # BS-PR-4: the bootstrap container needs ZTLP_NS_SERVER + ORG_NAME
        # so its boot-time auto-network + NS-reachability tasks have the
        # data they need. Both are injected via the `environment:` block on
        # the bootstrap service.
        self.assertIn("ZTLP_NS_SERVER:", compose_text,
                      "BS-PR-4: bootstrap container must receive ZTLP_NS_SERVER")
        self.assertIn('ORG_NAME: "Acme Corp"', compose_text,
                      "BS-PR-4: bootstrap container must receive ORG_NAME for Network row display")
        # subprocess.run should have been invoked with `docker compose up -d`.
        self.assertTrue(self._calls, "expected subprocess.run to have been called")
        last = self._calls[-1]
        self.assertEqual(["docker", "compose", "up", "-d"], last["cmd"])
        self.assertEqual(instance_dir, last["cwd"])

    def test_provision_handles_docker_compose_failure_without_raising(self):
        # Replace stub with one that returns a non-zero rc.
        import subprocess as _subprocess

        def failing_run(cmd, *args, **kwargs):
            return _subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="boom")

        _subprocess.run = failing_run
        captured_err = io.StringIO()
        orig_stderr = None
        import sys as _sys
        orig_stderr, _sys.stderr = _sys.stderr, captured_err
        try:
            row = self._create_row(org="FailCo", zone="failco.ztlp")
            result = self.app._provision_zone_dockers(row)  # must not raise
        finally:
            _sys.stderr = orig_stderr
        self.assertIsNone(result)
        self.assertIn("boom", captured_err.getvalue())
        # Files should still have been written before the failed docker call.
        instance_dir = os.path.join(self.instance_root.name, "failco")
        self.assertTrue(os.path.isfile(os.path.join(instance_dir, "instance.env")))
        self.assertTrue(os.path.isfile(os.path.join(instance_dir, "docker-compose.yml")))

    def test_provision_emits_compose_yaml_with_no_duplicate_keys(self):
        """
        Regression for BUG-2 (E2E walkthrough 2026-05-23): an earlier
        edit emitted `ORG_NAME:` twice in the bootstrap service's
        `environment:` block (once at the canonical position around
        line 747, once again ~15 lines later under the BS-PR-4 comment).
        Docker Compose's YAML parser rejects mappings with duplicate
        keys, so every tenant created via the Launch flow had a
        provisioning failure that was invisible to existing tests —
        none of them did duplicate-key detection on the compose file.

        Implementation note: the Launch app is intentionally stdlib-only
        (see `.github/workflows/ztlp-net-tests.yml` — "Launch app is
        intentionally stdlib-only — no pip install needed"), so we
        cannot depend on PyYAML in test code either. We parse the
        generated compose file with a small stdlib block-scanner
        specialised to the layout `_provision_zone_dockers` emits:

            services:
              <service>:
                <key>:
                ...
                environment:
                  KEY: "value"
                  ...
                volumes:        # or any sibling key at the same indent

        We walk the file line-by-line, track which service we're in,
        and for each service's `environment:` block we record every
        `KEY:` we see (skipping comments and blank lines). Any KEY
        that appears more than once inside the same service's
        environment block is reported as a BUG-2-style duplicate.

        Failure on this test means a future edit re-introduced
        BUG-2-style duplicate keys in the generated compose YAML.
        """
        from collections import defaultdict

        row = self._create_row(org="Acme Corp", zone="acme.ztlp")
        result = self.app._provision_zone_dockers(row)
        self.assertIsNotNone(result)
        compose_path = os.path.join(result["instance_dir"], "docker-compose.yml")
        with open(compose_path) as fh:
            compose_text = fh.read()

        def _indent(line):
            return len(line) - len(line.lstrip(" "))

        # service_name -> { env_key: occurrence_count }
        env_keys_by_service = defaultdict(lambda: defaultdict(int))

        current_service = None
        SERVICE_INDENT = 2   # LaunchApp emits services at indent 2
        ENV_KEY_INDENT = 6   # environment KEY: at indent 6
        in_env = False

        for raw_line in compose_text.splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            ind = _indent(raw_line)
            stripped = raw_line.strip()

            # New service: `  bootstrap:` style at indent 2.
            if ind == SERVICE_INDENT and stripped.endswith(":"):
                # Make sure the colon is the value-separator, not part
                # of a quoted scalar (we don't emit quoted service names).
                name = stripped[:-1].strip()
                if name and ":" not in name:
                    current_service = name
                    in_env = False
                    continue

            if current_service is None:
                continue

            # Leaving the services block entirely (back to column 0).
            if ind == 0:
                current_service = None
                in_env = False
                continue

            # Enter environment: block for current service.
            if ind == SERVICE_INDENT + 2 and stripped == "environment:":
                in_env = True
                continue

            # Sibling service-property (volumes:, restart:, command:, ports:)
            # ends the env block.
            if in_env and ind <= SERVICE_INDENT + 2:
                in_env = False
                # Fall through — this line is a sibling, not a key.

            if in_env and ind == ENV_KEY_INDENT and ":" in stripped:
                key = stripped.split(":", 1)[0].strip()
                if key and not key.startswith("-"):
                    env_keys_by_service[current_service][key] += 1

        # Report any duplicates.
        duplicates = {
            svc: sorted(k for k, count in keys.items() if count > 1)
            for svc, keys in env_keys_by_service.items()
        }
        duplicates = {svc: keys for svc, keys in duplicates.items() if keys}

        self.assertEqual(
            {}, duplicates,
            "generated docker-compose.yml has duplicate environment keys "
            f"(BUG-2 regression): {dict(duplicates)!r}. docker compose "
            "will refuse to parse this compose file. See "
            "~/hermes_session_handoff.md Task B for context."
        )

        # Sanity-check: ORG_NAME must appear exactly once in bootstrap's
        # environment block (the BS-PR-4 contract; BUG-2 made it twice).
        self.assertEqual(
            1, env_keys_by_service.get("bootstrap", {}).get("ORG_NAME", 0),
            "bootstrap service must have exactly one ORG_NAME env key "
            "(BS-PR-4 contract; BUG-2 regression check)"
        )


class AbsoluteUrlTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.app = LaunchApp(
            db_path=os.path.join(self.tmpdir.name, "launch.sqlite3"),
            token_secret="test-secret",
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_absolute_url_honours_x_forwarded_proto(self):
        environ = {
            "wsgi.url_scheme": "http",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_HOST": "www.ztlp.net",
        }
        result = self.app.absolute_url(environ, "/claim?token=X")
        self.assertTrue(
            result.startswith("https://www.ztlp.net/claim"),
            f"unexpected absolute URL: {result!r}",
        )

    def test_absolute_url_honours_x_forwarded_host(self):
        environ = {
            "wsgi.url_scheme": "http",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_X_FORWARDED_HOST": "public.example.com",
            "HTTP_HOST": "internal:8080",
        }
        result = self.app.absolute_url(environ, "/start")
        self.assertEqual("https://public.example.com/start", result)

    def test_absolute_url_handles_comma_separated_forwarded_headers(self):
        environ = {
            "wsgi.url_scheme": "http",
            "HTTP_X_FORWARDED_PROTO": "https, http",
            "HTTP_X_FORWARDED_HOST": "edge.example.com, internal",
            "HTTP_HOST": "internal",
        }
        result = self.app.absolute_url(environ, "/")
        self.assertEqual("https://edge.example.com/", result)

    def test_absolute_url_falls_back_to_wsgi_scheme_when_no_forwarded(self):
        environ = {
            "wsgi.url_scheme": "http",
            "HTTP_HOST": "localhost:8080",
        }
        result = self.app.absolute_url(environ, "/foo")
        self.assertEqual("http://localhost:8080/foo", result)


class ReferralCodeTest(unittest.TestCase):
    """Required-referral-code gate on POST /start.

    Pinned behaviour (2026-05-24):
      * `referrals_required=True` AND a valid code in `referral_codes`
        → request proceeds to provisioning.
      * `referrals_required=True` AND empty code → 400 with a "required" error.
      * `referrals_required=True` AND unknown code → 400 with a "not recognized" error.
      * `referrals_required=False` (legacy/dev mode) → empty code falls through
        to POW + rate-limit gate; the existing LaunchAppTest covers that path.

    Codes are uppercased on both sides; "steve-2026" and "STEVE-2026" are
    treated as the same code.
    """

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "launch.sqlite3")
        self.instance_root = tempfile.TemporaryDirectory()
        self._orig_instance_root = os.environ.get("LAUNCH_INSTANCE_ROOT")
        os.environ["LAUNCH_INSTANCE_ROOT"] = self.instance_root.name
        import subprocess as _subprocess
        self._subprocess = _subprocess
        self._real_subprocess_run = _subprocess.run

        def _fake_run(cmd, *args, **kwargs):
            return _subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        _subprocess.run = _fake_run

    def tearDown(self):
        self._subprocess.run = self._real_subprocess_run
        if self._orig_instance_root is None:
            os.environ.pop("LAUNCH_INSTANCE_ROOT", None)
        else:
            os.environ["LAUNCH_INSTANCE_ROOT"] = self._orig_instance_root
        self.instance_root.cleanup()
        self.tmpdir.cleanup()

    def _make_app(self, *, referrals_required, referral_codes):
        return LaunchApp(
            db_path=self.db_path,
            token_secret="test-secret",
            now=lambda: dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc),
            require_pow=False,
            referrals_required=referrals_required,
            referral_codes=referral_codes,
        )

    def _post_start(self, app, *, referral_code, organization_name="Acme Corp",
                    admin_email="ada@example.com", zone="acme.ztlp"):
        body = urlencode({
            "organization_name": organization_name,
            "admin_name": "Ada Admin",
            "admin_email": admin_email,
            "zone": zone,
            "referral_code": referral_code,
        }).encode("utf-8")
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/start",
            "QUERY_STRING": "",
            "SERVER_NAME": "testserver",
            "SERVER_PORT": "80",
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO(body),
            "wsgi.errors": io.StringIO(),
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
        }
        captured = {}

        def start_response(status, response_headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = dict(response_headers)

        response_body = b"".join(app(environ, start_response)).decode("utf-8")
        return int(captured["status"].split()[0]), response_body

    def test_required_gate_rejects_missing_code(self):
        app = self._make_app(referrals_required=True, referral_codes=["STEVE-2026"])
        status, body = self._post_start(app, referral_code="")
        self.assertEqual(HTTPStatus.BAD_REQUEST, status)
        self.assertIn("Referral code is required", body)

    def test_required_gate_rejects_unknown_code(self):
        app = self._make_app(referrals_required=True, referral_codes=["STEVE-2026"])
        status, body = self._post_start(app, referral_code="WRONG-CODE")
        self.assertEqual(HTTPStatus.BAD_REQUEST, status)
        self.assertIn("not recognized", body)

    def test_required_gate_accepts_known_code(self):
        app = self._make_app(referrals_required=True, referral_codes=["STEVE-2026"])
        status, body = self._post_start(app, referral_code="STEVE-2026")
        self.assertEqual(HTTPStatus.CREATED, status)
        self.assertIn("Claim link", body)

    def test_required_gate_normalizes_code_case_insensitively(self):
        # Operators configure codes uppercase; users may type lowercase.
        # Both directions must match.
        app = self._make_app(referrals_required=True, referral_codes=["steve-2026"])
        status, body = self._post_start(app, referral_code="STEVE-2026")
        self.assertEqual(HTTPStatus.CREATED, status)
        status2, body2 = self._post_start(app, referral_code="steve-2026", zone="acme2.ztlp", admin_email="ada2@example.com")
        self.assertEqual(HTTPStatus.CREATED, status2)

    def test_required_gate_with_empty_codes_set_rejects_everything(self):
        # Misconfiguration safety net: LAUNCH_REFERRAL_REQUIRED=1 with
        # LAUNCH_REFERRAL_CODES="" means NO ONE can onboard. This is the
        # intended fail-closed behaviour (better than fail-open).
        app = self._make_app(referrals_required=True, referral_codes=[])
        status, body = self._post_start(app, referral_code="ANYTHING")
        self.assertEqual(HTTPStatus.BAD_REQUEST, status)
        self.assertIn("not recognized", body)

    def test_legacy_mode_allows_empty_code(self):
        # Backwards-compat: with referrals_required=False, an empty code is
        # fine (POW + rate-limit gate the request instead). This is the
        # mode existing LaunchAppTest tests run in.
        app = self._make_app(referrals_required=False, referral_codes=[])
        status, body = self._post_start(app, referral_code="")
        self.assertEqual(HTTPStatus.CREATED, status)


class PhaseBCallbackTest(LaunchAppTest):
    """v0.30.9 — Phase B fix on the Launch side.

    Launch-issued *admin* enrollment tokens previously hard-coded
    ``callback_url=""`` (see app.py:1057 pre-fix), so the CLI's
    ``confirm_enrollment`` never fired and the token row stayed
    ``active`` indefinitely until the per-tenant ``TokenReconciler``
    swept NS. After this fix:

    1. ``ensure_enrollment_metadata`` derives the callback from the
       request's ``Host`` + ``wsgi.url_scheme`` (analogous to Rails'
       ``request.base_url`` used in the v0.30.8 Bootstrap-side fix).
    2. The token URI persisted in ``onboarding_requests.enrollment_token_uri``
       contains ``&callback=<public_url>/api/enrollment/confirm``.
    3. A new ``POST /api/enrollment/confirm`` endpoint accepts the CLI's
       ``token_id=...&node_id=...&name=...`` body, looks up the row by
       ``token_id`` embedded in the URI, and marks
       ``enrollment_status='redeemed'`` with a timestamp.

    These tests are the RED spec for that behaviour. They will fail on
    the v0.30.8 codebase and pass once the v0.30.9 patch lands.
    """

    def _start_and_claim(self, *, host="www.ztlp.net", scheme="https"):
        """Drive a full /start -> /claim/launch round-trip and return the token URI + token_id."""
        # POST /start to mint a claim token
        status, _h, body = self.post_form(
            "/start",
            {
                "organization_name": "Phase B Co",
                "admin_name": "Phase Admin",
                "admin_email": "pb@example.com",
                "zone": "phaseb.ztlp",
            },
        )
        self.assertEqual(HTTPStatus.CREATED, status)
        # Extract the claim token from the rendered link
        # Format: <a href="...claim?token=XYZ">...
        import re
        m = re.search(r"token=([A-Za-z0-9_\-]+)", body)
        self.assertIsNotNone(m, f"claim token not found in body: {body[:500]}")
        claim_token = m.group(1)

        # POST /claim/launch with the Host header set so we exercise the
        # public-URL derivation path.
        body_str = urlencode({"token": claim_token, "pubkey_hex": ""})
        env_headers = {
            "HTTP_HOST": host,
            "wsgi.url_scheme": scheme,
        }
        status, headers, body = self.request(
            "POST",
            "/claim/launch",
            body_str,
            {**env_headers, "CONTENT_TYPE": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(HTTPStatus.OK, status)

        # Read the persisted enrollment_token_uri out of the DB
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT enrollment_token_uri FROM onboarding_requests WHERE zone = ?",
            ("phaseb.ztlp",),
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        uri = row[0]
        self.assertTrue(uri.startswith("ztlp://enroll/?"))
        # Pull token_id out of the URI for later confirm calls
        q = parse_qs(urlparse(uri).query)
        self.assertIn("token", q, f"token param missing from URI: {uri}")
        return uri, q["token"][0]

    # ------------------------------------------------------------------
    # RED 1: the persisted token URI MUST contain a callback param that
    # points back to *this* Launch's public URL.
    # ------------------------------------------------------------------
    def test_enrollment_token_uri_embeds_launch_callback(self):
        uri, _token_id = self._start_and_claim(host="www.ztlp.net", scheme="https")
        q = parse_qs(urlparse(uri).query)
        self.assertIn(
            "callback",
            q,
            "v0.30.9 Phase B: enrollment URI must carry &callback=... so the "
            "CLI's confirm_enrollment() actually fires; pre-fix the URI was "
            "minted with callback_url='' hard-coded.",
        )
        # Exact URL shape: scheme://host/api/enrollment/confirm
        self.assertEqual(
            "https://www.ztlp.net/api/enrollment/confirm",
            q["callback"][0],
            "callback should be derived from the inbound request's scheme + Host, "
            "not from a static env var (matches the Bootstrap-side fix in v0.30.8).",
        )

    def test_enrollment_token_uri_callback_uses_request_scheme(self):
        # HTTP (dev) scheme should be reflected, not silently upgraded.
        uri, _token_id = self._start_and_claim(host="launch.dev.local", scheme="http")
        q = parse_qs(urlparse(uri).query)
        self.assertIn("callback", q)
        self.assertEqual(
            "http://launch.dev.local/api/enrollment/confirm",
            q["callback"][0],
        )

    def test_enrollment_token_uri_callback_honours_x_forwarded_proto(self):
        # Production reality: ngrok / ALB terminate TLS upstream and forward
        # plain HTTP into the container, so wsgi.url_scheme is 'http' even
        # though the client used 'https'. The X-Forwarded-Proto header is
        # the source of truth in that topology. Without this code path the
        # CLI would curl http://www.ztlp.net/..., get a 307 redirect to
        # https://, and (since curl is invoked without -L) report a loud
        # non-2xx warning to the operator on every enrollment.
        status, _h, body = self.post_form(
            "/start",
            {
                "organization_name": "Proto Co",
                "admin_name": "Proto Admin",
                "admin_email": "proto@example.com",
                "zone": "proto.ztlp",
            },
        )
        self.assertEqual(HTTPStatus.CREATED, status)
        import re
        m = re.search(r"token=([A-Za-z0-9_\-]+)", body)
        claim_token = m.group(1)
        # Simulate the ngrok-in-front-of-Launch reality: wsgi.url_scheme=http
        # but X-Forwarded-Proto=https because the user spoke TLS.
        status, _h, _body = self.request(
            "POST",
            "/claim/launch",
            urlencode({"token": claim_token, "pubkey_hex": ""}),
            {
                "HTTP_HOST": "www.ztlp.net",
                "wsgi.url_scheme": "http",
                "HTTP_X_FORWARDED_PROTO": "https",
                "CONTENT_TYPE": "application/x-www-form-urlencoded",
            },
        )
        self.assertEqual(HTTPStatus.OK, status)
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT enrollment_token_uri FROM onboarding_requests WHERE zone = ?",
            ("proto.ztlp",),
        ).fetchone()
        conn.close()
        q = parse_qs(urlparse(row[0]).query)
        self.assertEqual(
            "https://www.ztlp.net/api/enrollment/confirm",
            q["callback"][0],
            "X-Forwarded-Proto=https MUST override wsgi.url_scheme=http so the "
            "callback URL the CLI curls actually resolves on the first try, "
            "without relying on a 307 redirect (curl is invoked without -L).",
        )

    # ------------------------------------------------------------------
    # RED 2: the /api/enrollment/confirm endpoint MUST exist and MUST
    # flip the onboarding row's enrollment_status to 'redeemed'.
    # ------------------------------------------------------------------
    def test_post_api_enrollment_confirm_marks_redeemed(self):
        _uri, token_id = self._start_and_claim()
        # Pre-state: enrollment_status should be 'pending' (or NULL on
        # older rows; either way it must not be 'redeemed' yet).
        conn = sqlite3.connect(self.db_path)
        before = conn.execute(
            "SELECT enrollment_status FROM onboarding_requests WHERE zone = ?",
            ("phaseb.ztlp",),
        ).fetchone()
        conn.close()
        self.assertNotEqual("redeemed", (before[0] or "").lower())

        # Simulate the CLI's curl POST: form body with token_id, node_id, name.
        node_id_hex = "00" * 32  # 64-char hex node-id placeholder
        status, _headers, body = self.post_form(
            "/api/enrollment/confirm",
            {
                "token_id": token_id,
                "node_id": node_id_hex,
                "name": "phaseb-admin-laptop",
            },
        )
        self.assertEqual(
            HTTPStatus.OK,
            status,
            f"expected 200 OK from /api/enrollment/confirm, got {status}: {body[:300]}",
        )

        # Post-state: row should now reflect redemption.
        conn = sqlite3.connect(self.db_path)
        after = conn.execute(
            "SELECT enrollment_status, enrollment_redeemed_at, enrollment_redeemed_node_id "
            "FROM onboarding_requests WHERE zone = ?",
            ("phaseb.ztlp",),
        ).fetchone()
        conn.close()
        self.assertEqual("redeemed", after[0])
        self.assertIsNotNone(after[1], "enrollment_redeemed_at must be stamped")
        self.assertEqual(node_id_hex, after[2])

    def test_post_api_enrollment_confirm_unknown_token_returns_404(self):
        # Unknown token_id must NOT 500 and must NOT silently succeed.
        # A 404 keeps the API honest for the CLI's loud-warning behaviour.
        status, _headers, _body = self.post_form(
            "/api/enrollment/confirm",
            {
                "token_id": "deadbeef" * 4,  # 32-char hex, nonexistent
                "node_id": "00" * 32,
                "name": "nobody",
            },
        )
        self.assertEqual(HTTPStatus.NOT_FOUND, status)

    def test_post_api_enrollment_confirm_is_idempotent(self):
        # Calling confirm twice for the same token must not error and must
        # not flip the row back to pending. The second call is a no-op (or
        # at most updates the timestamp) but must remain 200 so the CLI
        # treats it as success.
        _uri, token_id = self._start_and_claim()
        body = {
            "token_id": token_id,
            "node_id": "11" * 32,
            "name": "phaseb-admin-laptop",
        }
        s1, _h1, _b1 = self.post_form("/api/enrollment/confirm", body)
        s2, _h2, _b2 = self.post_form("/api/enrollment/confirm", body)
        self.assertEqual(HTTPStatus.OK, s1)
        self.assertEqual(HTTPStatus.OK, s2)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT enrollment_status FROM onboarding_requests WHERE zone = ?",
            ("phaseb.ztlp",),
        ).fetchone()
        conn.close()
        self.assertEqual("redeemed", row[0])

    # ------------------------------------------------------------------
    # v0.30.12 — auto-bind admin pubkey from the confirm-callback path.
    #
    # The CLI's `ztlp setup` now appends `&pubkey_hex=<64hex>` to the
    # POST it sends to /api/enrollment/confirm. When present and valid,
    # Launch must:
    #   1. Rewrite ZTLP_ADMIN_PUBKEY_HEX in the tenant's instance.env
    #   2. Force-recreate the gateway container so the new env is loaded
    #   3. Return autobind=applied in the JSON ack
    #
    # Behaviour is gated by `first_bind_only=True` so an attacker who
    # scrapes the URI cannot rebind the admin pubkey after a legit
    # enrollment. Same pubkey → idempotent no-op; different pubkey →
    # silently refused with autobind=already_bound.
    # ------------------------------------------------------------------
    def test_confirm_with_pubkey_hex_auto_binds_admin_pubkey(self):
        _uri, token_id = self._start_and_claim()
        pubkey = "ab" * 32  # 64 lowercase hex

        # /claim/launch already created instance.env with an EMPTY
        # ZTLP_ADMIN_PUBKEY_HEX line. Sanity-check that pre-state.
        instance_dirs = [
            os.path.join(self.instance_root.name, d)
            for d in os.listdir(self.instance_root.name)
        ]
        self.assertEqual(1, len(instance_dirs), "expected exactly one provisioned tenant dir")
        instance_env = os.path.join(instance_dirs[0], "instance.env")
        with open(instance_env, "r") as fh:
            pre = fh.read()
        self.assertIn("ZTLP_ADMIN_PUBKEY_HEX=", pre)
        # Pre-state must be empty (or absent) — that's what makes this a
        # first-bind. Catch any future provisioning regression that
        # accidentally pre-fills the key.
        for line in pre.splitlines():
            if line.startswith("ZTLP_ADMIN_PUBKEY_HEX="):
                self.assertEqual("", line.split("=", 1)[1],
                                 "first-bind pre-state requires empty pubkey")

        status, _h, body = self.post_form(
            "/api/enrollment/confirm",
            {
                "token_id": token_id,
                "node_id": "22" * 32,
                "name": "admin-laptop",
                "pubkey_hex": pubkey,
            },
        )
        self.assertEqual(HTTPStatus.OK, status)
        # JSON ack must surface the autobind result so operators / CI can
        # tell whether the auto-bind path fired (and if not, why).
        payload = json.loads(body)
        self.assertEqual("redeemed", payload["status"])
        self.assertEqual("applied", payload["autobind"],
                         f"expected autobind=applied, got {payload}")

        # Post-state: instance.env should now have the pubkey.
        with open(instance_env, "r") as fh:
            post = fh.read()
        self.assertIn(f"ZTLP_ADMIN_PUBKEY_HEX={pubkey}", post)

        # Force-recreate must have been issued. Look for the `docker
        # compose up -d --force-recreate gateway` call.
        recreate_calls = [
            c for c in self._subprocess_calls
            if isinstance(c["cmd"], list)
            and "--force-recreate" in c["cmd"]
            and "gateway" in c["cmd"]
        ]
        self.assertTrue(recreate_calls,
                        f"expected docker compose --force-recreate gateway call, got {self._subprocess_calls}")

    def test_confirm_without_pubkey_hex_skips_autobind(self):
        # The CLI may omit pubkey_hex (legacy CLI, or non-admin enrollments).
        # In that case the autobind path must be a no-op and the JSON must
        # carry autobind=skipped.
        _uri, token_id = self._start_and_claim()
        status, _h, body = self.post_form(
            "/api/enrollment/confirm",
            {"token_id": token_id, "node_id": "33" * 32, "name": "no-pubkey"},
        )
        self.assertEqual(HTTPStatus.OK, status)
        payload = json.loads(body)
        self.assertEqual("skipped", payload["autobind"])

    def test_confirm_with_invalid_pubkey_hex_records_invalid(self):
        # A malformed pubkey must NOT 4xx the confirm (we don't want to
        # break enrollment over a bad bind). It must record autobind=invalid
        # so the CLI can warn the operator.
        _uri, token_id = self._start_and_claim()
        status, _h, body = self.post_form(
            "/api/enrollment/confirm",
            {
                "token_id": token_id,
                "node_id": "44" * 32,
                "name": "bad-pubkey",
                "pubkey_hex": "not-hex",
            },
        )
        self.assertEqual(HTTPStatus.OK, status)
        payload = json.loads(body)
        self.assertEqual("invalid", payload["autobind"])

    def test_confirm_with_same_pubkey_twice_is_idempotent(self):
        # CLI retries (e.g. transient network) MUST NOT trip the
        # first-bind gate when the same pubkey is being re-sent. This is
        # the idempotency carve-out in _apply_admin_pubkey.
        _uri, token_id = self._start_and_claim()
        pubkey = "cd" * 32
        body_form = {
            "token_id": token_id,
            "node_id": "55" * 32,
            "name": "retry-admin",
            "pubkey_hex": pubkey,
        }
        s1, _h1, b1 = self.post_form("/api/enrollment/confirm", body_form)
        s2, _h2, b2 = self.post_form("/api/enrollment/confirm", body_form)
        self.assertEqual(HTTPStatus.OK, s1)
        self.assertEqual(HTTPStatus.OK, s2)
        self.assertEqual("applied", json.loads(b1)["autobind"])
        # Second call: pubkey matches the now-bound one → applied (the
        # helper's idempotency branch returns (True, "") so the endpoint
        # reports applied, not already_bound. Either is acceptable; we
        # assert it's NOT an error.)
        autobind = json.loads(b2)["autobind"]
        self.assertIn(autobind, ("applied", "already_bound"),
                      f"second-bind of same pubkey must succeed, got {autobind}")

    def test_confirm_with_different_pubkey_after_first_bind_refuses(self):
        # First-bind gate: once a non-empty pubkey is in instance.env,
        # a confirm-callback with a DIFFERENT pubkey must NOT overwrite
        # it. This is the trust mitigation for an attacker who scrapes
        # the URI after the legit admin enrolls.
        _uri, token_id = self._start_and_claim()
        first = "ee" * 32
        second = "ff" * 32
        # First-bind: legit admin
        self.post_form("/api/enrollment/confirm", {
            "token_id": token_id,
            "node_id": "66" * 32,
            "name": "legit-admin",
            "pubkey_hex": first,
        })
        # Attacker tries to rebind with their own pubkey.
        status, _h, body = self.post_form("/api/enrollment/confirm", {
            "token_id": token_id,
            "node_id": "77" * 32,
            "name": "attacker",
            "pubkey_hex": second,
        })
        self.assertEqual(HTTPStatus.OK, status)
        payload = json.loads(body)
        self.assertEqual("already_bound", payload["autobind"])

        # Verify instance.env still has the LEGIT pubkey.
        instance_dirs = [
            os.path.join(self.instance_root.name, d)
            for d in os.listdir(self.instance_root.name)
        ]
        with open(os.path.join(instance_dirs[0], "instance.env"), "r") as fh:
            env = fh.read()
        self.assertIn(f"ZTLP_ADMIN_PUBKEY_HEX={first}", env)
        self.assertNotIn(f"ZTLP_ADMIN_PUBKEY_HEX={second}", env)

    # ------------------------------------------------------------------
    # v0.30.13 — rate limit on /api/enrollment/confirm + autobind audit.
    #
    # Closes issue #55. The v0.30.12 autobind path runs `docker compose
    # up -d --force-recreate gateway` server-side, so the endpoint is no
    # longer a cheap status flip. We rate-limit per token_id and write
    # an audit row on every confirm with a non-empty pubkey_hex so a
    # legit admin can detect URI-race attempts.
    # ------------------------------------------------------------------
    def test_confirm_rate_limit_blocks_excessive_attempts_per_token(self):
        # Default cap is 10/minute/token_id. The 11th call must 429.
        _uri, token_id = self._start_and_claim()
        body = {"token_id": token_id, "node_id": "00" * 32, "name": "spam"}
        # First 10 are 200.
        for i in range(10):
            status, _h, _b = self.post_form("/api/enrollment/confirm", body)
            self.assertEqual(HTTPStatus.OK, status, f"attempt {i+1} should be 200")
        # 11th is 429 with a structured JSON body.
        status, _h, body_429 = self.post_form("/api/enrollment/confirm", body)
        self.assertEqual(HTTPStatus.TOO_MANY_REQUESTS, status)
        payload = json.loads(body_429)
        self.assertEqual("rate_limited", payload["error"])
        self.assertEqual("enrollment_confirm", payload["scope"])
        self.assertEqual(60, payload["retry_after_seconds"])

    def test_confirm_rate_limit_is_per_token_not_global(self):
        # Two distinct tenants should each get their own bucket. Tenant A
        # hammering the endpoint must NOT 429 a totally separate tenant B.
        _uri_a, token_a = self._start_and_claim()
        # Need a second tenant — _start_and_claim uses a fixed zone, so
        # we go around it manually.
        from launch_app.app import LaunchApp  # noqa: F401 — referenced for clarity
        # Fire 10 confirms against tenant A to fill its bucket.
        for _ in range(10):
            self.post_form("/api/enrollment/confirm", {
                "token_id": token_a, "node_id": "00" * 32, "name": "a",
            })
        # 11th against A is 429.
        s_blocked, _h, _b = self.post_form("/api/enrollment/confirm", {
            "token_id": token_a, "node_id": "00" * 32, "name": "a",
        })
        self.assertEqual(HTTPStatus.TOO_MANY_REQUESTS, s_blocked)
        # A confirm against a DIFFERENT, unknown token_id should still
        # 404 (not 429) — the rate limit is keyed per token_id, and the
        # 404-vs-429 distinction proves the bucket is isolated.
        s_other, _h, _b = self.post_form("/api/enrollment/confirm", {
            "token_id": "deadbeef" * 4,  # different token_id, never used
            "node_id": "00" * 32,
            "name": "b",
        })
        self.assertEqual(HTTPStatus.NOT_FOUND, s_other,
                         "different token_id must use a separate rate-limit bucket")

    def test_confirm_rate_limit_disabled_when_zero(self):
        # Operator override: setting confirm_rate_limit_per_minute=0
        # disables the gate entirely (escape hatch for ops emergencies).
        # We rebuild the app with the override since it's a constructor arg.
        from launch_app.app import LaunchApp
        unlimited_app = LaunchApp(
            db_path=os.path.join(self.tmpdir.name, "unlimited.sqlite3"),
            token_secret="test-secret",
            now=lambda: dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc),
            require_pow=False,
            referrals_required=False,
            confirm_rate_limit_per_minute=0,
        )
        # Drive a /start + /claim against THIS app to get a valid token_id.
        # Hijack self.app temporarily for the helpers.
        original_app = self.app
        original_db = self.db_path
        self.app = unlimited_app
        self.db_path = unlimited_app.db_path
        try:
            _uri, token_id = self._start_and_claim()
            # 20 confirms — all must succeed when the limit is disabled.
            for i in range(20):
                status, _h, _b = self.post_form("/api/enrollment/confirm", {
                    "token_id": token_id, "node_id": "00" * 32, "name": f"x{i}",
                })
                self.assertEqual(HTTPStatus.OK, status,
                                 f"attempt {i+1} should succeed when limit=0")
        finally:
            self.app = original_app
            self.db_path = original_db

    def test_confirm_writes_audit_row_on_applied(self):
        # Every confirm with a non-empty pubkey_hex MUST write a row to
        # autobind_audit so the legit admin can see what happened. On a
        # successful first-bind, result='applied'.
        _uri, token_id = self._start_and_claim()
        pubkey = "ab" * 32
        self.post_form("/api/enrollment/confirm", {
            "token_id": token_id,
            "node_id": "11" * 32,
            "name": "admin",
            "pubkey_hex": pubkey,
        })
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT token_id, pubkey_hex_short, result FROM autobind_audit WHERE token_id = ?",
            (token_id,),
        ).fetchall()
        conn.close()
        self.assertEqual(1, len(rows), "exactly one audit row expected")
        self.assertEqual(token_id, rows[0][0])
        self.assertEqual(pubkey[:16], rows[0][1])
        self.assertEqual("applied", rows[0][2])

    def test_confirm_writes_audit_row_on_already_bound_refusal(self):
        # The audit log MUST capture an attempted rebind by a different
        # pubkey — that's the URI-race detection signal. Result should
        # read 'already_bound' on the second call.
        _uri, token_id = self._start_and_claim()
        legit = "aa" * 32
        attacker = "bb" * 32
        # First-bind by the legit admin.
        self.post_form("/api/enrollment/confirm", {
            "token_id": token_id,
            "node_id": "11" * 32,
            "name": "legit",
            "pubkey_hex": legit,
        })
        # Attacker attempts to rebind.
        self.post_form("/api/enrollment/confirm", {
            "token_id": token_id,
            "node_id": "22" * 32,
            "name": "attacker",
            "pubkey_hex": attacker,
        })
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT pubkey_hex_short, result FROM autobind_audit "
            "WHERE token_id = ? ORDER BY occurred_at",
            (token_id,),
        ).fetchall()
        conn.close()
        self.assertEqual(2, len(rows), "two audit rows expected")
        self.assertEqual((legit[:16], "applied"), rows[0])
        self.assertEqual((attacker[:16], "already_bound"), rows[1])

    def test_confirm_without_pubkey_does_not_write_audit(self):
        # Non-autobind confirms (no pubkey_hex) are book-keeping events,
        # NOT security events. We deliberately skip the audit write to
        # keep the table focused on URI-race-relevant entries.
        _uri, token_id = self._start_and_claim()
        self.post_form("/api/enrollment/confirm", {
            "token_id": token_id, "node_id": "33" * 32, "name": "no-pubkey",
        })
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT COUNT(*) FROM autobind_audit WHERE token_id = ?",
            (token_id,),
        ).fetchone()
        conn.close()
        self.assertEqual(0, rows[0],
                         "audit table should be empty when pubkey_hex was not sent")

    def test_api_audit_endpoint_returns_audit_rows(self):
        # GET /api/audit/<token_id> returns the rows as JSON so a legit
        # admin / dashboard can pull them through the Bootstrap tunnel.
        _uri, token_id = self._start_and_claim()
        legit = "cc" * 32
        attacker = "dd" * 32
        self.post_form("/api/enrollment/confirm", {
            "token_id": token_id, "node_id": "44" * 32,
            "name": "legit", "pubkey_hex": legit,
        })
        self.post_form("/api/enrollment/confirm", {
            "token_id": token_id, "node_id": "55" * 32,
            "name": "attacker", "pubkey_hex": attacker,
        })

        status, _h, body = self.request("GET", f"/api/audit/{token_id}")
        self.assertEqual(HTTPStatus.OK, status)
        payload = json.loads(body)
        self.assertEqual(token_id, payload["token_id"])
        self.assertEqual(2, len(payload["rows"]),
                         f"expected 2 audit rows for {token_id}, got {payload}")
        # Rows are returned most-recent-first, so [0] is the attacker.
        self.assertEqual(attacker[:16], payload["rows"][0]["pubkey_hex_short"])
        self.assertEqual("already_bound", payload["rows"][0]["result"])
        self.assertEqual(legit[:16], payload["rows"][1]["pubkey_hex_short"])
        self.assertEqual("applied", payload["rows"][1]["result"])

    def test_api_audit_endpoint_returns_empty_for_unknown_token(self):
        # No 404 — an unknown token_id just returns an empty rows array.
        # This is the right shape for the dashboard to render "no attempts
        # logged" rather than having to differentiate "404" from "0 rows".
        status, _h, body = self.request("GET", "/api/audit/deadbeef")
        self.assertEqual(HTTPStatus.OK, status)
        payload = json.loads(body)
        self.assertEqual("deadbeef", payload["token_id"])
        self.assertEqual([], payload["rows"])

    def test_api_audit_endpoint_rejects_missing_token(self):
        # GET /api/audit/ (no token) is malformed; return 400.
        status, _h, body = self.request("GET", "/api/audit/")
        self.assertEqual(HTTPStatus.BAD_REQUEST, status)
        payload = json.loads(body)
        self.assertEqual("missing token_id", payload["error"])


class EnrollmentHmacSigningTest(unittest.TestCase):
    """v0.30.10 — HMAC-BLAKE2s signing of enrollment-token query-param URIs.

    Closes the NS-1 architectural gap: prior to this change, Launch issued
    URIs with no MAC, so NS had to run with REGISTRATION_AUTH=false (accept
    anything). Now Launch optionally signs every URI with the shared
    ``ZTLP_ENROLLMENT_SECRET`` so NS can enforce signed registrations.

    The signing path is **opt-in by env**: if ``ZTLP_ENROLLMENT_SECRET`` is
    unset, URIs are emitted in the legacy unsigned form (zero nonce, no
    MAC). When set to a 64-hex-char value, URIs include ``&nonce=`` and
    ``&mac=`` params.

    The MAC covers the **canonical binary serialization** of the
    EnrollmentToken (matching ``serialize_without_mac()`` in
    ``proto/src/enrollment.rs``) — NOT the URI string itself. This lets the
    NS reuse its existing binary-token verification path with zero new
    verification logic.
    """

    # 32-byte test secret (NOT the placeholder; this is a deterministic
    # test value used only inside the test process).
    TEST_SECRET_HEX = "a" * 64
    TEST_SECRET_BYTES = bytes.fromhex(TEST_SECRET_HEX)

    def setUp(self):
        # Snapshot env so each test can mutate freely.
        self._saved_env = os.environ.get("ZTLP_ENROLLMENT_SECRET")
        if "ZTLP_ENROLLMENT_SECRET" in os.environ:
            del os.environ["ZTLP_ENROLLMENT_SECRET"]

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("ZTLP_ENROLLMENT_SECRET", None)
        else:
            os.environ["ZTLP_ENROLLMENT_SECRET"] = self._saved_env

    def _call(self, **overrides):
        """Invoke generate_enrollment_token_uri with sensible defaults."""
        from launch_app.app import generate_enrollment_token_uri
        kwargs = dict(
            zone="signed.example.ztlp",
            ns_server="ns.example.com:23096",
            expires_at=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc),
            secret_hex="deadbeef",  # legacy unused param; kept for API stability
        )
        kwargs.update(overrides)
        return generate_enrollment_token_uri(**kwargs)

    def _parse(self, uri):
        """Parse a ztlp://enroll/?… URI to a {key: value} dict.

        Note: relay/gateway can repeat in the protocol; we keep the LAST
        instance in tests since we never set multiple in these cases.
        """
        # Strip the scheme prefix; urlparse on a custom scheme works but
        # query-string parsing is awkward, so do it manually.
        self.assertTrue(uri.startswith("ztlp://enroll/?"))
        qs = uri.split("?", 1)[1]
        out = {}
        for pair in qs.split("&"):
            k, _, v = pair.partition("=")
            out[k] = v
        return out

    # ── Test 1: legacy unsigned path preserved ─────────────────────────
    def test_uri_omits_mac_when_no_secret(self):
        """Without ZTLP_ENROLLMENT_SECRET, URI is the legacy unsigned form.

        Regression guard: do not break existing deployments that run with
        ``REGISTRATION_AUTH=false`` while operators migrate.
        """
        uri = self._call()
        parsed = self._parse(uri)
        self.assertNotIn("mac", parsed)
        self.assertNotIn("nonce", parsed)
        # Required legacy params still present.
        self.assertEqual(parsed["zone"], "signed.example.ztlp")
        self.assertIn("token", parsed)
        self.assertIn("expires", parsed)

    # ── Test 2: signed path emits nonce + mac ──────────────────────────
    def test_uri_includes_mac_when_secret_set(self):
        """With secret set, URI carries both ``nonce`` (32 hex) and ``mac`` (64 hex)."""
        os.environ["ZTLP_ENROLLMENT_SECRET"] = self.TEST_SECRET_HEX
        uri = self._call()
        parsed = self._parse(uri)
        self.assertIn("nonce", parsed)
        self.assertIn("mac", parsed)
        self.assertEqual(len(parsed["nonce"]), 32, "nonce must be 16 bytes hex-encoded")
        self.assertEqual(len(parsed["mac"]), 64, "mac must be 32 bytes hex-encoded")
        # Both must be valid hex.
        bytes.fromhex(parsed["nonce"])
        bytes.fromhex(parsed["mac"])

    # ── Test 3: MAC is HMAC-BLAKE2s over the canonical binary form ─────
    def test_mac_matches_hmac_blake2s_over_canonical_serialization(self):
        """The MAC must match HMAC-BLAKE2s(secret, serialize_without_mac()).

        Canonical serialization matches ``proto/src/enrollment.rs::serialize_without_mac``:

            version u8 = 0x01
            flags u8   = 0x01 if gateway else 0x00
            zone     : u16-len-prefixed UTF-8
            ns_addr  : u16-len-prefixed UTF-8
            relay_count u8
            (relay_addr : u16-len-prefixed UTF-8) * relay_count
            gateway_addr : u16-len-prefixed UTF-8  (only if flags & 0x01)
            max_uses u16  (always 1 for query-param tokens)
            expires_at u64 BE
            nonce [16]

        Verifying parity here keeps Launch byte-compatible with the Rust
        CLI's parse + the NS's verify.
        """
        import hashlib
        import hmac as _hmac
        os.environ["ZTLP_ENROLLMENT_SECRET"] = self.TEST_SECRET_HEX

        uri = self._call(
            zone="signed.example.ztlp",
            ns_server="ns.example.com:23096",
            expires_at=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc),
        )
        parsed = self._parse(uri)
        nonce = bytes.fromhex(parsed["nonce"])
        mac_from_uri = bytes.fromhex(parsed["mac"])

        # Hand-compute the canonical serialization to verify.
        expires_unix = int(
            dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc).timestamp()
        )
        zone_b = b"signed.example.ztlp"
        ns_b = b"ns.example.com:23096"
        buf = bytearray()
        buf.append(0x01)  # version
        buf.append(0x00)  # flags (no gateway)
        buf += len(zone_b).to_bytes(2, "big") + zone_b
        buf += len(ns_b).to_bytes(2, "big") + ns_b
        buf.append(0)  # relay_count = 0
        buf += (1).to_bytes(2, "big")  # max_uses
        buf += expires_unix.to_bytes(8, "big")
        buf += nonce

        expected_mac = _hmac.new(
            self.TEST_SECRET_BYTES, bytes(buf), hashlib.blake2s
        ).digest()
        self.assertEqual(
            mac_from_uri,
            expected_mac,
            "MAC must equal HMAC-BLAKE2s(secret, serialize_without_mac())",
        )

    # ── Test 4: nonce randomness ───────────────────────────────────────
    def test_nonce_is_random_per_token(self):
        """Each call must produce a fresh 16-byte nonce.

        Reusing nonces enables replay even with a valid MAC (NS tracks
        nonces in ETS for one-shot enforcement on tokens with ``max_uses=1``).
        """
        os.environ["ZTLP_ENROLLMENT_SECRET"] = self.TEST_SECRET_HEX
        nonces = set()
        for _ in range(10):
            uri = self._call()
            nonces.add(self._parse(uri)["nonce"])
        self.assertEqual(len(nonces), 10, "nonce reused across calls — replay risk")

    # ── Test 5: gateway flag affects canonicalization ──────────────────
    def test_mac_covers_gateway_addr_when_present(self):
        """When ``gateway_addr`` is set, the flag byte is 0x01 and the gateway
        string is included in the canonical serialization. Two URIs with the
        same params except for ``gateway_addr`` must produce different MACs.
        """
        os.environ["ZTLP_ENROLLMENT_SECRET"] = self.TEST_SECRET_HEX
        # Same nonce path requires re-deriving; just compare MACs from two URIs
        # with different gateway. Different nonces are expected but if the
        # gateway weren't in the canonical form, MACs *could* still happen to
        # match in some malformed implementation. The strongest assertion is:
        # MAC differs because gateway is part of the canonical form. We
        # verify by recomputing.
        uri_no_gw = self._call(gateway_addr="")
        uri_gw = self._call(gateway_addr="gw.example.com:23097")
        p1 = self._parse(uri_no_gw)
        p2 = self._parse(uri_gw)
        # Different nonces, different MACs — but the assertion is that
        # the *flags byte* differs and so the canonical bytes differ.
        # We re-verify both MACs against their own canonical forms.
        # (This test mostly verifies test_mac_matches stays correct when
        # gateway is present.)
        import hashlib, hmac as _hmac
        expires_unix = int(
            dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc).timestamp()
        )

        def expected(zone, ns, relay, gw, nonce_hex):
            buf = bytearray()
            buf.append(0x01)
            buf.append(0x01 if gw else 0x00)
            buf += len(zone).to_bytes(2, "big") + zone.encode()
            buf += len(ns).to_bytes(2, "big") + ns.encode()
            if relay:
                buf.append(1)
                buf += len(relay).to_bytes(2, "big") + relay.encode()
            else:
                buf.append(0)
            if gw:
                buf += len(gw).to_bytes(2, "big") + gw.encode()
            buf += (1).to_bytes(2, "big")
            buf += expires_unix.to_bytes(8, "big")
            buf += bytes.fromhex(nonce_hex)
            return _hmac.new(self.TEST_SECRET_BYTES, bytes(buf), hashlib.blake2s).digest()

        self.assertEqual(
            bytes.fromhex(p2["mac"]),
            expected(
                "signed.example.ztlp",
                "ns.example.com:23096",
                "",
                "gw.example.com:23097",
                p2["nonce"],
            ),
            "MAC for gateway URI must match canonical form including gateway",
        )

    # ── Test 6: placeholder secret rejected loud ───────────────────────
    def test_placeholder_secret_is_rejected(self):
        """If the secret is the well-known ``00010203…`` byte-counting
        placeholder, refuse to mint a token.

        Background: the production ``.env`` was found to contain the
        sequential-byte placeholder (a copy-paste from a docs example).
        Without this guard, operators could ship a "signed" URI whose MAC
        is computed from a publicly-known key, defeating the whole
        signing scheme. Fail loud, not silently.
        """
        os.environ["ZTLP_ENROLLMENT_SECRET"] = bytes(range(32)).hex()
        with self.assertRaises(ValueError) as ctx:
            self._call()
        self.assertIn("placeholder", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
