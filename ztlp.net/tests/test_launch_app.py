import datetime as dt
import io
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
        self.assertIn("ztlp://enroll/", claim_body)
        self.assertIn("ztlp setup --token", claim_body)
        self.assertIn("34.219.38.89:23096", claim_body)
        self.assertIn("ztlp connect bootstrap.example.ztlp --ns-server 34.219.38.89:23096", claim_body)
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
        self.assertEqual("34.219.38.89:23096", row[4])

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
        self.assertIn("ztlp://enroll/", launch_body)
        self.assertIn("ztlp connect bootstrap.launch.ztlp --ns-server 34.219.38.89:23096", launch_body)
        self.assertNotIn("http://127.0.0.1", launch_body)
        self.assertNotIn("/login", launch_body)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, bootstrap_service_name, ns_server, bootstrap_listener_addr FROM onboarding_requests").fetchone()
        conn.close()
        self.assertEqual("launch_requested", row[0])
        self.assertEqual("bootstrap.launch.ztlp", row[1])
        self.assertEqual("34.219.38.89:23096", row[2])
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
        # Regression: `ztlp keygen` v0.26 does NOT accept -y (no interactive
        # prompt exists for keygen). Earlier compose generation copy-pasted
        # `-y` from `ztlp setup` and the gateway sidecar crash-looped.
        self.assertNotIn("ztlp keygen --output /data/keys/identity.json -y", compose_text)
        self.assertIn("ztlp keygen --output /data/keys/identity.json", compose_text)
        # Regression: `ztlp ns register` v0.26 takes --name <FQDN> + --zone
        # (positional NAME and `--type svc` were removed).
        self.assertIn("ns register --name bootstrap.acme.ztlp --zone acme.ztlp", compose_text)
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


if __name__ == "__main__":
    unittest.main()
