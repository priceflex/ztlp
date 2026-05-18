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
        self.app = LaunchApp(
            db_path=self.db_path,
            token_secret="test-secret",
            now=lambda: dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc),
        )

    def tearDown(self):
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

        status, _headers, claim_body = self.request("GET", f"/claim?token={token}")
        self.assertEqual(HTTPStatus.OK, status)
        self.assertIn("Status: claimed", claim_body)
        self.assertIn("bootstrap.example.ztlp", claim_body)
        self.assertIn("ztlp://enroll/", claim_body)
        self.assertIn("ztlp setup --token", claim_body)
        self.assertIn("10.69.95.14:23096", claim_body)
        self.assertIn("ztlp connect bootstrap.example.ztlp --ns-server 10.69.95.14:23096", claim_body)
        self.assertIn("Download ZTLP", claim_body)
        self.assertNotIn("http://127.0.0.1", claim_body)
        self.assertNotIn("/login", claim_body)
        self.assertNotIn(token, claim_body)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, claimed_at, enrollment_token_uri, bootstrap_service_name, ns_server FROM onboarding_requests").fetchone()
        conn.close()
        self.assertEqual("claimed", row[0])
        self.assertEqual("2026-01-02T03:04:05+00:00", row[1])
        self.assertTrue(row[2].startswith("ztlp://enroll/"))
        self.assertNotEqual(token, row[2])
        self.assertEqual("bootstrap.example.ztlp", row[3])
        self.assertEqual("10.69.95.14:23096", row[4])

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

        status, _headers, rejected = self.post_form("/claim/launch", {"token": token})
        self.assertEqual(HTTPStatus.BAD_REQUEST, status)
        self.assertIn("must be confirmed first", rejected)

        self.request("GET", f"/claim?token={token}")
        status, _headers, launch_body = self.post_form("/claim/launch", {"token": token})
        self.assertEqual(HTTPStatus.OK, status)
        self.assertIn("Status: launch_requested", launch_body)
        self.assertIn("bootstrap.launch.ztlp", launch_body)
        self.assertIn("ztlp://enroll/", launch_body)
        self.assertIn("ztlp connect bootstrap.launch.ztlp --ns-server 10.69.95.14:23096", launch_body)
        self.assertNotIn("http://127.0.0.1", launch_body)
        self.assertNotIn("/login", launch_body)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT status, bootstrap_service_name, ns_server, bootstrap_listener_addr FROM onboarding_requests").fetchone()
        conn.close()
        self.assertEqual("launch_requested", row[0])
        self.assertEqual("bootstrap.launch.ztlp", row[1])
        self.assertEqual("10.69.95.14:23096", row[2])
        self.assertEqual("10.69.95.14:23095", row[3])

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

    def extract_claim_link(self, body):
        marker = "http://testserver/claim?token="
        start = body.index(marker)
        end = body.index('"', start)
        return body[start:end].replace("&amp;", "&")


if __name__ == "__main__":
    unittest.main()
