#!/usr/bin/env python3
"""Minimal public-safe ZTLP Launch web app.

Stdlib-only WSGI app for local/dev preview. It accepts onboarding requests,
stores only HMAC digests of claim tokens, and renders public-safe claim/status
and download pages. It intentionally never exposes private Bootstrap admin URLs.
"""

from __future__ import annotations

import datetime as dt
import hmac
import hashlib
import html
import os
import re
import secrets
import sqlite3
from http import HTTPStatus
from typing import Callable, Dict, Iterable, Optional, Tuple
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

DEFAULT_DB_PATH = os.environ.get(
    "LAUNCH_DB_PATH",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "launch.sqlite3")),
)
DEFAULT_TOKEN_SECRET = os.environ.get("LAUNCH_TOKEN_SECRET") or os.environ.get("SECRET_KEY") or "ztlp-launch-dev-secret-change-me"
DEFAULT_HOST = os.environ.get("LAUNCH_PUBLIC_HOST", "localhost:8080")
TOKEN_TTL_DAYS = int(os.environ.get("LAUNCH_CLAIM_TOKEN_TTL_DAYS", "7"))
DEFAULT_ENVIRONMENT = os.environ.get("LAUNCH_ENV", os.environ.get("APP_ENV", "development")).lower()
DEV_TOKEN_SECRET = "ztlp-launch-dev-secret-change-me"
MAX_FORM_BYTES = int(os.environ.get("LAUNCH_MAX_FORM_BYTES", "65536"))
ZONE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$")


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def parse_iso(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value)


class RequestTooLarge(ValueError):
    pass


class LaunchApp:
    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        token_secret: str = DEFAULT_TOKEN_SECRET,
        now: Callable[[], dt.datetime] = utcnow,
        public_host: str = DEFAULT_HOST,
        environment: str = DEFAULT_ENVIRONMENT,
    ) -> None:
        self.db_path = db_path
        self.environment = (environment or "development").lower()
        if token_secret == DEV_TOKEN_SECRET and self.environment not in {"development", "test"}:
            raise ValueError("LAUNCH_TOKEN_SECRET must be set to a non-default value outside development/test.")
        self.token_secret = token_secret.encode("utf-8")
        self.now = now
        self.public_host = public_host
        self.ensure_schema()

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/") or "/"
        try:
            if method == "GET" and path == "/":
                response = self.render_landing()
            elif method == "GET" and path == "/start":
                response = self.render_start_form()
            elif method == "POST" and path == "/start":
                response = self.handle_start(environ)
            elif method == "GET" and path == "/claim":
                response = self.handle_claim(environ)
            elif method == "POST" and path == "/claim/launch":
                response = self.handle_claim_launch(environ)
            elif method == "GET" and path == "/downloads":
                response = self.render_downloads()
            elif method == "GET" and path == "/health":
                response = (HTTPStatus.OK, "text/plain; charset=utf-8", "ok\n")
            else:
                response = self.not_found("The requested Launch page was not found.")
        except RequestTooLarge as exc:
            response = (HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "text/html; charset=utf-8", self.page("Request too large", f"<p>{esc(str(exc))}</p>"))
        except ValueError as exc:
            response = (HTTPStatus.BAD_REQUEST, "text/html; charset=utf-8", self.page("Invalid request", f"<p>{esc(str(exc))}</p>"))
        except Exception:
            # Keep production responses boring; tests and container logs will have stack traces
            # only if callers run with their own WSGI middleware.
            response = (
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "text/html; charset=utf-8",
                self.page("Launch error", "<p>ZTLP Launch could not complete that request.</p>"),
            )
        status, content_type, body = response
        body_bytes = body.encode("utf-8")
        start_response(
            f"{status.value} {status.phrase}",
            [
                ("Content-Type", content_type),
                ("Content-Length", str(len(body_bytes))),
                ("Cache-Control", "no-store" if path.startswith("/claim") or path == "/start" else "no-cache"),
            ],
        )
        return [body_bytes]

    def connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def ensure_schema(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS onboarding_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_name TEXT NOT NULL,
                    admin_name TEXT NOT NULL,
                    admin_email TEXT NOT NULL,
                    zone TEXT NOT NULL,
                    status TEXT NOT NULL,
                    claim_token_digest TEXT NOT NULL UNIQUE,
                    claim_expires_at TEXT NOT NULL,
                    claimed_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_onboarding_requests_zone ON onboarding_requests(zone)")

    def render_landing(self) -> Tuple[HTTPStatus, str, str]:
        body = """
        <p class="eyebrow">ztlp.net public launcher</p>
        <h1>ZTLP Launch</h1>
        <p>Request a public-safe ZTLP onboarding flow without exposing Bootstrap admin to the public internet.</p>
        <div class="actions"><a class="button" href="/start">Start onboarding</a><a href="/downloads">Downloads</a></div>
        <section class="cards">
          <article><strong>Public-safe</strong><span>Marketing, onboarding, downloads, claim status, and provisioning state only.</span></article>
          <article><strong>Private admin stays private</strong><span>Bootstrap admin access is reserved for ZTLP-native service identity.</span></article>
          <article><strong>Service name</strong><span>Claimed requests receive a bootstrap.&lt;zone&gt; service name, not an admin URL.</span></article>
        </section>
        """
        return (HTTPStatus.OK, "text/html; charset=utf-8", self.page("ZTLP Launch", body))

    def render_start_form(self, errors: Optional[list[str]] = None, values: Optional[dict] = None) -> Tuple[HTTPStatus, str, str]:
        values = values or {}
        error_html = ""
        if errors:
            error_html = "<div class='error'><strong>Please fix:</strong><ul>" + "".join(f"<li>{esc(e)}</li>" for e in errors) + "</ul></div>"
        body = f"""
        <p class="eyebrow">Request onboarding</p>
        <h1>Start ZTLP onboarding</h1>
        <p>Submit organization details to create a local/dev claim token. Email delivery is not wired yet, so the claim link is shown once after submission.</p>
        {error_html}
        <form method="post" action="/start">
          <label>Organization name <input name="organization_name" required maxlength="200" value="{esc(values.get('organization_name', ''))}"></label>
          <label>Admin name <input name="admin_name" required maxlength="200" value="{esc(values.get('admin_name', ''))}"></label>
          <label>Admin email <input type="email" name="admin_email" required maxlength="320" value="{esc(values.get('admin_email', ''))}"></label>
          <label>Zone <input name="zone" required maxlength="253" placeholder="acme.ztlp" value="{esc(values.get('zone', ''))}"></label>
          <button type="submit">Create onboarding request</button>
        </form>
        """
        status = HTTPStatus.BAD_REQUEST if errors else HTTPStatus.OK
        return (status, "text/html; charset=utf-8", self.page("Request onboarding", body))

    def handle_start(self, environ: dict) -> Tuple[HTTPStatus, str, str]:
        form = self.read_form(environ)
        values = {key: clean(form.get(key, [""])[0]) for key in ["organization_name", "admin_name", "admin_email", "zone"]}
        values["zone"] = normalize_zone(values["zone"])
        errors = validate_start(values)
        if errors:
            return self.render_start_form(errors, values)

        token = secrets.token_urlsafe(32)
        digest = self.token_digest(token)
        now = self.now().replace(microsecond=0)
        expires = now + dt.timedelta(days=TOKEN_TTL_DAYS)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO onboarding_requests
                (organization_name, admin_name, admin_email, zone, status, claim_token_digest, claim_expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["organization_name"],
                    values["admin_name"],
                    values["admin_email"],
                    values["zone"],
                    "requested",
                    digest,
                    expires.isoformat(),
                    now.isoformat(),
                    now.isoformat(),
                ),
            )
        claim_url = self.absolute_url(environ, f"/claim?token={token}")
        body = f"""
        <p class="eyebrow">Onboarding request created</p>
        <h1>Claim link</h1>
        <p>The claim token is shown once for local/dev preview because email delivery is not wired yet. The database stores only the token digest.</p>
        <p><a class="claim-link" href="{esc(claim_url)}">{esc(claim_url)}</a></p>
        <dl>
          <dt>Organization</dt><dd>{esc(values['organization_name'])}</dd>
          <dt>Zone</dt><dd>{esc(values['zone'])}</dd>
          <dt>Status</dt><dd>requested</dd>
          <dt>Expires</dt><dd>{esc(expires.isoformat())}</dd>
        </dl>
        """
        return (HTTPStatus.CREATED, "text/html; charset=utf-8", self.page("Claim link", body))

    def handle_claim(self, environ: dict) -> Tuple[HTTPStatus, str, str]:
        token = self.query_param(environ, "token")
        if not token:
            return self.invalid_token()
        row = self.find_by_token(token)
        if not row:
            return self.invalid_token()
        if parse_iso(row["claim_expires_at"]) < self.now():
            return self.invalid_token("That claim token has expired or was revoked.")
        if not row["claimed_at"]:
            now = self.now().replace(microsecond=0).isoformat()
            with self.connect() as conn:
                conn.execute(
                    "UPDATE onboarding_requests SET status = ?, claimed_at = ?, updated_at = ? WHERE id = ?",
                    ("claimed", now, now, row["id"]),
                )
            row = self.find_by_token(token)
        return (HTTPStatus.OK, "text/html; charset=utf-8", self.render_claim_page(row))

    def handle_claim_launch(self, environ: dict) -> Tuple[HTTPStatus, str, str]:
        form = self.read_form(environ)
        token = form.get("token", [""])[0]
        row = self.find_by_token(token) if token else None
        if not row:
            return self.invalid_token()
        if parse_iso(row["claim_expires_at"]) < self.now():
            return self.invalid_token("That claim token has expired or was revoked.")
        if not row["claimed_at"]:
            return (HTTPStatus.BAD_REQUEST, "text/html; charset=utf-8", self.page("Claim confirmation required", "<p>The claim token must be confirmed first.</p>"))
        now = self.now().replace(microsecond=0).isoformat()
        with self.connect() as conn:
            conn.execute(
                "UPDATE onboarding_requests SET status = ?, claimed_at = COALESCE(claimed_at, ?), updated_at = ? WHERE id = ?",
                ("launch_requested", now, now, row["id"]),
            )
        row = self.find_by_token(token)
        return (HTTPStatus.OK, "text/html; charset=utf-8", self.render_claim_page(row, note="Launch request recorded. Provisioning is stubbed for now."))

    def render_claim_page(self, row: sqlite3.Row, note: str = "") -> str:
        service = f"bootstrap.{row['zone']}"
        note_html = f"<p class='notice'>{esc(note)}</p>" if note else ""
        body = f"""
        <p class="eyebrow">Claim status</p>
        <h1>{esc(row['organization_name'])}</h1>
        {note_html}
        <dl>
          <dt>Status</dt><dd>Status: {esc(row['status'])}</dd>
          <dt>Admin</dt><dd>{esc(row['admin_name'])} &lt;{esc(row['admin_email'])}&gt;</dd>
          <dt>Zone</dt><dd>{esc(row['zone'])}</dd>
          <dt>ZTLP service</dt><dd><code>{esc(service)}</code></dd>
          <dt>Connect command</dt><dd><code>ztlp connect {esc(service)}</code></dd>
        </dl>
        <p>Provisioning will expose the Bootstrap service through ZTLP-native identity only. No private admin URL is published here.</p>
        <p><a href="/downloads">Downloads</a></p>
        """
        return self.page("Claim status", body)

    def render_downloads(self) -> Tuple[HTTPStatus, str, str]:
        manifest_url = os.environ.get("ZTLP_DOWNLOAD_MANIFEST_URL", "https://www.ztlp.net/downloads/manifest.json")
        body = f"""
        <p class="eyebrow">Downloads</p>
        <h1>Download manifest</h1>
        <p>Signed installer publishing is not wired yet. Public ztlp.net will serve CLI and desktop artifacts here when available.</p>
        <ul>
          <li>Manifest: <code>{esc(manifest_url)}</code></li>
          <li>CLI: pending signed release artifact</li>
          <li>Desktop: pending signed release artifact</li>
        </ul>
        <p><a href="/start">Request onboarding</a></p>
        """
        return (HTTPStatus.OK, "text/html; charset=utf-8", self.page("Download manifest", body))

    def read_form(self, environ: dict) -> Dict[str, list[str]]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError as exc:
            raise ValueError("Invalid content length.") from exc
        if length > MAX_FORM_BYTES:
            raise RequestTooLarge("The request body is too large.")
        raw = environ["wsgi.input"].read(length).decode("utf-8")
        return parse_qs(raw, keep_blank_values=True)

    def query_param(self, environ: dict, name: str) -> str:
        return parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True).get(name, [""])[0]

    def token_digest(self, token: str) -> str:
        return hmac.new(self.token_secret, token.encode("utf-8"), hashlib.sha256).hexdigest()

    def find_by_token(self, token: str) -> Optional[sqlite3.Row]:
        digest = self.token_digest(token)
        with self.connect() as conn:
            return conn.execute("SELECT * FROM onboarding_requests WHERE claim_token_digest = ?", (digest,)).fetchone()

    def absolute_url(self, environ: dict, path: str) -> str:
        host = environ.get("HTTP_HOST")
        if not host:
            server_name = environ.get("SERVER_NAME")
            server_port = environ.get("SERVER_PORT")
            if server_name and server_port in ("80", "443", None, ""):
                host = server_name
            elif server_name and server_port:
                host = f"{server_name}:{server_port}"
            else:
                host = self.public_host
        scheme = environ.get("wsgi.url_scheme", "http")
        return f"{scheme}://{host}{path}"

    def invalid_token(self, message: str = "That claim token was not found.") -> Tuple[HTTPStatus, str, str]:
        return (HTTPStatus.NOT_FOUND, "text/html; charset=utf-8", self.page("Claim token not found", f"<p>{esc(message)}</p><p><a href='/start'>Start a new request</a></p>"))

    def not_found(self, message: str) -> Tuple[HTTPStatus, str, str]:
        return (HTTPStatus.NOT_FOUND, "text/html; charset=utf-8", self.page("Not found", f"<p>{esc(message)}</p>"))

    def page(self, title: str, body: str) -> str:
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} — ZTLP Launch</title>
  <style>
    :root {{ color-scheme: dark; font-family: Inter, system-ui, -apple-system, Segoe UI, sans-serif; }}
    body {{ margin: 0; min-height: 100vh; background: radial-gradient(circle at top left, #2142ff33, transparent 34%), #080b14; color: #eef3ff; }}
    main {{ width: min(920px, calc(100vw - 48px)); margin: 48px auto; padding: 42px; border: 1px solid #24314d; border-radius: 28px; background: #101827cc; box-shadow: 0 24px 80px #0008; }}
    a {{ color: #8be9ff; }}
    .button, button {{ display: inline-block; border: 0; border-radius: 999px; padding: 12px 18px; background: #73e6ff; color: #07111d; font-weight: 800; text-decoration: none; cursor: pointer; }}
    .actions {{ display: flex; gap: 16px; align-items: center; margin: 24px 0; }}
    .eyebrow {{ color: #73e6ff; text-transform: uppercase; letter-spacing: .18em; font-size: 12px; font-weight: 700; }}
    h1 {{ font-size: clamp(38px, 7vw, 72px); line-height: .94; margin: 14px 0; }}
    p, li, dd, label {{ color: #bdc9e7; font-size: 18px; line-height: 1.55; }}
    form {{ display: grid; gap: 16px; margin-top: 26px; }}
    label {{ display: grid; gap: 8px; }}
    input {{ width: min(620px, 100%); box-sizing: border-box; border: 1px solid #2a3a5d; border-radius: 12px; padding: 12px 14px; background: #080b14; color: #fff; font: inherit; }}
    dl {{ display: grid; grid-template-columns: minmax(130px, max-content) 1fr; gap: 10px 18px; padding: 20px; border: 1px solid #2a3a5d; border-radius: 16px; background: #0d1424; }}
    dt {{ color: #73e6ff; font-weight: 700; }}
    dd {{ margin: 0; }}
    code {{ color: #fff; background: #080b14; padding: 3px 6px; border-radius: 6px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 16px; margin-top: 34px; }}
    article {{ padding: 20px; border-radius: 18px; background: #172238; border: 1px solid #2a3a5d; }}
    article strong {{ display: block; color: #fff; margin-bottom: 8px; }}
    article span {{ color: #9fb0d5; }}
    .error {{ border: 1px solid #ff9b9b; background: #35191f; border-radius: 16px; padding: 16px; }}
    .notice {{ border: 1px solid #73e6ff; border-radius: 16px; padding: 14px; background: #0d2530; }}
  </style>
</head>
<body><main>{body}</main></body>
</html>
"""


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def clean(value: str) -> str:
    return " ".join((value or "").strip().split())


def normalize_zone(value: str) -> str:
    return clean(value).lower().strip(".")


def validate_start(values: dict) -> list[str]:
    errors = []
    if not values["organization_name"]:
        errors.append("Organization name is required.")
    if not values["admin_name"]:
        errors.append("Admin name is required.")
    if "@" not in values["admin_email"] or values["admin_email"].startswith("@") or values["admin_email"].endswith("@"):
        errors.append("A valid admin email is required.")
    zone = values["zone"]
    if not zone or not ZONE_RE.match(zone) or ".." in zone:
        errors.append("Zone must be a DNS-like name such as acme.ztlp.")
    return errors


application = LaunchApp()


def main() -> None:
    host = os.environ.get("LAUNCH_BIND_HOST", "0.0.0.0")
    port = int(os.environ.get("LAUNCH_BIND_PORT", "8080"))
    print(f"ZTLP Launch listening on {host}:{port}; db={application.db_path}", flush=True)
    with make_server(host, port, application) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
