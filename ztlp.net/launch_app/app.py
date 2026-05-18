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
import json
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
RELEASE_TAG = os.environ.get("ZTLP_RELEASE_TAG", "v-before-nebula-collapse")
RELEASE_BASE_URL = os.environ.get("ZTLP_RELEASE_BASE_URL", f"https://github.com/priceflex/ztlp/releases/download/{RELEASE_TAG}")
RELEASE_PAGE_URL = os.environ.get("ZTLP_RELEASE_PAGE_URL", f"https://github.com/priceflex/ztlp/releases/tag/{RELEASE_TAG}")
LAUNCH_NS_SERVER = os.environ.get("ZTLP_NS_SERVER", "10.69.95.14:23096")
LAUNCH_ENROLLMENT_SECRET_HEX = os.environ.get(
    "ZTLP_ENROLLMENT_SECRET",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
)
LAUNCH_ENROLLMENT_TTL_SECONDS = int(os.environ.get("ZTLP_ENROLLMENT_TTL_SECONDS", "86400"))
LAUNCH_RELAY_ADDR = os.environ.get("ZTLP_RELAY_ADDR", "")
LAUNCH_GATEWAY_ADDR = os.environ.get("ZTLP_GATEWAY_ADDR", "")
BOOTSTRAP_LISTENER_ADDR = os.environ.get("ZTLP_BOOTSTRAP_LISTENER_ADDR", "10.69.95.14:23095")
LAUNCH_RATE_LIMIT_EMAIL_PER_HOUR = int(os.environ.get("LAUNCH_RATE_LIMIT_EMAIL_PER_HOUR", "5"))
LAUNCH_RATE_LIMIT_IP_PER_HOUR = int(os.environ.get("LAUNCH_RATE_LIMIT_IP_PER_HOUR", "20"))
LAUNCH_POW_DIFFICULTY_BITS = int(os.environ.get("LAUNCH_POW_DIFFICULTY_BITS", "20"))
LAUNCH_POW_TTL_SECONDS = int(os.environ.get("LAUNCH_POW_TTL_SECONDS", "600"))
LAUNCH_REQUIRE_POW_DEFAULT = os.environ.get("LAUNCH_REQUIRE_POW", "1") not in ("0", "false", "False", "no", "off")

DOWNLOAD_ASSETS = [
    {
        "key": "windows",
        "label": "Windows CLI bundle",
        "platform": "Windows x64",
        "filename": f"ztlp-{RELEASE_TAG}-x86_64-pc-windows-msvc.zip",
        "description": "ZIP containing ztlp.exe and related command-line tools.",
        "install": "Download, unzip, then run ztlp.exe from PowerShell or add the folder to PATH.",
        "primary": True,
    },
    {
        "key": "linux",
        "label": "Linux CLI bundle",
        "platform": "Linux x86_64",
        "filename": f"ztlp-{RELEASE_TAG}-x86_64-unknown-linux-gnu.tar.gz",
        "description": "Tarball containing ztlp and related command-line tools for standard 64-bit Linux.",
        "install": "tar xzf the archive, then run ./ztlp or copy it into /usr/local/bin.",
        "primary": True,
    },
    {
        "key": "macos-apple-silicon",
        "label": "macOS CLI bundle",
        "platform": "macOS Apple Silicon",
        "filename": f"ztlp-{RELEASE_TAG}-aarch64-apple-darwin.tar.gz",
        "description": "Tarball containing ztlp for Apple Silicon Macs.",
        "install": "tar xzf the archive, then run ./ztlp from Terminal.",
        "primary": True,
    },
    {
        "key": "macos-intel",
        "label": "macOS CLI bundle",
        "platform": "macOS Intel",
        "filename": f"ztlp-{RELEASE_TAG}-x86_64-apple-darwin.tar.gz",
        "description": "Tarball containing ztlp for Intel Macs.",
        "install": "tar xzf the archive, then run ./ztlp from Terminal.",
        "primary": False,
    },
    {
        "key": "linux-arm64",
        "label": "Linux CLI bundle",
        "platform": "Linux ARM64",
        "filename": f"ztlp-{RELEASE_TAG}-aarch64-unknown-linux-gnu.tar.gz",
        "description": "Tarball containing ztlp for ARM64 Linux hosts.",
        "install": "tar xzf the archive, then run ./ztlp or copy it into /usr/local/bin.",
        "primary": False,
    },
    {
        "key": "windows-installer",
        "label": "Windows desktop installer",
        "platform": "Windows x64",
        "filename": "ZTLP_1.0.0_x64-setup.exe",
        "description": "Experimental desktop installer from the current release assets.",
        "install": "Use only for desktop-app testing; CLI ZIP is the safer first download path.",
        "primary": False,
    },
]
ASSET_BY_KEY = {asset["key"]: asset for asset in DOWNLOAD_ASSETS}
CHECKSUM_ASSET = "SHA256SUMS.txt"
ZONE_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def validate_zone(zone: str) -> list[str]:
    """RFC 1035 zone validation.

    Total length 1..253. At least one label (dot-separated). Each label 1..63 chars,
    matches LDH (letters/digits/hyphen) but cannot start or end with a hyphen.
    Assumes the caller has already lower-cased + stripped trailing dot; uppercase
    inputs and double-dots are rejected as invalid.
    """
    errors: list[str] = []
    if not zone:
        errors.append("Zone is required.")
        return errors
    if len(zone) > 253:
        errors.append("Zone is too long (must be 253 characters or fewer).")
    if ".." in zone:
        errors.append("Zone cannot contain empty labels (consecutive dots).")
    labels = zone.split(".")
    if not labels or any(label == "" for label in labels):
        errors.append("Zone cannot contain empty labels.")
    for label in labels:
        if not label:
            continue
        if len(label) > 63:
            errors.append(f"Zone label '{label[:16]}…' is longer than 63 characters.")
            continue
        if not ZONE_LABEL_RE.match(label):
            errors.append(f"Zone label '{label}' must be lowercase letters, digits, or hyphens (and may not start or end with a hyphen).")
    # de-dup while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for e in errors:
        if e not in seen:
            unique.append(e)
            seen.add(e)
    return unique


def has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    """True when the first `bits` bits of `digest` (MSB-first) are all zero."""
    if bits <= 0:
        return True
    full_bytes, rem = divmod(bits, 8)
    if full_bytes > len(digest):
        return False
    if any(b != 0 for b in digest[:full_bytes]):
        return False
    if rem == 0:
        return True
    if full_bytes >= len(digest):
        return False
    return (digest[full_bytes] >> (8 - rem)) == 0


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
        email_rate_limit_per_hour: int = LAUNCH_RATE_LIMIT_EMAIL_PER_HOUR,
        ip_rate_limit_per_hour: int = LAUNCH_RATE_LIMIT_IP_PER_HOUR,
        pow_difficulty_bits: int = LAUNCH_POW_DIFFICULTY_BITS,
        pow_ttl_seconds: int = LAUNCH_POW_TTL_SECONDS,
        require_pow: bool = LAUNCH_REQUIRE_POW_DEFAULT,
    ) -> None:
        self.db_path = db_path
        self.environment = (environment or "development").lower()
        if token_secret == DEV_TOKEN_SECRET and self.environment not in {"development", "test"}:
            raise ValueError("LAUNCH_TOKEN_SECRET must be set to a non-default value outside development/test.")
        self.token_secret = token_secret.encode("utf-8")
        self.now = now
        self.public_host = public_host
        self.email_rate_limit_per_hour = int(email_rate_limit_per_hour)
        self.ip_rate_limit_per_hour = int(ip_rate_limit_per_hour)
        self.pow_difficulty_bits = int(pow_difficulty_bits)
        self.pow_ttl_seconds = int(pow_ttl_seconds)
        self.require_pow = bool(require_pow)
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
                response = self.render_downloads(environ)
            elif method == "GET" and path == "/downloads/manifest.json":
                response = self.render_download_manifest(environ)
            elif method == "GET" and path.startswith("/downloads/"):
                response = self.handle_download_redirect(path)
            elif method == "GET" and path == "/api/zone-available":
                response = self.handle_zone_available(environ)
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
        if len(response) == 4:
            status, content_type, body, extra_headers = response
        else:
            status, content_type, body = response
            extra_headers = []
        body_bytes = body.encode("utf-8")
        headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body_bytes))),
            ("Cache-Control", "no-store" if path.startswith("/claim") or path == "/start" else "no-cache"),
        ]
        headers.extend(extra_headers)
        start_response(f"{status.value} {status.phrase}", headers)
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
                    enrollment_token_uri TEXT,
                    enrollment_expires_at TEXT,
                    enrollment_status TEXT,
                    bootstrap_service_name TEXT,
                    ns_server TEXT,
                    bootstrap_listener_addr TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_onboarding_requests_zone ON onboarding_requests(zone)")
            existing = {row[1] for row in conn.execute("PRAGMA table_info(onboarding_requests)")}
            for column, ddl in {
                "enrollment_token_uri": "TEXT",
                "enrollment_expires_at": "TEXT",
                "enrollment_status": "TEXT",
                "bootstrap_service_name": "TEXT",
                "ns_server": "TEXT",
                "bootstrap_listener_addr": "TEXT",
            }.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE onboarding_requests ADD COLUMN {column} {ddl}")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rate_limit_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL,
                    key TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_limit_scope_key_time ON rate_limit_attempts(scope, key, occurred_at)")

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
        pow_html = ""
        pow_script = ""
        noscript_html = ""
        if self.require_pow:
            pow_fields = self.issue_pow_challenge()
            pow_html = (
                f'<input type="hidden" name="pow_challenge" value="{esc(pow_fields["pow_challenge"])}">'
                f'<input type="hidden" name="pow_difficulty" value="{esc(pow_fields["pow_difficulty"])}">'
                f'<input type="hidden" name="pow_issued_at" value="{esc(pow_fields["pow_issued_at"])}">'
                f'<input type="hidden" name="pow_signature" value="{esc(pow_fields["pow_signature"])}">'
                f'<input type="hidden" name="math_question" value="{esc(pow_fields["math_question"])}">'
                f'<input type="hidden" name="math_signature" value="{esc(pow_fields["math_signature"])}">'
                f'<input type="hidden" name="pow_nonce" value="">'
            )
            # The math captcha is hidden by default and only shown when JS is off.
            noscript_html = (
                f'<noscript><label>Verification (no JavaScript): what is '
                f'{esc(pow_fields["math_question"].replace("+", " + "))}?'
                f' <input name="math_answer" inputmode="numeric" pattern="[0-9]+" required>'
                f'</label></noscript>'
            )
            pow_script = """
<script>
(function(){
  function hexToBytes(h){var a=new Uint8Array(h.length/2);for(var i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a;}
  function leadingZeroBits(buf,bits){var full=Math.floor(bits/8),rem=bits%8;for(var i=0;i<full;i++)if(buf[i]!==0)return false;if(rem===0)return true;return (buf[full]>>(8-rem))===0;}
  async function solve(challengeHex,bits){var c=hexToBytes(challengeHex);var enc=new TextEncoder();var n=0;while(true){var nonce=n.toString(16);var data=new Uint8Array(c.length+nonce.length);data.set(c,0);data.set(enc.encode(nonce),c.length);var hash=new Uint8Array(await crypto.subtle.digest('SHA-256',data));if(leadingZeroBits(hash,bits))return nonce;n++;if(n>5000000)return null;}}
  document.addEventListener('DOMContentLoaded',function(){
    var form=document.querySelector('form[action="/start"]');if(!form)return;
    var challenge=form.querySelector('input[name=pow_challenge]');
    var diff=form.querySelector('input[name=pow_difficulty]');
    var nonceField=form.querySelector('input[name=pow_nonce]');
    if(!challenge||!diff||!nonceField||!crypto||!crypto.subtle)return;
    form.addEventListener('submit',function(ev){
      if(nonceField.value)return; // already computed
      ev.preventDefault();
      solve(challenge.value,parseInt(diff.value,10)).then(function(nonce){nonceField.value=nonce||'';form.submit();});
    });
  });
})();
</script>
"""
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
          {pow_html}
          {noscript_html}
          <button type="submit">Create onboarding request</button>
        </form>
        {pow_script}
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

        if self.require_pow:
            pow_error = self.verify_pow(form)
            if pow_error is not None:
                return self.render_start_form([pow_error], values)

        email_key = values["admin_email"].lower()
        ip_key = self.client_ip(environ)
        now_dt = self.now().replace(microsecond=0)
        # Always record the attempt — denying does not give bots a freebie.
        self.record_rate_attempt("email", email_key, now_dt)
        self.record_rate_attempt("ip", ip_key, now_dt)
        if self.rate_limit_exceeded("email", email_key, now_dt, self.email_rate_limit_per_hour):
            return self.rate_limited_response("email")
        if self.rate_limit_exceeded("ip", ip_key, now_dt, self.ip_rate_limit_per_hour):
            return self.rate_limited_response("ip")

        token = secrets.token_urlsafe(32)
        digest = self.token_digest(token)
        now = now_dt
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
        row = self.ensure_enrollment_metadata(row)
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
        row = self.ensure_enrollment_metadata(row)
        now = self.now().replace(microsecond=0).isoformat()
        service = row["bootstrap_service_name"] or f"bootstrap.{row['zone']}"
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE onboarding_requests
                SET status = ?, claimed_at = COALESCE(claimed_at, ?),
                    bootstrap_service_name = COALESCE(bootstrap_service_name, ?),
                    ns_server = COALESCE(ns_server, ?),
                    bootstrap_listener_addr = COALESCE(bootstrap_listener_addr, ?),
                    updated_at = ?
                WHERE id = ?
                """,
                ("launch_requested", now, service, LAUNCH_NS_SERVER, BOOTSTRAP_LISTENER_ADDR, now, row["id"]),
            )
        row = self.find_by_token(token)
        return (HTTPStatus.OK, "text/html; charset=utf-8", self.render_claim_page(row, note="Launch request recorded. Bootstrap provisioning metadata is ready for the private ZTLP service path."))

    def render_claim_page(self, row: sqlite3.Row, note: str = "") -> str:
        service = row["bootstrap_service_name"] or f"bootstrap.{row['zone']}"
        ns_server = row["ns_server"] or LAUNCH_NS_SERVER
        enrollment_token = row["enrollment_token_uri"] or ""
        enrollment_command = f"ztlp setup --token '{enrollment_token}' --name '<HOSTNAME>' -y" if enrollment_token else "Claim this request to generate enrollment instructions."
        connect_command = f"ztlp connect {service} --ns-server {ns_server} --service http -L 18080:127.0.0.1:3000"
        note_html = f"<p class='notice'>{esc(note)}</p>" if note else ""
        body = f"""
        <p class="eyebrow">Claim status</p>
        <h1>{esc(row['organization_name'])}</h1>
        {note_html}
        <dl>
          <dt>Status</dt><dd>Status: {esc(row['status'])}</dd>
          <dt>Admin</dt><dd>{esc(row['admin_name'])} &lt;{esc(row['admin_email'])}&gt;</dd>
          <dt>Zone</dt><dd>{esc(row['zone'])}</dd>
          <dt>NS server</dt><dd><code>{esc(ns_server)}</code></dd>
          <dt>Enrollment status</dt><dd>{esc(row['enrollment_status'] or 'pending')}</dd>
          <dt>Enrollment expires</dt><dd>{esc(row['enrollment_expires_at'] or '')}</dd>
          <dt>Setup command</dt><dd><code>{esc(enrollment_command)}</code></dd>
          <dt>ZTLP service</dt><dd><code>{esc(service)}</code></dd>
          <dt>Connect command</dt><dd><code>{esc(connect_command)}</code></dd>
        </dl>
        <form method="post" action="/claim/launch">
          <input type="hidden" name="token" value="">
          <p class="small">Use the original claim link to request private Bootstrap provisioning. The public page never exposes a Bootstrap admin URL.</p>
        </form>
        <p>Provisioning exposes the Bootstrap service through ZTLP-native identity only. No private admin URL is published here.</p>
        <p><a class="button" href="/downloads">Download ZTLP</a></p>
        """
        return self.page("Claim status", body)

    def ensure_enrollment_metadata(self, row: sqlite3.Row) -> sqlite3.Row:
        if row["enrollment_token_uri"] and row["bootstrap_service_name"] and row["ns_server"]:
            return row
        now = self.now().replace(microsecond=0)
        expires = now + dt.timedelta(seconds=LAUNCH_ENROLLMENT_TTL_SECONDS)
        service = f"bootstrap.{row['zone']}"
        token_uri = generate_enrollment_token_uri(
            zone=row["zone"],
            ns_server=LAUNCH_NS_SERVER,
            expires_at=expires,
            secret_hex=LAUNCH_ENROLLMENT_SECRET_HEX,
            relay_addr=LAUNCH_RELAY_ADDR,
            gateway_addr=LAUNCH_GATEWAY_ADDR,
            callback_url="",
        )
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE onboarding_requests
                SET enrollment_token_uri = COALESCE(enrollment_token_uri, ?),
                    enrollment_expires_at = COALESCE(enrollment_expires_at, ?),
                    enrollment_status = COALESCE(enrollment_status, ?),
                    bootstrap_service_name = COALESCE(bootstrap_service_name, ?),
                    ns_server = COALESCE(ns_server, ?),
                    bootstrap_listener_addr = COALESCE(bootstrap_listener_addr, ?),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    token_uri,
                    expires.isoformat(),
                    "ready",
                    service,
                    LAUNCH_NS_SERVER,
                    BOOTSTRAP_LISTENER_ADDR,
                    now.isoformat(),
                    row["id"],
                ),
            )
        with self.connect() as conn:
            return conn.execute("SELECT * FROM onboarding_requests WHERE id = ?", (row["id"],)).fetchone()

    def render_downloads(self, environ: dict) -> Tuple[HTTPStatus, str, str]:
        cards = []
        for asset in DOWNLOAD_ASSETS:
            badge = "Primary" if asset["primary"] else "Optional"
            cards.append(
                f"""
                <article>
                  <strong>{esc(asset['label'])}</strong>
                  <span>{esc(asset['platform'])} · {esc(badge)}</span>
                  <p>{esc(asset['description'])}</p>
                  <p class="small">{esc(asset['install'])}</p>
                  <p><a class="button" href="/downloads/{esc(asset['key'])}">Download</a></p>
                  <p class="small"><code>{esc(asset['filename'])}</code></p>
                </article>
                """
            )
        body = f"""
        <p class="eyebrow">Downloads</p>
        <h1>Download ZTLP</h1>
        <p>Start with the command-line binary bundles. They match the current public release assets and are enough for enrollment/setup testing while the full desktop installers mature.</p>
        <p class="notice">Windows prerequisite: install the Microsoft Visual C++ Redistributable x64 if <code>ztlp.exe</code> exits immediately with missing runtime DLL errors.</p>
        <div class="actions">
          <a class="button" href="/downloads/windows">Windows ZIP</a>
          <a class="button" href="/downloads/linux">Linux tar.gz</a>
          <a class="button" href="/downloads/macos-apple-silicon">Mac Apple Silicon</a>
          <a href="/downloads/manifest.json">Manifest JSON</a>
        </div>
        <section class="cards">{''.join(cards)}</section>
        <h2>Verify downloads</h2>
        <p>Release: <a href="{esc(RELEASE_PAGE_URL)}">{esc(RELEASE_TAG)}</a></p>
        <p><a href="/downloads/checksums">SHA256 checksums</a></p>
        <p class="small">Archives include <code>ztlp</code>/<code>ztlp.exe</code>, <code>ztlp-node</code>, <code>ztlp-inspect</code>, <code>ztlp-load</code>, <code>ztlp-fuzz</code>, and <code>ztlp-bench</code>. Desktop installers are present in GitHub releases, but the CLI bundles are the cleanest first path for Launch onboarding.</p>
        <p><a href="/start">Request onboarding</a></p>
        """
        return (HTTPStatus.OK, "text/html; charset=utf-8", self.page("Download ZTLP", body))

    def render_download_manifest(self, environ: dict) -> Tuple[HTTPStatus, str, str]:
        payload = {
            "release": RELEASE_TAG,
            "release_url": RELEASE_PAGE_URL,
            "checksums_url": self.download_url(CHECKSUM_ASSET),
            "downloads": [
                {
                    "key": asset["key"],
                    "label": asset["label"],
                    "platform": asset["platform"],
                    "filename": asset["filename"],
                    "url": self.download_url(asset["filename"]),
                    "launch_url": self.absolute_url(environ, f"/downloads/{asset['key']}"),
                    "description": asset["description"],
                    "install": asset["install"],
                    "primary": asset["primary"],
                }
                for asset in DOWNLOAD_ASSETS
            ],
        }
        return (HTTPStatus.OK, "application/json; charset=utf-8", json.dumps(payload, indent=2) + "\n")

    def handle_download_redirect(self, path: str) -> Tuple[HTTPStatus, str, str, list[tuple[str, str]]]:
        key = path.rsplit("/", 1)[-1]
        if key == "checksums":
            return self.redirect(self.download_url(CHECKSUM_ASSET))
        asset = ASSET_BY_KEY.get(key)
        if not asset:
            status, content_type, body = self.not_found("That ZTLP download was not found.")
            return (status, content_type, body, [])
        return self.redirect(self.download_url(asset["filename"]))

    def handle_zone_available(self, environ: dict) -> Tuple[HTTPStatus, str, str]:
        raw = self.query_param(environ, "zone")
        zone = normalize_zone(raw)
        errors = validate_zone(zone)
        if errors:
            payload = {"zone": zone, "available": False, "reason": "invalid"}
            return (HTTPStatus.OK, "application/json; charset=utf-8", json.dumps(payload) + "\n")
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT 1 FROM onboarding_requests WHERE zone = ? LIMIT 1", (zone,)
            ).fetchone()
        if existing:
            payload = {"zone": zone, "available": False, "reason": "taken_locally"}
            return (HTTPStatus.OK, "application/json; charset=utf-8", json.dumps(payload) + "\n")
        # TODO: also consult the upstream ZtlpRelay/NS lookup to detect zones
        # taken on the public ztlp.net mesh; until then "taken_upstream" is reserved
        # in the response schema for that future check.
        payload = {"zone": zone, "available": True, "reason": "ok"}
        return (HTTPStatus.OK, "application/json; charset=utf-8", json.dumps(payload) + "\n")

    def redirect(self, url: str) -> Tuple[HTTPStatus, str, str, list[tuple[str, str]]]:
        body = f"<p>Redirecting to <a href=\"{esc(url)}\">{esc(url)}</a>.</p>"
        return (HTTPStatus.FOUND, "text/html; charset=utf-8", self.page("Download redirect", body), [("Location", url)])

    def download_url(self, filename: str) -> str:
        return f"{RELEASE_BASE_URL.rstrip('/')}/{filename}"

    def client_ip(self, environ: dict) -> str:
        """Resolve the client IP, preferring X-Forwarded-For when behind a reverse proxy.

        Production runs behind a reverse proxy that sets HTTP_X_FORWARDED_FOR.
        The first value in the list is the original client. Fall back to
        REMOTE_ADDR for direct connections, then to 'unknown'.
        """
        xff = environ.get("HTTP_X_FORWARDED_FOR", "")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
        remote = environ.get("REMOTE_ADDR", "").strip()
        return remote or "unknown"

    def record_rate_attempt(self, scope: str, key: str, occurred_at: dt.datetime) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO rate_limit_attempts (scope, key, occurred_at) VALUES (?, ?, ?)",
                (scope, key, occurred_at.isoformat()),
            )

    def rate_limit_exceeded(self, scope: str, key: str, now_dt: dt.datetime, limit: int) -> bool:
        if limit <= 0:
            return False
        window_start = (now_dt - dt.timedelta(hours=1)).isoformat()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM rate_limit_attempts WHERE scope = ? AND key = ? AND occurred_at >= ?",
                (scope, key, window_start),
            ).fetchone()
        count = row[0] if row else 0
        return count > limit

    def rate_limited_response(self, scope: str) -> Tuple[HTTPStatus, str, str]:
        body = f"""
        <p class=\"eyebrow\">Slow down</p>
        <h1>Rate limit reached</h1>
        <p>Too many onboarding attempts in the last hour for this {esc(scope)}. Please wait a bit and try again — this protects ztlp.net from abuse.</p>
        <p><a href=\"/\">Back to home</a></p>
        """
        return (HTTPStatus.TOO_MANY_REQUESTS, "text/html; charset=utf-8", self.page("Rate limit reached", body))

    def issue_pow_challenge(self) -> Dict[str, str]:
        challenge = secrets.token_hex(16)  # 16 bytes = 32 hex chars
        difficulty = self.pow_difficulty_bits
        issued_at = int(self.now().timestamp())
        signature = self.sign_pow(challenge, difficulty, issued_at)
        # Noscript math captcha — small 1..9 + 1..9 problem, signed identically.
        a = secrets.randbelow(9) + 1
        b = secrets.randbelow(9) + 1
        math_question = f"{a}+{b}"
        math_signature = self.sign_pow(math_question, 0, issued_at)
        return {
            "pow_challenge": challenge,
            "pow_difficulty": str(difficulty),
            "pow_issued_at": str(issued_at),
            "pow_signature": signature,
            "math_question": math_question,
            "math_signature": math_signature,
            "math_expected": str(a + b),
        }

    def sign_pow(self, challenge: str, difficulty: int, issued_at: int) -> str:
        msg = f"{challenge}|{int(difficulty)}|{int(issued_at)}".encode("ascii")
        return hmac.new(self.token_secret, msg, hashlib.sha256).hexdigest()

    def verify_pow(self, form: Dict[str, list[str]]) -> Optional[str]:
        """Verify proof-of-work fields from a POST form.

        Accepts either the JS PoW (challenge/nonce) or the noscript math captcha
        (math_question/math_signature/math_answer). Returns None on success, or
        a string describing the failure reason for re-rendering with an error.
        """
        # Noscript math captcha fallback path
        math_question = form.get("math_question", [""])[0]
        math_answer = form.get("math_answer", [""])[0]
        math_signature = form.get("math_signature", [""])[0]
        math_issued_at = form.get("pow_issued_at", [""])[0]
        if math_question and math_answer and math_signature:
            try:
                issued_at = int(math_issued_at)
            except ValueError:
                return "Browser verification failed: malformed math captcha."
            expected_sig = self.sign_pow(math_question, 0, issued_at)
            if not hmac.compare_digest(expected_sig, math_signature):
                return "Browser verification failed: math captcha signature mismatch."
            now_unix = int(self.now().timestamp())
            if (now_unix - issued_at) > self.pow_ttl_seconds:
                return "Browser verification expired: please reload and try again."
            try:
                a_str, b_str = math_question.split("+", 1)
                expected = int(a_str) + int(b_str)
            except (ValueError, TypeError):
                return "Browser verification failed: malformed math captcha."
            try:
                if int(math_answer.strip()) != expected:
                    return "Browser verification failed: incorrect math captcha answer."
            except ValueError:
                return "Browser verification failed: math captcha answer must be a number."
            return None

        # JS proof-of-work path
        try:
            challenge = form.get("pow_challenge", [""])[0]
            difficulty_raw = form.get("pow_difficulty", [""])[0]
            issued_at_raw = form.get("pow_issued_at", [""])[0]
            signature = form.get("pow_signature", [""])[0]
            nonce = form.get("pow_nonce", [""])[0]
        except Exception:
            return "Browser verification failed: missing PoW fields."
        if not (challenge and difficulty_raw and issued_at_raw and signature and nonce):
            return "Browser verification failed: missing PoW fields."
        try:
            difficulty = int(difficulty_raw)
            issued_at = int(issued_at_raw)
        except ValueError:
            return "Browser verification failed: malformed PoW fields."
        # length check on challenge: 16 bytes hex = 32 chars
        if len(challenge) != 32:
            return "Browser verification failed: invalid challenge."
        try:
            challenge_bytes = bytes.fromhex(challenge)
        except ValueError:
            return "Browser verification failed: invalid challenge."
        expected_sig = self.sign_pow(challenge, difficulty, issued_at)
        if not hmac.compare_digest(expected_sig, signature):
            return "Browser verification failed: signature mismatch."
        now_unix = int(self.now().timestamp())
        if issued_at > now_unix + 60:
            return "Browser verification failed: future timestamp."
        if (now_unix - issued_at) > self.pow_ttl_seconds:
            return "Browser verification expired: please reload and try again."
        if difficulty < 1 or difficulty > 32:
            return "Browser verification failed: invalid difficulty."
        digest = hashlib.sha256(challenge_bytes + nonce.encode("ascii")).digest()
        if not has_leading_zero_bits(digest, difficulty):
            return "Browser verification failed: nonce does not satisfy the difficulty target."
        return None

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
    .small {{ font-size: 14px; color: #93a4c9; }}
    h2 {{ margin-top: 32px; }}
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
    zone_errors = validate_zone(zone)
    if zone_errors:
        # Surface a friendly summary; keep the detail for logging via the list.
        errors.append("Zone must be a valid DNS name (RFC 1035): " + zone_errors[0])
    return errors


def generate_enrollment_token_uri(
    *,
    zone: str,
    ns_server: str,
    expires_at: dt.datetime,
    secret_hex: str,
    relay_addr: str = "",
    gateway_addr: str = "",
    callback_url: str = "",
) -> str:
    import base64
    import struct

    secret = bytes.fromhex(secret_hex)
    if len(secret) != 32:
        raise ValueError("ZTLP_ENROLLMENT_SECRET must be 32 bytes of hex.")
    nonce = secrets.token_bytes(16)
    flags = 1 if callback_url else 0
    max_uses = 1
    issued_at = int(utcnow().timestamp())
    expires_unix = int(expires_at.timestamp())

    body = bytearray()
    body.extend(b"ZTLPENR1")
    body.append(flags)
    body.extend(struct.pack(">Q", issued_at))
    body.extend(struct.pack(">Q", expires_unix))
    body.extend(struct.pack(">I", max_uses))
    body.extend(nonce)
    for text in (zone, ns_server):
        data = text.encode("utf-8")
        body.extend(struct.pack(">H", len(data)))
        body.extend(data)
    body.append(1 if relay_addr else 0)
    if relay_addr:
        data = relay_addr.encode("utf-8")
        body.extend(struct.pack(">H", len(data)))
        body.extend(data)
    if gateway_addr:
        body.append(1)
        data = gateway_addr.encode("utf-8")
        body.extend(struct.pack(">H", len(data)))
        body.extend(data)
    else:
        body.append(0)
    if callback_url:
        data = callback_url.encode("utf-8")
        body.extend(struct.pack(">H", len(data)))
        body.extend(data)
    sig = hmac.new(secret, bytes(body), hashlib.sha256).digest()
    payload = bytes(body) + sig
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"ztlp://enroll/{encoded}"


application = LaunchApp()


def main() -> None:
    host = os.environ.get("LAUNCH_BIND_HOST", "0.0.0.0")
    port = int(os.environ.get("LAUNCH_BIND_PORT", "8080"))
    print(f"ZTLP Launch listening on {host}:{port}; db={application.db_path}", flush=True)
    with make_server(host, port, application) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
