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
import urllib.parse
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
LAUNCH_NS_SERVER = os.environ.get("ZTLP_NS_SERVER") or "34.219.38.89:23096"
# Legacy: this was a module-level cache of the signing secret with a
# byte-counting placeholder default ("000102…1e1f"). The placeholder
# leaked into the production .env and made signed-enrollment a no-op:
# tokens were "signed" with a publicly-known key. v0.30.10 reads the
# env var lazily inside generate_enrollment_token_uri() and refuses to
# mint signed tokens against the placeholder. The module-level read is
# kept for the (now-unused) secret_hex= legacy argument so callers that
# pass it explicitly don't break, but the default is now an empty
# string — when the env is unset, Launch emits LEGACY UNSIGNED URIs and
# NS must run with REGISTRATION_AUTH=false.
LAUNCH_ENROLLMENT_SECRET_HEX = os.environ.get("ZTLP_ENROLLMENT_SECRET", "")
LAUNCH_ENROLLMENT_TTL_SECONDS = int(os.environ.get("ZTLP_ENROLLMENT_TTL_SECONDS", "86400"))
LAUNCH_RELAY_ADDR = os.environ.get("ZTLP_RELAY_ADDR", "")
LAUNCH_GATEWAY_ADDR = os.environ.get("ZTLP_GATEWAY_ADDR", "")
BOOTSTRAP_LISTENER_ADDR = os.environ.get("ZTLP_BOOTSTRAP_LISTENER_ADDR") or "34.218.240.106:23095"
LAUNCH_RATE_LIMIT_EMAIL_PER_HOUR = int(os.environ.get("LAUNCH_RATE_LIMIT_EMAIL_PER_HOUR", "5"))
LAUNCH_RATE_LIMIT_IP_PER_HOUR = int(os.environ.get("LAUNCH_RATE_LIMIT_IP_PER_HOUR", "20"))
# v0.30.13: per-token_id rate limit on POST /api/enrollment/confirm. Tracks
# issue #55 — the v0.30.12 autobind path runs `docker compose up -d
# --force-recreate` server-side, so the endpoint is no longer a cheap
# status-flip. 10 confirms/minute/token_id is the documented threshold;
# legit `ztlp setup` issues exactly 1, so the cap doesn't squeeze the
# happy path. Set to 0 to disable.
LAUNCH_CONFIRM_RATE_LIMIT_PER_MINUTE = int(os.environ.get("LAUNCH_CONFIRM_RATE_LIMIT_PER_MINUTE", "10"))
LAUNCH_POW_DIFFICULTY_BITS = int(os.environ.get("LAUNCH_POW_DIFFICULTY_BITS", "20"))
LAUNCH_POW_TTL_SECONDS = int(os.environ.get("LAUNCH_POW_TTL_SECONDS", "600"))
LAUNCH_REQUIRE_POW_DEFAULT = os.environ.get("LAUNCH_REQUIRE_POW", "1") not in ("0", "false", "False", "no", "off")

# Pre-shared referral codes. By default a valid referral code is REQUIRED to
# onboard — flip LAUNCH_REFERRAL_REQUIRED=0 to fall back to the older
# "optional code, POW + rate limit gate the rest" behaviour (only used in
# dev/test). Codes are stored as uppercase; submitted codes are uppercased
# before comparison. Comma-separated list. Operators can rotate codes by
# editing the env var on the Launch container — no rebuild required.
LAUNCH_REFERRAL_CODES = set(
    c.strip().upper() for c in os.environ.get("LAUNCH_REFERRAL_CODES", "").split(",") if c.strip()
)
LAUNCH_REFERRAL_REQUIRED_DEFAULT = os.environ.get("LAUNCH_REFERRAL_REQUIRED", "1") not in (
    "0", "false", "False", "no", "off",
)

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
        confirm_rate_limit_per_minute: int = LAUNCH_CONFIRM_RATE_LIMIT_PER_MINUTE,
        pow_difficulty_bits: int = LAUNCH_POW_DIFFICULTY_BITS,
        pow_ttl_seconds: int = LAUNCH_POW_TTL_SECONDS,
        require_pow: bool = LAUNCH_REQUIRE_POW_DEFAULT,
        referral_codes: Optional[Iterable[str]] = None,
        referrals_required: bool = LAUNCH_REFERRAL_REQUIRED_DEFAULT,
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
        self.confirm_rate_limit_per_minute = int(confirm_rate_limit_per_minute)
        self.pow_difficulty_bits = int(pow_difficulty_bits)
        self.pow_ttl_seconds = int(pow_ttl_seconds)
        self.require_pow = bool(require_pow)
        # Referral gating. Codes are stored uppercase. None == fall back to the
        # module-level LAUNCH_REFERRAL_CODES env-derived set so production
        # behaviour stays env-driven; tests pass an explicit iterable.
        if referral_codes is None:
            self.referral_codes = set(LAUNCH_REFERRAL_CODES)
        else:
            self.referral_codes = {c.strip().upper() for c in referral_codes if c and c.strip()}
        self.referrals_required = bool(referrals_required)
        self.ensure_schema()

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        # Strict HTTPS Enforce
        forwarded_proto = environ.get("HTTP_X_FORWARDED_PROTO", "").split(",")[0].strip().lower()
        scheme = forwarded_proto or environ.get("wsgi.url_scheme", "http").lower()
        if self.environment in ["production", "staging" "launch"] and scheme != "https":
            host = environ.get("HTTP_X_FORWARDED_HOST", "").split(",")[0].strip() or environ.get("HTTP_HOST") or self.public_host
            path = environ.get("PATH_INFO", "/") or "/"
            query = environ.get("QUERY_STRING", "")
            url = f"https://{host}{path}"
            if query:
                url += f"?{query}"
            
            body = f"<p>Redirecting to secure connection: <a href=\"{esc(url)}\">{esc(url)}</a>.</p>"
            headers = [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Location", url),
                ("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            ]
            start_response("301 Moved Permanently", headers)
            return [body.encode("utf-8")]

        # HSTS Header enforcement for HTTPS connections
        extra_hsts = [("Strict-Transport-Security", "max-age=31536000; includeSubDomains")] if scheme == "https" else []

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
            elif method == "POST" and path == "/api/admin-pubkey":
                response = self.handle_admin_pubkey(environ)
            elif method == "POST" and path == "/api/enrollment/confirm":
                # v0.30.9 Phase B (Launch side): the CLI's confirm_enrollment
                # curls back here with token_id+node_id+name after a successful
                # `ztlp setup`. We flip the onboarding row's
                # enrollment_status to 'redeemed' so the dashboard reflects the
                # device pickup instead of waiting on TokenReconciler.
                response = self.handle_enrollment_confirm(environ)
            elif method == "GET" and path.startswith("/api/audit/"):
                # v0.30.13 (issue #55): expose the autobind audit log per
                # token_id so the legit admin / dashboard can detect a
                # URI-race attempt. No auth — the token_id is itself a
                # secret (32-hex), so knowing it implies you held the URI.
                # The rows only carry a 16-char pubkey prefix, source IP,
                # and result — enough to spot foreign bind attempts but
                # not enough to recover the attacker's key material.
                response = self.handle_audit_query(path)
            elif method == "GET" and path == "/downloads":
                response = self.render_downloads(environ)
            elif method == "GET" and path == "/downloads/manifest.json":
                response = self.render_download_manifest(environ)
            elif method == "GET" and path.startswith("/downloads/"):
                response = self.handle_download_redirect(path)
            elif method == "GET" and path == "/api/zone-available":
                response = self.handle_zone_available(environ)
            elif method in ["GET", "HEAD"] and path == "/health":
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
        
        extra_headers.extend(extra_hsts)

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
                    referral_code TEXT,
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
                # v0.30.9 Phase B: track when the CLI calls back to confirm
                # token redemption. These were added in the Launch-side
                # Phase B patch — see handle_enrollment_confirm() and the
                # PhaseBCallbackTest suite for the spec.
                "enrollment_redeemed_at": "TEXT",
                "enrollment_redeemed_node_id": "TEXT",
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
            # v0.30.13: audit trail for every admin-pubkey bind attempt.
            # Tracks issue #55. Written by _apply_admin_pubkey on every
            # call — applied, refused-by-first-bind, error, anything.
            # Lets the legit admin see if a foreign pubkey was bound
            # to their gateway first (i.e. an attacker won the
            # URI-race). Exposed via GET /api/audit/<token_id>.
            #
            # pubkey_hex_short: first 16 chars of the requested pubkey,
            # plenty to confirm identity without storing the full key
            # in plaintext audit. Source IP for forensic correlation.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS autobind_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT NOT NULL,
                    pubkey_hex_short TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    result TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    occurred_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_autobind_audit_token_time ON autobind_audit(token_id, occurred_at)")

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
          <label>Referral code (required — ask Steve for a code) <input name="referral_code" maxlength="64" required placeholder="e.g. ZTLP-BETA-2026" value="{esc(values.get('referral_code', ''))}"></label>
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
        
        # Enforce strict input sanitization: drop characters that could be used for XSS.
        # XSS defense lives at the output boundary: every render site funnels
        # user values through `esc()` (= html.escape(..., quote=True)). Stripping
        # angle brackets here on the way in silently mutates legitimate values
        # (e.g. an admin name like "Alice <Admin>") AND defeats the unit test
        # that proves output-side escaping is wired up — because by the time
        # `esc()` runs there are no `<`/`>` left to escape. Keep only the
        # whitespace-collapsing `clean()` here.
        def sanitize(text: str) -> str:
            return clean(text)

        values = {key: sanitize(form.get(key, [""])[0]) for key in ["organization_name", "admin_name", "admin_email", "zone", "referral_code"]}
        values["zone"] = normalize_zone(values["zone"])
        errors = validate_start(values)
        if errors:
            return self.render_start_form(errors, values)

        referral_code = values.get("referral_code", "").strip().upper()
        has_valid_referral = bool(self.referral_codes and referral_code in self.referral_codes)

        # Referral gate: when referrals are required, reject the request before
        # any POW/rate-limit work happens so abusers can't fish for valid
        # codes by side-channel timing. Two distinct error messages so the
        # operator can tell "user forgot the code" apart from "user typed a
        # wrong / revoked code" in support tickets.
        if self.referrals_required and not has_valid_referral:
            if not referral_code:
                err = "Referral code is required. Ask Steve for a code."
            else:
                err = "That referral code is not recognized. Ask Steve for a current code."
            return self.render_start_form([err], values)

        # Skip POW and rate limiting when a valid referral code is provided
        if not has_valid_referral:
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
            now = now_dt
        else:
            now = self.now().replace(microsecond=0)

        token = secrets.token_urlsafe(32)
        digest = self.token_digest(token)
        expires = now + dt.timedelta(days=TOKEN_TTL_DAYS)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO onboarding_requests
                (organization_name, admin_name, admin_email, zone, status, claim_token_digest, claim_expires_at, referral_code, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["organization_name"],
                    values["admin_name"],
                    values["admin_email"],
                    values["zone"],
                    "requested",
                    digest,
                    expires.isoformat(),
                    referral_code if has_valid_referral else None,
                    now.isoformat(),
                    now.isoformat(),
                ),
            )
        claim_url = self.absolute_url(environ, f"/claim?token={token}")
        claim_text = claim_url  # Show the full URL when referral code used
        if has_valid_referral:
            body = f"""
        <p class="eyebrow">Onboarding request created (referral code accepted)</p>
        <h1>Claim link</h1>
        <p>Use the link below to claim your zone and download the ZTLP client. The token is also shown in plain text for copy-paste.</p>
        <p><a class="claim-link" href="{esc(claim_url)}">{esc(claim_text)}</a></p>
        <p><code>{esc(token)}</code></p>
        <dl>
          <dt>Organization</dt><dd>{esc(values['organization_name'])}</dd>
          <dt>Zone</dt><dd>{esc(values['zone'])}</dd>
          <dt>Status</dt><dd>requested</dd>
          <dt>Claim token</dt><dd><code>{esc(token)}</code></dd>
          <dt>Expires</dt><dd>{esc(expires.isoformat())}</dd>
        </dl>
        """
        else:
            body = f"""
        <p class="eyebrow">Onboarding request created</p>
        <h1>Claim link</h1>
        <p>The claim token is shown once for local/dev preview because email delivery is not wired yet. The database stores only the token digest.</p>
        <p><a class="claim-link" href="{esc(claim_url)}">{esc(claim_text)}</a></p>
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

        # First visit (token not yet claimed): render a confirmation form
        # asking the user to optionally paste their ztlp pubkey BEFORE we
        # spin up the docker stack. This lets us bake the admin pubkey
        # into ZTLP_ADMIN_PUBKEY_HEX on first start and skip the
        # post-provision /api/admin-pubkey + force-recreate dance.
        #
        # Subsequent visits (already claimed) just render the status view
        # — same behavior as before so users can revisit the page to
        # copy commands.
        if not row["claimed_at"]:
            return (HTTPStatus.OK, "text/html; charset=utf-8", self.render_claim_confirm(row, token, environ=environ))

        row = self.ensure_enrollment_metadata(row, environ)
        return (HTTPStatus.OK, "text/html; charset=utf-8", self.render_claim_page(row, token=token))

    def handle_claim_launch(self, environ: dict) -> Tuple[HTTPStatus, str, str]:
        form = self.read_form(environ)
        token = form.get("token", [""])[0].strip()
        # Optional admin pubkey paste — see /api/admin-pubkey for the same
        # validation rule. Empty is allowed (user opts out of passwordless,
        # falls back to Rails password form).
        pubkey_hex = form.get("pubkey_hex", [""])[0].strip().lower()

        row = self.find_by_token(token) if token else None
        if not row:
            return self.invalid_token()
        if parse_iso(row["claim_expires_at"]) < self.now():
            return self.invalid_token("That claim token has expired or was revoked.")

        if pubkey_hex and not re.fullmatch(r"[0-9a-f]{64}", pubkey_hex):
            # Re-render the confirm form with an error so the user can fix
            # their paste instead of being thrown to an empty 400 page.
            return (
                HTTPStatus.BAD_REQUEST,
                "text/html; charset=utf-8",
                self.render_claim_confirm(
                    row, token,
                    error="Public key must be exactly 64 lowercase hex characters (32-byte X25519 key).",
                    submitted_pubkey=pubkey_hex,
                    environ=environ,
                ),
            )

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
        if not row:
            return self.invalid_token()
        row = self.ensure_enrollment_metadata(row, environ)

        import sys
        try:
            self._provision_zone_dockers(row, pubkey_hex=pubkey_hex)
        except Exception as e:
            print(f"Error executing provision: {e}", file=sys.stderr)

        note = (
            "Bootstrap is provisioning. Passwordless sign-in is enabled for the device whose public key you pasted."
            if pubkey_hex
            else "Bootstrap is provisioning. Passwordless sign-in is OFF — sign in with the email/password the admin sets on first launch, or POST your device pubkey to /api/admin-pubkey later."
        )
        return (HTTPStatus.OK, "text/html; charset=utf-8", self.render_claim_page(row, token=token, note=note))

    def _provision_zone_dockers(self, row: sqlite3.Row, pubkey_hex: str = "") -> Optional[dict]:
        """Provision the docker compose scaffold for a zone's bootstrap container.

        Pure-Python rewrite of the old bin/launch bash wrapper: writes
        instance.env and docker-compose.yml under LAUNCH_INSTANCE_ROOT/<slug>/
        and then runs ``docker compose up -d`` directly. Any failure is logged
        to stderr but never raised (the caller is a daemon-style thread).

        If ``pubkey_hex`` is a non-empty 64-char lowercase hex string, it is
        written into ``ZTLP_ADMIN_PUBKEY_HEX`` so the gateway emits an
        ``--admin-pubkey-email`` flag on first start and passwordless
        Bootstrap sign-in is live immediately — no separate
        ``/api/admin-pubkey`` call + recreate is needed.

        Returns {slug, port, instance_dir} on success or None on failure.
        """
        import subprocess
        import sys
        import traceback
        try:
            org_name = row["organization_name"] or ""
            slug = self._slug_for_row(row)
            if not slug:
                print("_provision_zone_dockers: empty slug, skipping", file=sys.stderr)
                return None

            base_port = int(os.environ.get("LAUNCH_INSTANCE_BASE_PORT", "39000"))
            digest_prefix = hashlib.sha256(slug.encode("utf-8")).hexdigest()[:6]
            port = base_port + (int(digest_prefix, 16) % 900)
            gw_port = base_port + (int(digest_prefix, 16) % 900) + 1000

            instance_dir = self._instance_dir_for_slug(slug)
            os.makedirs(instance_dir, exist_ok=True)

            image = os.environ.get("LAUNCH_BOOTSTRAP_IMAGE", "priceflex/ztlp-bootstrap:latest")
            zone = row["zone"] or ""
            admin_email = row["admin_email"] or ""
            admin_name = row["admin_name"] or "Admin"
            created_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

            # Each bootstrap instance gets a stable, randomly-generated set of
            # Rails secrets so sessions survive container restarts and ActiveRecord
            # encrypted columns can be decrypted across restarts. We store them
            # in instance.env (chmod 600) and reference them from docker-compose.yml
            # so the same values get rehydrated every recreate. Generated once per
            # instance and never re-emitted to the user.
            secrets_env_path = os.path.join(instance_dir, "secrets.env")
            if os.path.exists(secrets_env_path):
                # Reuse existing secrets — never rotate on re-provision.
                pass
            else:
                with open(secrets_env_path, "w", encoding="utf-8") as fh:
                    fh.write(
                        f"SECRET_KEY_BASE={secrets.token_hex(64)}\n"
                        f"ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY={secrets.token_hex(16)}\n"
                        f"ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY={secrets.token_hex(16)}\n"
                        f"ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT={secrets.token_hex(16)}\n"
                        # Per-zone HMAC secret shared between the ZTLP gateway
                        # (which signs X-ZTLP-* headers) and the bootstrap Rails app
                        # (which verifies them via Ztlp::HeaderVerifier). Forged
                        # headers from any other source are rejected.
                        f"ZTLP_GATEWAY_HEADER_SECRET={secrets.token_hex(32)}\n"
                    )
                # Best-effort chmod — fine if we're already non-root.
                try:
                    os.chmod(secrets_env_path, 0o600)
                except OSError:
                    pass

            env_lines = [
                f"ZTLP_INSTANCE_SLUG={slug}",
                f"ZTLP_ORG_NAME={org_name}",
                f"ZTLP_ADMIN_EMAIL={admin_email}",
                f"ZTLP_ZONE={zone}",
                f"ZTLP_PRIVATE_PORT={port}",
                f"ZTLP_CREATED_AT={created_at}",
                # ZTLP_ADMIN_PUBKEY_HEX: the admin's Noise static public key
                # (hex). When set at provision time (from the claim
                # confirmation form), the gateway compose command emits
                # `--admin-pubkey-email HEX=EMAIL` on first start, so
                # passwordless sign-in is live the moment the bootstrap
                # container is healthy — no recreate needed. When left
                # blank, the gateway accepts traffic but injects no admin
                # headers and Rails falls back to the password form.
                #
                # To bind a pubkey AFTER provisioning (e.g. when an admin
                # enrolls a second device), POST to /api/admin-pubkey with
                # token=<claim_token>&pubkey_hex=<64hex> — the handler
                # rewrites this line and runs
                # `docker compose up -d --force-recreate gateway`.
                f"ZTLP_ADMIN_PUBKEY_HEX={pubkey_hex}",
            ]
            with open(os.path.join(instance_dir, "instance.env"), "w", encoding="utf-8") as fh:
                fh.write("\n".join(env_lines) + "\n")

            import sys, subprocess
            service = row["bootstrap_service_name"] or f"bootstrap.{zone}"
            os.makedirs(os.path.join(instance_dir, "gateway_keys"), exist_ok=True)
            # Generate a temporary identity for the gateway if one doesn't exist
            key_path = os.path.join(instance_dir, "gateway_keys", "identity.json")
            if not os.path.exists(key_path):
                import json
                with open(key_path, "w") as kf:
                    # Write an empty marker so the container `sh -c` initialization loop works correctly, 
                    # even if Python doesn't have the binary installed to actually build the key keys
                    json.dump({"node_id":"", "static_private_key":"", "static_public_key":""}, kf)

            ns_server_docker_host = LAUNCH_NS_SERVER.split(":")[0]
            # For dev, assume NS is on the same machine on docker bridge or host IP. 
            # Because NS is on the host we can just use 172.17.0.1 or the public IP
            if ns_server_docker_host in ["localhost", "127.0.0.1", "0.0.0.0"]:
                ns_server_docker_host = "172.17.0.1" 
            
            compose_yaml = (
                "services:\n"
                "  bootstrap:\n"
                f"    image: \"{image}\"\n"
                f"    container_name: \"ztlp-bootstrap-{slug}\"\n"
                "    ports:\n"
                f"      - \"127.0.0.1:{port}:3000\"\n"
                "    volumes:\n"
                f"      - bootstrap_{slug}_data:/data\n"
                "    env_file:\n"
                "      # Stable per-instance Rails secrets (SECRET_KEY_BASE and the\n"
                "      # ActiveRecord encryption triplet). Generated once on first\n"
                "      # provision and re-read on every recreate.\n"
                "      - secrets.env\n"
                "    environment:\n"
                "      RAILS_ENV: \"production\"\n"
                "      DATABASE_PATH: \"/data/production.sqlite3\"\n"
                f"      ZTLP_INSTANCE_SLUG: \"{slug}\"\n"
                f"      ORG_NAME: \"{org_name}\"\n"
                f"      ADMIN_EMAIL: \"{admin_email}\"\n"
                f"      ADMIN_NAME: \"{admin_name}\"\n"
                f"      ZONE: \"{zone}\"\n"
                # BS-PR-4: tell the bootstrap container where to find
                # the NS so its boot-time UDP reachability diagnostic
                # logs a useful status line. The bootstrap container
                # uses LAUNCH_NS_SERVER (the address the launch app
                # itself uses to register tenants); this is the same
                # endpoint the tenant gateway is configured against.
                f"      ZTLP_NS_SERVER: \"{LAUNCH_NS_SERVER}\"\n"
                # v0.30.2: shared production NS+Relay addresses the bootstrap
                # uses to auto-seed Machine rows on first boot, so token-mint
                # works on the operator's first dashboard click. Bootstrap's
                # Ztlp::EnsureSharedMachines service falls back to ZTLP_NS_SERVER
                # if ZTLP_SHARED_NS_ADDR is missing — these are belt-and-
                # suspenders so the env shape is explicit.
                f"      ZTLP_SHARED_NS_ADDR: \"{LAUNCH_NS_SERVER}\"\n"
                f"      ZTLP_SHARED_RELAY_ADDR: \"{BOOTSTRAP_LISTENER_ADDR}\"\n"
                # BS-PR-4 NOTE: ORG_NAME is emitted above (line ~747); it is
                # consumed by Bootstrap's auto-created Network row to produce
                # a human-readable display name (e.g. "Acme Inc" instead of
                # "Network acme.ztlp"). Do NOT duplicate it here — docker
                # compose rejects compose files with duplicate mapping keys.
                "      # The bootstrap entrypoint reads ZTLP_BOOTSTRAP_ADMIN_EMAIL\n"
                "      # to auto-promote the registering admin to super_admin on\n"
                "      # first start. The matching ZTLP_BOOTSTRAP_ADMIN_PASSWORD is\n"
                "      # NOT set here — admin sets it during ZTLP-native enrollment.\n"
                "      ZTLP_BOOTSTRAP_ADMIN_EMAIL: \"" + admin_email + "\"\n"
                f"      ZTLP_BOOTSTRAP_ADMIN_NAME: \"{admin_name}\"\n"
                "      # Trust X-ZTLP-Authenticated + X-ZTLP-Admin-Email headers\n"
                "      # injected by an upstream ZTLP gateway, so users authenticate\n"
                "      # via their ZTLP identity instead of passwords. The variable\n"
                "      # name MUST be ZTLP_TRUST_GATEWAY_AUTH (not TRUST_GATEWAY_AUTH)\n"
                "      # — application_controller.rb reads ENV['ZTLP_TRUST_GATEWAY_AUTH'].\n"
                "      ZTLP_TRUST_GATEWAY_AUTH: \"true\"\n"
                "      FORCE_SSL: \"false\"\n"
                "      RAILS_LOG_TO_STDOUT: \"1\"\n"
                "      RAILS_SERVE_STATIC_FILES: \"true\"\n"
                "    restart: unless-stopped\n"
                "\n"
                "  gateway:\n"
                "    image: priceflex/ztlp-node:v0.30.10\n"
                f"    container_name: \"ztlp-gateway-{slug}\"\n"
                "    network_mode: host\n"
                "    volumes:\n"
                "      - ./gateway_keys:/data/keys\n"
                # Read the per-instance HMAC secret + (optional) admin pubkey
                # hex from secrets.env / instance.env so the same value used by
                # Rails (ZTLP_GATEWAY_HEADER_SECRET) is what the gateway uses to
                # sign X-ZTLP-* headers. Without this, signatures would be
                # generated under a different key than Rails verifies and every
                # request would 401.
                #
                # File-permissions note: secrets.env is chmod 600 and owned by
                # the Launch process user. That's compatible with this env_file
                # mount because docker-compose v2 reads env_file from disk in
                # the CLI process (run by the same user that wrote it) and
                # injects the parsed KEY=VALUE pairs into the container env at
                # start time — the container itself never sees the file. So the
                # gateway container does NOT need read perms on secrets.env;
                # only the user invoking `docker compose up` does.
                "    env_file:\n"
                "      - secrets.env\n"
                "      - instance.env\n"
                # If key doesn't exist, this shell command writes it first.
                # `ztlp listen` v0.26 CLI: --service-name (NOT --service) is the
                # short label registered with the relay (max 16 bytes, padded).
                # We deliberately use a short slug-derived name to stay under
                # the 16-byte cap; the user-facing SVC record (bootstrap.<zone>)
                # is registered separately by the register_ns sidecar below.
                #
                # **Marker file detection (subtle):** Python's `json.dump` emits
                # `"node_id": ""` (with a space after the colon) using default
                # `separators=(', ', ': ')`. The shell grep MUST tolerate that
                # whitespace or it will always think the marker has real keys
                # and skip keygen — see the live triage 2026-05-20 where
                # --force-recreate of an existing gateway crash-looped with
                # `error: json error: expected 16 bytes for NodeId, got 0`.
                # Use an extended regex with optional whitespace around the
                # colon AND look for ANY of the three empty values so partial
                # corruption (e.g. a half-written file) still triggers keygen.
                # HTTP header injection: when ZTLP_GATEWAY_HEADER_SECRET is set
                # (always true under Launch — see secrets.env above) the gateway
                # strips inbound X-ZTLP-* spoofing attempts and injects
                # authoritative `X-ZTLP-Authenticated/Admin-Email/Timestamp/
                # Signature` headers on the first HTTP request of every TCP
                # connection. Rails (`Ztlp::HeaderVerifier`) verifies the
                # signature with the same secret. When ZTLP_ADMIN_PUBKEY_HEX is
                # empty (default until an admin enrolls a device through ZTLP),
                # no `--admin-pubkey-email` flag is rendered and the gateway
                # passes traffic through unmodified — Rails then falls back to
                # the password login form. Operators set this var in
                # instance.env after the admin's device is enrolled to flip on
                # passwordless auth without rebuilding the image.
                #
                # **`--forward 127.0.0.1:{port}` (unnamed default service):**
                # We deliberately use the unnamed/default forward form instead
                # of `--forward http:127.0.0.1:{port}`. Reason: the on-wire
                # `dst_svc_hash` (Option C) is one field that the relay uses
                # to pick which gateway to forward HELLO to AND the gateway
                # uses to pick which backend to bridge into. With a per-tenant
                # `--service-name gw-{slug}`, the CLI client sets
                # `dst_svc_hash = SHA256("gw-{slug}")` so the relay routes to
                # the right tenant — but then the same hash has to resolve to
                # a backend name on the gateway side, which a NAMED forward
                # like `http:...` can't satisfy. The single-default-service
                # fallback in ServiceRegistry::resolve (see tunnel.rs) routes
                # any unrecognized hash to the sole DEFAULT_SERVICE entry,
                # so the gateway accepts the tenant-routed HELLO and bridges
                # to Bootstrap. Verified end-to-end with `ztlp connect` +
                # passwordless autologin on 2026-05-21.
                f"    command: [\"sh\", \"-c\", \"[ -s /data/keys/identity.json ] && ! grep -Eq '\\\"node_id\\\"[[:space:]]*:[[:space:]]*\\\"\\\"' /data/keys/identity.json || ztlp keygen --output /data/keys/identity.json && exec ztlp listen --bind 0.0.0.0:{gw_port} --forward 127.0.0.1:{port} --key /data/keys/identity.json --gateway --ns-server {LAUNCH_NS_SERVER} --relay {BOOTSTRAP_LISTENER_ADDR} --service-name gw-{slug[:11]} --zone {zone} --http-inject-headers --quic --header-hmac-secret \\\"$$ZTLP_GATEWAY_HEADER_SECRET\\\" $$([ -n \\\"$$ZTLP_ADMIN_PUBKEY_HEX\\\" ] && echo \\\"--admin-pubkey-email $$ZTLP_ADMIN_PUBKEY_HEX=$$ZTLP_ADMIN_EMAIL\\\")\"]\n"
                "    restart: unless-stopped\n"
                "\n"
                "  register_ns:\n"
                "    image: priceflex/ztlp-node:v0.30.10\n"
                f"    container_name: \"ztlp-ns-reg-{slug}\"\n"
                "    network_mode: host\n"
                "    volumes:\n"
                "      - ./gateway_keys:/data/keys\n"
                # `ztlp ns register` v0.26 CLI takes --name (FQDN) + --zone
                # explicitly, plus --address for the SVC endpoint. The legacy
                # positional NAME + `--type svc` flags were removed; pass the
                # canonical `--name {fqdn} --zone {zone}` shape instead.
                f"    command: [\"sh\", \"-c\", \"while [ ! -s /data/keys/identity.json ] || grep -q '\\\"node_id\\\":\\\"\\\"' /data/keys/identity.json; do sleep 1; done; exec ztlp ns register --name {service} --zone {zone} --address {BOOTSTRAP_LISTENER_ADDR} --key /data/keys/identity.json --ns-server {LAUNCH_NS_SERVER}\"]\n"
                "\n"
                "volumes:\n"
                f"  bootstrap_{slug}_data:\n"
                f"    name: \"ztlp_bootstrap_{slug}_data\"\n"
            )
            with open(os.path.join(instance_dir, "docker-compose.yml"), "w", encoding="utf-8") as fh:
                fh.write(compose_yaml)

            result = subprocess.run(
                ["docker", "compose", "up", "-d"],
                cwd=instance_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            print(f"docker compose up stdout for {slug}: {result.stdout}", file=sys.stderr)
            print(f"docker compose up stderr for {slug}: {result.stderr}", file=sys.stderr)
            sys.stderr.flush()
            if result.returncode != 0:
                print(
                    f"_provision_zone_dockers: docker compose up failed for {slug} (rc={result.returncode})",
                    file=sys.stderr,
                )
                return None
            return {"slug": slug, "port": port, "instance_dir": instance_dir}
        except Exception as exc:  # pragma: no cover - defensive
            print(f"_provision_zone_dockers failed: {exc}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
            return None

    def render_claim_confirm(
        self,
        row: sqlite3.Row,
        token: str,
        error: str = "",
        submitted_pubkey: str = "",
        environ: Optional[dict] = None,
    ) -> str:
        """Pre-provision confirmation page.

        Shown on the FIRST visit to /claim?token=... before any docker
        containers are spun up. Asks the user to optionally paste their
        ztlp device public key (printed at the end of ``ztlp setup``) so
        the gateway can bake passwordless sign-in into ZTLP_ADMIN_PUBKEY_HEX
        on first start.

        ``error`` and ``submitted_pubkey`` are populated when handle_claim_launch
        re-renders this page after rejecting a malformed pubkey paste, so
        the user doesn't lose their input.
        """
        row = self.ensure_enrollment_metadata(row, environ)
        enrollment_token = row["enrollment_token_uri"] or ""
        enrollment_command = (
            f"ztlp setup --token \"{enrollment_token}\" -y"
            if enrollment_token
            else "Claim this request to generate enrollment instructions."
        )
        error_html = (
            f"<p class='notice' style='color:#c00'>{esc(error)}</p>" if error else ""
        )
        body = f"""
        <p class="eyebrow">Confirm your claim</p>
        <h1>{esc(row['organization_name'])}</h1>
        <p>You're about to provision a private Bootstrap admin panel for
        zone <code>{esc(row['zone'])}</code>. This step spins up the
        per-tenant docker stack on the ZTLP host.</p>

        <h2 style="margin-top:1.5em">Step 1 — Enroll a device (recommended)</h2>
        <p>Run the setup command on the machine you want to use to
        administer this zone. <code>ztlp setup</code> will print your
        device's public key at the end — copy it into the box below to
        enable passwordless Bootstrap sign-in from that device.</p>
        <pre><code>{esc(enrollment_command)}</code></pre>

        <h2 style="margin-top:1.5em">Step 2 — Bind your device (optional)</h2>
        <p>Paste the 64-character hex public key from the end of the
        <code>ztlp setup</code> output. Leave blank to use the classic
        email + password sign-in on the Bootstrap UI.</p>
        {error_html}
        <form method="post" action="/claim/launch">
          <input type="hidden" name="token" value="{esc(token)}">
          <p>
            <label for="pubkey_hex">Device public key (hex, 64 chars):</label><br>
            <input type="text" name="pubkey_hex" id="pubkey_hex"
                   value="{esc(submitted_pubkey)}"
                   pattern="[0-9a-fA-F]{{64}}"
                   placeholder="a1b2c3...  (or leave blank)"
                   style="width:100%;font-family:monospace;font-size:0.9em">
          </p>
          <p>
            <button type="submit" class="button">Provision Bootstrap</button>
          </p>
        </form>
        <p class="small">Only the public half of your ztlp identity is
        sent to ztlp.net. The private key stays in <code>~/.ztlp/identity.json</code>
        on the machine that ran <code>ztlp setup</code>.</p>
        """
        return self.page("Confirm claim", body)

    def render_claim_page(self, row: sqlite3.Row, token: str = "", note: str = "") -> str:
        service = row["bootstrap_service_name"] or f"bootstrap.{row['zone']}"
        ns_server = row["ns_server"] or LAUNCH_NS_SERVER
        # The displayed Connect command uses the V2 routing key `gw:<zone>`
        # so clients land on the right tenant's gateway even when V1 slug
        # truncation would collide (e.g. "Tech Rockstars" vs "Tech
        # Rockstars Test" — both V1-truncate to gw-tech-rockst). The
        # gateway also emits V1 frames for back-compat; if a client still
        # uses the V1 slug, the relay's V1 routing path catches it.
        # See docs/plans/2026-05-24-zone-keyed-gateway-register-IMPL.md.
        zone = row["zone"] or ""
        slug = self._slug_for_row(row)
        gw_service = f"gw:{zone}" if zone else (f"gw-{slug[:11]}" if slug else "gw-bootstrap")
        connect_command = (
            f"ztlp connect {service} --ns-server {ns_server} "
            f"--service {gw_service} -L 18080:127.0.0.1:3000"
        )
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
          <dt>ZTLP service</dt><dd><code>{esc(service)}</code></dd>
          <dt>Connect command</dt><dd><code>{esc(connect_command)}</code></dd>
        </dl>
        <form method="post" action="/claim/launch">
          <input type="hidden" name="token" value="{esc(token)}">
          <p class="small">Already provisioned — to bind a different
          device pubkey, POST to <code>/api/admin-pubkey</code> with
          your token and the new pubkey hex.</p>
        </form>
        <p>Provisioning exposes the Bootstrap service through ZTLP-native identity only. No private admin URL is published here.</p>
        <p><a class="button" href="/downloads">Download ZTLP</a></p>
        """
        return self.page("Claim status", body)

    def _public_url(self, environ: Optional[dict]) -> str:
        """Derive this Launch's externally-reachable base URL from the WSGI environ.

        v0.30.9 Phase B (Launch side): mirrors the Rails-side fix shipped in
        v0.30.8 (Bootstrap), where ``request.base_url`` was used to derive
        the callback URL embedded in minted enrollment tokens. We pull
        ``HTTP_HOST`` + ``wsgi.url_scheme`` from the inbound request — both
        are populated by every WSGI server (gunicorn, the std-lib
        ``wsgiref`` runner used in tests, etc.). The advantage over a
        static ``LAUNCH_PUBLIC_URL`` env var is that the same code path
        works in dev (``http://localhost:8080``), behind ngrok
        (``https://<random>.ngrok-free.app``), and in prod
        (``https://www.ztlp.net``) without any config changes.

        Returns ``""`` (empty) if either the scheme or the host header is
        missing — callers treat that as "no callback URL" and omit
        ``&callback=`` from the minted URI (legacy v0.30.8 behaviour).
        """
        if not environ:
            return ""
        # Honour X-Forwarded-Proto first — ngrok / Cloudflare / ALB terminate
        # TLS upstream and forward plain HTTP to the container, so the bare
        # ``wsgi.url_scheme`` is wrong in those topologies. The forwarded
        # header reflects what the *client* spoke. Fall back to the WSGI
        # scheme (correct for direct connections, dev, and tests).
        scheme = (
            environ.get("HTTP_X_FORWARDED_PROTO")
            or environ.get("wsgi.url_scheme")
            or "https"
        ).split(",")[0].strip().lower()
        host = environ.get("HTTP_HOST") or ""
        if not host:
            return ""
        return f"{scheme}://{host}"

    def ensure_enrollment_metadata(
        self,
        row: sqlite3.Row,
        environ: Optional[dict] = None,
    ) -> sqlite3.Row:
        if row["enrollment_token_uri"] and row["bootstrap_service_name"] and row["ns_server"]:
            return row
        now = self.now().replace(microsecond=0)
        expires = now + dt.timedelta(seconds=LAUNCH_ENROLLMENT_TTL_SECONDS)
        service = f"bootstrap.{row['zone']}"
        # v0.30.9 Phase B: derive the callback URL from the inbound request
        # so the minted token URI carries `&callback=<public_url>/api/enrollment/confirm`.
        # The CLI's confirm_enrollment() will POST there after a successful
        # `ztlp setup`, flipping the row's enrollment_status to 'redeemed'.
        public_url = self._public_url(environ)
        callback_url = f"{public_url}/api/enrollment/confirm" if public_url else ""
        token_uri = generate_enrollment_token_uri(
            zone=row["zone"],
            ns_server=LAUNCH_NS_SERVER,
            expires_at=expires,
            secret_hex=LAUNCH_ENROLLMENT_SECRET_HEX,
            relay_addr=LAUNCH_RELAY_ADDR,
            gateway_addr=LAUNCH_GATEWAY_ADDR,
            callback_url=callback_url,
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

    def handle_enrollment_confirm(self, environ: dict) -> Tuple[HTTPStatus, str, str]:
        """v0.30.9 Phase B — record CLI confirmation of admin enrollment.

        Called by ``ztlp setup`` (via ``confirm_enrollment`` in proto/src/bin/
        ztlp-cli.rs) after the CLI successfully enrolls the device against NS.
        The CLI POSTs ``token_id``, ``node_id``, and ``name`` as an
        ``application/x-www-form-urlencoded`` body.

        Side effects on a known token_id:
          1. Stamps ``enrollment_redeemed_at`` with current UTC time.
          2. Stamps ``enrollment_redeemed_node_id`` with the device's NodeId.
          3. Flips ``enrollment_status`` from ``ready`` (or anything else) to
             ``redeemed``. This is what the dashboard / operator views read.

        Idempotency: a repeat call for the same ``token_id`` updates the
        timestamp + node_id (so a re-enroll attempt is observable) but
        leaves the status as ``redeemed``. Always returns 200 — the CLI
        treats anything ≥ 400 as a loud warning, so we reserve those for
        true errors (unknown token, malformed body).

        Why this exists: the URI that Launch mints embeds
        ``&callback=<launch_public_url>/api/enrollment/confirm`` so the
        CLI can call back here. Pre-v0.30.9 this URL was hard-coded to
        empty, and the CLI silently skipped the callback. See
        PhaseBCallbackTest for the spec, and the v0.30.8 commit 464cd61
        for the analogous Rails-side fix in Bootstrap.

        Auth: none. The CLI doesn't have a session here — it just curls
        with the token_id. We do NOT trust the body for anything more
        than book-keeping; we only flip a status flag. The actual
        enrollment authorization happens at NS, not here. Worst case
        an attacker scrapes the URI from the claim page (already a
        one-shot, gated by referral code) and POSTs a false confirm —
        the result is a row that reads "redeemed" without a real device
        behind it. Not a privilege escalation; just a noisy status row.
        """
        form = self.read_form(environ)
        token_id = (form.get("token_id") or [""])[0].strip()
        node_id = (form.get("node_id") or [""])[0].strip()
        name = (form.get("name") or [""])[0].strip()
        # v0.30.12: optional auto-bind of the admin's Noise static pubkey.
        # When present and valid, we run the same env-rewrite +
        # docker-compose-recreate dance as /api/admin-pubkey — but gated by
        # `first_bind_only` so an attacker who scrapes the URI after a
        # legitimate enrollment cannot rebind the admin pubkey to their own
        # device. The first call (legit admin) binds; all subsequent calls
        # for the same row are no-ops (or silently ignored if the pubkey
        # differs).
        pubkey_hex = (form.get("pubkey_hex") or [""])[0].strip().lower()

        if not token_id:
            return (
                HTTPStatus.BAD_REQUEST,
                "text/plain; charset=utf-8",
                "missing token_id\n",
            )

        # v0.30.13: per-token_id rate limit (issue #55). The legit `ztlp
        # setup` issues exactly one confirm; anyone hammering the same
        # token_id is either a buggy retry loop or an attacker trying to
        # force-recreate the gateway repeatedly. Returns 429 + Retry-After
        # without recording an autobind audit row — the rate-limit table
        # is enough forensic signal. The CLI handles 429 gracefully (does
        # not fail the enrollment).
        #
        # Order matches handle_start: record FIRST, then check. With
        # limit=N, that means calls 1..N pass and call N+1 trips the gate
        # — even though the helper uses ``count > limit``, the always-
        # record-first pattern shifts the trigger up by 1. See
        # ``test_rate_limit_blocks_after_email_threshold`` for the same
        # idiom.
        now_dt = self.now()
        source_ip = self.client_ip(environ)
        self.record_rate_attempt("enrollment_confirm", token_id, now_dt)
        if self.rate_limit_exceeded(
            "enrollment_confirm",
            token_id,
            now_dt,
            self.confirm_rate_limit_per_minute,
            window=dt.timedelta(minutes=1),
        ):
            import json as _json_rl
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                "application/json; charset=utf-8",
                _json_rl.dumps({
                    "error": "rate_limited",
                    "scope": "enrollment_confirm",
                    "retry_after_seconds": 60,
                }) + "\n",
            )

        # Look up by the token_id that the URI's `&token=` param embeds.
        # We persist the full URI in enrollment_token_uri, so we match by
        # substring. The URI shape is canonical (see _build_token_uri),
        # so this is unambiguous in practice — but we still LIMIT 1 to
        # keep behaviour deterministic if two rows ever collide.
        needle = f"token={token_id}"
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM onboarding_requests "
                "WHERE enrollment_token_uri LIKE ? LIMIT 1",
                (f"%{needle}%",),
            ).fetchone()
            if not row:
                return (
                    HTTPStatus.NOT_FOUND,
                    "text/plain; charset=utf-8",
                    "no onboarding row matches that token_id\n",
                )
            now_iso = self.now().replace(microsecond=0).isoformat()
            conn.execute(
                """
                UPDATE onboarding_requests
                SET enrollment_status = 'redeemed',
                    enrollment_redeemed_at = ?,
                    enrollment_redeemed_node_id = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (now_iso, node_id, now_iso, row["id"]),
            )

        # v0.30.12 auto-bind: if the CLI sent a valid pubkey_hex, treat
        # this confirm call as an implicit first-bind of the admin's Noise
        # static pubkey. Errors are logged but do NOT fail the confirm —
        # the device IS enrolled at NS regardless, and the admin can still
        # POST to /api/admin-pubkey explicitly with the claim_token.
        import re as _re
        autobind_status = "skipped"  # skipped | applied | already_bound | invalid | provisioning_incomplete | error
        autobind_detail = ""
        if pubkey_hex:
            if not _re.fullmatch(r"[0-9a-f]{64}", pubkey_hex):
                autobind_status = "invalid"
                autobind_detail = "pubkey_hex must be 64 lowercase hex chars"
            else:
                slug = self._slug_for_row(row)
                if not slug:
                    autobind_status = "error"
                    autobind_detail = "tenant has no derivable slug"
                else:
                    instance_dir = self._instance_dir_for_slug(slug)
                    if not os.path.isfile(os.path.join(instance_dir, "instance.env")):
                        autobind_status = "provisioning_incomplete"
                        autobind_detail = "instance.env not found"
                    else:
                        applied, detail = self._apply_admin_pubkey(
                            instance_dir=instance_dir,
                            pubkey_hex=pubkey_hex,
                            first_bind_only=True,
                        )
                        if applied:
                            autobind_status = "applied"
                        elif detail.startswith("admin pubkey already bound"):
                            autobind_status = "already_bound"
                            autobind_detail = detail
                        else:
                            autobind_status = "error"
                            autobind_detail = detail

        # v0.30.13: write an audit row for every confirm with a non-empty
        # pubkey_hex — applied, refused, error, anything. Lets the legit
        # admin detect URI-race attempts via GET /api/audit/<token_id>.
        # (issue #55). We deliberately do NOT audit empty-pubkey confirms
        # because the original Phase B contract is "this is best-effort
        # status book-keeping" — non-autobind confirms aren't security
        # events.
        if pubkey_hex:
            self.record_autobind_audit(
                token_id=token_id,
                pubkey_hex=pubkey_hex,
                source_ip=source_ip,
                result=autobind_status,
                detail=autobind_detail,
                occurred_at=now_dt,
            )

        # Tiny JSON-ish ack so curl users see what happened.
        import json as _json
        return (
            HTTPStatus.OK,
            "application/json; charset=utf-8",
            _json.dumps({
                "status": "redeemed",
                "name": name,
                "autobind": autobind_status,
                **({"autobind_detail": autobind_detail} if autobind_detail else {}),
            }) + "\n",
        )

    def handle_admin_pubkey(self, environ: dict) -> Tuple[HTTPStatus, str, str]:
        """Bind (or rebind) the admin's Noise static pubkey for passwordless gateway auth.

        Auth: holder of the original claim_token. The token was issued at /start
        time, shown once to the admin who provisioned the tenant, and stored in
        the DB only as an HMAC digest. Anyone with the raw token already has
        full control of this tenant (they used it to claim it), so re-using it
        as the auth credential for this endpoint does not widen the trust
        boundary.

        Side effects on success:
          1. Rewrites the ZTLP_ADMIN_PUBKEY_HEX line in <instance_dir>/instance.env.
          2. Runs `docker compose up -d --force-recreate gateway` in the
             instance dir so the new env var is picked up — without this the
             running gateway keeps using whatever it loaded at last start.

        Body (application/x-www-form-urlencoded):
          token=<claim_token>&pubkey_hex=<64 hex chars>

        Returns JSON:
          200 {"status":"ok","slug":"...","applied":true}
          400 {"error":"<reason>"}
          401 {"error":"invalid or expired token"}
          404 {"error":"instance not provisioned yet"}
          500 {"error":"docker recreate failed","detail":"..."}
        """
        import json
        import re
        import sys
        import subprocess

        def err(status: HTTPStatus, msg: str, **extra) -> Tuple[HTTPStatus, str, str]:
            payload = {"error": msg, **extra}
            return (status, "application/json; charset=utf-8", json.dumps(payload))

        form = self.read_form(environ)
        token = form.get("token", [""])[0].strip()
        pubkey_hex = form.get("pubkey_hex", [""])[0].strip().lower()

        if not token:
            return err(HTTPStatus.UNAUTHORIZED, "invalid or expired token")
        # Mirror the Rust gateway's --admin-pubkey-email validation: must be
        # exactly 64 lowercase hex chars (32-byte X25519 public key). Reject
        # early so the admin gets a clear error instead of a silent "gateway
        # still asks for a password" after the recreate.
        if not re.fullmatch(r"[0-9a-f]{64}", pubkey_hex):
            return err(
                HTTPStatus.BAD_REQUEST,
                "pubkey_hex must be exactly 64 lowercase hex characters (32-byte X25519 public key)",
            )

        row = self.find_by_token(token)
        if not row:
            return err(HTTPStatus.UNAUTHORIZED, "invalid or expired token")
        if parse_iso(row["claim_expires_at"]) < self.now():
            # Unclaimed expired tokens are clearly invalid. Claimed-then-expired
            # tokens are also rejected: once claimed, the admin should be using
            # the tenant's own UI, not Launch endpoints, to manage state.
            if not row["claimed_at"]:
                return err(HTTPStatus.UNAUTHORIZED, "invalid or expired token")

        slug = self._slug_for_row(row)
        if not slug:
            return err(HTTPStatus.BAD_REQUEST, "tenant has no derivable slug (empty organization name)")

        instance_dir = self._instance_dir_for_slug(slug)
        instance_env_path = os.path.join(instance_dir, "instance.env")
        if not os.path.isfile(instance_env_path):
            return err(
                HTTPStatus.NOT_FOUND,
                "instance not provisioned yet — visit the claim link first",
            )

        # Delegate the actual env-rewrite + force-recreate to the shared
        # helper so this endpoint and the confirm-callback path can't drift.
        # Explicit endpoint, so first_bind_only=False — operators can rebind
        # via this endpoint even after a prior bind (token still gates it).
        applied, detail = self._apply_admin_pubkey(
            instance_dir=instance_dir,
            pubkey_hex=pubkey_hex,
            first_bind_only=False,
        )
        if not applied:
            return err(HTTPStatus.INTERNAL_SERVER_ERROR, "could not bind admin pubkey", detail=detail)

        return (
            HTTPStatus.OK,
            "application/json; charset=utf-8",
            json.dumps({"status": "ok", "slug": slug, "applied": True}),
        )

    # ------------------------------------------------------------------
    # _apply_admin_pubkey: shared helper for the two endpoints that can
    # bind/rebind the admin's Noise static pubkey.
    #
    # Called by:
    #   1. handle_admin_pubkey            — explicit, claim_token-authed
    #   2. handle_enrollment_confirm      — implicit, piggybacks on the
    #                                        CLI's post-enrollment callback
    #
    # The confirm-callback path passes first_bind_only=True so an attacker
    # who scrapes the URI cannot rebind the admin pubkey after the legit
    # admin has already enrolled. The explicit /api/admin-pubkey path
    # bypasses the first-bind gate because the claim_token in the body is
    # already a stronger auth signal than the unauthenticated callback.
    #
    # Returns (applied: bool, detail: str). detail is empty on success and
    # a human-readable reason on failure ("already bound", "docker recreate
    # failed: ...", "could not update instance.env: ...", etc.).
    # ------------------------------------------------------------------
    def handle_audit_query(self, path: str) -> Tuple[HTTPStatus, str, str]:
        """GET /api/audit/<token_id> — return autobind audit rows as JSON.

        v0.30.13 (issue #55). Lets the holder of an enrollment URI (the
        legit admin or their dashboard) check whether any other party
        attempted to bind a different pubkey to this tenant's gateway.

        Auth: none. The token_id is a 32-char hex secret already; holding
        it implies you also held the URI. Rows expose only:
          * pubkey_hex_short (first 16 chars — enough to confirm "is this
            MY key?", not enough to recover the attacker's key)
          * source_ip
          * result + detail
          * occurred_at

        Returns JSON:
          200 {"token_id":"...","rows":[{...}, ...]}
          400 {"error":"missing token_id"}
        """
        import json as _json_aq
        token_id = path[len("/api/audit/"):].strip()
        if not token_id:
            return (
                HTTPStatus.BAD_REQUEST,
                "application/json; charset=utf-8",
                _json_aq.dumps({"error": "missing token_id"}) + "\n",
            )
        rows = self.fetch_autobind_audit(token_id)
        return (
            HTTPStatus.OK,
            "application/json; charset=utf-8",
            _json_aq.dumps({"token_id": token_id, "rows": rows}) + "\n",
        )

    def _apply_admin_pubkey(
        self,
        instance_dir: str,
        pubkey_hex: str,
        first_bind_only: bool,
    ) -> Tuple[bool, str]:
        import subprocess
        import sys

        instance_env_path = os.path.join(instance_dir, "instance.env")
        try:
            with open(instance_env_path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as exc:
            return (False, f"could not read instance.env: {exc}")

        # First-bind gate: if a non-empty ZTLP_ADMIN_PUBKEY_HEX is already
        # present, refuse to overwrite it from the confirm-callback path.
        # This is the trust mitigation Steve signed off on — the URI is a
        # one-shot bind credential; subsequent confirms (e.g. an attacker
        # who scraped it) must not be able to rebind to their own pubkey.
        if first_bind_only:
            current = ""
            for line in lines:
                if line.startswith("ZTLP_ADMIN_PUBKEY_HEX="):
                    current = line.split("=", 1)[1].strip()
                    break
            if current:
                # Idempotency: if the caller is binding the SAME pubkey,
                # treat as a no-op success so a CLI retry doesn't print a
                # scary warning.
                if current.lower() == pubkey_hex.lower():
                    return (True, "")
                return (False, "admin pubkey already bound (first-bind gate)")

        # Rewrite ZTLP_ADMIN_PUBKEY_HEX in-place. Preserve all other lines
        # exactly so we don't disturb other operator-set keys.
        new_lines = []
        saw_key = False
        for line in lines:
            if line.startswith("ZTLP_ADMIN_PUBKEY_HEX="):
                new_lines.append(f"ZTLP_ADMIN_PUBKEY_HEX={pubkey_hex}\n")
                saw_key = True
            else:
                new_lines.append(line)
        if not saw_key:
            # Older instances provisioned before this key existed — append.
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines[-1] += "\n"
            new_lines.append(f"ZTLP_ADMIN_PUBKEY_HEX={pubkey_hex}\n")
        try:
            with open(instance_env_path, "w", encoding="utf-8") as fh:
                fh.writelines(new_lines)
        except OSError as exc:
            return (False, f"could not update instance.env: {exc}")

        # Re-create the gateway container so the new env var is picked up.
        # --force-recreate is required: `up -d` alone is a no-op when the
        # image+config hash is unchanged and a new env_file value alone does
        # not bust that hash for already-running containers.
        try:
            result = subprocess.run(
                ["docker", "compose", "up", "-d", "--force-recreate", "gateway"],
                cwd=instance_dir,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return (False, f"docker recreate failed: {exc}")

        if result.returncode != 0:
            print(
                f"_apply_admin_pubkey: docker compose up failed for "
                f"{instance_dir} (rc={result.returncode}) stderr={result.stderr!r}",
                file=sys.stderr,
            )
            return (False, result.stderr.strip() or f"exit code {result.returncode}")

        return (True, "")

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
            # We track uniqueness by zone, not company name, because zone translates directly
            # to the DNS routing required. Company name is superficial.
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

    def rate_limit_exceeded(
        self,
        scope: str,
        key: str,
        now_dt: dt.datetime,
        limit: int,
        window: dt.timedelta = dt.timedelta(hours=1),
    ) -> bool:
        """Check whether ``(scope, key)`` has exceeded ``limit`` attempts in ``window``.

        The original signature was a fixed 1-hour window for onboarding
        anti-abuse. v0.30.13 generalises it so the confirm-callback
        endpoint can apply a tighter per-minute window without
        duplicating the SQL.
        """
        if limit <= 0:
            return False
        window_start = (now_dt - window).isoformat()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM rate_limit_attempts WHERE scope = ? AND key = ? AND occurred_at >= ?",
                (scope, key, window_start),
            ).fetchone()
        count = row[0] if row else 0
        return count > limit

    # v0.30.13: audit log helpers for the autobind flow (issue #55).
    # Every call into _apply_admin_pubkey records a row here regardless of
    # outcome — that's the visibility tool that lets a legit admin detect
    # an attacker who tried to win the URI-race. Read back by tenant via
    # GET /api/audit/<token_id>.
    def record_autobind_audit(
        self,
        token_id: str,
        pubkey_hex: str,
        source_ip: str,
        result: str,
        detail: str,
        occurred_at: dt.datetime,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO autobind_audit
                  (token_id, pubkey_hex_short, source_ip, result, detail, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    token_id,
                    (pubkey_hex or "")[:16],
                    source_ip or "unknown",
                    result,
                    detail or "",
                    occurred_at.isoformat(),
                ),
            )

    def fetch_autobind_audit(self, token_id: str, limit: int = 50) -> list[dict]:
        """Return the most-recent ``limit`` audit rows for ``token_id``."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, pubkey_hex_short, source_ip, result, detail, occurred_at
                FROM autobind_audit
                WHERE token_id = ?
                ORDER BY occurred_at DESC
                LIMIT ?
                """,
                (token_id, int(limit)),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "pubkey_hex_short": r["pubkey_hex_short"],
                "source_ip": r["source_ip"],
                "result": r["result"],
                "detail": r["detail"],
                "occurred_at": r["occurred_at"],
            }
            for r in rows
        ]

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

    def _slug_for_row(self, row: sqlite3.Row) -> str:
        """Derive the deterministic instance slug from a request row.

        Same algorithm as _provision_zone_dockers — extracted into a helper so
        post-claim endpoints (e.g. POST /api/admin-pubkey) can locate the
        instance directory without re-implementing the rules.
        """
        org_name = row["organization_name"] or ""
        slug_raw = "".join(c if c.isalnum() else "-" for c in org_name.lower())
        while "--" in slug_raw:
            slug_raw = slug_raw.replace("--", "-")
        return slug_raw.strip("-")

    def _instance_dir_for_slug(self, slug: str) -> str:
        instance_root = os.environ.get(
            "LAUNCH_INSTANCE_ROOT",
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "instances")),
        )
        return os.path.join(instance_root, slug)

    def find_by_token(self, token: str) -> Optional[sqlite3.Row]:
        digest = self.token_digest(token)
        with self.connect() as conn:
            return conn.execute("SELECT * FROM onboarding_requests WHERE claim_token_digest = ?", (digest,)).fetchone()

    def absolute_url(self, environ: dict, path: str) -> str:
        # Honour reverse-proxy forwarded headers (ngrok / load balancers etc.).
        # Both may be comma-separated; take the first entry, stripped.
        def _first(header_value: Optional[str]) -> Optional[str]:
            if not header_value:
                return None
            first = header_value.split(",")[0].strip()
            return first or None

        forwarded_host = _first(environ.get("HTTP_X_FORWARDED_HOST"))
        host = forwarded_host or environ.get("HTTP_HOST")
        if not host:
            server_name = environ.get("SERVER_NAME")
            server_port = environ.get("SERVER_PORT")
            if server_name and server_port in ("80", "443", None, ""):
                host = server_name
            elif server_name and server_port:
                host = f"{server_name}:{server_port}"
            else:
                host = self.public_host
        forwarded_proto = _first(environ.get("HTTP_X_FORWARDED_PROTO"))
        scheme = forwarded_proto or environ.get("wsgi.url_scheme", "http")
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
    """Generate a ztlp://enroll/ URI in the canonical query-param format.

    The canonical URI shape is:
      ztlp://enroll/?zone=<zone>&ns=<host:port>&token=<hex>&expires=<unix>
                    [&relay=<addr>][&gateway=<addr>][&callback=<url>]
                    [&nonce=<32hex>&mac=<64hex>]

    The trailing ``nonce`` + ``mac`` are present iff the environment variable
    ``ZTLP_ENROLLMENT_SECRET`` is set to a 64-hex-char value (32 bytes).
    When present, the MAC is HMAC-BLAKE2s over the canonical *binary*
    serialization of the token (matching ``serialize_without_mac()`` in
    ``proto/src/enrollment.rs``), so the Rust CLI and Elixir NS can verify
    using their existing binary-token paths with zero new verify logic.

    Without the secret, URIs are emitted in the legacy unsigned form
    (no ``nonce`` or ``mac``). This keeps existing deployments working
    while operators migrate. NS must be configured with
    ``ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false`` to accept unsigned URIs.

    Args:
        zone: DNS zone for the enrolled device (e.g. ``acme.ztlp``).
        ns_server: NS UDP listener as ``host:port``.
        expires_at: Token expiry (UTC).
        secret_hex: **Legacy unused parameter**, kept for callsite API
            stability. The actual HMAC key comes from
            ``ZTLP_ENROLLMENT_SECRET`` env when present. Future PRs may
            remove this argument once all callers stop passing it.
        relay_addr: Optional relay address as ``host:port``.
        gateway_addr: Optional gateway address as ``host:port``. When set,
            the canonical-form flag byte is 0x01 and the gateway string
            is part of the MAC input.
        callback_url: Optional callback URL for redemption confirmation
            (Phase B). Not part of the MAC (callback is delivery metadata,
            not auth-critical token content).

    Returns:
        A canonical ``ztlp://enroll/?…`` URI string.

    Raises:
        ValueError: If ``ZTLP_ENROLLMENT_SECRET`` is set but is the
            well-known sequential-byte placeholder ``000102…1e1f``. Fails
            loud rather than minting tokens with a publicly-known key.
    """
    # Generate token_id and nonce. The token_id is the URI-level
    # identifier used by the Phase B callback to look up the row; the
    # nonce is the 16-byte replay-prevention field embedded in the
    # binary token's serialized form.
    expires_unix = int(expires_at.timestamp())
    token_hex = secrets.token_hex(16)

    # Resolve the shared signing secret. When set, the placeholder check
    # below guards against accidentally shipping a publicly-known key.
    raw_secret = os.environ.get("ZTLP_ENROLLMENT_SECRET", "").strip()
    signing_key: bytes | None = None
    if raw_secret:
        # Reject the well-known byte-counting placeholder
        # ``000102…1e1f`` (32 sequential bytes) that appears in the
        # ``.env.example`` doc. Operators must generate a real secret
        # with e.g. ``openssl rand -hex 32``. We compare on the canonical
        # lowercase-hex form to catch case-mismatch variants.
        placeholder_hex = bytes(range(32)).hex()
        if raw_secret.lower() == placeholder_hex:
            raise ValueError(
                "ZTLP_ENROLLMENT_SECRET is set to the byte-counting "
                "placeholder value (00010203…1e1f). Generate a real "
                "32-byte secret with `openssl rand -hex 32` and store "
                "it in the .env file. Refusing to mint a token signed "
                "with a publicly-known key."
            )
        try:
            signing_key = bytes.fromhex(raw_secret)
        except ValueError as exc:
            raise ValueError(
                "ZTLP_ENROLLMENT_SECRET must be 64 hex chars (32 bytes); "
                f"got invalid hex: {exc}"
            ) from exc
        if len(signing_key) != 32:
            raise ValueError(
                "ZTLP_ENROLLMENT_SECRET must decode to exactly 32 bytes; "
                f"got {len(signing_key)} bytes."
            )

    # Build query string manually to avoid over-encoding colons in host:port values.
    qs_parts = [
        f"zone={urllib.parse.quote(zone)}",
        f"ns={ns_server}",
        f"token={token_hex}",
        f"expires={expires_unix}",
    ]
    qs = "&".join(qs_parts)

    if relay_addr:
        qs += f"&relay={relay_addr}"
    if gateway_addr:
        qs += f"&gateway={gateway_addr}"
    if callback_url:
        qs += f"&callback={urllib.parse.quote(callback_url)}"

    # If a signing secret is configured, append &nonce=<hex>&mac=<hex>.
    # The MAC covers the binary serialization of the token (NOT the URI
    # string), so NS can reuse its existing HMAC-BLAKE2s verify path.
    if signing_key is not None:
        nonce = secrets.token_bytes(16)
        canonical = _serialize_enrollment_token_for_signing(
            zone=zone,
            ns_addr=ns_server,
            relay_addrs=[relay_addr] if relay_addr else [],
            gateway_addr=gateway_addr or None,
            max_uses=1,
            expires_at=expires_unix,
            nonce=nonce,
        )
        mac = hmac.new(signing_key, canonical, hashlib.blake2s).digest()
        qs += f"&nonce={nonce.hex()}&mac={mac.hex()}"

    return f"ztlp://enroll/?{qs}"


def _serialize_enrollment_token_for_signing(
    *,
    zone: str,
    ns_addr: str,
    relay_addrs: list[str],
    gateway_addr: str | None,
    max_uses: int,
    expires_at: int,
    nonce: bytes,
) -> bytes:
    """Byte-for-byte port of ``serialize_without_mac()`` from
    ``proto/src/enrollment.rs``.

    Must produce identical bytes to the Rust implementation so the Rust CLI
    can parse the URI, reconstruct the binary token, and the NS can verify
    the MAC using its existing HMAC-BLAKE2s code path.

    Wire format (big-endian):

        version u8     = 0x01
        flags u8       = 0x01 if gateway_addr else 0x00
        zone           : u16 length + UTF-8 bytes
        ns_addr        : u16 length + UTF-8 bytes
        relay_count u8
        relay_addr[]   : (u16 length + UTF-8 bytes) * relay_count
        gateway_addr   : u16 length + UTF-8 bytes  [ONLY when flags & 0x01]
        max_uses u16
        expires_at u64
        nonce          : 16 raw bytes

    The MAC field (32 bytes) is NOT included here — that's the whole point
    of "without_mac"; it's the input over which the MAC is computed.
    """
    buf = bytearray()
    buf.append(0x01)  # version
    buf.append(0x01 if gateway_addr else 0x00)  # flags

    def _write_len_prefixed(s: str) -> None:
        s_bytes = s.encode("utf-8")
        buf.extend(len(s_bytes).to_bytes(2, "big"))
        buf.extend(s_bytes)

    _write_len_prefixed(zone)
    _write_len_prefixed(ns_addr)

    buf.append(len(relay_addrs))
    for addr in relay_addrs:
        _write_len_prefixed(addr)

    if gateway_addr:
        _write_len_prefixed(gateway_addr)

    buf.extend(max_uses.to_bytes(2, "big"))
    buf.extend(expires_at.to_bytes(8, "big"))
    if len(nonce) != 16:
        raise ValueError(f"nonce must be exactly 16 bytes, got {len(nonce)}")
    buf.extend(nonce)

    return bytes(buf)


application = LaunchApp()


def main() -> None:
    host = os.environ.get("LAUNCH_BIND_HOST", "0.0.0.0")
    port = int(os.environ.get("LAUNCH_BIND_PORT", "8080"))
    print(f"ZTLP Launch listening on {host}:{port}; db={application.db_path}", flush=True)
    with make_server(host, port, application) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()

