#!/usr/bin/env python3
"""ZTLP Bootstrap Z2LS reference client (Python).

Self-contained example of how to sign and POST a request to the
ZTLP-secured Bootstrap API. Designed to be copied into a Z2LS
codebase verbatim and adapted.

Documented in detail in `bootstrap/docs/z2ls_enrollment_runbook.md`.

Usage:

  export BOOTSTRAP_URL="https://bootstrap.acme.ztlp"
  export ZTLP_ZONE="acme.ztlp"
  export ZTLP_CLIENT="z2ls.acme"
  export ZTLP_HMAC_SECRET_ACME_ZTLP="<64-char hex OR raw bytes>"

  python3 bootstrap/script/z2ls_request_token.py alice-laptop
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
from typing import Any, Mapping
from urllib import error, request


def _decode_secret(secret: str | bytes) -> bytes:
    """Match the Bootstrap authenticator's decoding rule.

    A 64-character pure-hex string is decoded to its 32 raw bytes.
    Anything else is returned as UTF-8 bytes (or passed through if
    already bytes).
    """
    if isinstance(secret, bytes):
        return secret
    if len(secret) == 64 and all(c in "0123456789abcdefABCDEF" for c in secret):
        return bytes.fromhex(secret)
    return secret.encode("utf-8")


def ztlp_sign(*, method: str, path: str, zone: str, client: str,
              timestamp: int, body: str | bytes, secret: str | bytes) -> str:
    """Return the hex HMAC-SHA256 for a ZTLP-secured Bootstrap request.

    See `bootstrap/docs/api_v1_ztlp_secured.md` § "Request signing"
    for the canonical 6-line message.
    """
    key = _decode_secret(secret)
    body_bytes = body.encode("utf-8") if isinstance(body, str) else (body or b"")
    body_digest = hashlib.sha256(body_bytes).hexdigest()

    message = "\n".join([
        method.upper(),
        path,
        zone,
        client,
        str(timestamp),
        body_digest,
    ]).encode("utf-8")

    return hmac.new(key, message, hashlib.sha256).hexdigest()


def request_enrollment_token(
    *, bootstrap_url: str, zone: str, client: str, secret: str,
    computer_name: str, metadata: Mapping[str, Any] | None = None,
    timeout: float = 10.0,
) -> dict:
    """End-to-end: sign + POST + return the parsed JSON response.

    Raises on non-2xx responses with the server-provided JSON body
    in the exception message.
    """
    path = "/api/v1/enrollment_tokens"
    payload: dict[str, Any] = {"computer_name": computer_name}
    if metadata:
        payload["metadata"] = dict(metadata)

    body = json.dumps(payload, separators=(",", ":"))
    ts = int(time.time())
    sig = ztlp_sign(
        method="POST", path=path, zone=zone, client=client,
        timestamp=ts, body=body, secret=secret,
    )

    req = request.Request(
        url=f"{bootstrap_url.rstrip('/')}{path}",
        data=body.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type":     "application/json",
            "X-ZTLP-Zone":      zone,
            "X-ZTLP-Client":    client,
            "X-ZTLP-Timestamp": str(ts),
            "X-ZTLP-Signature": sig,
        },
    )
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Bootstrap returned {e.code}: {body}") from None


def _env_secret_for_zone(zone: str) -> str:
    """Look up the per-zone secret env var by the same slugify rule
    the gateway/relay use:

        zone.upper().replace_non_alnum_to_underscore().strip("_")

    e.g. "acme.ztlp" -> "ZTLP_HMAC_SECRET_ACME_ZTLP".
    """
    slug = "".join(c if c.isalnum() else "_" for c in zone.upper())
    slug = "_".join(s for s in slug.split("_") if s)
    return os.environ[f"ZTLP_HMAC_SECRET_{slug}"]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"usage: {argv[0]} <computer_name>", file=sys.stderr)
        return 2

    computer_name = argv[1]
    bootstrap_url = os.environ.get("BOOTSTRAP_URL", "http://localhost:3000")
    zone = os.environ["ZTLP_ZONE"]
    client = os.environ["ZTLP_CLIENT"]
    secret = _env_secret_for_zone(zone)

    metadata: dict[str, Any] = {}
    for kv in argv[2:]:
        if "=" in kv:
            k, v = kv.split("=", 1)
            metadata[k] = v

    result = request_enrollment_token(
        bootstrap_url=bootstrap_url,
        zone=zone,
        client=client,
        secret=secret,
        computer_name=computer_name,
        metadata=metadata or None,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
