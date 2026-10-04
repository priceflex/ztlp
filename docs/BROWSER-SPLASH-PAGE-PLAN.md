# Browser splash page while the tunnel connects

Status: plan, not built. Written 2026-09-30 after the v0.35.12 Windows release.
Branch: `feat/browser-splash-page` (from main at `829016f`).

## 1. Problem

The first time a browser opens `https://<name>.<zone>.ztlp/`, the agent has to
resolve the name, dial the relay, and run the handshake before any bytes can
flow. During that time Chrome shows a blank page and a spinning tab. The user
cannot tell whether ZTLP is working, and may give up or reload.

## 2. Goal

When a real browser is loading a page and the tunnel is not up yet, show a
branded splash page (ZTLP logo, a rotating friendly line, a spinner). The page
checks readiness itself and reloads when the tunnel is up, so the real site
appears with no user action.

Hard requirement: API clients must never see the splash. Anything that is not
a browser page load keeps today's behavior (the request waits for the tunnel,
then is forwarded; or fails with the existing error).

## 3. Where this lives in the code

All in `proto/src/agent/daemon.rs` (and a new small module for the page).

- `handle_tcp_connection_with_tls` (about line 1430): terminates local TLS
  via `local_tls::maybe_wrap_tls`, then calls the bridge.
- `proxy_dial_phase` (about line 1535): NS resolve, relay `CLIENT_ROUTE`,
  QUIC connect, Noise handshake, forwards the client's first bytes, waits for
  the backend's first response frame. Owns only `client_read`.
- `proxy_dial_then_bridge`: split-socket handler. The write half stays with the
  outer task so it can write a page on deadline expiry. Deadline is
  `DEFAULT_FIRST_BYTE_TIMEOUT` = 15s.
- `stall_response_for_port` / `stall_close_strategy`: today's branded 504,
  plain unstyled HTML, ports 80, 8080, 443, 8443 only.

The existing split-socket design is what makes this feasible: the write half
is still available while the dial is in progress, so the agent can answer the
browser before the tunnel exists.

## 4. Telling a browser from an API client

Do not use User-Agent (any client can send anything).

A request gets the splash only if ALL are true:

1. Method is `GET`.
2. `Sec-Fetch-Mode: navigate`.
3. `Sec-Fetch-Dest: document` (also allow `iframe`? decide: no, document only).
4. `Accept` includes `text/html`.

Browsers add the `Sec-Fetch-*` headers themselves on page loads and page
scripts cannot set them. `curl`, `requests`, Postman, and `fetch()`/XHR do not
send `navigate`. Everything else takes the existing path.

Known limits:
- A browser tab doing API calls uses `fetch`, so it gets the normal path.
- Old browsers without `Sec-Fetch-*` get no splash (acceptable, safe default).
- A custom API client that sends `Sec-Fetch-Mode: navigate` gets the splash.
  Real clients do not send it by default.

## 5. Request flow

1. TLS handshake completes as today.
2. Read the first HTTP request head from the client (up to the blank line,
   capped at 16 KiB, with a short read timeout). Keep the bytes buffered.
3. Classify with section 4.
4. Start the dial as today, replaying the buffered bytes into the tunnel once
   it is up.
5. Grace period (about 1s, tunable): if the first backend byte arrives within
   it, forward normally and nobody sees a splash. This is the common case
   when the tunnel is warm.
6. If the grace period passes and the request is a browser page load, write
   the splash response (200, `Cache-Control: no-store`, `Connection: close`)
   through the retained write half, then close. Keep the dial running in the
   background so the tunnel warms up.
7. Non-browser request: no splash. Same behavior as today (hold until the
   tunnel is up, forward, or 504 on deadline).

Open question: the splash closes the connection, so the dial for THIS request
is abandoned. The warm-up must finish and be cached (the tunnel pool already
exists: `tunnel_pool.rs`) so the page's reload finds a ready tunnel. Verify
that the pool keeps a tunnel that finished dialing after its first request
was dropped.

## 6. Readiness endpoint

The splash script polls `GET /.ztlp/ready` on the same origin.

- The agent answers this itself, before the tunnel, for any host it serves.
- Response: `200 {"ready":true}` once a tunnel for that host is established,
  else `200 {"ready":false}`. Never forwarded to the backend.
- Reserved path `/.ztlp/` must be documented as agent-owned. Check that no
  existing backend uses it (low risk).
- Poll every 500 ms. On `ready`, `location.reload()`.
- Give up after about 60s and show a clear message with a Retry button and the
  agent status text, not an endless spinner.

## 7. The page

- Single self-contained HTML string baked into the agent (no network needed,
  no external requests; the logo is an inlined data URI).
- Logo: `desktop/src/assets/ztlp-logo.png` (shield with padlock). Downscale to
  about 160 px wide to keep the page small; inline as base64. A small SVG
  fallback (`shield.svg`) if the PNG is too heavy.
- Look: centered card, soft gradient background, subtle pulse on the logo,
  CSS-only spinner, system font stack, works in light and dark
  (`prefers-color-scheme`), respects `prefers-reduced-motion`.
- Rotating message every ~3s, random start, no repeat in a row. Starter list:
  - Securing your connection
  - Zipping through the internet securely
  - Look mom, no passwords
  - Knocking politely on the zero-trust door
  - Teaching the packets to whisper
  - Checking everyone's name tag
  - Building you a private tunnel
  - Almost there, it is worth the wait
  Keep them mild and safe for customer-facing screens. Final list to be
  approved by Steven.
- Show the site name being connected to (HTML-escaped; it is attacker
  influenced via DNS/Host, so escape it, same lesson as the Home-screen XSS
  fix in #113).
- Same look reused for the 504 page, with a "Retry" button, replacing the
  plain HTML in `stall_response_for_port`.

## 7b. Security notes

- Escape the hostname before putting it in HTML. No other request data is
  reflected.
- Send `Content-Security-Policy: default-src 'none'; img-src data:;
  style-src 'unsafe-inline'; script-src 'unsafe-inline'`, and
  `X-Content-Type-Options: nosniff`. Use a per-response nonce instead of
  `'unsafe-inline'` for the script if the CSP review wants it.
- The `/.ztlp/ready` endpoint must not leak anything beyond ready/not ready
  for the requested host.
- Splash is only ever served after the local TLS handshake with the
  agent's own cert for that host, so no new trust surface.
- Limit the pre-dial request-head read (size and time) so a slow client
  cannot hold resources.

## 8. Implementation steps (TDD, one slice each)

1. Pure function `is_browser_navigation(head: &[u8]) -> bool` with table
   tests: Chrome/Firefox/Safari navigation (true); curl, python-requests,
   `fetch` (`Sec-Fetch-Mode: cors`), POST, missing Accept, forged User-Agent
   only (all false).
2. Request-head reader: reads to `\r\n\r\n`, 16 KiB cap, timeout, returns the
   buffered bytes. Tests: split reads, oversize, slow client.
3. Splash HTML builder in a new `proto/src/agent/splash.rs`: takes the
   hostname, returns a complete HTTP response. Tests: escaping, headers
   (no-store, CSP), contains logo data URI, size under a budget (target
   under 60 KB).
4. `/.ztlp/ready` handler with a tunnel-ready lookup. Tests: not ready,
   ready, unknown host, never forwarded.
5. Wire into `handle_tcp_connection_with_tls` / `proxy_dial_then_bridge`:
   grace period, splash on browser navigations only, buffered replay for the
   normal path. Integration test with a stalled dial: browser request gets
   the splash; `curl`-style request does not.
6. Restyle the 504 page to match and add Retry.
7. Windows end-to-end on the AI computer (10.170.3.207): fresh install,
   enroll, open the site in Chrome with the tunnel cold, confirm the splash
   shows and the site appears on its own; confirm `curl.exe` against the same
   host never gets HTML from the splash.
8. Docs: short section in the user docs, mention the reserved
   `/.ztlp/` path.

## 9. Acceptance

- Cold tunnel, Chrome: splash appears (after the grace period) and the real
  site loads by itself, no click.
- Warm tunnel: no splash at all, no added latency beyond the header read.
- `curl`, Python `requests`, Postman, `fetch()`: byte-for-byte same behavior
  as today. No HTML from the splash.
- POST/PUT and non-HTML Accept requests never see the splash.
- Hostname with HTML characters is escaped.
- No regression on Windows first-run flow (clean install cycle).
- Same code works on macOS and Linux (the proxy path is shared).

## 10. Risks and open questions

1. Tunnel-pool behavior when the first request is dropped (section 5).
2. Pages that depend on the very first response being the real site
   (rare): the grace period keeps these working when the tunnel is warm.
3. HSTS and caching: `no-store` on the splash so the browser never caches it
   as the site.
4. HTTP/2: the browser may negotiate h2 on the local TLS side. Check whether
   the local listener offers ALPN h2; if it only speaks HTTP/1.1 this plan
   works as written, otherwise the head parsing needs an h2 path.
5. Non-HTTP ports (SSH, RDP, DB): never touched. Only 80, 8080, 443, 8443.
6. Message list needs Steven's approval before release.

## 11. Context for the next session

- Repo `/home/trs/ztlp`, this branch, no code written yet.
- The test PC for end-to-end is 10.170.3.207 (see skill
  `ztlp-ai-computer-agent-deploy` and the Windows first-run handoffs).
  Enrollment codes are single use; mint a fresh one per test.
- Release flow: PR, CI green, read CodeRabbit comments, then merge, then tag
  (see skill `ztlp-github-repo-release`). Do not push or merge without
  Steven's go-ahead.
- Related unfinished items: worker API key rotation and port 7777
  lockdown, relay secret inside the enrollment code, Setup/Settings
  restyle to match Home, design doc
  `docs/WINDOWS-MULTI-USER-IDENTITY-DESIGN.md` (committed on branch
  `docs/windows-multi-user-identity`, not pushed).
