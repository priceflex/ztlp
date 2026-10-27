# UI walkthrough: bring up a new service using only admin.trs.ztlp

Goal (Steven, 2026-10-27): host a tiny app that shows the ZTLP identity (examples/whoami) and bring it
online using only what the admin panel offers, to find what the UI is missing.

Setup: app `ztlp-whoami` on the Hermes VM (10.69.95.14), Docker, 127.0.0.1:8095. Gateway on the same
box, UDP 23098 (23095/23097 already taken there). Name `whoami.trs.ztlp`. Panel v0.5.2.
Driven as a real admin: HTTP through ZTLP from Steven's Mac Studio (SSO), submitting the forms the
pages render.

## Steps and findings
| # | Step (UI) | Result | Gap? |
|---|-----------|--------|------|
| 1 | Services, Add service: full name, runs on, backend, protocol, sign-in headers, who can reach it, advanced (UDP port, NS, relay, image, subject map) | Every gateway setting needed was on the form; created as "planned" with a step list on the service page | no |
| 2 | Show install script (POST, 30 min window) | 87-line script + the 2 app env lines; secrets only in a mode-600 .env, clear "contains secrets" warning | no |
| 3 | `sudo bash install.sh` on the box | identity created on the box, persistent QUIC cert, UDP 23098, registered with relay (V1+V2) and NS (KEY+SVC) | see G2 (image) |
| 4 | App settings into the app's env | whoami verified the very first request: signature, audience, freshness all OK | no |
| 5 | Check now | "Gateway on the name server: Yes" within a minute | no |
| 6 | Open http://whoami.trs.ztlp/ from the Mac Studio (allowed device) | 200 in 0.26 s, person steve@trs.ztlp, device stevens-mac-studio.trs.ztlp | no |
| 7 | Same from the MacBook Pro (NOT in the rule) | 200, verified, device stevens-macbook-pro-2. Should have been refused | **G1** |

Signed SVC record for whoami.trs.ztlp carries the new gateway's cert pin (582ae789 = the gateway's own cert),
signed by the NS key 584a83c8: clients enrolled with a v0.5 token pin it from the NS, no TOFU.

## Gaps
- **G1 (security, gateway not panel): access rules are not enforced.** The Rust gateway's QUIC accept path
  (`cmd_listen`, `proto/src/bin/ztlp-cli.rs` ~5790 on main) resolves the service and signs the identity
  headers but never calls `policy.authorize[_async]`; only the legacy UDP `handle_new_session` path
  refuses. The panel's "Who can reach it", device/group/role rules, and Disable (user/device) therefore
  change nothing at the gateway. Until fixed, the app must enforce access itself from the signed headers.
  Fix: authorize (async, with NS resolver) after the service hash resolves and before dialling the
  backend; close the stream with a deny. Needs a gateway release + gateway restarts.
- **G2: the gateway image is not obtainable from the UI.** The script `docker pull`s
  `ztlp-gateway-rust:v0.36.0`, which exists only as a locally built image (not on any registry). Worked
  here only because the Hermes VM already had it. A fresh box fails with "load it on this box first".
  Fix: publish the image (GHCR) and default to that tag, or link a download from the install page.
- **G3 (minor): the panel does not show the gateway's cert pin** (`quic_cert_sha256` from the signed SVC
  record) on the service page. Useful when diagnosing "certificate does not match" reports.
- **G4 (noise): `KEY registration failed: rate-limited ... retry in 28800s`** on the first start: the
  gateway publishes the KEY twice within milliseconds; the first succeeded (records are present, signed,
  TTL 24 h). The 8 h retry is inside the 24 h TTL, so it self-heals, but it reads like a failure.
