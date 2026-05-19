# Hermes Session Handoff — ZTLP End-to-End Stack Test

> **Active session:** 2026-05-19 — feature/ztlp-end-to-end-stack-test
> **Agent:** Hermes (google/gemini-3.1-pro-preview)
> **Operator:** Steve Price

---

## 1. Mission

Run a real end-to-end test of the entire ZTLP stack — public site → bootstrap →
enrollment → device-to-device communication — exactly like a human user would.

Validate the data model: **a user can have many devices; a device must be
registered before it can communicate; both device-to-device and
user-on-device communication must work over the ZTLP network.**

Bonus: clean up the bootstrap UX so next-steps are obvious.

---

## 2. Topology — Locked In

| Role | Host | Port | Notes |
|------|------|------|-------|
| **Public site (ztlp.net)** | runs on Nameserver host, behind ngrok at `www.ztlp.net` | 8080 → 443 | Python WSGI launch app |
| **Nameserver (NS)** | `35.91.88.177` *(replaced 34.219.38.89 — OOM'd on bootstrap build)* | UDP 23096 | Also hosts ztlp.net + bootstrap. Ubuntu, 3.8GB RAM, 77GB disk |
| **Relay** | `34.218.240.106` | UDP 23095 | |
| **Gateway** | `54.218.127.30` | UDP 23097 | gateway = "copy private key" device |
| **Windows user box** | `10.170.3.111` | — | Steve runs commands here — private LAN, not reachable from dev box |
| **Vaultwarden test app** | TBD — co-locate on Gateway host | 80/443 | ZTLP-only access |

**SSH key** for all 3 AWS hosts: `~/ztlp/.ssh/ztlp_aws_key` (RSA, 0600, untracked).

**Users / roles:**
- `trs` — standard user, enrolled on the nameserver
- `hermes` — admin (auto-promoted by the registration flow on ztlp.net)

---

## 3. Implementation Plan

### ✅ Phase 1 — ztlp.net branded ngrok URL
- Re-launched ngrok with the supplied authtoken and `--url=www.ztlp.net`
- Updated `.env` values and hardcoded paths in `docker-compose.yml`
- Committed and pushed changes to NS.

### ✅ Phase 2 — Real human onboarding flow
- Walked through `https://www.ztlp.net/` → /start → /claim using a headless browser.
- Verified SQLite `onboarding_requests` row.
- Addressed multiple bugs in the provision dockers logic. 
- Clean deployment of `ztlp-bootstrap-tech-rockstars` to the NS host via `_provision_zone_dockers()`.

### ✅ Phase 3 — Bootstrap reachable + admin login
- Auto-promotion works: `[entrypoint] super_admin ensured: hermes@techrockstars.com`
- Header forgery protection hardened: Ported the Elixir HMAC verifier to Ruby (`Ztlp::HeaderVerifier`). Bootstrap now requires valid, per-zone `X-ZTLP-Signature` HMACs for `trusted_gateway_admin` logins.
- Tested bare-headers rejection, forged-signature rejection, and valid-signature success.

### ✅ Phase 5a — Enroll hermes admin device via ZTLP CLI
- Setup `ztlp-ns` on new NS host with required `ZTLP_ENROLLMENT_SECRET`.
- AWS SG UDP 23096 opened.
- Enrolled Hermes from Dev Box (`NodeID: 2ccc4c2621eac67ccbe5679f97cd37c3`).
- Verified `ztlp ns lookup hermes-dev.techrockstars.ztlp` returns the ZTLP_KEY record.

### ⏳ Phase 4 — Re-point the relay + gateway to the new zone
- Existing `ztlp-relay` (34.218.240.106) and `ztlp-gateway` (54.218.127.30) are running but need to point to the new NS `35.91.88.177`.
- For the Gateway, we must verify the "gateway works from key-copy alone" flow. We will wire the HTTP proxying to bootstrap.

### ⏳ Phase 5b — Enroll trs user device
- Provision an enrollment token via the bootstrap (now secure context) for Steve's user.

### ⏳ Phase 6 — Register Windows test box as trs's user-computer
- Steve runs `ztlp setup --token "..."` on the Windows box (I supply the URI).
- Confirm device appears in bootstrap, status=enrolled.

### ⏳ Phase 7 — Vaultwarden behind ZTLP
- `docker run -d vaultwarden/server` on Gateway host.
- Register as ZTLP service via gateway forwarder (svc_id → vault.techrockstars.ztlp).
- Verify reachability across the network (Dev Box & Windows test machine).

### ⏳ Phase 8 — Bootstrap UX cleanup
- Add prominent "Next Step" CTAs on the dashboard.
- Improve nav labels (Networks/Users/Devices/Tokens/Services).
- Make "create enrollment token" reachable in 1 click.
- Add inline help on every form.

### ⏳ Phase 9 — Tests + CI
- Test cleanup (38 launch tests ALREADY passing, 28 bootstrap auth VERIFIED passing).
- Push branch, open PR, watch CI, merge when green.

---

## 4. Ground State (Current)

| Item | Status |
|------|--------|
| Branch `feature/ztlp-end-to-end-stack-test` | All fixes committed locally (`47bc9fb`, `063f2f5`, `d60abe6`, `c6eec24`, `a20e754`, `46f8376`). |
| `ztlp-launch` | ✅ healthy on NS host (`35.91.88.177`), `0.0.0.0:8080` |
| `ngrok-launch` | ✅ tunneling to `www.ztlp.net` (HTTP 200 OK) |
| `ztlp-ns` | ✅ healthy on NS host |
| `ztlp-bootstrap-tech-rockstars`| ✅ healthy on NS host |
| `ztlp-relay` | ✅ healthy on Relay Host (`34.218.240.106`) |
| `ztlp-gateway` | ✅ healthy on Gateway Host (`54.218.127.30`) |

---

## 5. Decisions

1. **New NS Host**: `34.219.38.89` crashed due to OOM when building `priceflex/ztlp-bootstrap` from source. Switched to `35.91.88.177`.
2. **Docker Compile Strategy**: Never `docker build` the Rails app on the small NS instance. Build it on the dev box and copy via `docker save | ssh 'docker load'` to avoid OOM killer.
3. **Header Forgery Prevention**: We ported the Elixir HMAC verifier into the Rails Bootstrap codebase. Gateway authentication unconditionally requires valid cryptographic signatures over `X-ZTLP-*` headers.

---

## 6. Session Log

(See Git history for detailed commit summaries)
- **08:25 - 09:25 UTC** — Initial startup, bugs 1-6 found and fixed, original host `34.219.38.89` OOM crashed.
- **[Host Migrated to `35.91.88.177`]**
- Provisioned Docker. Migrated `priceflex/ztlp-bootstrap` and `ztlp-ns` using `docker save | docker load` to avoid OOM crash.
- Deployed ZTLP Launch and Ngrok. Web app healthy at `https://www.ztlp.net/health`.
- Fixed **Bug 7 & 8**: `ZTLP_NS_SERVER` pass-through via `docker-compose.yml` and correct `.get("ENV_VAR") or "default"` empty string logic.
- Conducted Phase 2 E2E workflow: Requested onboarding (`techrockstars.ztlp` using `ZTLP-HERMES-2026`) via browser. Claim token parsed, clicked, zone generated. `docker compose up -d` operated correctly via docker socket.
- Phase 3 & Security: Addressed **Bug 9 & 10**. Handled persistent `secrets.env` (for `SECRET_KEY_BASE` and ActiveRecord encryption) so instances survive container bounces. Created `ZTLP_GATEWAY_HEADER_SECRET` on generation. Fixed ENV var naming mismatch.
- Added **Bug 11**: Wired `docker-entrypoint` to parse `ZTLP_BOOTSTRAP_ADMIN_EMAIL` to automatically generate the `super_admin` (`hermes@techrockstars.com`).
- Ported Elixir `ZtlpGateway.HeaderVerifier` to Ruby in Bootstrap for Gateway auth check. Controller fully enforces HMAC logic and tests mock/test invalid, missing, and matched signatures.
- Recreated the bootstrap stack manually to ensure the new secrets workflow functioned.
- Ensured NS UDP 23096 was functionally accessible from WAN. Enrolled `hermes` agent locally with `ztlp setup`. Registration created node `2ccc4c2621eac67ccbe5679f97cd37c3` mapping to `hermes-dev.techrockstars.ztlp`.