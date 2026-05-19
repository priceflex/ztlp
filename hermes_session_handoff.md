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
| **Nameserver (NS)** | `35.91.88.177` | UDP 23096 | Also hosts ztlp.net + bootstrap. Ubuntu, 3.8GB RAM, 77GB disk |
| **Relay** | `34.218.240.106` | UDP 23095 | |
| **Gateway** | `54.218.127.30` | UDP 23097 | gateway = "copy private key" device |
| **Windows user box** | `10.170.3.111` | — | Steve runs commands here — private LAN, not reachable from dev box |
| **Vaultwarden test app** | TBD — co-locate on Gateway host | 80/443 | ZTLP-only access |

**SSH key** for all 3 AWS hosts: `~/ztlp/.ssh/ztlp_aws_key` (RSA, 0600, untracked).

**Users / roles:**
- `trs` — standard user, enrolled on the nameserver
- `hermes` — admin (auto-promoted by the registration flow on ztlp.net)

---

## 3. Implementation Plan & Progress

### ✅ Phase 1-3 & 5a: Initial Provisioning & Admin Enrollment
- Ngrok branded at `www.ztlp.net`
- Human onboarding flow successful via web interface
- Bootstrap reachable, hermes admin auto-promoted
- HMAC header forgery protection ported from Elixir to Ruby
- `hermes-dev` enrolled on new NS `35.91.88.177`.

### ✅ Phase 4: Network Re-pointing & Gateway Hardening
- **Gateway Repointed**: Re-pointed relay+gateway to `35.91.88.177:23096`. Confirmed UDP reachability matrix.
- **Config Bugs Fixed (Elixir/TDD)**:
  - Implemented `ZTLP_HEADER_SIGNING_ENABLED` to allow Docker environment orchestration for mTLS passthrough.
  - Implemented `Config.ns_server()` consolidating fragmented API paths checking multiple environment variables for NS endpoints (`ZTLP_NS_SERVER` vs `_HOST/_PORT`).
  - Fixed a `ServiceRegistrar.derive_service_names/1` boot crash related to calling `to_string/1` on an Erlang IPv4 tuple.
- **Service Registration**: Gateway correctly registers `web.techrockstars.ztlp` and `ssh.techrockstars.ztlp` with the NS (Verified via `ztlp ns lookup --record-type 2`).
- **HMAC UI Protection**: 3-curl smoke test verified that the Bootstrap properly accepts signed `X-ZTLP-*` requests and denies missing/forged headers.

### ✅ Phase 5b: Provision trs ZtlpUser & Token
- Provisioned `trs@techrockstars.com` via Rails runner, tied to `techrockstars.ztlp` network.
- Enrollment token explicitly generated for Phase 6.

### ✅ Phase 6: Enroll trs user device
- Steve successfully ran `ztlp setup --token "..."` on the Windows box (`10.170.3.111`).
- Enrolled as `desktop-trs.techrockstars.ztlp` (NodeID: `568d21043db7a37b783ac1350dffb63b`).
- Config written to `~/.ztlp/config.toml` natively.

### ✅ Phase 7: Vaultwarden test app
- Deployed Vaultwarden Container natively bridging `127.0.0.1:8081` onto gateway host `54.218.127.30`.
- Configured Gateway `ZTLP_GATEWAY_BACKENDS="vault:127.0.0.1:8081"` mapping onto policy arrays (`*:vault`).
- Discovered and mitigated an Elixir `PolicyEngine` matching bug resulting in backend `Session` hashes falling back to an unreadable state. Refactored `session.ex` to resolve against configuration string lookup matrices.
- Discovered and fixed a native bug where `ztlp proxy` failed to parse Type 2 `ZTLP_SVC` records using CBOR. Patched Rust binary for `0.26.0`, rebuilt natively and cross-deployed to Windows target.
- Sent test proxy HTTP pipeline through `ztlp proxy vault.techrockstars.ztlp 80` validating deep network traversal end-to-end to Vaultwarden backend!

### ⏳ Phase 4c-4: Wire HTTP HttpHeaderInjector (PENDING)
- The plain-ZTLP Session path on the Gateway does not yet invoke `HttpHeaderInjector`. Without this, forwarding an identity over HTTP to the Bootstrap/Vaultwarden via ZTLP natively in-browser is blocked. We have verified ZTLP network functionality over proxied TCP natively. Decided to delegate this significant Elixir refactoring to the next autonomous session due to project scope.

### ⏳ Phase 8 & 9: Testing & UX (PENDING)
- Re-architect UI UX (Next-Step CTAs, labels, 1-click generation)
- Continuous Integration & PR deployment.

---

## 4. Current State

| Component | Status | Note |
|-----------|---------|------|
| `ztlp-ns` | ✅ Healthy | Resolving `type 1` and `type 2` queries |
| `ztlp-relay` | ✅ Healthy | UDP tests clear |
| `ztlp-gateway` | ✅ Redeployed | Header signing turned ON, `ZTLP_NS_SERVER` wired properly, auto-registering services. Build `d418a9efd059` saved/shipped. |

Elixir tests: 832/832 passing.
Bootstrap tests: 38/38 passing.

---

## 5. Decisions Made

1. **Split Phase 4c HTTP Injection**: Discovered the underlying Gateway `Session` codebase forwards pure TCP streams. The logic for header injection existed exclusively within the `tls_session` abstraction. Opted to defer the refactor enabling `HttpHeaderInjector` logic on the plain-ZTLP paths to maintain targeted velocity and ensure TDD stability.
2. **Elixir Gateway Hardening In-Flight**: Addressed core gateway crashes (specifically Erlang tuple parsing the backend) natively in the current branch instead of working around the NS registration loop. Deployed the hotfixed container manually over Docker save/load.
3. **Elixir Gateway Policy Hash Override Fixed**: Discovered that Option C Hash routing created a failure inside the PolicyEngine matrix. Resolved the session lookup before handing evaluation to Policy rules dynamically preventing Vaultwarden from registering.
4. **Rust DNS Parser Fixing**: Validated and hotpatched `0.26.0` binary natively parsing Type 2 SVC records inside `proxy.rs` removing an internal CBOR unwrap bug. 

---

## 6. Known Problems & Caveats
- `~/.ztlp/config.toml` contains `relay = []` which logs a warning. Will fix during the UX polish stage.
- Gateway `CertProvisioner` currently throws `:ca_not_initialized`. Expected, non-blocking. CAs have not been provisioned for mTLS tests.

---

## 7. Next Session Startup Plan

1. Tackle **Phase 4c-4:** Refactor the Gateway Elixir codebase (`gateway/lib/ztlp_gateway/session.ex` & `backend.ex` / `http_injector.ex`) to allow ZTLP Sessions to proxy HTTP requests and inject signed `X-ZTLP-*` Headers properly automatically.
2. Test browser-based vaultwarden integration testing natively via `techrockstars.ztlp` instead of via TCP proxy piping.
3. Execute Phase 8 UX tweaks.
4. Open PR & merge (Phase 9).

## 8. Git Workflow & Continuity
All code modifications have accompanying comprehensive TDD suites (`config_test.exs`, `service_registrar_derive_test.exs`). Commits logically separated. We are ready to push the feature branch to origin.