# Hermes Session Handoff

> **Active session:** 2026-05-21 — ZTLP QUIC Pivot Remediation (v0.28.5) -> ZTLP E2E Autologin Test
> **Agent:** Hermes (google/gemini-3.1-pro-preview)
> **Operator:** Steve Price

---

## 1. Project Goal
- **Primary Objective:** Fix the regressions introduced by the monolithic QUIC pivot in v0.28.5 (already done), then **perform a complete human-style E2E test** of the onboarding flow on `ztlp.net`—including claiming a network, running `ztlp setup/connect`, and accessing the Bootstrap dashboard to verify **passwordless autologin** via the ZTLP tunnel.
- **Business/Technical Reason:** Ensure that the entire v0.28.5/v0.28.6 stack works smoothly end-to-end for a prospective user. A critical feature is the `--http-inject-headers` autologin capability which allows the Rails Bootstrap dashboard to trust the authenticated Noise session for passwordless entry.
- **Success Criteria:** 
  1. The CLI tunnel establishes correctly using NS resolution and UDP relay routing.
  2. The local browser connects to `127.0.0.1:18080`.
  3. The local browser successfully loads the Rails dashboard without being prompted for a password (autologin succeeds).
  4. The goal is complete after running a couple of clicks in the browser.

---

## 2. Current Progress
- **Completed:**
  - Diagnosed and fixed the CLI regressions (NS resolution, Noise Auth, Relay UDP Fallback) in `proto/src/bin/ztlp-cli.rs`.
  - The CLI code compiles and passes tests flawlessly.
  - Performed the E2E onboarding via the browser on `www.ztlp.net` (created "Hermes Test Org").
  - Ran `ztlp setup` locally to generate an identity and enroll.
  - Found the claim token and submitted the generated *admin pubkey* to the token claim page for passwordless auth.
  - Verified local CLI can execute `ztlp connect` which uses NS to resolve the gateway, binds locally, and establishes the tunnel on port `18080`.
- **In Progress:** 
  - Fixing an infrastructure provisioning collision issue on `35.91.88.177`.
- **Blocked/Failing:**
  - The `launch_requested` provisioning on `www.ztlp.net` is perpetually crash-looping for our test tenant: `ztlp-gateway-hermes-test-org`.
  - **Root Cause:** In `ztlp.net/launch_app/app.py`, the `docker-compose.yml` generation for the tenant uses `network_mode: host` and hardcodes `exec ztlp listen --bind 0.0.0.0:23097` for *every* gateway. Since this runs on a shared EC2 host, the second tenant onboarded hits an `Address already in use (os error 98)` and fails to start.
- **Recent Changes:** We identified the exact line in `launch_app/app.py` causing the conflict.

---

## 3. Active Tasks

### Task A: Fix Gateway Port Collision in `ztlp.net` Launch App
- **Status:** In Progress
- **Description:** Modify `launch_app/app.py` in the `ztlp.net` repository so that `ztlp listen` inside the gateway container binds to a dynamically generated (unique) UDP port, rather than hardcoding `23097`.
- **Next exact step:** 
  - Update `ztlp.net/launch_app/app.py` line ~821 to use a dynamic `gw_port` (e.g., `base_port + (int(digest_prefix, 16) % 900) + 1000`).
  - Run the `python3 -m unittest discover -s tests -v` locally in `ztlp.net`.
  - Commit the fix.
- **Relevant Files:** `ztlp.net/launch_app/app.py`

### Task B: Deploy Fix to ZTLP.net Launch Server
- **Status:** Pending
- **Description:** Deploy the fixed `launch_app/app.py` to the `35.91.88.177` Launch server and restart the `ztlp-launch` service.
- **Relevant Commands:** `ssh ubuntu@35.91.88.177` and patching/restarting the `ztlp-launch` container or Python app.

### Task C: Complete E2E Autologin Verification
- **Status:** Pending (Blocked on Task B)
- **Description:** With the remote gateway finally running, keep the local `ztlp connect` active. Open the browser to `http://127.0.0.1:18080`, verify it auto-logs into the Rails Bootstrap, and perform a couple of clicks in the UI.

---

## 4. Technical Context
- **Architecture:** 
  - The CLI `ztlp connect` dials an enrolled ZTLP network. 
  - The `www.ztlp.net` Launch app (Python stdlib) mints new Docker stacks (Rails Bootstrap + ZTLP Gateway container).
  - The local `127.0.0.1:18080` port acts as a TCP forwarder over QUIC/UDP, dropping out on the remote gateway which intercepts HTTP headers to inject `X-ZTLP-Authenticated` and `X-ZTLP-Admin-Email` based on the Noise identity. The Rails app trusts this.
- **Folder Structure:** 
  - `~/ztlp/proto/` -> Rust CLI code.
  - `~/ztlp/ztlp.net/` -> Python Launch App code & tests.
- **Environment Variables:** `ZTLP_GATEWAY_HEADER_SECRET` is shared between Gateway and Bootstrap to sign the auth headers.
- **Testing:** We use Python's `unittest` in the `ztlp.net` folder for the launcher.

---

## 5. Decisions Made
- **Decision:** Do NOT rely on manual workaround or hardcoded port assignment.
  - *Why:* ZTLP is designed to host many tenants. Hardcoding `23097` on a `network_mode: host` container breaks multi-tenancy on the SaaS instance.
- **Decision:** Keep `network_mode: host` for now on the gateway, but randomize the `--bind` port.
  - *Why:* The gateway is making an *outbound* registration request to the Relay via `GATEWAY_REGISTER`. The actual port it binds locally on the EC2 host does not matter to the client as long as it's uninhibited, but it must not conflict with other tenants on the same EC2.

---

## 6. Known Problems
- **Bugs:** The port collision bug in `app.py`.
- **Blocked State:** We have an active claim for `hermes-test-org` on the server which is crash-looping. Once the code is pushed, we may just nuke that test instance or deploy the update and create a new org.

---

## 7. Open Questions
- None right now. The collision logic is completely understood.

---

## 8. Next Session Startup Plan
1. **Review first:** This file (`hermes_session_handoff.md`).
2. **Checkout Branch:** Remain on `feature/restore-relay-routing`.
3. **Execute Task A:** Edit `~/ztlp/ztlp.net/launch_app/app.py` around line 821 to create a `gw_port` calculation (e.g. `port + 10000`, guaranteeing it's unique per tenant). Replace `--bind 0.0.0.0:23097` with `--bind 0.0.0.0:{gw_port}`.
4. **Test Task A:** `cd ~/ztlp/ztlp.net && python3 -m unittest discover -s tests -v`.
5. **Commit:** `git add ztlp.net/launch_app/app.py && git commit -m "fix(launch): assign unique gateway ports to prevent host collision"`.
6. **Task B:** SSH to `35.91.88.177` as `ubuntu` and patch the live `app.py`. 
7. **Task C:** Launch the E2E test through the browser again and hit the dashboard!
