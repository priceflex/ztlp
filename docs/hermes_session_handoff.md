# Hermes Session Handoff

> **Active session:** 2026-05-21 — ZTLP E2E Autologin Test (Gateway Collision Fixed, Blocked by QUIC Architecture)
> **Operator:** Steve Price

---

## 1. Project Goal
- **Primary Objective:** Fix the regressions introduced by the monolithic QUIC pivot in v0.28.5, then **perform a complete human-style E2E test** of the onboarding flow on `ztlp.net`—including claiming a network, running `ztlp setup/connect`, and accessing the Bootstrap dashboard to verify **passwordless autologin** via the ZTLP tunnel.
- **Business/Technical Reason:** Ensure that the entire v0.28.5/v0.28.6 stack works smoothly end-to-end for a prospective user. A critical feature is the `--http-inject-headers` autologin capability which allows the Rails Bootstrap dashboard to trust the authenticated Noise session for passwordless entry.
- **Success Criteria:** 
  1. The CLI tunnel establishes correctly using NS resolution and UDP relay routing.
  2. The local browser connects to `127.0.0.1:18080`.
  3. The local browser successfully loads the Rails dashboard without being prompted for a password (autologin succeeds).
  4. The goal is complete after running a couple of clicks in the browser.
- **Long-Term Vision:** A zero-touch provisioning pipeline where multi-platform clients seamlessly tunnel into isolated, passwordless tenant Rails environments over QUIC via intelligent Relay routing.

---

## 2. Current Progress
- **Completed:**
  - **Task A:** Fixed the gateway port collision in `ztlp.net/launch_app/app.py`. Added dynamic `gw_port` calculation (base_port + hash + 1000 offset).
  - Fixed YAML escaping regression in the same file causing alias mapping mapping errors during `docker compose up`.
  - Verified all 48 `ztlp.net` unit tests pass locally.
  - **Task B:** Deployed the fixed launch app to the production server (`35.91.88.177`).
  - Created new test organizations "HermesCorp" and "HermesE2E" on live endpoints.
  - Fixed the v0.26 service hash mismatch (`cmd_connect` now properly hashes `--service http` instead of zero-padded ASCII).
  - Fixed `ServiceRegistry` to fallback to default unnamed services to allow pre-Option-C `docker-compose` (`--forward <ip>:<port>`) to accept `dst_svc_hash` requests seamlessly.
  - **Task D:** Resolved the active blocker causing Layer 1 drops on the Relay. Modified `udp_listener.ex` to bypass strict `0x5A37` magic requirements if the incoming `{IP, Port}` exactly matches an active `ztlp_forwarded_session`. Deployed natively to EC2 host: `34.218.240.106:23095`.

- **Blocked/Failing:**
  - **QUIC Gateway Registration (Task E):** The integration of QUIC via `quinn::Endpoint` completely hides the primary `UdpSocket` descriptor traversing the network. Because the Relay (`34.218.240.106`) validates active Gateway IPs uniquely based on the UDP packet transmission source port (`from`), trying to establish a separate UDP background thread transmitting 60-second `GATEWAY_REGISTER` tokens (`0x0A`) results in a misaligned Port identity block (e.g. EC2 mapping token binding natively to 40416 while gateway connection drops in at 51221). 
  - Attempts to extract the Toki socket, bind with `SO_REUSEADDR` or replicate file-descriptors crash via rustc lifetime/mutability locking. The SaaS gateways are currently failing `Unknown_Session` checks at L2 on Relay endpoints. 

---

## 3. Active Tasks

### Task A: Fix Gateway Port Collision ✅ COMPLETED

### Task B: Deploy Fix to ZTLP.net Launch Server ✅ COMPLETED

### Task D: Resolve Relay L1 Drop ✅ COMPLETED

### Task E: Resolve QUIC Re-registration Blocks
- **Status:** blocked
- **Description:** Implement synchronized out-of-band UDP registry token dispatches natively bypassing `quinn::Endpoint` architecture mappings across dual ephemeral NAT constraints. 
- **Important implementation notes:** Currently logging `WARNING: QUIC automatic Relay Gateway Registration requires manual routing exception mappings via config.yaml in v0.28.5.` in `ztlp-cli.rs`. Do NOT revert to `Arc<UdpSocket>` standard passing without guaranteeing strict SO_REUSEPORT adherence isolated from Toki runtimes, or QUIC crashes the CLI on boot with OS Error 98.
- **Next exact step to perform:** Define architectural standard for how Native (non-QUIC) Relay tracking tables sync with external multiplexed Gateway nodes. 
- **Relevant files:** 
  - `proto/src/bin/ztlp-cli.rs` -> `spawn_relay_registration`
  - `proto/src/quic_transport.rs` -> `QuicEndpoint::bind_with_socket()`
  - `relay/lib/ztlp_relay/udp_listener.ex` -> `GatewayForwarder` ETS mappings.

### Task C: Complete E2E Autologin Verification 
- **Status:** blocked (Gated by Task E)
- **Description:** Use the local `ztlp connect` command to reach the `ztlp-bootstrap` container via the instantiated `ztlp-gateway` container and the relay.
- **Details:** With the CLI fix for service hash (Option C) and Relay `handle_info` bypassing L1 filters, all routing paths are technically green. We strictly need stable network port visibility between QUIC integration wrappers before `curl 127.0.0.1:18080` succeeds fully.

---

## 4. Technical Context
- **Overall architecture:**
  - `www.ztlp.net` Launch app (Python) provisions multi-tenant Docker stacks (Bootstrap + Gateway).
  - Gateway dynamically registers its port (randomized) with the Relay.
  - NS Server (`35.91.88.177:23096`) resolves tenant zones to the Relay (`34.218.240.106:23095`).
  - Client looks up zone via NS, routes QUIC/Noise wrapped ZTLP UDP packets to Relay.
  - Relay forwards packets to the dynamically registered Gateway port.
  - Gateway decrypts Noise session, injects HTTP authentication headers, forwards to Bootstrap container.
- **Services involved:**
  - Launch Server: `35.91.88.177` (port 8080, Docker)
  - NS Server: `35.91.88.177` (port 23096)
  - Relay Server: `34.218.240.106` (port 23095, Elixir)
  - Local Client: `~/.ztlp/identity.json`
- **Networking details:**
  - NAT mapping actively breaks multi-socket deployments if distinct connections map independently on consumer hardware. 
  - Elixir instances MUST natively execute with `--network host` flag mapping. 
- **Deployment assumptions:**
  - Elixir binaries are modified sequentially utilizing `mix compile --warnings-as-error`. Never attempt SSH pipe code string modifications. 

---

## 5. Code Documentation Standards
- Rust code changes must include `//!` or `///` doc comments for all public structures.
- Elixir code uses `@moduledoc` and `@doc`.
- Python code uses standard docstrings.
- **Avoid "magic behavior":** Always comment *why* a particular constant (e.g., the +1000 port offset) was chosen. All undocumented testing assertions lacking protocol context flag regressions.

---

## 6. Testing Requirements
- **Validation:** Always test end-to-end integration via actual command-line execution or `curl` against local listeners rather than relying blindly on unit tests passing. The entire stack must run natively across AWS EC2 domains without isolated test harnesses.
- Launch components evaluated natively using Python HTTP endpoint scripts validating Claim mappings via POST blocks against live endpoints. 
- Ensure `docker ps`, `netstat`, and `lsof` tracking natively evaluate Docker host-mapped volumes correctly. 

---

## 7. Decisions Made
- **Decision:** Keep `network_mode: host` for Gateways but randomize `--bind` ports.
  - *Why:* Solved `Address already in use` error while permitting the Gateway to make un-NAT'd outbound connections to the Relay.
- **Decision:** Switch Relay server Docker container to `network_mode: host`.
  - *Why:* Previously, Docker bridge caused SNAT (masquerading), making all gateway/client connections appear to come from `172.17.0.x`. Host networking passes true IP/Port up to the Elixir UDP listener.
- **Decision:** Explicitly block `spawn_relay_registration` integration for QUIC v0.28.5 endpoints gracefully via warning printouts.
  - *Why:* Unsafely injecting Socket clones or exploiting SO_REUSEPORT failed OS port checks preventing stable deployment. By tracking this bug independently, we preserve stable `cargo build` results protecting legacy deployment architecture while staging a dedicated overhaul.

---

## 8. Known Problems
- **QUIC vs UdpSocket Control Blocks:** Protocol `v0.28.5` effectively breaks headless background gateway relay tracking due to `quinn-proto` natively securing descriptors aggressively across Tokio threads. E2E validations using `ztlp connect` over NAT fail via Timeout logic inherently.
- **Relay ETS Metric Display Mismatch:** The previous active blocker (dropped_l1 count due to Magic prefixes missing on Transport Packets) forced the Relay to actively rely on `ztlp_session_registry` and bypass validation. The metrics display previously matched `ztlp_sessions` incorrectly natively displaying zero counts.

---

## 9. Open Questions
- When implementing Task E, should the Elixir Relay accept duplicate IPs under ephemeral port connections securely scaling to specific MAC/Hardware fingerprints instead of strictly enforcing {IP:PORT} logic to accommodate QUIC?
- Could Native `UdpSocket` pass down logic reliably be integrated through FFI structs safely mapping to Swift without enforcing active memory tracking conflicts across architectures?

---

## 10. Next Session Startup Plan
1. **Review first:** This file (`hermes_session_handoff.md`).
2. **Review Github:** Checkout `feature/quic-relay-registration`. 
3. **Determine Task E Approach:** Discuss the open questions with Steve. Figure out the canonical implementation mapping QUIC token injection cleanly across ephemeral bindings.
4. **Re-Test Tunnel Stability:** Try routing the proxy logic dynamically natively verifying `ztlp proxy gw-hermescorp 80`. 
5. **Gateway Upgrade Prep:** Check `testing` and `testing321` crash-loops on launch server. Plan the `ztlp-node` Docker update to get header-injection code deployed natively matching the upgraded Node tracking format. 

---

## 11. Git Workflow
- Handoff file meticulously integrated.
- Elixir Relay fix pushed and committed locally (`feature/relay-l1-drop-fix`).
- Rust Quinn Gateway fixes mapped with explicit fallback architecture notes pushed and tracked securely via `feature/quic-relay-registration`. 
