# Hermes Session Handoff (Updated 2026-05-18)

## 1. Project Goal
- **Primary objective:** Enable Hermes to SSH to a Windows machine (specifically `trs@10.170.3.111` initially) through the full ZTLP stack (Gateway -> Relay -> Client), bypassing the need for direct Internet SSH exposure and ensuring resilience via the relay.
- **Vision:** Hermes acts autonomously to administer, test, and manage remote Windows (and eventually macOS/Linux) workstations securely over ZTLP.
- **Definition of Done:** Hermes can seamlessly establish an interactive SSH session to the target Windows machine through the ZTLP relay path, proving both the control plane (handshake) and data plane (traffic forwarding) function perfectly.

## 2. Current Progress
- **What Was Completed This Session:**
  - **Identified and fixed the root cause of the data-plane stall over relay:** After the Noise_XX handshake completes, ZTLP peers switch to Noise transport packets (which lack the ZTLP magic header). The relay's admission pipeline was dropping these at Layer 1.
  - **Implemented the fix in the Relay:**
    - Modified `GatewayForwarder` to maintain a public ETS table (`:ztlp_gateway_peers`) mapping `peer_addr` -> `{session_id, other_peer_addr}`.
    - Added an O(1) fast-path lookup (`lookup_by_peer/1`) to `GatewayForwarder`.
    - Modified `UdpListener.handle_packet/3` to fall back to this fast-path lookup when a packet fails the Layer 1 magic check. If the sender is a known peer in an established forwarded session, the relay now blind-forwards the raw bytes to the other peer.
  - **Added comprehensive tests:** Wrote 4 new unit tests in `gateway_forwarder_test.exs` verifying client->gateway routing, gateway->client routing, unknown peer drops, and NAT rebinding (`update_client/2`).
  - **Validated the Relay Fix:** All 583 Elixir tests pass locally with 0 failures (`mix compile --warnings-as-errors` and `mix test`).
  - **Committed and Pushed:** The relay fix is committed locally (`bf687ec`) and pushed to the remote branch `feature/ssh-over-ztlp-relay-fix`.
  - **DevOps Skill Created:** Formally documented the "always mirror and compile locally before patching production" rule as a Hermes skill to prevent the hours of blind `sed` patching errors encountered today.

- **What is Currently in Progress / Blocked:**
  - **Blocked:** Deploying the validated relay fix to the AWS production server (`34.219.64.205`). The `scp` command to transfer the fixed `.ex` files and the subsequent SSH command to trigger the docker rebuild require user approval due to the raw IP address.

- **System Stability:** The relay codebase on `feature/ssh-over-ztlp-relay-fix` in the `ztlp` repo is heavily tested and stable locally. The production AWS server is currently running an older image.

## 3. Active Tasks

### Task 1: Deploy Relay Fix to Production
- **Status:** **Blocked** (Awaiting user approval for SCP/SSH commands to raw IP)
- **Description:** Transfer the validated Elixir source files to the AWS relay server and rebuild the docker container.
- **Relevant Files:**
  - `relay/lib/ztlp_relay/gateway_forwarder.ex`
  - `relay/lib/ztlp_relay/udp_listener.ex`
  - `relay/test/ztlp_relay/gateway_forwarder_test.exs`
- **Next exact step:** Once approved, execute the `scp` transfer and `ssh` rebuild commands.
  ```bash
  scp -i /home/trs/.ssh/id_rsa -o ConnectTimeout=10 /home/trs/ztlp/relay/lib/ztlp_relay/gateway_forwarder.ex /home/trs/ztlp/relay/lib/ztlp_relay/udp_listener.ex /home/trs/ztlp/relay/test/ztlp_relay/gateway_forwarder_test.exs ubuntu@34.219.64.205:/tmp/
  
  ssh -o ConnectTimeout=10 -i /home/trs/.ssh/id_rsa ubuntu@34.219.64.205 "mv /tmp/gateway_forwarder.ex ~/ztlp-relay/lib/ztlp_relay/gateway_forwarder.ex && mv /tmp/udp_listener.ex ~/ztlp-relay/lib/ztlp_relay/udp_listener.ex && mv /tmp/gateway_forwarder_test.exs ~/ztlp-relay/test/ztlp_relay/gateway_forwarder_test.exs && cd ~/ztlp-relay && docker build -t ztlp-relay:noise-fix . && docker rm -f ztlp-relay && docker run -d --name ztlp-relay -p 23095:23095/udp -p 9101:9101 -e ZTLP_RELAY_PORT=23095 -e ZTLP_RELAY_VIP_ENABLED=false -e ZTLP_RELAY_METRICS_ENABLED=true -e ZTLP_RELAY_METRICS_PORT=9101 -e ZTLP_LOG_LEVEL=debug -e ZTLP_RELAY_SESSION_TIMEOUT_MS=300000 ztlp-relay:noise-fix"
  ```
- **Testing:** Production deployment must be followed immediately by an end-to-end SSH test.

### Task 2: End-to-End SSH Validation
- **Status:** **Not Started** (Depends on Task 1)
- **Description:** Verify that Hermes can establish an interactive SSH session to the Windows host through the updated relay.
- **Next exact step:** Run the proxy command and attempt SSH.
  ```bash
  /home/trs/ztlp/proto/target/release/ztlp proxy windows-workstation.techrockstars.ztlp 22 --key /home/trs/.ztlp/identity.json --relay 34.219.64.205:23095
  ```
  (Note: The proxy command needs to bridge stdio to the SSH client).

## 4. Technical Context
- **Architecture:** 
  - **Relay (Elixir):** Runs on AWS (`34.219.64.205`). Handles UDP packet routing. Uses a 3-layer admission pipeline. 
  - **Client/Gateway (Rust):** Windows host runs `ztlp listen` (acting as gateway). Hermes Linux host runs `ztlp proxy` (acting as client).
- **Core issue resolved:** The Relay previously only routed ZTLP handshake packets. It now acts as a pure UDP forwarder for recognized peer pairs after the handshake, enabling the Noise transport packets (which lack ZTLP headers) to flow.
- **Folder Structure:** 
  - Rust client/gateway code: `/home/trs/ztlp/proto/`
  - Elixir relay code: `/home/trs/ztlp/relay/` (Crucially, the relay source is tracked within the main `ztlp` repo.)
- **Configuration:** Static proxy mappings are defined in `/home/trs/.ztlp/agent.toml`.

## 5. Decisions Made
1. **Relay Data-Plane Forwarding via ETS:** Decided to implement the post-handshake forwarding lookup as an O(1) ETS read (`:ztlp_gateway_peers`) rather than a GenServer call to `GatewayForwarder`. This avoids adding a GenServer bottleneck to the hot data path in the UDP listener.
2. **"Never edit production source blind" Skill:** Established a hard rule (saved as a Hermes skill) to always pull production code into a local git branch and compile it using the local toolchain before attempting fixes. This decision was made after wasting significant time battling Elixir syntax errors via remote `sed` patches. The local toolchain guarantees syntax correctness before deployment.

## 6. Known Problems
- **Stale Gateway Registrations:** Previously, a stale docker gateway from an old AWS testbed (`172.26.11.164:23097`) was interfering with the round-robin gateway selection on the relay. This was killed earlier, but if the full-stack testbed is spun up again, it may cause routing conflicts unless gateway targeting is strictly scoped (e.g., via distinct service names rather than round-robin).

## 7. Open Questions
- Does the Windows `ztlp listen` command currently running (`PID 8832` via Scheduled Tasks) need to be restarted to re-register with the relay after the Docker container is rebuilt and restarted? (Most likely, yes, or wait 30s for its periodic `--relay` registration tick).

## 8. Next Session Startup Plan
1. **Review:** Read this handoff document completely.
2. **Check Git:** Run `git status` and `git branch` (Ensure you are on `feature/ssh-over-ztlp-relay-fix`).
3. **Execute Deployment (Action Required):** Once user approval is granted for the raw IP, run the `scp` and `ssh` docker rebuild commands detailed in Task 1.
4. **Restart Windows Listener:** Ensure the Windows host (`trs@10.170.3.111`) has restarted its `ztlp` listener to register with the freshly started relay.
5. **Validation Test:** Run the `ztlp proxy` command and use the `ssh` client to connect through it. Verify the SSH banner arrives and an interactive terminal is established.
6. **Merge and Release:** Once E2E testing passes, merge `feature/ssh-over-ztlp-relay-fix` to `main`, push, ensure CI/CD is green, and create the final GitHub release.
7. **Risk Avoidance:** Do NOT edit `.ex` files directly on the AWS server. Use the `relay/` directory locally, run `mix compile --warnings-as-errors`, and then push.
