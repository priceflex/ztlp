# Project Goal
- **Primary Objective:** Wire up end-to-end "passwordless" authentication for the ZTLP SaaS UI (the Bootstrap admin portal) when accessed through a per-tenant gateway via `ztlp connect`.
- **Reason:** Users claiming a new ZTLP tenant via the orchestration flow should be able to access their private `bootstrap.<zone>.ztlp` console seamlessly, deriving their identity from their cryptographic Noise session rather than typing a password.
- **Success Criteria:** A user runs `ztlp connect bootstrap.<zone>.ztlp ... -L 18080:127.0.0.1:3000`, opens `127.0.0.1:18080` in their browser, and is transparently signed in to the Rails UI. The gateway injects `X-ZTLP-*` headers validated via HMAC.
- **Long-term Vision/Architecture:** The Rust application `ztlp listen` (acting as the edge proxy) acts as a Zero Trust proxy. It validates the peer's public key against a predefined set of admins (`--admin-pubkey-email`), strips inbound `X-ZTLP-*` spoofing attempts, injects authoritative trust headers + HMAC signatures, and routes to Rails. Rails validates this signature via `Ztlp::HeaderVerifier`.

# Current Progress
- **Completed:** 
  - PR #5 (HTTP header injection module in Rust ZTLP gateway).
  - PR #6 (`POST /api/admin-pubkey` API in `ztlp.net` python launch app and UI fixes).
  - Deployment of `v0.26.3` to production (`35.91.88.177`).
  - Handled Docker Compose `$$VAR` escape bugs for environment variables in the launch app.
  - Successfully provisioned a tenant (`passwordless-test.ztlp`) and successfully bound the user's local X25519 public key via the new API.
  - Verified the Gateway container arms the HTTP injection module (`✦ HTTP header injection ENABLED for 1 admin pubkey(s)`).
- **In Progress:** Diagnosing why the injected headers are not arriving at the Rails backend.
- **Blocked/Failing:**
  - The browser hits the Rails backend but receives a 302 redirect to `/login` because `X-ZTLP-Signature` is missing.
  - The Gateway logs show it is executing `run_bridge (nebula dumb-pipe)` instead of `run_bridge_demuxed_with_http_injection`. Due to the recent "Nebula pivot", the default bridge path completely bypasses the L7 HTTP injection logic.
  - User noted potential TCP stream crashes/hangups and requested transitioning from guessing to empirical capture (tcpdump/trace logging).
- **Temporary Workarounds:** 
  - Hot-patched `/home/ubuntu/ztlp.net/launch_app/app.py` directly on the AWS server to escape `$$ZTLP_GATEWAY_HEADER_SECRET` in Docker Compose execution. This needs to be synced back to the codebase.
- **System Stability:** Prod Launch app is stable. Prod Gateway nodes are fighting for port `0.0.0.0:23097` due to `network_mode: host` (known legacy issue).

# Active Tasks

**Task 1: TCP/HTTP Stream Diagnostics & tcpdump Capture**
- **Status:** not started
- **Description:** Turn on aggressive trace logging and run `tcpdump` on both the AWS server (`35.91.88.177`) and the local client machine to empirically track the TCP stream lifecycle. Determine exactly how the TCP connection is formed, carried over the UDP tunnel, and terminated.
- **Important implementation notes:** We must stop static code analysis guessing and capture actual network packets to see if injecting bytes into the stream causes TCP sequence desynchronization or if the "dumb-pipe" architecture fundamentally precludes L7 header injection.
- **Next exact step to perform:** SSH into AWS server, set up `tcpdump` targeting the specific backend port (`39690` for the test tenant), and run a client-side `ztlp connect` with `RUST_LOG=trace`.
- **Relevant files:** `proto/src/tunnel.rs`, `proto/src/bin/ztlp-cli.rs`.
- **Relevant commands:** `sudo tcpdump -i any port 39690 -w /tmp/ztlp_backend.pcap`
- **Dependencies:** Access to the AWS test server and the local binary.

**Task 2: Reconcile "Nebula Dumb-Pipe" Pivot with L7 Header Injection**
- **Status:** blocked
- **Description:** The `--http-inject-headers` flag relies on terminating the TCP stream to safely inject HTTP headers. The "Nebula pivot" architecture routes everything through `run_bridge`, treating the tunnel as a dumb UDP pipe (fire-and-forget payload). We need to determine if we can route specific sessions through `run_bridge_demuxed_with_http_injection` or if the injection logic must be fundamentally rewritten to operate on raw packets.
- **Known issues:** Injecting bytes into a "dumb-pipe" raw TCP stream modifies the payload length, which inevitably desyncs standard TCP sequence numbers resulting in hanging or dropped connections.
- **Next exact step to perform:** Review the design discrepancy with the user based on the tcpdump findings.

# Technical Context
- **Overall architecture:** Local ZTLP client (Rust) tunnels TCP over UDP (Noise Protocol Framework encrypted) to an Elixir Relay, which routes to a Rust ZTLP Gateway on the target host. The Gateway unpacks the tunnel and forwards raw traffic to a Rails (Bootstrap) application.
- **Folder structure:** 
  - `proto/`: Rust ZTLP daemon (`ztlp`).
  - `ztlp.net/launch_app/`: Python backend for provisioning tenants.
  - `bootstrap/`: Ruby on Rails SaaS UI.
- **Important source files:** 
  - `proto/src/bin/ztlp-cli.rs`: CLI entrypoints and bridge routing.
  - `proto/src/tunnel.rs`: The asynchronous bridging loops carrying traffic.
  - `proto/src/http_injector.rs`: The HTTP parser & HMAC signer.
- **Environment variables:** `ZTLP_GATEWAY_HEADER_SECRET`, `ZTLP_ADMIN_PUBKEY_HEX`, `ZTLP_TRUST_GATEWAY_AUTH`.
- **Deployment assumptions:** Target host is AWS Ubuntu (`35.91.88.177`). Python launch app controls `docker-compose` to spawn tenant gateways and Rails apps via mounted `docker.sock`.
- **Networking:** Tenant Gateways bind `network_mode: host` to port 23097.

# Code Documentation Standards
All code written by Hermes MUST be thoroughly documented.
Requirements:
- Functions must include clear comments/docstrings
- Complex logic must explain WHY it exists
- Public APIs/classes/modules must be documented
- Edge cases and assumptions must be documented
- Configuration files should contain explanatory comments where possible
- Avoid "magic behavior" without explanation
- Code should be understandable by a brand-new engineer reviewing it later
Documentation should prioritize maintainability and operational clarity over minimalism.

# Testing Requirements
Hermes MUST follow a test-first or test-alongside-development workflow.
Requirements:
- Write tests while implementing features, not afterward
- Add/update unit tests for new logic
- Add/update integration tests where applicable
- Ensure edge cases are tested
- Verify bug fixes with regression tests
- Ensure all tests pass before ending a session
- Never leave knowingly failing tests without documenting them clearly
- For every major feature or fix, document what was tested, how, commands used, and remaining gaps.

# Validation Requirements
Before considering work complete Hermes MUST:
- Run tests
- Validate the application starts correctly
- Verify integrations function correctly
- Check logs for hidden failures
- Ensure no obvious regressions were introduced
- Verify linting/static analysis if available
- Confirm documentation was updated
If something cannot be validated, explicitly document what could not be verified, why, and what still needs testing.

# Decisions Made
- **Docker Compose interpolation fix:** Used `$$ZTLP_GATEWAY_HEADER_SECRET` in `ztlp.net/launch_app/app.py` so Docker Compose literal-escapes the variable down to the container shell, preventing empty variable evaluation at compose-parse time.
- **XSS sanitization:** Removed input-time stripping of `<>{}[];` in `ztlp.net/launch_app/app.py` as it mutated legitimate inputs (like email names); relied strictly on output-time `html.escape(quote=True)`.

# Known Problems
- **Architectural Match:** The Gateway `run_bridge` (Nebula dumb-pipe) completely ignores `--http-inject-headers`.
- **TCP Stream Instability Risk:** The user suspects TCP sequence numbers/hangups occur if payload manipulation is attempted improperly over the tunnel.
- **Port Collisions:** Prod Launch app spins up gateways with `network_mode: host` mapping to a static `0.0.0.0:23097`. Concurrency fails; only one container holds the port at a time.
- **Uncommitted Hot-patches:** `ztlp.net/launch_app/app.py` on the AWS server contains a hot-patch for the `$$VAR` fix that is NOT YET tracked in git.

# Open Questions
- To achieve L7 HTTP Injection over a Zero Trust tunnel, do we fall back to a full TCP-terminating proxy architecture for `http` services, or do we handle HTTP injection completely differently under the new Nebula architecture?

# Next Session Startup Plan
1. Review this document (`hermes_session_handoff.md`).
2. Run git status and branch check. Make sure you are on `main`.
3. Commit the uncommitted hot-patch from AWS (`$$VAR` fix) to the local ZTLP codebase.
4. Set up an empirical testing rig: execute `tcpdump` on the AWS server and use `RUST_LOG=trace` on the local binary to capture the exact TCP/HTTP lifecycle where the stream hangs or bypasses our HTTP injection layer.
5. Address Task 1 (empirical logging).
6. Avoid guessing; rely solely on captured packet/log behaviors.

# Git Workflow Requirements
Hermes MUST use Git as part of the workflow.
- Review all changed files.
- Update `hermes_session_handoff.md`.
- Verify tests pass.
- Stage all intentional changes.
- Create a highly descriptive git commit explaining WHY changes were made.
- Commit before ending a session.
