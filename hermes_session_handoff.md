# Project Goal
- **Primary Objective:** Wire up end-to-end "passwordless" authentication for the ZTLP SaaS UI (the Bootstrap admin portal) when accessed through a per-tenant gateway via `ztlp connect`.
- **Reason:** Users claiming a new ZTLP tenant via the orchestration flow should be able to access their private `bootstrap.<zone>.ztlp` console seamlessly, deriving their identity from their cryptographic Noise session rather than typing a password.
- **Success Criteria:** A user runs `ztlp connect bootstrap.<zone>.ztlp ... -L 18080:127.0.0.1:3000`, opens `127.0.0.1:18080` in their browser, and is transparently signed in to the Rails UI. The gateway injects `X-ZTLP-*` headers validated via HMAC.
- **Long-term Vision/Architecture:** The Rust application `ztlp listen` (acting as the edge proxy) acts as a Zero Trust proxy. It validates the peer's public key against a predefined set of admins (`--admin-pubkey-email`), strips inbound `X-ZTLP-*` spoofing attempts, injects authoritative trust headers + HMAC signatures, and routes to Rails. Rails validates this signature via `Ztlp::HeaderVerifier`.

# Current Progress
- **Completed:** 
  - Validated that the Docker Compose interpolation fix (`$$VAR`) correctly resolves the host shell escaping issue. Committed the hot-patch and added regression tests to `test_launch_app.py`.
  - Demystified the "Nebula Dumb-Pipe" bypass concern: Found that the gateway **does** use the L7 injection bridge path (`run_bridge_demuxed_with_http_injection`). The "nebula dumb-pipe" log message was a red herring. Fixed this logging bug and added regression tests for `HttpInjectionConfig::lookup_email`.
  - Discovered and **proved** the root cause of the "lag" that causes a white page: The ZTLP client's `cmd_connect` architecture operates synchronously. It proxies one TCP stream at a time using `FRAME_RESET`. If the browser attempts to download 6 assets simultaneously, 5 of them are queued out on the OS backlog, waiting until the Keep-Alive for the first connection times out (65 seconds).
  - Drafted an implementation plan to work around this by spawning **parallel noise sessions** so the browser streams don't stall (`docs/plans/2026-05-20-ztlp-parallel-sessions-workaround.md`).
- **Blocked/Failing:**
  - The client binary natively starves modern browsers.

# Active Tasks

**Task 1: Implement Parallel Sessions Workaround (Next Session)**
- **Status:** ready for execution
- **Description:** Shift the payload loop in the client's `cmd_connect` block (`proto/src/bin/ztlp-cli.rs`) so that `tcp_listener.accept()` kicks off a dedicated tokio spawned task. That spawned task must conduct its own fresh Noise Handshake before wrapping via `run_bridge`.
- **References:** See the plan written in `docs/plans/2026-05-20-ztlp-parallel-sessions-workaround.md`.

# Technical Context
- **Overall architecture:** Local ZTLP client (Rust) tunnels TCP over UDP (Noise Protocol Framework encrypted) to an Elixir Relay, which routes to a Rust ZTLP Gateway on the target host. The Gateway unpacks the tunnel and forwards raw traffic to a Rails (Bootstrap) application.
- **Mux support realities:** Both the Elixir gateway (`@max_mux_streams`) and the Rust client (`vip.rs` `StreamDispatcher`) support sophisticated high-performance stream multiplexing (`[FRAME_OPEN | stream_id]`). However, the Rust gateway (`tunnel.rs`) actively drops these packets, and `cmd_connect` (the desktop CLI) is hardcoded to not use `vip.rs`. Properly mapping them together is a major protocol engineering task, necessitating the Parallel Sessions workaround as a bridge.

# Testing Requirements
Hermes MUST follow a test-first or test-alongside-development workflow.
Requirements:
- Verify bug fixes with regression tests
- For every major feature or fix, document what was tested, how, commands used, and remaining gaps.

# Validation Requirements
Before considering work complete Hermes MUST:
- Run tests
- Validate the application starts correctly
- Verify integrations function correctly
If something cannot be validated, explicitly document what could not be verified, why, and what still needs testing.

# Next Session Startup Plan
1. Review this document (`hermes_session_handoff.md`).
2. Read the full documented plan in `docs/plans/2026-05-20-ztlp-parallel-sessions-workaround.md`.
3. Read the relevant lines in `proto/src/bin/ztlp-cli.rs` mapping out how to refactor `cmd_connect` to defer the handshake until after the TCP stream has been accepted.
4. Apply the refactor, build the client proxy locally.
5. Have Steve test the experience using `ztlp connect ... -L 18080:127.0.0.1:3000 --service http -k ~/.ztlp/identity.json` and a fresh browser network tab.

# Git Workflow Requirements
Hermes MUST use Git as part of the workflow.
- Format commits cleanly with clear "why".
