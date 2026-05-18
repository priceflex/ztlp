# Hermes Session Handoff — SSH over ZTLP Relay

Date: 2026-05-18
Branch: feature/end-to-end-ssh-over-ztlp-relay
Repo: /home/trs/ztlp

## Project Goal
- **Primary objective:** Enable Hermes to SSH to a Windows machine (specifically `trs@10.170.3.111` initially) through the full ZTLP stack (Gateway -> Relay -> Client), bypassing the need for direct Internet SSH exposure and ensuring resilience via the relay.
- **Business/Technical Reason:** ZTLP avoids open ports and prevents volumetric DDoS/unauthenticated connections. Having Hermes utilize ZTLP directly proves the stack in production and lets the AI agent securely administer nodes.
- **Definition of Done:** Hermes seamlessly establishes an interactive SSH session via `ProxyCommand` to the target Windows machine through the ZTLP relay path, proving both control plane (handshake) and data plane (traffic forwarding).
- **Long-term Vision:** Autonomous administration of remote Windows, macOS, and Linux workstations through identity-gated routing without any open firewall ports.

## Current Progress
- **Completed:** 
  - Relay post-handshake forwarding fix deployed to AWS relay (`34.219.64.205`).
  - Added service name fallback for unnamed gateway forwards (`923fe72`).
  - Diagnostic improvements to `proxy.rs` (implemented this session) to catch and decode `RejectFrame` payloads in a 500ms post-handshake window.
- **In Progress:** Diagnosing SSH data plane failure (`auth_tag_invalid`).
- **Failing / Blocked:** 
  - SSH over the relay fails because incoming data packets from the gateway are being rejected by the proxy's local pipeline at Layer 3 (`auth_tag_invalid`).
- **Recently Changed:** 
  - `proto/src/agent/proxy.rs` was updated with `decode_reject_payload`, `poll_for_post_handshake_reject`, and related unit tests.
- **Temporary Workarounds:** 
  - `dst_svc_id` is unconditionally zeroed in `proxy.rs:388` to accommodate an older Windows gateway that defaults to `_default`.
  - Environmental block on `172.26.11.164:23097` on the relay due to it being a stale testbed.
- **Stability Status:** The codebase builds cleanly. Rust unit tests pass (13/13 in proxy, 800+ repo-wide). Elixir tests pass (583). Data plane routing via relay works, but encryption/decryption is failing due to a presumed key/nonce mismatch.

## Active Tasks

### Task 1: Resolve `auth_tag_invalid` (Layer 3) Data Plane Drop
- **Status:** In Progress
- **Detailed Description:** The ZTLP Noise_XX handshake succeeds and the tunnel establishes. The Windows gateway sends back encrypted SSH traffic via the relay. However, the Hermes proxy drops these packets locally with `SECURITY: auth_tag_invalid (rx)`. Because `dst_svc_id` is included in the Noise transcript, the current hack in `proxy.rs` (setting `dst_svc_id` to all zeros) likely causes a hash mismatch between the client's handshake transcript and the gateway's handshake transcript, causing derived AEAD keys to differ.
- **Important implementation notes:** Noise keys depend on identical protocol transcripts. If the gateway expects `tcp:22` and Hermes sends/hashes `0u8; 16`, the keys will diverge without the handshake explicitly failing.
- **Known issues:** SSH times out during banner exchange.
- **Next exact step:** Revert the `dst_svc_id = [0u8; 16]` zeroing in `proxy.rs` (restore `encode_service_name(service_name)`), compile, and test the SSH connection again.
- **Relevant files:** `proto/src/agent/proxy.rs`
- **Dependencies or assumptions:** Assumes the Windows gateway actually fails at decoding due to this hash mismatch, or vice-versa.
- **Testing status:** Unit tests for diagnostics are passing. Live integration failing.

### Task 2: Validate Windows Gateway Binary Build
- **Status:** Not Started
- **Detailed Description:** Check the actual deployed binary on `10.170.3.111` to see if it includes the newest `tunnel.rs` fallback logic and the latest relay-aware listener logic.
- **Next exact step:** Run PowerShell commands over the existing working raw SSH connection to determine the file creation date or hash of `ztlp.exe` running on `10.170.3.111`.
- **Relevant files:** N/A
- **Relevant commands:** `ssh -T trs@10.170.3.111 "cmd /c dir ztlp.exe"`
- **Testing status:** Blocked behind Task 1.

## Technical Context
- **Architecture:** `Hermes Client` -> `AWS Relay (Elixir UDP 23095)` -> `Windows ZTLP Gateway` -> `localhost:22`
- **Folder Structure:** 
  - `/home/trs/ztlp/proto/` -> Rust client/gateway code 
  - `/home/trs/ztlp/relay/` -> Elixir relay code 
- **Important source files:** `proto/src/agent/proxy.rs`, `proto/src/handshake.rs`, `relay/lib/ztlp_relay/gateway_forwarder.ex`
- **Services involved:** ZTLP Relay (34.219.64.205), ZTLP Windows Listener (47.180.216.203)
- **Deployment assumptions:** The Windows target currently requires regular proxy commands without PowerShell specific formatting issues `&`/`&&` due to shell invocation nuances over Windows SSH.
- **Build/runtime commands:** `cargo build --release --bin ztlp`
- **Security assumptions:** Standard ZTLP Zero-Trust model; relay cannot read payload logic; magic byte checking is enforced.

## Code Documentation Standards
- Functions must include clear docstrings.
- Explanations for *why* specific frame drop handlers (e.g. `poll_for_post_handshake_reject`) exist must be documented inline.
- Maintainability and consistency with the rest of the `ztlp-proto` codebase is mandatory.

## Testing Requirements
- **Test-first/TDD executed this session:** Wrote three unit tests for `decode_reject_payload` prior to integrating the polling logic.
- **What was tested:** The proxy's ability to decode `RejectFrames` properly, reject malformed bytes, and ignore standard data frames.
- **Commands used:** `cargo test --lib decode_reject_payload -- --nocapture` and `cargo test --lib agent::proxy::tests`
- **Remaining testing gaps:** Need integration testing to automatically replicate end-to-end `auth_tag_invalid` state without manually invoking `ssh`.

## Validation Requirements
- Ran `cargo test --lib` successfully.
- Ran live proxy command to SSH target.
- Discovered and explicitly documented that the live application fails specifically at the local pipeline auth tag validation due to AEAD decryption failures.

## Decisions Made
- **Implemented 500ms post-handshake REJECT polling in the proxy:** 
  - *Why:* To mirror `ztlp-cli.rs` and `ffi.rs`, and quickly diagnose if gateways were cleanly dropping data due to policy or service unavailability.
  - *Tradeoffs:* Adds a blocking 500ms delay to proxy setup, but this is negligible for human-driven SSH and critical for clear diagnostics.
- **Retained `dst_svc_id` hack (for now):**
  - *Why:* Originally added as a temporary workaround for an old gateway build; retained in this session solely to isolate the diagnostic fix testing.
  - *Current stance:* This decision should be reversed in the next session as it is highly likely the cause of the `auth_tag_invalid` drop.

## Known Problems
- **Bugs/Incomplete Implementations:** Data plane AES/ChaCha authentication drops packets returning from the Windows gateway (`auth_tag_invalid`).
- **Temporary workarounds:** `dst_svc_id = [0u8; 16]` zeroing.

## Open Questions
- Is the Windows gateway using an older version of the `snow` / Noise transcript protocol, or is the `dst_svc_id` hack solely responsible for the transcript hash divergence?

## Next Session Startup Plan
1. **What to review first:** Read this handoff document completely.
2. **What commands to run:** `cd /home/trs/ztlp ; git status && git log --oneline -5`
3. **What files to inspect:** `proto/src/agent/proxy.rs` specifically around line 386-398.
4. **What task to continue next:** Task 1 (Resolve `auth_tag_invalid` data plane drop).
5. **What to execute:** Remove `dst_svc_id = [0u8; 16]`, build the client (`cargo build --release --bin ztlp`), and run the live `ssh -v ...` command to confirm if the `auth_tag_invalid` issue resolves.
6. **Risks to avoid:** Do not assume the gateway binary on Windows is up-to-date without verifying it. Do not use powershell command separators (`&&` or `&`) when invoking commands on the Windows SSH target.

## Git Workflow Requirements
- Commit format utilized: `<type>: short summary\n\nDetailed description...`
- Commits generated strictly before session completion to ensure seamless state transition.
