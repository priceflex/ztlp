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
  - Diagnostic improvements to `proxy.rs` to catch and decode `RejectFrame` payloads.
  - Implemented HELLO retransmit loops in the proxy to handle initial UDP drop during the Noise_XX handshake.
  - **ROOT CAUSE IDENTIFIED** for the `auth_tag_invalid` data plane drop: The `dst_svc_id` in the `HandshakeHeader` is mixed into the Noise protocol transcript. Our temporary hack in `tunnel.rs` returning `[0u8; 16]` for `encode_service_name` causes the proxy and the Windows listener to have mismatched transcripts (since the gateway sees the service name differently and hashes it differently).
- **In Progress:** Reverting the `encode_service_name` hack, rebuilding the Windows binary, and testing the end-to-end SSH tunnel.
- **Failing / Blocked:** 
  - SSH session establishment currently hangs or drops due to the `auth_tag_invalid` decryption failure at the pipeline level.
- **Recently Changed:** 
  - `proto/src/tunnel.rs`: Hacked `encode_service_name` to return `[0u8; 16]` to isolate the error.
  - `proto/src/agent/proxy.rs`: Rewrote the `HELLO_ACK` wait loop to support `node.recv_raw()` and retransmissions.
- **Temporary Workarounds:** 
  - `encode_service_name` in `tunnel.rs` is hardcoded to return `[0u8; 16]`. **This must be reverted immediately in the next session.**
- **Current System Stability Status:** The codebase is compiling, but the temporary `[0u8; 16]` hack breaks authentication for named services.

## Active Tasks

### Task 1: Revert `encode_service_name` Hack & Validate End-to-End SSH
- **Status:** In Progress
- **Detailed Description:** The ZTLP Noise_XX handshake succeeds and establishes a tunnel, but the Windows gateway and Hermes proxy derive different AEAD keys because their handshake transcripts differ. This is directly caused by the `encode_service_name` hack in `tunnel.rs` (setting it to `[0u8; 16]`). We must revert this so both sides use the identical `dst_svc_id` derived from the string `"win"`, recompile the Windows listener, and re-test.
- **Important implementation notes:** Noise keys depend on identical protocol transcripts. Even a 1-byte difference in the hashed prologue (which includes `dst_svc_id`) alters the resulting cipher keys.
- **Known issues:** The Windows Agent Daemon currently fails to bind port 53 / 4433 without Administrator privileges, so we are bypassing it by using the primitive `ztlp listen` command for testing.
- **Next exact step:** 
  1. Revert `encode_service_name` in `proto/src/tunnel.rs`.
  2. `cargo build --release --target x86_64-pc-windows-gnu --bin ztlp`
  3. `scp target/x86_64-pc-windows-gnu/release/ztlp.exe trs@10.170.3.111:C:/Users/TRS/ztlp.exe`
  4. Restart listener: `ssh -T trs@10.170.3.111 "cmd /c ztlp.exe listen --bind 0.0.0.0:23095 --key %USERPROFILE%\.ztlp\identity.json --relay 34.219.64.205:23095 --forward win:127.0.0.1:22 --service-name win"`
  5. Test connection: `ssh -v -o ProxyCommand="/home/trs/ztlp/proto/target/release/ztlp proxy win 22 --relay 34.219.64.205:23095" trs@win.ztlp`
- **Relevant files:** `proto/src/tunnel.rs`
- **Testing status:** Pending integration test in the next session.

## Technical Context
- **Architecture:** `Hermes Client` -> `AWS Relay (Elixir UDP 23095)` -> `Windows ZTLP Listener` -> `localhost:22` (sshd)
- **Folder Structure:** 
  - `/home/trs/ztlp/proto/` -> Rust client/gateway code 
  - `/home/trs/ztlp/relay/` -> Elixir relay code 
- **Important source files:** `proto/src/tunnel.rs`, `proto/src/agent/proxy.rs`
- **Services involved:** ZTLP Relay (34.219.64.205)
- **Deployment assumptions:** Windows target (`10.170.3.111`) has SSH running natively but ZTLP must act as the routing wrapper.

## Code Documentation Standards
- Functions must include clear comments/docstrings.
- Complex logic must explain WHY it exists.
- Public APIs/classes/modules must be documented.
- Edge cases and assumptions must be documented.
- Configuration files should contain explanatory comments where possible.
- Avoid “magic behavior” without explanation.
- Code should be understandable by a brand-new engineer reviewing it later.

## Testing Requirements
- Write tests while implementing features, not afterward.
- Add/update unit tests for new logic.
- Verify bug fixes with regression tests.
- Ensure all tests pass before ending a session.
- Never leave knowingly failing tests without documenting them clearly.
- **What was tested this session:** Verified `ztlp proxy` handshake retransmission resilience against simulated packet drops. Verified Windows gateway correctly connects and registers with the AWS relay using `.toml` configs.

## Validation Requirements
Before considering work complete Hermes MUST:
- Run tests (`cargo test --lib`).
- Validate the application starts correctly.
- Check logs for hidden failures (like `auth_tag_invalid`).
- Ensure no obvious regressions were introduced.

## Decisions Made
- **Bypassed Agent Daemon on Windows:** The full `ztlp agent start` failed on Windows because it attempts to bind to DNS port 53 and Control port 4433, which requires Administrator privileges or specific socket configurations.
  - *Why:* To keep momentum on the actual SSH data-plane proxying issue, we fell back to the primitive standalone `ztlp listen` command.
  - *Tradeoffs:* We are manually specifying the relay and forward mapping instead of relying on the configured `agent.toml` for the gateway.
- **Hacked `tunnel.rs` to isolate hash mismatch:** Replaced `encode_service_name` with `[0u8; 16]` to definitively prove the AEAD decryption drops were tied to `dst_svc_id` mismatches. (It must be reverted).

## Known Problems
- **Bugs:** `auth_tag_invalid` drops data connection.
- **Technical debt:** Windows agent daemon fails to start gracefully as a standard user.
- **Temporary workarounds:** `[0u8; 16]` hack in `tunnel.rs` `encode_service_name`.

## Open Questions
- Does the Windows `sshd` properly handle `ProxyCommand` connections routed through `ztlp listen` without dropping due to unexpected `CRLF` conversions on stdin/stdout?

## Next Session Startup Plan
1. **What to review first:** Read this handoff document completely.
2. **What commands to run:** `cd /home/trs/ztlp && git status`
3. **What files to inspect:** `proto/src/tunnel.rs` (look for `encode_service_name`).
4. **What tests to run first:** `cargo test --lib --manifest-path=proto/Cargo.toml`
5. **What task to continue next:** Task 1 (Revert `encode_service_name` Hack & Validate End-to-End SSH).
6. **What risks to avoid:** Ensure you cross-compile for Windows (`x86_64-pc-windows-gnu`) before copying the binary over, otherwise the Windows host will throw executable format errors.

## Git Workflow Requirements
- Commit format utilized: `<type>: short summary\n\nDetailed description...`
- Commits generated strictly before session completion to ensure seamless state transition.