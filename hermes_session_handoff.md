# Hermes Session Handoff (Updated 2026-05-18)

## 1. Project Goal
- Primary objective: enable Hermes to SSH to a Windows machine through ZTLP using the real relay-backed production path, so Hermes can administer Windows hosts without direct Internet SSH exposure.
- Immediate target host: `trs@10.170.3.111`.
- Scope for this session: complete the client-side/proxy-side engineering needed for relay-based SSH targeting, document the workflow, and verify what is still missing on the Windows host.

## 2. What Was Completed This Session
1. Created feature branch: `feature/windows-relay-ssh-access`.
2. Reviewed repo docs, existing handoff, git state, CI workflow, proto README, and proxy-related design docs.
3. Verified the Windows host is reachable by normal SSH and inspected its current state.
4. Confirmed on the Windows host:
   - hostname: `DESKTOP-LRC8DKH`
   - user: `desktop-lrc8dkh\trs`
   - OpenSSH `sshd` service is running
   - port 22 is listening on `0.0.0.0` and `::`
   - OpenSSH firewall rules are enabled
   - `ztlp` is NOT currently installed on PATH there
5. Replaced the temporary hardcoded Windows hack in `proto/src/agent/proxy.rs` with a production-safe, config-driven mechanism.
6. Added agent config support for static proxy targets in `proto/src/agent/config.rs`.
7. Added/updated unit tests with TDD coverage for:
   - static proxy target TOML parsing
   - optional NodeID decoding
   - static-target preference over NS lookup
   - domain-map / native-name fallback to NS lookup
   - SVC parsing error path when address is missing
   - resolved peer address usage
8. Added operator documentation: `docs/WINDOWS-RELAY-SSH.md`.
9. Saved implementation plan: `docs/plans/2026-05-18-windows-relay-ssh-access.md`.

## 3. Code Changes Landed
### Commit 1
- `9d8c1ca` — Add config-driven static proxy targets

### Commit 2
- `8d38559` — Remove remaining hardcoded Windows-specific fallback logic from proxy runtime path

### Files changed
- `proto/src/agent/config.rs`
- `proto/src/agent/proxy.rs`
- `docs/WINDOWS-RELAY-SSH.md`
- `docs/plans/2026-05-18-windows-relay-ssh-access.md`

## 4. New Behavior
`ztlp proxy` now resolves a target in this order:
1. exact hostname match in `~/.ztlp/agent.toml` `[proxy_targets."host"]`
2. otherwise existing native `.ztlp` / `dns.domain_map` → NS lookup path

Static proxy targets support:
- `ztlp_name` (optional)
- `addr` (required, `host:port`)
- `node_id` (optional, 32-char hex)

This gives us a clean bridge for real-world relay testing before NS records are fully present.

## 5. Example Operator Config
Example Linux-side `~/.ztlp/agent.toml`:

```toml
[ns]
servers = ["<ns-host>:23096"]

[tunnel]
prefer_relay = true
relays = ["<relay-host>:23095"]

[proxy_targets."windows-relay.internal.techrockstars.com"]
ztlp_name = "windows.techrockstars.ztlp"
addr = "10.170.3.111:23095"
node_id = "b88397923c2518ca6aa400eb79a18c7b"
```

Example SSH config:

```sshconfig
Host windows-relay.internal.techrockstars.com
    User trs
    ProxyCommand ztlp proxy %h %p
```

## 6. Validation Performed
### Git / repo startup checks
- current working repo: `/home/trs/ztlp`
- starting branch was `main`
- feature branch created successfully
- existing unrelated local changes were present before work:
  - `proto/src/agent/proxy.rs` was already modified with a dev hack
  - `v30-telemetry-evidence.log` untracked

### Test execution
Ran from `/home/trs/ztlp/proto`:
- `cargo test --lib agent::config` → passed
- `cargo test --lib agent::proxy` → passed
- `cargo test --lib` → passed (`884 passed, 0 failed`)

Note: test output still contains pre-existing warnings in unrelated proto code (`ffi.rs`, `recv_window.rs`, `tunnel.rs`). No failures.

### CI relevance
Current CI in `.github/workflows/ci.yml` covers:
- Rust formatting, clippy, build, lib tests
- relay/ns/gateway Elixir tests
- interop suite
- performance gate

This session only reran the Rust lib-test subset locally.

## 7. What Is Still Blocked
End-to-end ZTLP SSH to the Windows host is NOT complete yet because the Windows machine does not currently have `ztlp` installed/running.

That means:
- client-side ProxyCommand support is ready
- relay-first config shape is ready
- but the remote Windows endpoint is not yet exposing a ZTLP listener such as:

```powershell
ztlp listen --key C:\ProgramData\ztlp\machine.json --bind 0.0.0.0:23095 --forward ssh:127.0.0.1:22
```

Without that listener, Hermes cannot complete a real ZTLP handshake to the Windows box.

## 8. Exact Next Steps
1. Build or provide a Windows `ztlp.exe` binary for the target machine.
2. Copy/install it on `10.170.3.111`.
3. Generate or provision a ZTLP identity on that host.
4. Start `ztlp listen` on Windows forwarding to `127.0.0.1:22`.
5. Decide the final relay endpoint and populate Linux-side `tunnel.relays` / `prefer_relay = true`.
6. If NS records are not ready, keep using `proxy_targets`; if NS is ready, register proper SVC/KEY records and remove the static override.
7. From Hermes/Linux, run:
   - `ztlp proxy windows-relay.internal.techrockstars.com 22`
   - then `ssh windows-relay.internal.techrockstars.com`
8. If the Windows listener is long-lived, install it as a Windows service after validation.

## 9. Operational Notes / Pitfalls
- `proxy_targets` is exact-match by hostname.
- `addr` must point to the actual ZTLP endpoint, not just the SSH endpoint.
- `node_id` is optional; omit it if not yet known.
- `parse_svc_response` now fails cleanly instead of silently substituting a host-specific fallback.
- `run_proxy` now uses the resolved address; there is no remaining runtime hardcoded `10.170.3.111` logic.
- Remaining appearances of `10.170.3.111` in `proxy.rs` are test fixtures only.
- Do not lose sight of the unrelated untracked file: `v30-telemetry-evidence.log`.

## 10. Recommended Startup For Next Session
1. Read this handoff and `docs/WINDOWS-RELAY-SSH.md`.
2. Check branch and git status.
3. Build or locate a Windows `ztlp.exe`.
4. SSH to `trs@10.170.3.111` and install/configure ZTLP.
5. Start a Windows-side ZTLP listener for SSH.
6. Run a real `ztlp proxy` / `ssh` validation over the relay path.
