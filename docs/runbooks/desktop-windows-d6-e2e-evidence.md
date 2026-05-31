# D6 — Setup Wizard UI: Runbook

**Status:** Implemented, unit-tested. CI builds the Windows MSI; live E2E performed by clicking through the wizard on the bench.

**Branch:** `feat/d6-setup-wizard-ui`
**PR:** (filled in after open)

---

## What D6 delivers

A single-user-friendly **Setup Wizard** page in the ZTLP desktop app that drives the entire post-enrollment one-time setup with **5 button clicks** — no PowerShell, no command line, no admin terminal:

1. **Step 1 — Identity** — enrollment status (read-only; user clicks "Enrollment" if needed)
2. **Step 2 — Generate CA Chain** — runs `ztlp admin ca-init --zone <z>` (no admin needed)
3. **Step 3 — Install CA in System Trust** — UAC-elevates `ztlp agent install-ca-cert --machine-scope`
4. **Step 4 — Configure DNS** — UAC-elevates `ztlp agent dns-setup --zone <z>`
5. **Step 5 — Browser Smoke Test** — `curl --cacert ~/.ztlp/ca/root.pem https://<hostname>/` and shows the HTTP code

Every step is **idempotent** and **safe to re-run**. After each click the wizard re-fetches `setup_status` from the agent and re-renders the green check.

## Runtime architecture changes (D6.T1)

The agent daemon (`proto/src/agent/daemon.rs`) now loads the intermediate CA from `~/.ztlp/ca/` at startup and constructs the `SniCertResolver` with `with_mint_ca(...)`. When a TLS ClientHello arrives for an unseen SNI hostname, the resolver mints a leaf cert on-demand (signed by the per-zone intermediate), caches it to disk, and serves the handshake — no manual cert provisioning required.

If the CA chain isn't initialized at agent startup, the daemon logs a single `info!` line and falls back to the disk-only resolver. The Setup Wizard's `setup_status` step "CA initialized?" tells the user how to fix this.

## New control-plane command: `setup_status`

The agent's TCP control plane (`127.100.255.1:4433`) gains one new command:

```json
→ {"cmd": "setup_status"}
← {"ok": true, "data": {
    "identity_present": true,
    "identity_enrolled": true,
    "ca_initialized": true,
    "ca_installed_system_trust": true,
    "dns_configured": true,
    "daemon_running": true,
    "zone": "trs.ztlp",
    "ca_root_pem_path": "C:\\Users\\trs\\.ztlp\\ca\\root.pem",
    "identity_path": "C:\\Users\\trs\\.ztlp\\identity.json"
}}
```

The UI uses this snapshot to render the wizard's checkmarks and to know which button to enable next.

## UAC elevation pattern (Windows)

Steps 3 and 4 modify the **machine-wide** trust store / NRPT, which require Administrator. We **never** run the desktop app as admin. Instead, the desktop binary calls `ShellExecuteW(..., "runas", "ztlp.exe", "agent install-ca-cert --machine-scope", ...)`, which pops the standard Windows UAC dialog. After the user accepts, an elevated `ztlp.exe` instance runs the privileged operation as a detached process, exits, and the wizard polls `setup_status` to detect the new state and re-render the green check.

This means the desktop process itself has only standard-user privileges — the only elevation is per-operation, scoped to the exact ztlp subcommand.

## Test coverage

| Layer | Tests |
|---|---|
| `proto` lib (D6.T1 daemon wiring + setup_status) | **1084 / 1084 pass** |
| `desktop` Tauri commands (D6 setup module) | **8 / 8 pass** (4 new D6 + 4 pre-existing) |
| Live E2E on Windows bench | See "Live E2E" section below |

## How to test on the Windows bench (live E2E)

Once CI ships the MSI (or you tauri-build locally), on `10.170.3.111`:

1. **Install** the MSI by double-clicking `ZTLP_1.0.0_x64_en-US.msi`. The installer drops `ZTLP.exe` (the GUI) and `ztlp.exe` (the CLI/daemon) into `C:\Program Files\ZTLP\`.
2. **Launch** `ZTLP.exe` from the Start menu. The tray icon appears.
3. **Enroll** — navigate to the Enrollment tab, paste the `ztlp://enroll/...` token, accept the attestation checkbox, click **Enroll**.
4. **Open Setup** — click the new "🚀 Setup" tab in the sidebar.
5. **Run the wizard top to bottom**:
   - Step 2: click **Generate CA Chain** — green check within ~2 sec
   - Step 3: click **Install CA (admin required)** — UAC prompt → accept → green check
   - Step 4: click **Configure DNS (admin required)** — UAC prompt → accept → green check
   - Step 5: type `vault.trs.ztlp` (or any zone hostname) in the text box → click **Test** — expect `HTTP 200 from https://vault.trs.ztlp/` plus a "your browser will show a green lock!" green message
6. **Verify in browser** — open Edge/Chrome, navigate to `https://vault.trs.ztlp/`. The lock icon should be solid green (no warnings, no exceptions).

If Step 5 fails, the wizard surfaces the exact `curl` exit code and stderr — usually one of:
- "connection refused" → daemon not running; restart it from the tray
- "could not resolve" → NRPT rules didn't take; re-run Step 4
- "self signed certificate in certificate chain" → CA not in trust store; re-run Step 3
- "Connection reset" → tunnel didn't establish; check the daemon log

## Known constraints

- **Windows-only privileged steps.** On macOS the agent's existing `dns_setup.rs` already does the equivalent under the user's keychain at install time — no wizard prompt needed. On Linux there's no per-app NSS trust store, so the CA-install step is best-effort.
- **One zone at a time.** The wizard operates on the enrolled zone in `~/.ztlp/identity.json`. Multi-zone is a D7 concern.
- **No automatic rollback.** If Step 4 succeeds but Step 5 fails, the user has to manually click "Configure DNS" again or use `ztlp agent dns-teardown` from the CLI. A "Reset Setup" button is a D7 nice-to-have.

## Files changed

- `proto/src/agent/daemon.rs` — D6.T1 wire `cert_mint::IntermediateCa::load_from_dir` + `SniCertResolver::with_mint_ca`
- `proto/src/agent/control.rs` — new `SetupStatus` struct + `cmd_setup_status` + dispatch
- `desktop/src-tauri/src/setup.rs` — 5 new `#[tauri::command]` handlers + UAC ShellExecuteW shellout
- `desktop/src-tauri/src/main.rs` — register the new commands
- `desktop/src/components/setup.js` — wizard UI (status card + 5 step cards + button handlers)
- `desktop/src/index.html` — sidebar nav entry + page container + script tag
- `desktop/src/app.js` — wire `SetupComponent.render() + .load()` into init
- `desktop/src/styles.css` — `.setup-ok` / `.setup-err` / `.setup-pending` colors
- `.gitignore` — exclude `desktop/src-tauri/binaries/` (Tauri build sidecar)
