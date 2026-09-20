# HANDOFF — 2026-09-14 — Mac client: make it work like Windows (very simple)

Branch: `macos-simple-direct-connect` (in `/home/trs/ztlp`, remote `priceflex/ztlp`)
Commit: `5a657c0` (local, NOT pushed)
Author: steve@techrockstars.com

## What the user asked
"I think the windows version is more ready than the mac one. Get the mac
version all caught up... take a look at the windows version. We should have
started it already. ... look at what we have but make it work like windows,
very simple."

Chosen target (confirmed with user): the **native Swift `macos/ZTLP` app** is
the real Mac client. Goal = make it behave like the Windows client: connect to
a ZTLP service by name through the same proven FFI path, dead-simple surface,
no re-architecture.

## Key finding (the whole thing hinges on this)
The Mac is NOT actually behind on the protocol. The shared Rust core
`proto/` (v0.35.10) is caught up:
- `proto/src/ffi.rs` (153 exported C fns, 8858 lines) already ships the
  modern surface: `ztlp_connect` (QUIC), VIP proxy, DNS resolver, packet
  router, iOS tunnel engine, CA fetch, gateway-key pin, handshake, crypto.
- `.github/workflows/release.yml` already cross-compiles `libztlp_proto.a`
  + `ztlp`/`ztlp-node` binaries for `aarch64-apple-darwin` +
  `x86_64-apple-darwin` on every tag.
- `proto/Cargo.toml` crate-type is `["lib","staticlib"]` = the `libztlp_proto.a`
  the Swift app links; `default = ["tokio-runtime","quic-transport"]`.

So the gap was NOT the core. It was the two client shells being built on
different foundations:
- Tauri `desktop/` app (the Windows one, "ready"): web UI over `src-tauri`
  Rust backend that drives the real `ztlp`/`ztlp-node` QUIC CLI + agent
  daemon. Single-path by construction.
- Native `macos/ZTLP` Swift app: a Network Extension (`PacketTunnelProvider`)
  + a userspace "Direct Connect" path. The Direct Connect path
  (`TunnelViewModel.connectDirect`) ALREADY does the right thing (NS-resolve
  service name -> QUIC `ztlp_connect` -> VIP proxy + DNS). The problem was
  everything bolted around it: a two-mode design (system-VPN + direct) where
  VPN was auto-preferred, plus NAT/STUN assumptions and a pile of hidden
  advanced fields. That's why it *felt* less ready than Windows.

## What was changed (commit 5a657c0, UI/config/behavior only)
No data-plane / FFI changes. Four files, all under `macos/ZTLP/ZTLP/`:

1. `ViewModels/TunnelViewModel.swift`
   - `preferVPN` stays default `false`.
   - `checkVPNAvailability()` no longer sets `preferVPN = true` just because a
     VPN config exists; it only mirrors VPN status into the UI when the user
     actually opted in.
   - `connectDirect()` no longer forces `setNatAssist`; only sends NAT assist
     when `configuration.natAssist` is explicitly on (NAT assist pulls in the
     legacy raw-UDP path).
2. `Models/ZTLPConfiguration.swift`
   - `natAssist` default flipped `true -> false` (init + `reset()`).
3. `Views/SettingsView.swift`
   - General section now LEADS with a simple `Service` field (the NS service
     name, e.g. `beta`) — the Windows connect-by-name model.
   - Removed the STUN field from the UI (property retained for the VPN path).
   - NAT Assist moved from General into a clearly-labeled Advanced
     `NAT Traversal (legacy)` toggle with a help string.
   - Connection section relabeled `Connection (advanced)`.
4. `Views/HomeView.swift`
   - The transport-mode chip now only shows for the opt-in VPN path, not on
     the default Direct Connect path.

## Verification done here (Linux build box)
- No `swiftc`/`swift`/`xcodegen` on this box — a Mac is REQUIRED to build,
  codesign (dev team `5527A7TH5P`, auto-sign), and run the app + System
  Extension (Apple-gated). So this commit is NOT compile-verified.
- Structural checks pass on all 4 changed files: brace/paren/bracket balance
  (with strings+comments stripped) all balanced.
- Reference audit: `stunServer` still exists in the model (only the UI field
  was removed); all remaining references are model/VPN-path, nothing dangles.
  `preferVPN` is self-contained in TunnelViewModel. No broken symbol refs.

## NOT DONE / BLOCKED
- BLOCKED: real `xcodebuild` / codesign / run. Needs a Mac. There is NO Mac in
  the known SSH config; the only reachable box (10.170.3.207) is the Windows
  AI computer (Session 0, no GUI for this). Ask Steven which Mac to use, or
  have him build.
- The System Extension target (`PacketTunnelProvider.swift`) still uses the
  older hand-wired data path (raw `ztlp_send` + manual 2-byte proto framing +
  NAT/STUN). That is now only reachable via the opt-in VPN path, so it's
  parked — but it is the "port the data plane onto the QUIC agent/CLI model"
  item if the user later wants the VPN path to also be clean. Left untouched
  per the "make it work like windows, very simple / don't re-architect" scope.

## Next steps (on a Mac)
1. `cd /home/trs/ztlp` (or the Mac's copy), check out
   `macos-simple-direct-connect`.
2. Build: the Xcode project is generated from `macos/ZTLP/project.yml`
   (xcodegen) into `macos/ZTLP/ZTLP.xcodeproj`. On the Mac:
   `cd macos/ZTLP && xcodegen` (if needed) then build the `ZTLP` scheme
   (deployment target macOS 13.0, dev team 5527A7TH5P, auto-sign).
3. Confirm the `libztlp_proto.a` for the host arch is in `macos/ZTLP/Libraries/`
   (link is `-lztlp_proto -lresolv -lz`). If missing, drop in the
   `aarch64-apple-darwin` (Apple Silicon) or `x86_64-apple-darwin` (Intel)
   `libztlp_proto.a` from the latest `v0.35.10` release tarball.
4. Run: connect with the simple flow — set `Service` = a real NS name in
   Settings, ensure Relay (e.g. prod `44.230.7.100:23095`) is set, tap the
   Home Connect button. Expect the Direct Connect path (NS-resolve -> QUIC
   connect -> VIP + DNS), NOT the VPN path. Verify traffic in the tunnel and
   that `https://<service>.<zone>` resolves through the local DNS/VIP.
5. Only push `macos-simple-direct-connect` after a green build on the Mac.

## Open questions for Steven
- Which service(s) should be the default in `startVipProxy()`? It's currently
  hardcoded to `beta` + `vault` on VIPs 127.0.55.1/127.0.55.2. If the goal is a
  truly generic "connect to whatever service I typed" surface, that block
  should be driven by `configuration.serviceName` instead of the two literals.
- Do you want the System Extension (VPN) path cleaned up too, or is parking it
  (opt-in, older data path) fine for now?
