# ZTLP iOS Nebula-style architecture plan — 2026-05-03

## Goal

Make ZTLP on iOS behave like a normal VPN/browser path, comparable to DefinedNet/mobile_nebula, without continuing two months of rwnd/queue/RTO micro-tuning and without destabilizing the parts that already work.

## Current conclusion

The Vaultwarden backend is healthy and the ZTLP path can deliver multiple MB. The failure is the tail of browser-scale asset delivery through the current hybrid path:

WKWebView / iOS TCP stack
-> utun
-> ZTLP PacketRouter synthetic TCP state
-> mux stream actions
-> gateway session-level UDP reliable packet stream
-> backend TCP

That creates stacked reliability and flow-control layers. The latest fixes improved queue explosion, backend pause, stale stream-id reuse, and RTO blast size, but the same class of stall remains.

Nebula does not do this. Nebula passes the utun fd to one native engine and lets that engine own packet I/O, routing, encryption, timers, retransmit behavior, and peer state as one coherent system. Swift configures the tunnel, gets the fd, starts the native engine, and mostly gets out of the data plane.

## What Nebula mobile does that matters

Observed in DefinedNet/mobile_nebula:

- iOS PacketTunnelProvider obtains the utun fd.
- It configures NEPacketTunnelNetworkSettings and DNS/routes.
- It calls MobileNebulaNewNebula(config, key, logFile, tunFD).
- The Go Nebula engine is created with overlay.NewFdDeviceFromConfig(&tunFd).
- The engine owns the fd and calls Control.Start().
- Swift is not running readPackets/writePackets loops or synthetic per-flow TCP recovery.

This is the key difference, not the UI.

## What ZTLP currently has

Ztlp already started the right migration:

- proto/src/ios_tunnel_engine.rs has IosUtun and IosTunnelEngine.
- It can read/write raw utun fd packets with the 4-byte Darwin header.
- PacketTunnelProvider.swift already discovers a utun fd and can start a Rust fd path.
- But the current Rust fd path still feeds the existing PacketRouter/mux action model and still relies on Swift callbacks for transport dispatch. It has not become a single coherent native tunnel engine.

## Plan: stop tuning current browser congestion path; build a Nebula-style ZTLP engine behind a feature flag

### Non-negotiables

1. Do not restart gateway/relay/NS without warning Steve first.
2. Do not rip out the existing Swift PacketTunnelProvider path until the new path passes controlled tests.
3. Keep WKWebView, not SFSafariViewController.
4. Do not change Vaultwarden/backend/service config while testing iOS data plane.
5. Preserve the current working benchmark path as rollback.
6. Every new engine build needs a startup marker in app-group ztlp.log so stale NE deploys are obvious.

### Phase 0 — freeze current state

- Commit or stash current uncommitted changes separately:
  - gateway/lib/ztlp_gateway/backend.ex
  - gateway/lib/ztlp_gateway/session.ex
  - ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
- Tag the current deployment state in docs as the last rwnd/queue/RTO experiment.
- Do not do further queue_high/rwnd/RTO edits unless needed for rollback.

### Phase 1 — validate and harden the existing Rust utun fd foundation

Target files:

- proto/src/ios_tunnel_engine.rs
- proto/src/ffi.rs
- ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift

Work:

- Keep this behind a compile/runtime flag.
- Add a clean FFI API shaped like Nebula:
  - ztlp_ios_engine_new(config, identity, relay/ns info, tun_fd, log callback) -> engine
  - ztlp_ios_engine_start(engine)
  - ztlp_ios_engine_stop(engine)
  - ztlp_ios_engine_free(engine)
- The new engine must own:
  - utun fd read loop
  - utun fd write loop
  - UDP socket or transport send/recv loop
  - PacketRouter or replacement flow engine
  - timers/keepalive/reconnect state
- Swift should only configure NE settings, pass config/fd, start engine, stop engine, and receive logs/status.

Validation before any browser test:

- Unit test utun header read/write behavior.
- Unit test engine start/stop is idempotent.
- Unit test no Swift packetFlow read loop is active when Rust fd engine is active.
- Build libztlp_proto_ne.a with ios-sync.
- Unsigned Xcode build succeeds.
- Device log shows explicit marker:
  - ZTLP iOS native fd engine ACTIVE

### Phase 2 — make the native engine transport-coherent

This is the real architecture change.

The engine should not keep bolting more state onto Swift + PacketRouter + gateway rwnd. It needs one owner for these decisions:

- received gateway packet sequence state
- client ACK generation
- replay filtering
- retransmit/reconnect policy
- router outbound delivery to utun
- mux stream open/send/close lifecycle
- close/FIN timing
- per-stream backpressure

Minimum viable version:

- Rust owns utun and gateway UDP socket.
- Rust reads utun packets and emits mux frames directly.
- Rust receives gateway packets, decrypts, applies session ACK/replay logic, feeds PacketRouter, and drains outbound to utun in the same event loop.
- Swift does not mediate router actions or packet writes.

This removes a major source of current problems: state transitions split across Rust, Swift queues, NWConnection callbacks, and gateway timers.

### Phase 3 — decide whether PacketRouter remains or gets replaced for browser TCP

There are two viable tracks:

#### Track A: keep PacketRouter temporarily, but make it single-owner inside Rust

This is the shortest path because the code already exists.

Required improvements:

- PacketRouter must expose explicit per-flow pressure and close state to the engine.
- Engine must never issue local router reset without gateway session reset.
- Gateway CLOSE must wait for delivered-to-utun completion.
- The engine must drive both read and write sides; no Swift flush timers.

This may be enough once the split Swift/Rust data-plane issue is removed.

#### Track B: replace synthetic TCP-over-mux with stream-level flow control

This is the more correct long-term transport.

Required protocol model:

- Each browser TCP flow maps to one gateway stream.
- Gateway has a per-stream send window in bytes/frames.
- Client sends per-stream consumed/delivered ACKs.
- Gateway reads backend only when that stream has window.
- Gateway CLOSE is not sent until all bytes for that stream are acknowledged/delivered.
- Session packet ACK is only for UDP reliability, not browser stream flow control.

This is more work but addresses the root issue instead of tuning packet rwnd.

### Phase 4 — test matrix before asking for normal use

For every candidate build:

1. Run server preflight locally:
   ~/ztlp/scripts/ztlp-server-preflight.sh
   Must end with PRECHECK GREEN.

2. Device startup verification:
   - Pull ztlp.log.
   - Confirm native engine startup marker.
   - Confirm no old Swift packetFlow read marker when engine is active.

3. Smoke tests:
   - VPN connects.
   - DNS *.ztlp resolves.
   - 8/8 benchmark passes.
   - Simple HTTP service loads.

4. Browser tests:
   - Open Vaultwarden in WKWebView.
   - Record exact time.
   - Pull phone log and gateway log only for that window.
   - Classify failure by:
     - no useful RX
     - replay storm
     - utun write error
     - stream close before tail
     - gateway queue/backpressure
     - NE lifecycle drop

5. Regression criteria:
   - No VPN 5 -> 1 crash unless user manually stopped VPN.
   - No duplicate FRAME_OPEN caused by local-only reset.
   - No send_queue already overloaded lines in current window.
   - No queue thousands for Vaultwarden.
   - Page reaches login and resources finish.

## What not to do next

- Do not keep tweaking rwnd from 8 to 4 to 12 to 16.
- Do not lower queue_high again as a primary fix.
- Do not add another Swift health/reconnect workaround on top of stale flow state.
- Do not move back to SFSafariViewController.
- Do not conclude Vaultwarden is broken unless direct backend/VPN-independent tests fail.

## Immediate next engineering task

Create a small design/implementation branch for the native iOS engine API and make the first PR do only this:

- Add clean Rust FFI engine object.
- Start/stop engine with utun fd.
- Engine owns fd read/write loops.
- No gateway protocol changes yet.
- Feature flag in PacketTunnelProvider.swift.
- Startup markers and tests.

Then the second PR moves gateway UDP transport and ACK/replay into the Rust engine. Only after that should Vaultwarden/WKWebView be used as the acceptance test.
