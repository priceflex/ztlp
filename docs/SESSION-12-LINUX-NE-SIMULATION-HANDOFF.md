# Session 12: Linux NE Simulation Handoff

Date: 2026-04-10
Status: Research complete, implementation not started yet

## Goal
Replace most of the slow iPhone/Xcode deploy-test-debug cycle with a deterministic local workflow that simulates the ZTLP iOS Network Extension data plane on Linux.

## Core Decision
Do NOT try to simulate "the iPhone" literally.

Instead, simulate the ZTLP Network Extension data plane.

Reason:
- iOS Simulator is not trustworthy for `NEPacketTunnelProvider`
- it will not reproduce real NetworkExtension routing, lifecycle, entitlements, packetFlow semantics, or jetsam memory behavior
- Linux also cannot reproduce Apple control-plane/runtime behavior
- but Linux CAN simulate most of the tunnel logic we actually need to validate

## Industry Validation (added 2026-04-10)

This approach is not novel — it's the **industry standard** for production iOS VPN apps:

| Project      | Core Language | Tested On  | iOS Adapter    | NE Memory |
|-------------|--------------|------------|----------------|-----------|
| Tailscale   | Go            | Linux      | cgo bridge     | 30-50MB   |
| WireGuard   | Go            | Linux/macOS| cgo bridge     | 10-12MB   |
| Mullvad     | Rust          | Linux      | Swift FFI      | 5-10MB    |
| Outline VPN | Go            | Linux      | cgo bridge     | 10-13MB   |

Every project: thin Swift NE + cross-platform core + test core on Linux + device for lifecycle/memory only.

The key semantic equivalence: iOS `packetFlow` and Linux TUN both handle raw IP packets in/out. They differ only in control-plane behavior.

## Main Conclusion
The winning strategy is:
1. move most correctness testing to Linux
2. keep only a small real-device smoke suite for final validation
3. move VIP proxy to relay to get NE under 15MB
4. add `os_proc_available_memory()` monitoring to device tests

This should turn the current build → deploy → fail loop into a mostly deterministic local harness workflow.

## What Linux Can Validate Well
Linux can deterministically test:
- DNS responder behavior for `.ztlp`
- AAAA / HTTPS / SVCB / NXDOMAIN handling
- non-`.ztlp` DNS pass-through behavior
- NS client query/response parsing
- gateway resolution policy
- mux frame generation/parsing
- ACK batching and send queue behavior
- packet-router behavior
- VIP/service mapping logic
- UDP tunnel flow
- reconnect behavior in the transport/core layer
- many memory regressions caused by our own queues, buffers, `Data` copies, maps, and timers

## What Linux Cannot Prove
Linux cannot faithfully validate:
- actual `NEPacketTunnelProvider` lifecycle quirks
- real Apple `packetFlow` scheduling/backpressure semantics
- entitlement/install behavior
- exact `NEDNSSettings` DNS steering behavior
- real-device NetworkExtension resident-memory budget / jetsam
- exact NWConnection / NWListener runtime behavior inside iOS NE
- NWConnection.send() internal queue growth under load
- Network.framework per-instance overhead (each NWListener ~200-400KB)

So the phone still matters — but only as a short final smoke test.

## iOS NE Memory Reality (added 2026-04-10)

Apple has never published specific jetsam limits. Empirically observed:

| Device Class      | RAM    | NE jetsam threshold |
|-------------------|--------|---------------------|
| iPhone SE / older | 2 GB   | ~50-80 MB           |
| iPhone 12/13/14   | 4-6 GB | ~80-120 MB          |
| iPhone 15 Pro+    | 6-8 GB | ~120-150 MB+        |

ZTLP NE current: 18-21 MB resident. Over budget. Biggest drivers:
- 5 NWListeners (VIP proxy): ~1-2 MB at rest
- NWConnection.send() queue growth: ~3-5 MB under load
- Network.framework overhead: ~1-2 MB

**`os_proc_available_memory()`** (iOS 13+) is the ONLY official Apple API for checking NE memory at runtime. WireGuard and Tailscale both use it. The device smoke suite MUST log this every 10 seconds and alert if available drops below 50MB.

## VIP Proxy → Relay Architecture with NS-driven Relay Selection (added 2026-04-10)

The VIP proxy is the biggest actionable memory savings target. Currently:
- 5 NWListeners (80, 443, 8080, 8443, 8200) = ~1-2 MB at rest
- Accepted TCP connections + NWConnection.send() queues = ~3-7 MB under load
- Total VIP proxy overhead: ~5-8 MB of 18-21 MB NE footprint

**Proposed: Move VIP proxy to relay servers. NS drives relay selection.** This is the Tailscale DERP model.

Architecture:
1. NE connects → handshake with gateway
2. NE queries NS: "what relays are available?"
3. NS responds with relay list + stats (RelayInfo: relay_id, address, region, latency_ms, load_pct, active_connections, health)
4. NE picks best relay: filter Healthy only, sort by `latency_ms * (1 + load_pct/100)`, pick lowest
5. NE tunnels all VIP traffic through chosen relay (packetFlow → encrypt → UDP tunnel → relay)
6. Relay terminates TCP to backend, sends response back through tunnel
7. NE decrypts → writes to packetFlow → app receives response

Failover: relay drops → NE detects failure → re-queries NS → picks next best relay → reconnects

Benefits:
- Eliminate ALL NWListeners from NE = ~5-8 MB savings
- NE memory target: ~10-13 MB (comfortably under 15 MB)
- NE becomes 3 components: packetFlow, UDP tunnel, encrypt/decrypt
- Relay selection algorithm is pure computation — 100% testable on Linux
- Multi-relay deployment: deploy relay in any region → register with NS → clients auto-discover
- Graceful maintenance: mark relay Degraded in NS → clients drain to others
- No app update needed to add new relays

Linux harness implications:
- Relay selection tests: pure computation, fake NS responses, fully testable
- Relay failover tests: simulate relay drop → re-query → reconnect
- No VIP proxy to simulate in harness at all

This is higher priority than the Linux harness because it directly fixes the NE memory problem.

## Three Broken NS Resolution Implementations (added 2026-04-10)

1. **proxy.rs: ns_resolve()** — ASYNC, tokio-gated, unavailable in ios-sync builds
2. **ffi.rs: ztlp_ns_resolve()** — creates throwaway tokio runtime, also tokio-gated, stripped from NE
3. **ZTLPNSClient.swift** — SYNC BSD sockets, but only used for service discovery, NOT gateway resolution

Result: `resolveGateway()` bypasses NS entirely, uses hardcoded config target.

Fix: implement `ztlp_ns_resolve_sync` in Rust, delete tokio-gated paths from NE code path, keep Swift NSClient for service discovery, use Rust sync resolver for gateway resolution.

## Current Repo Facts Supporting This Plan
Relevant files:
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPDNSResponder.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPNSClient.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPVIPProxy.swift`
- sync Rust FFI / packet-router seams in `proto/src/ffi.rs`

Important observations:
- the iOS NE is already close to a thin adapter over sync FFI and standalone router logic
- `resolveGateway()` is still incomplete and falls back to `targetNodeId`
- this is still one of the main production-readiness gaps
- current benchmark code already simulates small parts of the send path
- relay integration tests already exercise real UDP behavior locally

## Key Production Gaps To Fix

### Gap 1: VIP proxy memory overhead (HIGHEST PRIORITY)
Move VIP proxy to relay. This is the biggest single memory savings and makes the NE testable.

### Gap 2: Gateway resolution
`PacketTunnelProvider.resolveGateway()` bypasses NS resolution. Need `ztlp_ns_resolve_sync`.

## Recommended Architecture
Build a Linux tunnel harness around the data-plane seams, NOT around Apple APIs.

### Layer 1: pure deterministic tests
Test directly:
- DNS responder packet parsing and synthesis
- NS client parsing
- gateway resolution rules
- mux framing
- ACK batching
- router action serialization

### Layer 2: Linux socket integration harness
Run locally:
- fake NS UDP server
- fake gateway UDP server
- optional fake backend services
- sync Rust crypto/router APIs

Validate:
- handshake
- NS lookup
- target resolution
- encrypted UDP flow
- mux exchange
- ACK timing/aggregation
- reconnect behavior

### Layer 3: Linux packetFlow replacement
Create either:
- in-memory packetFlow harness first (with batch delivery semantics)
- then TUN-backed Linux mode for higher fidelity

This should simulate:
- `readPackets()` (including iOS batch delivery semantics)
- `writePackets()`
- service VIP routing (or plain packet routing with relay model)
- local DNS interception

**Note:** iOS packetFlow delivers packets in batches with cooperative backpressure. Linux TUN read() is single-packet. Harness must simulate batch delivery to catch queue accumulation regressions.

### Layer 4: tiny Apple-only smoke suite
Keep real-device checks limited to:
1. tunnel starts
2. DNS settings apply
3. one `.ztlp` lookup works
4. one backend request works
5. one short benchmark works
6. memory stays under threshold during smoke run
7. `os_proc_available_memory()` > 50MB available throughout

## Concrete Next Steps
Recommended order:

1. design relay VIP architecture with NS-driven relay selection (`docs/RELAY-VIP-ARCHITECTURE.md`)
2. add NS relay discovery protocol (RelayInfo response format)
3. implement relay selection algorithm in Rust (pure computation, testable on Linux)
4. add relay-side TCP termination and service routing to relay server
5. remove VIP proxy from NE, route VIP traffic through packetFlow → tunnel → relay
6. implement `ztlp_ns_resolve_sync`
7. add resolver tests for "NS first, fallback to direct target second"
8. build fake-NS + fake-gateway Linux harness
9. add in-memory packetFlow harness
10. add TUN-backed Linux mode
11. reduce phone validation to smoke-only

## CryptoKit Swap Consideration (added 2026-04-10)

The skill doc mentions Phase 2: moving Noise_XX + ChaCha20 to CryptoKit to save ~2-3MB. With relay architecture:
- NE handles fewer code paths (no VIP mux framing), Rust TEXT segment may shrink further
- TEXT is already at 1.65MB (well under budget)
- CryptoKit code can ONLY be tested on iOS, undermining the Linux harness goal
- Currently Rust crypto (snow/chacha20poly1305) is fully testable on Linux

If we swap to CryptoKit, we lose Linux crypto testability. With relay architecture, the NE Rust surface is already small. CryptoKit swap may not be worth the tradeoff. Decide after relay migration.

## Files Written This Session
Plan document created:
- `/home/trs/ztlp/docs/LINUX-NE-SIMULATION-PLAN.md` (updated with research findings, relay architecture, memory reality)

This handoff file created for the next session:
- `/home/trs/ztlp/docs/SESSION-12-LINUX-NE-SIMULATION-HANDOFF.md` (updated)

## Recommended First Task Next Session
Start here:
1. Design relay VIP architecture with NS-driven relay selection — write `docs/RELAY-VIP-ARCHITECTURE.md`
   - Define RelayInfo format, selection algorithm, failover flow
   - This is pure design, no code yet
2. Implement relay selection algorithm in Rust (pure computation, testable on Linux immediately)
3. Then implement `ztlp_ns_resolve_sync` + tests

Why relay selection first:
- biggest single memory win (eliminates ~5-8MB of NE overhead)
- NS already knows about relays — natural discovery point
- selection algorithm is pure computation — can be written and tested on Linux right away
- makes NE dramatically simpler → easier to simulate on Linux
- relay already exists (34.219.64.205), just needs TCP termination + NS registration
- after relay migration, NE memory should drop to ~10-13MB (under 15MB target)
- adding new relays later requires zero NE code changes — just register with NS

Why NS resolve second:
- fixes a current production-readiness gap
- creates the first reusable building block for the Linux harness
- reduces duplicated resolution logic across environments

## Final Summary
Do not chase a full iPhone simulator solution.

Instead:
- move VIP proxy to relay with NS-driven relay selection (biggest memory win, makes NE thin enough)
- NS discovers relays, NE picks best based on latency/load stats, tunnels through it
- relay failover via NS re-query (automatic, no app update needed for new relays)
- treat Apple NetworkExtension as a thin platform adapter (packetFlow + UDP tunnel + encrypt/decrypt)
- move the real tunnel correctness work into a Linux-testable harness
- relay selection algorithm is pure computation — test it on Linux from day one
- keep the phone only for short final confirmation with `os_proc_available_memory()` monitoring
- keep Rust crypto (don't swap to CryptoKit) so Linux harness can test it

That is the path most likely to give consistent, repeatable wins instead of long Xcode/device debug cycles.
