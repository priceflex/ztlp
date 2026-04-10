# ZTLP Linux NE Simulation Plan

> Goal: replace most of the slow iPhone deploy/test loop with a deterministic local harness that exercises the ZTLP tunnel data plane on Linux, while keeping a very small real-device smoke suite for the Apple-only pieces.

## Bottom line

We should NOT try to "simulate the iPhone" in a literal sense.

That will not solve the hard parts because:
- iOS Simulator is not trustworthy for `NEPacketTunnelProvider`
- Simulator will not reproduce NetworkExtension lifecycle, packetFlow behavior, entitlements, routing, or jetsam memory limits
- Linux cannot emulate Apple NetworkExtension control-plane semantics

But we CAN get most of the value by simulating the ZTLP Network Extension data plane on Linux.

That means:
- simulate `packetFlow.readPackets()` / `writePackets()`
- simulate tunnel bring-up inputs
- run DNS responder / NS client / mux framing / packet router / UDP tunnel flow locally
- test full packet movement through a TUN-backed harness or an in-memory harness

This is the right path because the current iOS extension is already mostly a thin adapter over sync FFI and standalone packet-router logic.

## Industry validation

This is not a novel approach. It is the **industry standard pattern** for production iOS VPN apps:

| Project      | Core Language | Core Tested On | iOS Adapter    | NE Memory |
|-------------|--------------|-----------------|----------------|-----------|
| Tailscale   | Go            | Linux (tstest)  | cgo bridge     | 30-50MB   |
| WireGuard   | Go            | Linux/macOS     | cgo bridge     | 10-12MB   |
| Mullvad     | Rust          | Linux           | Swift FFI      | 5-10MB    |
| Outline VPN | Go            | Linux (tun2socks)| cgo bridge    | 10-13MB   |
| Mozilla VPN | Rust (neqo)   | Linux           | Swift adapter  | N/A (discontinued) |

Every one of these projects:
1. Tests protocol/crypto/routing logic on Linux, not on iOS
2. Keeps the iOS NE as a thin Swift adapter (~200-500 lines)
3. Uses an interface/trait for "packet source" — TUN on Linux, packetFlow on iOS
4. Only tests lifecycle and memory on real devices

The semantic equivalence is key: `NEPacketTunnelProvider.packetFlow` and Linux `/dev/net/tun` both handle raw IP packets in/out. They differ only in control-plane behavior, which is Apple-only territory.

## What Linux can prove

Linux can validate, deterministically:
- DNS responder behavior for `.ztlp`, AAAA, HTTPS/SVCB, NXDOMAIN, pass-through
- NS client query and parsing behavior
- gateway resolution behavior
- mux frame generation and parsing
- ACK batching / send queue logic
- packet-router behavior
- VIP/service mapping logic
- UDP tunnel send/receive flow
- reconnect logic at the transport/core layer
- large classes of memory growth caused by our own queues, buffers, `Data` copies, maps, and timers

## What Linux cannot prove

Linux cannot faithfully validate:
- actual `NEPacketTunnelProvider` lifecycle quirks
- real `packetFlow` scheduling/backpressure semantics
- entitlement/install behavior
- iOS DNS steering exactly as `NEDNSSettings` applies it
- real-device NetworkExtension resident-memory budget / jetsam
- exact NWConnection / NWListener runtime behavior inside an iOS Network Extension
- NWConnection.send() internal queue growth under load
- Network.framework per-instance overhead (each NWListener/NWConnection costs ~200-400KB)

**Critical implication:** NWListener/NWConnection memory overhead is the #1 actionable savings target in the NE (currently 5 NWListeners burning ~1-2MB of a 15MB budget). This can ONLY be measured on-device. The Linux harness catches our-own-code regressions; Apple-framework overhead must be caught by the device smoke suite.

So the correct strategy is:
1. move 80-90% of correctness testing to Linux
2. keep 10-20% as short real-device smoke tests
3. target NE steady-state under 15MB with explicit `os_proc_available_memory()` monitoring

## iOS Network Extension memory reality

Apple has **never published** specific jetsam memory limits for Network Extension processes. All known limits are empirically determined by developers through crash log analysis. Observed thresholds vary by device RAM and system pressure:

| Device Class        | RAM      | Observed NE jetsam threshold |
|---------------------|----------|------------------------------|
| iPhone SE / older   | 2 GB     | ~50-80 MB                    |
| iPhone 12/13/14     | 4-6 GB   | ~80-120 MB                   |
| iPhone 15 Pro+      | 6-8 GB   | ~120-150 MB+                 |

Key facts:
- Jetsam kills are SIGKILL — no chance to clean up
- NE runs 24/7 in background, iOS aggressively reclaims from background
- `os_proc_available_memory()` (iOS 13+) is the ONLY official API to check at runtime
- Apple DTS engineers recommend: process packets immediately, don't queue them

**ZTLP NE current state (measured 2026-04-10):** 18-21MB resident. Over budget on all devices. Main drivers:
- Rust staticlib TEXT: 1.65MB (already optimized)
- Swift runtime + Foundation: ~2-3MB
- Network.framework: ~1-2MB
- 5 NWListeners: ~1-2MB (biggest actionable target)
- NWConnection.send() queue growth under load: ~3-5MB
- Explicit buffers: ~0.5MB
- VIP accepted connections: variable

### Memory monitoring requirement

The device smoke suite MUST include `os_proc_available_memory()` monitoring. WireGuard and Tailscale both do this. Log every 10 seconds during smoke tests. Alert if available memory drops below 50MB. This is the only way to catch memory regressions that Linux cannot reproduce.

```swift
// Inside NE — log available memory periodically
import os
func logMemoryUsage() {
    let available = os_proc_available_memory()
    // Typical NE: 80-200MB available on modern iPhones
    // Alert threshold: <50MB available = danger zone
}
```

## Current repo facts that make this feasible

The iOS extension already has the right architecture boundary:
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPDNSResponder.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPNSClient.swift`
- standalone sync packet-router / crypto / connect FFI in Rust

Important facts:
- `PacketTunnelProvider` is already using sync FFI and standalone router
- `resolveGateway()` is still incomplete and falls back to `targetNodeId`
- current benchmark runner already simulates small pieces of the send path
- relay integration tests already exercise real UDP behavior locally

### Three broken NS resolution implementations

The NE currently has THREE implementations of NS resolution that cannot work together:

1. **proxy.rs: ns_resolve()** — ASYNC, requires tokio UdpSocket. Used by desktop/server. UNAVAILABLE in ios-sync builds (tokio-gated).
2. **ffi.rs: ztlp_ns_resolve()** — Wrapper that creates a throwaway tokio runtime just for one UDP send/recv. `#[cfg(feature = "tokio-runtime")]` — stripped from NE lib.
3. **ZTLPNSClient.swift** — SYNC, pure BSD sockets. Used ONLY for service discovery (populating VIP table). NOT used for gateway resolution.

Result: `resolveGateway()` bypasses NS entirely, uses hardcoded config target.

Fix: implement `ztlp_ns_resolve_sync` using `std::net::UdpSocket` (~40 lines Rust), delete the two tokio-gated paths from the NE code path, keep Swift NSClient for service discovery, add the Rust sync resolver for gateway resolution.

## VIP proxy memory problem and relay architecture

### The problem

The VIP proxy is the biggest memory consumer in the NE that we can actually eliminate:

Current VIP proxy architecture:
- 5 NWListener instances (ports 80, 443, 8080, 8443, 8200)
- Each NWListener creates its own Network.framework protocol state machine (~200-400KB)
- Each accepted TCP connection adds NWConnection state + buffers
- NWConnection.send() queues grow without bound during bulk transfers
- VIPProxy forwardToGateway() allocates per-call even with reusable buffers

Memory cost of VIP proxy:
- 5 NWListeners at rest: ~1-2 MB
- Accepted connections under load: ~0.5-1 MB per connection
- NWConnection.send() queue growth: ~3-5 MB during sustained transfers
- **Total VIP proxy overhead: ~5-8 MB of the ~18-21 MB NE footprint**

This is over a quarter of the NE memory budget spent on something that could run server-side with no memory constraints.

### Relay-based VIP architecture with NS-driven relay selection

**Idea:** Move VIP proxy / TCP termination to relay servers. The NE discovers available relays via the Name Server, picks the best one based on stats, and tunnels all VIP traffic through it. The NE becomes a pure packet encryptor/decryptor with zero NWListeners.

This is the Tailscale DERP model: NS knows the topology, NE queries NS for relay candidates, picks the best, and tunnels through it. If the relay fails, NE re-queries NS and fails over to the next best.

Current flow:
```
App → TCP connect 127.0.0.1:443 → NWListener accepts → NWConnection
  → read data → ztlp_frame_data() → ztlp_encrypt_packet() → sendPacket()
  Gateway response → decrypt → parse_frame → deliverData → NWConnection write → App
```

Proposed flow:
```
1. NE connects → handshake with gateway
2. NE queries NS: "what relays are available?"
3. NS responds with relay list + stats (latency, load, region, health)
4. NE picks best relay (lowest latency + least loaded)
5. NE tunnels all VIP traffic through chosen relay

App → packetFlow captures outbound → NE encrypts → sends to relay via UDP tunnel
  Relay → decrypts → terminates TCP to backend → receives response
  Relay → encrypts response → sends back through tunnel
  NE → decrypts → writes to packetFlow → App receives response
```

Failover flow:
```
1. Relay drops or becomes unhealthy
2. NE detects failure (timeout / no ACK advance)
3. NE re-queries NS for updated relay list
4. NS returns fresh list (may exclude failed relay)
5. NE picks next best relay
6. NE reconnects tunnel through new relay
```

#### Relay selection protocol

The NS already knows about relays — it's the natural place to distribute relay info. The relay list response should include:

```
RelayInfo {
  relay_id: String,        // unique relay identifier
  address: SocketAddr,     // relay endpoint (e.g., "34.219.64.205:23095")
  region: String,          // geographic region (e.g., "us-west-2")
  latency_ms: u32,         // last measured latency from NS perspective
  load_pct: u8,            // current load 0-100%
  active_connections: u32,  // number of active tunneled connections
  health: RelayHealth,     // Healthy | Degraded | Unhealthy
}
```

Relay selection algorithm (runs in NE, fully testable on Linux):
1. Filter: only `health == Healthy` relays
2. Sort by: `latency_ms * (1 + load_pct/100)` — penalize loaded relays
3. Pick: lowest score
4. Tiebreak: prefer same region as gateway, then fewest active connections

This algorithm is pure computation — no Apple APIs — so it's 100% testable on Linux.

#### Architecture: Model A (relay-side TCP termination, zero NWListeners)

- NE has ZERO NWListeners — only the single UDP NWConnection + packetFlow
- Apps send traffic to VIP addresses → captured by packetFlow
- NE encrypts raw IP packets → sends through tunnel to selected relay
- Relay decrypts → makes TCP connections to actual backend services
- Relay sends responses back through tunnel
- NE decrypts → writes to packetFlow → apps receive responses
- This is the WireGuard model: NE is just a raw packet encryptor/decryptor
- Memory savings: eliminate ALL 5 NWListeners + all accepted connection state = ~5-8 MB
- NE memory target: ~10-13 MB (comfortably under 15 MB)

#### Multi-relay deployment

With NS-driven relay selection, you can deploy relays in multiple regions:
- US-West relay (current: 34.219.64.205)
- US-East relay (future)
- EU relay (future)
- Any edge location

NS tracks relay health and steers clients to the best one. Adding a new relay is just: deploy relay → register with NS → clients automatically discover it. No NE code changes, no app updates.

This also enables:
- Graceful relay maintenance: mark relay as Degraded in NS → clients drain to others
- Load balancing: spread clients across relays based on load
- Geographic optimization: steer clients to nearest relay
- Redundancy: if one relay dies, clients fail over automatically

### Impact on Linux simulation plan

Moving VIP to the relay with NS-driven selection makes the Linux harness simpler and MORE testable:
- No VIP proxy logic to simulate in the harness
- The harness just needs: TUN device ↔ encrypt/decrypt ↔ UDP tunnel ↔ relay
- Relay-side code runs on Linux natively — test it directly
- NE simulation becomes: raw IP packets in → encrypt → send → receive → decrypt → raw IP packets out
- Relay selection algorithm is pure computation — 100% testable on Linux with fake NS responses
- Relay failover logic is testable: simulate relay drop → re-query NS → pick next → reconnect
- Multi-relay routing logic is testable: different stats from NS → verify correct relay chosen
- This is exactly the TUN-backed harness described in Layer 3, but without the VIP complexity

### Impact on CryptoKit swap decision

The skill doc mentions Phase 2: moving Noise_XX + ChaCha20-Poly1305 to CryptoKit to save ~2-3MB more. With the relay architecture, the NE handles fewer code paths (no VIP mux framing in the NE), so the Rust staticlib TEXT segment could shrink further. Consider whether CryptoKit swap is still necessary if:
- VIP proxy moves to relay (removes VIP-related Rust code from NE build)
- TEXT segment is already at 1.65MB (well under budget)
- CryptoKit code can ONLY be tested on iOS, undermining the Linux harness goal

If we swap to CryptoKit, we lose the ability to test crypto on Linux. Currently the Rust crypto (snow/chacha20poly1305) is fully testable on Linux. With the relay architecture and no VIP proxy, the NE's Rust surface is already small. CryptoKit swap may not be worth the loss of Linux testability.

## Recommended architecture

Build a new cross-platform harness around the data-plane seams, NOT around Apple APIs.

### Layer 1: pure deterministic core tests

Add tests for:
- `ZTLPDNSResponder` packet parsing and response synthesis
- `ZTLPNSClient` parsing with captured NS responses
- gateway resolution rules
- mux frame encode/decode
- ACK batching behavior
- packet-router action serialization

These should run with no TUN device and no Xcode.

### Layer 2: Linux socket integration harness

Build a local harness that runs:
- fake gateway UDP endpoint
- fake NS UDP server
- optional fake backend service endpoints
- the sync Rust crypto/router APIs

This should validate:
- handshake
- NS lookup
- target resolution
- encrypted UDP flow
- mux frame exchange
- ACK timing/aggregation
- reconnect behavior

### Layer 3: Linux TUN integration harness

Build a TUN-backed packetFlow replacement:
- read raw packets from a Linux TUN device
- feed them through the same sync router path
- emit response packets back to the TUN device

This gives us the closest equivalent to:
- `packetFlow.readPackets()`
- `packetFlow.writePackets()`
- service VIP routing (if VIP stays in NE) or plain packet routing (relay model)
- local DNS interception

**Note on packetFlow batch semantics:** iOS `packetFlow.readPackets()` delivers packets in batches with cooperative backpressure (the NE controls when to call readPackets next). Linux TUN `read()` is a single-packet syscall. The harness should simulate batch delivery to test queue accumulation under bursty load — this is a known memory regression vector.

### Layer 4: tiny Apple-only smoke suite

Keep only a short iPhone validation loop for:
- tunnel starts
- DNS settings are applied
- one `.ztlp` lookup works
- one backend request works
- memory remains below threshold during a short smoke transfer
- `os_proc_available_memory()` logged every 10 seconds, alert if <50MB available

That means the phone becomes final confirmation, not the primary debugger.

## Most important engineering change

We need to stop treating `PacketTunnelProvider` as the core.
It should become a thin adapter.

Extract a platform-neutral tunnel core with interfaces roughly like:
- `PacketFlowAdapter`
- `GatewayResolver`
- `DNSInterceptor`
- `TunnelTransport`
- `VIPServiceRegistry` (only if VIP stays in NE; eliminated with relay model)
- `TimerDriver`

Then provide two implementations:
- Apple adapter: real `NEPacketTunnelProvider` / NWConnection / NWListener (or no NWListener with relay)
- Linux adapter: TUN + UDP sockets + deterministic fake timers where useful

With relay architecture, the Apple adapter becomes even simpler:
- `PacketFlowAdapter`: real `NEPacketTunnelProvider.packetFlow`
- `TunnelTransport`: single `NWConnection` UDP to relay
- `GatewayResolver`: sync NS resolution
- `DNSInterceptor`: `ZTLPDNSResponder`
- No `VIPServiceRegistry` — relay handles it
- `TimerDriver`: GCD `DispatchSourceTimer`

## Immediate priorities

### Priority 0: move VIP proxy to relay (biggest memory win)

This is higher priority than the Linux harness because it's the biggest single memory savings available. It directly addresses the NE being 18-21MB (over the 15MB target).

Steps:
1. Add TCP termination / service routing to the relay
2. Wire the relay to accept VIP-muxed frames and connect to backends
3. Remove VIP proxy from NE (delete 5 NWListeners + all accepted connection state)
4. Route VIP traffic through packetFlow → encrypt → tunnel → relay instead
5. Verify NE memory drops to ~10-13MB
6. Verify end-to-end service access still works

### Priority 1: fix gateway resolution logic in a portable way

Current issue:
- `resolveGateway()` still bypasses true NS resolution
- sync NE path is not production-ready
- THREE broken NS resolution implementations need cleanup

Best fix:
- implement a portable sync resolver path once
- add `ztlp_ns_resolve_sync` in Rust using `std::net::UdpSocket`
- delete tokio-gated NS resolution paths from NE code path
- keep Swift `ZTLPNSClient` for service discovery only
- use the same logic from Linux harness and iOS extension

### Priority 2: create a Linux data-plane harness before more iPhone tuning

Do this before another large round of phone-only debugging.

### Priority 3: make memory issues measurable locally

We cannot reproduce jetsam exactly, but we CAN measure our own allocation growth.
Add harness metrics for:
- queue lengths
- pending ACK count
- sends in flight
- router buffer sizes
- seen-sequence set size
- repeated `Data` allocation counts/bytes
- total RSS on Linux process over time

This will catch many regressions before phone deploy.

## Concrete implementation plan

### Task 0: relay VIP architecture design with NS-driven relay selection

Create:
- `docs/RELAY-VIP-ARCHITECTURE.md`

Define:
- relay-side TCP termination protocol
- how VIP mux frames map to relay TCP connections
- relay-to-backend connection lifecycle
- NS relay discovery protocol (RelayInfo response format)
- relay selection algorithm (filter → sort → pick → tiebreak)
- relay failover flow (detect failure → re-query NS → reconnect)
- multi-relay deployment and registration with NS
- fallback path if no relays are available (direct gateway? error?)
- migration plan from current NE VIP proxy

### Task 0b: relay selection tests (pure computation, no Apple APIs)

These can be written and run entirely on Linux:
- given a list of RelayInfo from NS, selection picks lowest `latency_ms * (1 + load_pct/100)`
- Unhealthy relays are filtered out
- Degraded relays are deprioritized
- Tiebreak: same region as gateway wins
- Tiebreak: fewest active connections wins
- Empty relay list returns error (fallback path)
- Relay failover: after failure, re-query NS, new relay selected
- Relay stats update: if NS returns updated load/latency, NE may re-select

### Task 1: write a short design doc for the harness boundary

Create:
- `docs/LINUX-TUNNEL-HARNESS-DESIGN.md`

Define:
- what is Apple-only
- what is cross-platform
- required interfaces
- what the harness must simulate
- explicit non-goals
- packetFlow batch delivery semantics

### Task 2: add portable gateway-resolution tests

Add tests around the desired policy:
- resolve via NS first
- fallback to configured direct target only if NS fails
- reject empty/invalid targets
- preserve reconnect behavior

This should happen before changing production code.

### Task 3: implement `ztlp_ns_resolve_sync` in Rust

Why first:
- it closes the biggest production gap
- it is cross-platform
- it immediately makes iOS and Linux share one resolver path
- it replaces TWO broken tokio-gated NS implementations

Validation:
- unit tests for parse/timeout/error cases
- socket integration test against a fake local NS server

### Task 4: build a Linux fake-NS + fake-gateway integration harness

Create a small harness binary or test target that:
- starts fake NS on UDP
- starts fake gateway on UDP
- runs sync connect + encrypt/decrypt + ACK flow
- asserts resolution and traffic path

### Task 5: build an in-memory packetFlow harness

Add a harness object that mimics:
- readPackets
- writePackets
- injected packets from apps
- captured emitted packets back to apps
- batch delivery semantics (simulate iOS packetFlow batch reads)

Use it first without TUN for fast tests.

### Task 6: add Linux TUN mode

For high-fidelity integration:
- create a TUN device
- assign test subnet
- inject traffic via local sockets or curl in a netns
- observe tunnel behavior end-to-end

### Task 7: port DNS responder tests into the harness

Specifically prove:
- `.ztlp` A query returns VIP
- AAAA returns NXDOMAIN intentionally
- HTTPS/SVCB returns NXDOMAIN intentionally
- non-`.ztlp` traffic is not falsely treated as matched-without-response

This directly targets one of the current audit failures.

### Task 8: instrument memory-sensitive queues

Add debug counters and optional sampling in:
- `ZTLPTunnelConnection`
- packet router bridge path
- VIP proxy path / equivalent relay path

Track high-water marks in logs/tests.

### Task 9: reduce real-device validation to a smoke checklist

After the harness exists, the iPhone checklist should be only:
1. install build
2. start tunnel
3. resolve one `.ztlp` service
4. load one service
5. run one short benchmark
6. confirm resident memory threshold
7. confirm `os_proc_available_memory()` > 50MB available throughout

## Proposed repository additions

Suggested new paths:
- `docs/RELAY-VIP-ARCHITECTURE.md`
- `docs/LINUX-TUNNEL-HARNESS-DESIGN.md`
- `docs/IOS-LINUX-TEST-STRATEGY.md`
- `proto/tests/ns_resolve_sync_integration.rs`
- `proto/tests/tunnel_harness_integration.rs`
- `tools/ztlp-tunnel-harness/` or `proto/src/bin/ztlp-tunnel-harness.rs`
- `tools/ztlp-fake-ns/`
- `tools/ztlp-fake-gateway/`

## Decision

Yes, we should do this.

But the deliverable is NOT "simulate the whole iPhone".
The deliverable is:
- a Linux tunnel data-plane harness
- a shared sync NS resolution path (replacing two broken tokio-gated implementations)
- deterministic tests for DNS / NS / mux / router / UDP flow
- VIP proxy moved to relay with NS-driven relay selection (biggest single memory win)
- relay selection algorithm (pure computation, fully testable on Linux from day one)
- multi-relay failover via NS re-query
- a much smaller iPhone confirmation loop with `os_proc_available_memory()` monitoring

That is the path most likely to get us to a slam dunk instead of repeating the slow build → deploy → fail cycle.

## Recommended next move

Start with these in order:
1. design relay VIP architecture with NS-driven relay selection (Task 0) — biggest memory win, enables thinner NE
2. implement relay selection algorithm in Rust (Task 0b) — pure computation, testable on Linux immediately
3. implement `ztlp_ns_resolve_sync` — closes production gap, building block for harness
4. write tests for resolver fallback policy
5. build a fake-NS/fake-gateway Linux harness
6. then wire a packetFlow/TUN harness

Once those exist, we will be debugging with repeatable local tests instead of blind phone iterations.
