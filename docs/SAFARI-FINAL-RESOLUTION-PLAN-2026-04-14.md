# ZTLP Safari Resolution — Final Isolation & Fix Plan
# Date: 2026-04-14
# Status: PLAN — Systematic isolation to stop iteration loops

---

## THE PROBLEM WITH HOW WE'VE BEEN WORKING

We keep chasing symptoms without isolating variables. Each session finds a
new possible cause, pushes a fix, but we never confirm whether the previous
fix actually worked because:

1. Fixes are committed in source but NOT deployed to the phone
2. Multiple issues are changed at once, so we can't tell what helped
3. Server-side issues mask client-side fixes (and vice versa)
4. Logging is too weak to distinguish failure modes
5. No structured test protocol — just "run Safari, see what happens"

This plan changes that. ONE variable at a time. Verify before moving on.

---

## WHAT WE ACTUALLY KNOW (Evidence-Based, Not Guesses)

### From 20 benchmark records on bootstrap:
- 89% overall pass rate, but HTTP response tests are flaky (33-67% fail)
- ALL failures are "No response" — requests go out, responses never arrive
- 526 streams opened vs 420 closed = 106 LEAKED streams (all vault service)
- Memory is stable at 15-21MB (NOT the problem, never was)
- No VPN disconnects, no router throttle, no ERROR-level logs
- Replay rejections escalate over session lifetime (6 -> 384)

### From gateway server logs (24 hours):
- 41 mux streams REJECTED because send_queue > 256 (CRITICAL)
- Queue sizes reached 1800+ packets — 7x the rejection threshold
- 304 mux/legacy framing mismatches adding overhead
- 858 STALL teardowns (client never ACKs gateway's FIN)
- 856 session replacements + 330,209 unknown_session rejections
- 73 RECV_GAP_SKIP events (UDP packet loss on the path)
- 1,515 NS lookup timeouts (100% failure rate, adds 2s per session)

### From NS server:
- NS relay record has TYPO: "techrockstories" instead of "techrockstars"
- NS continuously rejects registration for "missing_pubkey"
- NS is effectively dead — every lookup falls back to hex identity

### From iOS source code:
- Packet drop fix is committed but NOT on the phone (stale .a libraries)
- Logger still does read-modify-write per entry (expensive but not fatal)
- Memory throttle was removed (good)
- DNS AAAA/NXDOMAIN fix status needs verification

---

## THE FIVE ACTUAL BUGS (Ordered by Impact)

### BUG 1: Gateway send_queue overload rejects mux streams [SERVER]
When send_queue exceeds 256 packets, the gateway IMMEDIATELY REJECTS
new mux stream opens. From the phone's perspective: stream opens, stream
instantly closes, no data ever flows. This is THE primary cause of the
"OpenStream -> immediate CloseStream" pattern we keep seeing.

Queue reaches 1800+ packets because:
- BBR congestion control can't drain fast enough on lossy mobile path
- Client keeps opening new streams (Safari opens 6+ per page)
- Rejected streams cause Safari to retry, opening MORE streams
- Cascade failure

### BUG 2: NS is completely broken [SERVER]
Every NS lookup times out (1,515 in 24h). Registration rejected for
"missing_pubkey". Relay record has typo "techrockstories". This adds
2 seconds of latency to EVERY new session and means service routing
falls back to static defaults, which may not be correct.

### BUG 3: Vault streams never close [CLIENT + SERVER]
106 leaked streams across 20 benchmarks, ALL vault service. Web and
HTTP streams close properly. Either:
- Gateway never sends CloseStream for vault backend responses
- iOS never processes the CloseStream for vault
- Vault backend holds connections open (keepalive?)
These leaked streams accumulate flows in the router, eventually
contributing to resource exhaustion.

### BUG 4: MUX/legacy framing mismatch [CLIENT]
304 occurrences of inner mux payload wrapped in legacy outer framing.
The client negotiated mux mode but still wraps frames in legacy format.
This adds overhead and parsing cost that contributes to queue buildup.

### BUG 5: Stale client libraries on phone [DEPLOY]
The packet-drop fix, queue increase (128->256), PSH fix, and throttle
removal are all in source but NOT deployed. Every test we run is
against the OLD broken code.

---

## ISOLATION PROTOCOL

### Principle: ONE change, ONE test, ONE measurement. No exceptions.

Each phase deploys exactly ONE fix category, runs a structured test,
and records results before moving to the next phase.

### Test Protocol (same for every phase):

```
1. Note the current time (UTC)
2. On phone: Force-quit ZTLP app, relaunch, connect VPN
3. Wait 10 seconds for tunnel to stabilize
4. Run benchmark (all 8 tests)
5. Immediately tap "Send Logs"
6. On bootstrap: GET /api/benchmarks?limit=3
7. Record: benchmark_id, pass/fail per test, stream counts,
   replay count, memory, latency values
8. On phone: Open Safari, navigate to http://10.122.0.2/
9. Wait 30 seconds (full page load attempt)
10. Tap "Send Logs" again
11. On bootstrap: GET /api/benchmarks?limit=1 (manual log dump)
12. Record: did page load? partial? which resources?
13. On gateway: docker logs ztlp-gateway --since 5m 2>&1 | tail -100
14. Record: stream accepts/rejects, queue sizes, stalls
```

---

## PHASE 1: Fix the servers FIRST (no iOS rebuild needed)

### Why servers first:
The gateway is rejecting streams at queue=256. Even if we deploy the
perfect iOS build, the gateway will still reject streams under load.
Fix the server side so we have a clean path to test against.

### 1A: Fix NS relay record typo and registration

```bash
# SSH to NS server
ssh ubuntu@34.217.62.46

# Check current config
docker inspect ztlp-ns | grep -A5 RELAY_RECORDS

# Fix the typo: "techrockstories" -> "techrockstars"
# Fix the missing_pubkey registration issue
# This requires editing the docker-compose or env and restarting
```

Verify: After restart, gateway logs should show successful NS lookups
instead of "NS lookup timed out" every session.

### 1B: Increase gateway send_queue high watermark

The current hardcoded limit of 256 is way too low for mux mode with
6+ concurrent Safari streams. Each stream can have multiple packets
in flight.

```elixir
# In gateway session.ex, find the send_queue high watermark
# Change from 256 to 2048 (or make it configurable via env var)
# Also: instead of rejecting streams, apply backpressure:
#   - Accept the stream but pause sending until queue drains
#   - Or: queue the OPEN and process it when queue drops below threshold
```

Deploy gateway:
```bash
ssh ubuntu@44.246.33.34
cd ~/ztlp/gateway
git pull origin main
# rebuild and restart gateway container
```

IMPORTANT: Tell Steve before restarting gateway.

### 1C: Reduce NS lookup timeout on gateway

Even after fixing NS, reduce the fallback timeout from 2s to 500ms.
NS is a nice-to-have for identity, not a hard dependency.

### TEST AFTER PHASE 1:
Run the test protocol above with the CURRENT (old) phone build.
If the gateway was the main blocker, even the old phone build might
work better. Record results as "Phase 1 baseline".

---

## PHASE 2: Deploy iOS packet-drop fix (the one sitting in source)

### What this deploys:
- Outbound queue 128 -> 256
- Spill-to-send-buf instead of packet drops
- PSH only on final chunk
- Throttle break removed from flush loop
- Missing FFI declarations

### Build on Steve's Mac:

```bash
cd ~/ztlp
git pull origin main

# NE library (ios-sync, no tokio)
cargo build \
  --manifest-path proto/Cargo.toml \
  --target aarch64-apple-ios \
  --release --lib \
  --no-default-features \
  --features ios-sync \
  --target-dir proto/target-ios-sync

cp proto/target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a \
  ios/ZTLP/Libraries/libztlp_proto_ne.a

# Main app library (default features, tokio)
touch proto/src/ffi.rs
cargo build \
  --manifest-path proto/Cargo.toml \
  --target aarch64-apple-ios \
  --release --lib

cp proto/target/aarch64-apple-ios/release/libztlp_proto.a \
  ios/ZTLP/Libraries/libztlp_proto.a

# Headers
cp proto/include/ztlp.h ios/ZTLP/Libraries/ztlp.h
cp proto/include/ztlp.h ios/ZTLP/ZTLPTunnel/ztlp.h

# Xcode: Clean Build Folder (Cmd+Shift+K) -> Build -> Deploy
```

### TEST AFTER PHASE 2:
Run the SAME test protocol. Compare against Phase 1 results.
Expected: Fewer stream failures because packets aren't being dropped.
The gateway queue fix from Phase 1 + this fix together should eliminate
most "No response" failures.

---

## PHASE 3: Fix vault stream leaks (targeted investigation)

Only do this if Phase 1+2 don't fully resolve it.

### Investigation steps:

A. Check the gateway vault backend behavior:
```bash
ssh ubuntu@44.246.33.34
# Is the vault backend even running?
curl -s http://127.0.0.1:8080/ | head -20

# Check if vault sends Connection: close or keeps alive
curl -sv http://127.0.0.1:8080/ 2>&1 | grep -i "connection\|close\|keep"

# Watch gateway logs for vault-specific stream handling
docker logs -f ztlp-gateway 2>&1 | grep -i vault
```

B. Check iOS packet_router.rs for vault CloseStream handling:
- Does the router send CloseStream when it receives TCP FIN from vault?
- Is there a code path where vault flows never get cleaned up?
- Is the 10-second cleanup timer actually running?

C. Add targeted logging (if needed):
```rust
// In packet_router.rs, log when a flow is created and destroyed
// Include the service name so we can see vault vs web vs http
log::info!("Flow created: flow_id={} service={} stream_id={}",
    flow.id, flow.service, flow.stream_id);
log::info!("Flow destroyed: flow_id={} service={} reason={}",
    flow.id, flow.service, reason);
```

### TEST AFTER PHASE 3:
Run test protocol. Check that vault stream count matches between
OpenStream and CloseStream in the logs.

---

## PHASE 4: Fix mux/legacy framing mismatch (if still needed)

### Investigation:
The iOS client is sending mux-framed payloads inside legacy outer
framing. This means the protocol negotiation is incomplete.

Check ZTLPTunnelConnection.swift:
- When does the client switch from legacy to mux framing?
- Is there a flag that should be set after mux mode is negotiated?
- Is the outer frame always legacy regardless of mux mode?

Check gateway session.ex:
- When does the gateway expect full mux framing?
- Is there a "both sides agree" handshake for mux mode?

### Fix:
Ensure the client uses pure mux outer framing once mux mode is active.
This eliminates 304 instances of the gateway having to detect and
re-parse inner mux inside legacy frames.

---

## PHASE 5: Session lifetime improvements (hardening)

Only after Phases 1-4 are resolved:

### 5A: Replay rejection escalation
- Why do replay rejects grow from 6 to 384 over session lifetime?
- Is the anti-replay window too small for mobile latency?
- Should the window be adaptive based on observed RTT?

### 5B: Session replacement storm
- 856 replacements + 330K unknown_session in 24h
- Is the client reconnecting too aggressively?
- Is there a reconnect loop triggered by gateway queue rejections?

### 5C: STALL teardown optimization
- 858 STALL teardowns (30s timeout) for unACKed FINs
- Reduce STALL timeout for sessions that have already exchanged FIN?
- Client needs to ACK the gateway's FIN properly

---

## LOGGING IMPROVEMENTS (Deploy alongside Phase 2)

These go into the next iOS build to make future debugging deterministic:

### A. Per-benchmark session isolation
```swift
// At benchmark start:
let runId = UUID().uuidString.prefix(8)
TunnelLogger.shared.log("[BENCH-START] run=\(runId)")

// At benchmark end:
TunnelLogger.shared.log("[BENCH-END] run=\(runId) pass=\(pass) fail=\(fail)")

// Include runId in benchmark upload
```

### B. Stream lifecycle tracking
```swift
// Log every stream event with consistent format:
// [STREAM] action=open id=N service=S
// [STREAM] action=data id=N bytes=B direction=in|out
// [STREAM] action=close id=N reason=R elapsed_ms=T
```

### C. Gateway response tracking
```swift
// When data arrives from gateway, log:
// [GW-DATA] stream=N seq=S bytes=B queue_depth=D
// This tells us if responses are arriving but not being delivered
```

### D. Edge-triggered diagnostics
```swift
// On any stream close, if no data was ever sent:
// [GHOST-STREAM] id=N service=S opened_at=T closed_at=T reason=R

// On benchmark failure:
// [DIAG-DUMP] open_streams=[...] queue_depth=N memory=M replay_count=R
```

### E. Logger performance fix
```swift
// Replace read-modify-write with append-only FileHandle
// Move rotation check to periodic timer (every 60s)
// This is not the primary issue but prevents I/O overhead in hot path
```

---

## DECISION TREE (What to do based on results)

```
Phase 1 (server fixes) + old phone build:
  ├── Safari works       -> Gateway was the whole problem. Deploy Phase 2 anyway for safety.
  ├── Better but flaky   -> Gateway was part of it. Proceed to Phase 2.
  └── No change          -> Not primarily a server issue. Proceed to Phase 2.

Phase 2 (iOS packet-drop fix):
  ├── Safari works       -> DONE. Packet drops were the remaining issue.
  ├── Better, some fails -> Check which tests fail. If vault-only, go to Phase 3.
  └── No change          -> Something else is wrong. Check:
      ├── Did the .a file actually get rebuilt? (check file dates)
      ├── Did Xcode actually link the new .a? (Clean Build Folder?)
      └── Are we testing against the right gateway?

Phase 3 (vault stream leaks):
  ├── Vault tests pass   -> Leak was the cause. Verify with 5 consecutive runs.
  └── Still failing      -> Go to Phase 4 (framing mismatch).

Phase 4 (framing fix):
  ├── All tests pass     -> DONE.
  └── Still failing      -> Deep packet capture needed. tcpdump on gateway.
```

---

## THE RECONNECTION STORM (Bug 1 + 4 + 5 Interaction)

This is the part I missed in the initial plan. The numbers don't make
sense as independent bugs — they form a cascade:

The reconnect trigger chain:
  Keepalive timer fires every 25 seconds.
  If keepalive SEND fails (sendData returns false) 3 times in a row,
  AND no data received for 60 seconds → scheduleReconnect().
  Also: tunnelConnection didFailWithError → immediate scheduleReconnect().

  Reconnect does: exponential backoff (1s base, 60s cap, 10 max attempts)
    → stop old tunnelConnection
    → create new NWConnection to relay
    → new ZTLP HELLO to gateway

The storm happens because:
  1. Gateway queue fills (1800+ packets) → rejects mux streams
  2. Safari gets no responses → keeps retrying → more streams
  3. Eventually keepalive send also fails (NWConnection overwhelmed)
     OR tunnelConnection reports error
  4. NE reconnects → new HELLO → gateway replaces session
  5. Old in-flight packets still arriving → 330K unknown_session rejects
  6. New session starts with queue already backed up
  7. Goto 1

The 856 session replacements in 24 hours = roughly one every 100 seconds.
That means the tunnel is reconnecting constantly. Each reconnect creates
a fresh session, but the underlying queue problem persists, so it just
cycles.

CRITICAL IMPLICATION: Even if the iOS packet-drop fix is deployed, if the
gateway queue still hits 256 and rejects streams, the NE will still enter
the reconnect storm. The gateway fix in Phase 1 is mandatory.

---

## THE AAAA/NXDOMAIN FIX STATUS

Verified: The DNS fix IS in the source code. ZTLPDNSResponder.swift at
line 164 returns NXDOMAIN for AAAA (type 28) and other non-A queries.
This was the fix from the April 13 session.

However: like everything else, this fix is only in source. If the phone
is running stale libraries, it still has the old DNS behavior that hangs
Safari on AAAA lookups. This gets deployed in Phase 2 with the rest.

---

## QUICK WINS WE CAN DO RIGHT NOW (Before Phase 1)

1. Fix NS typo — 5 minute fix, eliminates 2s latency per session
2. Verify vault backend is actually running on gateway (curl localhost:8080)
3. Check if gateway send_queue limit is configurable via env var already
4. Pull the EXACT file dates of .a libraries on Steve's Mac to confirm
   they're stale

---

## SUCCESS CRITERIA

Safari resolution is FIXED when:
1. Benchmark passes 8/8 on 5 consecutive runs
2. Safari loads http://10.122.0.2/ fully (HTML + CSS + JS + images)
3. Safari loads https://10.122.0.2/ fully
4. No stream leaks (OpenStream count == CloseStream count in logs)
5. Gateway shows 0 rejected mux streams during the test
6. No STALL teardowns during the test
7. Reproducible — works on fresh VPN connect, not just warm tunnel

---

## FILES REFERENCED

- ztlp/docs/SAFARI-FIX-HANDOFF-2026-04-14.md (previous session handoff)
- ztlp/docs/SAFARI-RESOLUTION-REVIEW-2026-04-14.md (gpt-5.4 review)
- /home/trs/ztlp_gateway_server_issues_report.txt (server-side analysis)
- /home/trs/benchmark_analysis_report.txt (benchmark data analysis)
- /home/trs/benchmark_data.json (raw benchmark data, 20 records)
- proto/src/packet_router.rs (packet routing, queue, stream lifecycle)
- ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift (NE main logic)
- ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift (tunnel framing)
- gateway/lib/ztlp_gateway/session.ex (gateway session handling)
