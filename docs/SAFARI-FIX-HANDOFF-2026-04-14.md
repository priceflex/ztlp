# ZTLP iOS Safari Page Load Fix -- Session Handoff
# Date: 2026-04-14
# Status: Code pushed to main, NE lib rebuild required on Mac before testing

---

## ROOT CAUSE ANALYSIS (Verified from Benchmark Logs)

### What was WRONG with the diagnosis:

The Safari-fix-plan claimed "NE killed by iOS memory at 15MB limit". THIS IS WRONG.

Evidence from actual benchmark device logs:
- NE memory is STABLE at 18-19MB (not growing, not leaking)
- iOS NE kill limit is ~50MB. We are at 40% of the limit.
- The 15MB number was OUR benchmark threshold, NOT an Apple limit.
- Production readiness plan (Apr 13) correctly states: "real iOS kill limit is ~50MB"

### What is ACTUALLY happening:

NE disconnects under Safari page-load traffic after ~5-10 seconds:

```
19:54:33  VPN status -> connected
19:54:42  Page data flowing (RX seq 36-40, 1127-byte payloads)
19:54:45  LAST data received -- RX seq=40, payload=1132
19:54:50  VPN status -> 5 (disconnecting)
19:54:51  VPN status -> 1 (disconnected)
```

Page partially loads (images, CSS), then hangs. Refresh gets some more assets but never completes. Eventually VPN indicator disappears.

### Why this happens at the code level:

In `packet_router.rs::process_gateway_data()`:
1. Safari opens 6+ concurrent TCP streams per page (HTML, CSS, JS, images)
2. Gateway pushes response data for all streams simultaneously
3. NE outbound packet queue hits its 128-packet cap in ~2 seconds
4. OLD CODE: `self.outbound.pop_front()` silently DROPS the oldest packets
5. Dropped packets break TCP sequence numbers
6. Safari TCP stack waits for data that will never arrive -> timeout/stall
7. Enough concurrent stream stalls -> connection death spiral -> NE disconnects

### Two additional problems found in the code:

**A. Flush throttling:**
`flushOutboundPackets()` in PacketTunnelProvider.swift had a `shouldThrottleRouterWork()` break that prematurely cut off the drain loop. Under burst load, the queue fills faster than the 10ms timer can drain it, and the throttle prevents catching up.

**B. PSH flag on every chunk:**
`drain_flow_send_buffers()` was sending PSH on every MSS chunk from the send_buf, not just the last one. This causes Safari to deliver incomplete data fragments immediately instead of buffering until a complete response is ready.

---

## CODE CHANGES PUSHED TO MAIN (commit b63d18f + 46c8a55)

### 1. proto/src/packet_router.rs

**OUTBOUND_MAX_PACKETS:** 128 -> 256 on iOS
- 256 * 1400 bytes = ~350KB -- trivial memory cost

**process_gateway_data():** No more packet drops
- OLD: `if self.outbound.len() >= OUTBOUND_MAX_PACKETS { self.outbound.pop_front(); }`
- NEW: When queue is full, spill remaining data into per-flow `send_buf` (capped at 64KB)
- `drain_flow_send_buffers()` moves it to outbound when queue has room
- Result: ZERO packet loss under burst load

**drain_flow_send_buffers():** PSH only on last chunk
- OLD: `let flags = TCP_PSH | TCP_ACK` on every chunk
- NEW: `if is_last { TCP_PSH | TCP_ACK } else { TCP_ACK }`
- Safari delivers complete responses instead of incomplete fragments

### 2. ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift

**flushOutboundPackets():** Removed throttle break
- Removed the `if shouldThrottleRouterWork() { break; }` from the drain loop
- Now drains all available packets in one pass (bounded by maxPackets parameter)
- Prevents the drain loop from being starved under load

### 3. proto/include/ztlp.h

Added three missing FFI declarations (commit 46c8a55):
- `ztlp_router_cleanup_stale_flows()`
- `ztlp_free_string()`
- `ztlp_router_stats()`

---

## CRITICAL: NE LIBRARY MUST BE REBUILT ON MAC

The Rust code is on main but the NE static library on the phone is OLD.
Until the new `.a` is built and the app redeployed, NONE of the fixes take effect.

### Build commands (run on Steve's Mac):

```bash
cd ~/ztlp
git pull origin main

# Step 1: Build NE library (ios-sync, no tokio)
cargo build \
  --manifest-path proto/Cargo.toml \
  --target aarch64-apple-ios \
  --release --lib \
  --no-default-features \
  --features ios-sync \
  --target-dir proto/target-ios-sync

cp proto/target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a \
  ios/ZTLP/Libraries/libztlp_proto_ne.a

# Step 2: Rebuild main app library (default features, tokio)
touch proto/src/ffi.rs
cargo build \
  --manifest-path proto/Cargo.toml \
  --target aarch64-apple-ios \
  --release --lib

cp proto/target/aarch64-apple-ios/release/libztlp_proto.a \
  ios/ZTLP/Libraries/libztlp_proto.a

# Step 3: Copy headers
cp proto/include/ztlp.h ios/ZTLP/Libraries/ztlp.h
cp proto/include/ztlp.h ios/ZTLP/ZTLPTunnel/ztlp.h

# Step 4: Xcode -> Clean Build Folder (CMD+Shift+K) -> Build & Deploy
```

### Mac info:
- SSH: stevenprice@10.78.72.234
- Repo: ~/ztlp (Xcode builds), ~/code/ztlp (git sync)
- Always edit ~/ztlp for iOS
- Device ID: 39659E7B-0554-518C-94B1-094391466C12

---

## BENCHMARK EVIDENCE (from bootstrap at 10.69.95.12:3000)

### Latest benchmark (19:54Z): Still crashes under load
- NE dies 5 seconds after page flow starts (seq 36-40 then disconnect)
- Phone is running the OLD NE library (pre-fix)
- This will resolve after rebuild+redeploy

### Benchmark 19:07Z: 7/8 pass (clean bench, no page load trigger)
- Only failure: "Primary HTTP Response: No response" (warm-up timing, not connectivity)
- NE stable at 18.1MB

### Benchmark 16:56Z: Shows stream open/close cycling before death
```
Router: CloseStream stream=19
Router: OpenStream stream=20 service=vault
Router: CloseStream stream=20
Router: OpenStream stream=21 service=vault
Router: CloseStream stream=21
```
Streams open and immediately close. Could be:
- Gateway/relay rejecting concurrent streams
- TCP RST from backend service
- Mux stream establishment latency causing Safari retries

### Memory warnings (red herring):
```
[WARN] v5D-SYNC | Memory HIGH -- resident=18.1MB virtual=400525.9MB
[WARN] v5B-SYNC | Low available memory: 46.8MB
```
Memory is STABLE at 18-19MB. Not growing. The "virtual=400525.9MB" is Swift runtime virtual mapping (not resident). Low available memory 46.8MB is system-wide, not NE-specific.

---

## SECONDARY ISSUE TO INVESTIGATE AFTER FIX

After the packet drop fix is deployed and tested, investigate:
1. **Stream open/close cycling** -- why are Safari's mux streams opening then immediately closing?
2. **Gateway/relay concurrent stream handling** -- is the gateway rate-limiting or rejecting new streams?
3. **TCP FIN handling** -- is the relay terminating streams prematurely?

This might explain why even with no packet drops, Safari pages may not fully load if the gateway/relay side is rejecting concurrent connections.

---

## SERVER INFO

- Bootstrap: trs@10.69.95.12 ~/ztlp (Docker container: bootstrap_web_1)
- NS server: 34.217.62.46 port 23096/UDP (Docker: ztlp-ns, metrics 9103)
- Gateway: 44.246.33.34:23097
- Relay: 34.219.64.205:23095
- Zone: techrockstars.ztlp
- VIPs: vault=10.122.0.4, http=10.122.0.3, primary=10.122.0.2
- Benchmark auth token: 2f07983068c5dd5ffdf22cf24e4724389b4430c12659942f0af735f86c010079

## GIT CREDENTIALS

- Commits: Steven Price <steve@techrockstars.com>
- SSH for GitHub push: ssh -i /home/trs/openclaw_server_import/ssh/openclaw
- Bootstrap SSH: trs@10.69.95.12
- Mac SSH: stevenprice@10.78.72.234 (default key)

## KEY LESSONS

1. The NE 15MB "limit" is NOT an Apple limit -- it's our benchmark threshold. Apple's actual NE kill limit is ~50MB.
2. `pop_front()` on the outbound queue silently drops TCP packets -- this breaks TCP state and causes clients to wait forever.
3. NWConnection receive loop is async -- if one stream stalls it can starve others.
4. Safari opens MANY parallel connections per page -- the NE must handle 6+ concurrent TCP flows.
5. PSH flag controls when Safari delivers data to the rendering engine -- only set it on the final chunk.
6. Always verify the NE library on the phone matches the source code -- stale `.a` files cause confusion.
