# iOS Nebula-Style Collapse Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Move all ZTLP tunnel data-plane state (mux framing, ACK/rwnd, pacing, stream lifecycle, keepalive, reconnect, UDP transport) from Swift into Rust, so Swift NE becomes a thin shell that only extracts the utun fd and hands it to Rust — the DefinedNet mobile_nebula model.

**Why:** Two months of Vaultwarden/WKWebView failures are all seam bugs between Swift and Rust owning different halves of the tunnel. Every patch creates a new seam bug. The architecture is wrong, not the individual fixes.

**Architecture target:**

```
Swift NE (~250 lines):
  startTunnel -> NEPacketTunnelNetworkSettings (routes, DNS, MTU)
              -> find utun fd
              -> ztlp_ios_tunnel_engine_start(fd, config_json)
              -> sleep until stop

Rust (owns everything else):
  IosTunnelEngine
    - utun read/write
    - UDP socket to gateway/relay
    - Noise_XX handshake (ztlp_connect_sync)
    - PacketRouter (TCP state machine to utun)
    - MuxEngine (FRAME_OPEN/CLOSE/DATA/ACK)
    - SendController (cwnd, rwnd, pacing, retransmit)
    - SessionHealth (probe, reconnect decisions)
    - DNS responder (already done)
```

**Tech stack:**
- Rust 1.94+, feature `ios-sync` (no tokio)
- C FFI surface via `proto/include/ztlp.h`
- Swift NE target `ZTLPTunnel`, linked against `libztlp_proto_ne.a`
- Build on Steve's Mac (10.78.72.234, `~/ztlp`), deploy from Xcode GUI
- Gateway Elixir unchanged except where bugs are uncovered

**Scope boundaries:**
- In scope: ZTLPTunnel NE + `proto/src/ios_tunnel_engine.rs` + new Rust modules.
- NOT in scope: main app `ZTLP` target, desktop CLI, Android, relay/gateway (we fix those separately only if tests prove a bug).
- NOT in scope: rewriting crypto. Keep `snow` + `chacha20poly1305` + `ztlp_connect_sync`.

**Rollback tag:** `v-before-nebula-collapse` created before Phase 1.

**Success criteria:**
1. ZTLP benchmark (8/8) passes on device after the new build.
2. Open Vaultwarden in WKWebView, page reaches login screen, three consecutive times.
3. After Vaultwarden, benchmark still passes without manual VPN restart.
4. NE resident memory stays under 22MB through the Vaultwarden test.
5. Gateway queue stays shallow; no `send_queue already overloaded`; no RTO retransmit storm on early data_seq.

**Stop-if-blocked criteria:**
- If Phase 3 (MuxEngine) cannot reproduce current behavior after 2 days, reassess.
- If any phase introduces a regression that is not fixable within its own phase, stop and revisit plan.

---

## Phase Overview

- **Phase 0**: Tag baseline, set up Linux harness. ~0.5 day.
- **Phase 1**: Rust owns UDP transport (send/recv). ~1 day.
- **Phase 2**: Rust owns mux framing + ACK/rwnd + pacing. ~1.5 days.
- **Phase 3**: Rust owns session lifecycle (handshake, health, reconnect). ~1 day.
- **Phase 4**: Swift NE becomes thin shell; delete ZTLPTunnelConnection + ACK/rwnd logic. ~0.5 day.
- **Phase 5**: Vaultwarden + benchmark validation. ~0.5 day.

Total: ~5 days with focused work.

Each task below is 2–5 minutes of focused work. Use TDD where a test is realistic. Commit after each task.

---

## Phase 0: Baseline and Harness

### Task 0.1: Tag rollback baseline

**Objective:** Ensure we can revert the whole effort in one command.

**Steps:**

1. On Linux:

```bash
cd /home/trs/ztlp
git pull --rebase origin main
git tag -a v-before-nebula-collapse -m "Pre-Nebula-collapse baseline (rwnd=4 vault stall known state)"
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push --tags
```

2. Verify:

```bash
git tag | grep nebula
```

Expected: `v-before-nebula-collapse`.

**Commit:** tag is the commit.

---

### Task 0.2: Freeze current capture as reference

**Objective:** Keep latest working-ish capture so we can compare later runs.

**Steps:**

1. Copy latest capture dir to a named reference:

```bash
cp -r /home/trs/ztlp/captures/vault-20260503-013504 /home/trs/ztlp/captures/reference-pre-nebula
```

2. Confirm exists:

```bash
ls /home/trs/ztlp/captures/reference-pre-nebula/summary.txt
```

**Commit:** none (captures are gitignored).

---

### Task 0.3: Add Linux-runnable Rust harness stub for IosTunnelEngine

**Objective:** Ensure we can unit/integration test the new Rust pieces on Linux without iOS, to break the "only-testable-on-device" loop.

**Files:**
- Create: `proto/tests/ios_tunnel_engine_harness.rs`

**Step 1: Write failing harness test**

```rust
// proto/tests/ios_tunnel_engine_harness.rs
#![cfg(feature = "ios-sync")]

#[test]
fn harness_loads_module() {
    // smoke: we just need the ios-sync feature build to compile this test.
    let _ = ztlp_proto::ios_tunnel_engine::IosUtun::new(-1);
}
```

**Step 2: Run**

```bash
cd /home/trs/ztlp/proto
cargo test --no-default-features --features ios-sync --test ios_tunnel_engine_harness
```

Expected: 1 passed.

**Commit:**

```bash
git add proto/tests/ios_tunnel_engine_harness.rs
git -c user.name='Steven Price' -c user.email='steve@techrockstars.com' \
  commit -m "test: add ios-sync harness stub for nebula collapse"
```

---

## Phase 1: Rust Owns UDP Transport

**Goal:** Move UDP send/recv for the tunnel from Swift `ZTLPTunnelConnection` into Rust `IosTunnelEngine`. After this phase, Swift still runs mux/ACK/rwnd — transport is the only thing we moved.

Intent: any data Swift currently writes via `NWConnection.send` goes through new FFI `ztlp_ios_tunnel_engine_send`; any data Swift currently receives via NWConnection callback is delivered via a new Rust-owned `ztlp_ios_tunnel_engine_on_packet` callback.

### Task 1.1: Add UDP socket owner to IosTunnelEngine

**Files:**
- Modify: `proto/src/ios_tunnel_engine.rs`

**Step 1: Write failing unit test** in `ios_tunnel_engine.rs` `mod tests`:

```rust
#[test]
fn engine_can_configure_gateway_endpoint() {
    let engine = IosTunnelEngine::start(-1).err();
    // existing behavior: rejects bad fd
    assert!(engine.is_some());
}

#[test]
fn engine_bind_udp_and_expose_local_port() {
    // use 127.0.0.1:0 for test
    let mut engine = IosTunnelEngine::new_for_tests();
    engine.bind_udp_any().expect("bind");
    let port = engine.local_udp_port().expect("port");
    assert!(port > 0);
}
```

**Step 2: Implement:**

```rust
// add to IosTunnelEngine:
udp_socket: Mutex<Option<std::net::UdpSocket>>,
peer_addr: Mutex<Option<std::net::SocketAddr>>,
```

Methods:
- `fn bind_udp_any(&self) -> io::Result<()>`: binds `0.0.0.0:0`, stores socket, sets non-blocking false, sets read timeout 100ms.
- `fn local_udp_port(&self) -> Option<u16>`
- `fn set_peer(&self, addr: SocketAddr)`
- `fn udp_send(&self, bytes: &[u8]) -> io::Result<usize>`: send_to peer_addr.
- `fn udp_recv(&self, buf: &mut [u8]) -> io::Result<usize>`

**Step 3: Run tests:**

```bash
cd /home/trs/ztlp/proto
cargo test --no-default-features --features ios-sync ios_tunnel_engine
```

Expected: all tests pass.

**Commit:** `ios: rust owns UDP socket in IosTunnelEngine`.

---

### Task 1.2: FFI — expose UDP send/recv to Swift

**Files:**
- Modify: `proto/src/ffi.rs`, `proto/include/ztlp.h`

**Add FFI:**

```rust
#[no_mangle]
pub extern "C" fn ztlp_ios_tunnel_engine_udp_bind(engine: *mut ZtlpIosTunnelEngine, peer: *const c_char) -> i32
#[no_mangle]
pub extern "C" fn ztlp_ios_tunnel_engine_udp_send(engine: *mut ZtlpIosTunnelEngine, data: *const u8, len: usize) -> i32
```

(No recv FFI — recv lives in Rust ingress loop, delivered via existing router action callback.)

**Header:** add corresponding `int32_t ztlp_ios_tunnel_engine_udp_bind(...)` etc. in `proto/include/ztlp.h`.

**Step: Sync headers:**

```bash
cp /home/trs/ztlp/proto/include/ztlp.h /home/trs/ztlp/ios/ZTLP/Libraries/ztlp.h
```

**Step: Build verify both features:**

```bash
cd /home/trs/ztlp/proto
cargo check --lib
cargo check --lib --no-default-features --features ios-sync
```

Expected: both pass.

**Commit:** `ffi: expose udp bind/send on IosTunnelEngine`.

---

### Task 1.3: Start UDP recv loop inside Rust ingress thread

**Objective:** Rust ingress thread already owns utun reads. Add a second thread that owns UDP socket reads and passes received ZTLP packets into PacketRouter / delivers them to Swift via the existing router action callback, using a new action_type for "decrypted tunnel payload".

**Files:**
- Modify: `proto/src/ios_tunnel_engine.rs`

Implementation notes:
- Spawn an OS thread at `ztlp_ios_tunnel_engine_udp_bind` time.
- In loop: `udp_recv` → pass to (for now) Swift callback with action_type=252 (raw encrypted packet).
- Swift will still decrypt/process through `ZTLPTunnelConnection` for this phase. This is scaffolding for Phase 2.

Add field and thread lifecycle:
```rust
udp_thread: Mutex<Option<JoinHandle<()>>>
```

**Step: Add test** that spawns engine, binds UDP, sends to itself, confirms callback fires. Use `std::net::UdpSocket::connect` loopback trick.

**Step: Run tests:**

```bash
cargo test --no-default-features --features ios-sync ios_tunnel_engine
```

Expected: all pass.

**Commit:** `ios: rust-owned UDP recv thread`.

---

### Task 1.4: Swift uses Rust UDP instead of NWConnection

**Files:**
- Modify: `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`

**Changes:**
- Remove `NWConnection` for UDP send path.
- `sendPacket(_ data: Data)` now calls `ztlp_ios_tunnel_engine_udp_send(engine, bytes, len)`.
- Keep the NWConnection for ACK path for this phase to reduce blast radius — we remove it in Phase 4.
- Add a new callback action type decoder in `PacketTunnelProvider`: when action_type == 252, feed bytes back into `ZTLPTunnelConnection.receiveRawPacket(_ data: Data)` which drives existing decrypt/mux logic.

**Step: Swift compile check on Mac:**

```bash
ssh stevenprice@10.78.72.234 'export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin" && \
  cd ~/ztlp/ios/ZTLP && \
  xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
    -destination "generic/platform=iOS" -configuration Debug build \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO 2>&1 | \
  grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" | tail -80'
```

Expected: `BUILD SUCCEEDED`.

**Commit:** `ios: route tunnel UDP through rust IosTunnelEngine (phase 1)`.

**Phase 1 validation:**
- Ask Steve to Clean Build Folder, deploy, run benchmark once.
- Pull capture, confirm: benchmark still passes, no new regressions.
- If benchmark fails, revert Task 1.4 only, investigate, retry.

---

## Phase 2: Rust Owns Mux + ACK + rwnd + Pacing

**Goal:** Move all the mux framing and sequence/ack/rwnd/pacing/retransmit logic from `ZTLPTunnelConnection.swift` into Rust as a new `MuxEngine` module.

This is the biggest phase. It replaces:
- Swift `flushPendingAcks` / `setAdvertisedReceiveWindow` / `sendsInFlight` counter.
- Swift rwnd adaptation in `PacketTunnelProvider.maybeRampAdvertisedRwnd`.
- Swift `mux summary` / stream bookkeeping.

### Task 2.1: Create `proto/src/mux.rs`

**Files:**
- Create: `proto/src/mux.rs`

**Types:**

```rust
pub struct MuxEngine {
    // encryption context
    ctx: ZtlpCryptoContext,
    // sequence state
    next_send_packet_seq: u64,
    next_expected_recv_seq: u64,
    // per-stream state
    streams: HashMap<u32, MuxStream>,
    // pending plaintext waiting for window
    send_queue: VecDeque<MuxItem>,
    // inflight sends waiting for ACK
    send_buffer: HashMap<u64, InflightPacket>,
    // advertised receive window (rwnd we tell gateway)
    advertised_rwnd: u16,
    // router interaction
    router: *mut ZtlpPacketRouter,
}

pub enum MuxItem {
    OpenStream { stream_id: u32, service: String },
    StreamData { stream_id: u32, payload: Vec<u8> },
    CloseStream { stream_id: u32 },
    Ack { cumulative: u64, rwnd: u16 },
    Probe { nonce: u64 },
}
```

**Methods (declarations only, implement in later tasks):**
- `new(ctx) -> Self`
- `on_utun_packet(&mut self, ip_pkt: &[u8])` — pushes through PacketRouter, generates OpenStream/StreamData/CloseStream MuxItems.
- `on_udp_from_gateway(&mut self, encrypted: &[u8]) -> Vec<UtunWrite>` — decrypt, parse mux, emit utun IP writes.
- `take_send_bytes(&mut self) -> Vec<Vec<u8>>` — returns encrypted UDP packets ready to send, respecting rwnd / cwnd / pacing budget.
- `on_ack(&mut self, cumulative: u64, rwnd: u16)`
- `tick(&mut self, now: Instant)` — retransmit, rwnd ramp, health.

**Step: Wire module into `proto/src/lib.rs`:**

```rust
#[cfg(feature = "ios-sync")]
pub mod mux;
```

**Step: compile check:**

```bash
cd /home/trs/ztlp/proto
cargo check --lib --no-default-features --features ios-sync
```

Expected: pass.

**Commit:** `feat: scaffold proto::mux for ios-sync`.

---

### Task 2.2: Port FRAME encode/decode into mux.rs

Lift the frame constants and encode/decode code currently sitting in `ZTLPTunnelConnection.swift` into `mux.rs`:

- `FRAME_DATA = 0x00`
- `FRAME_OPEN = 0x06`
- `FRAME_CLOSE = 0x05`
- `FRAME_ACK = 0x04` (with rwnd variant)
- `FRAME_FIN = 0x07`
- `FRAME_PROBE / PONG`

**Add unit tests** in `mux.rs`:
- encode FRAME_ACK with rwnd=12 decodes back to {cumulative=N, rwnd=12}.
- encode FRAME_OPEN(stream_id=5, service="vault") decodes back.

**Step: run:**

```bash
cargo test --no-default-features --features ios-sync mux
```

Expected: pass.

**Commit:** `feat: mux frame codec (ios-sync)`.

---

### Task 2.3: Port ACK generation + rwnd policy into mux.rs

Port current rwnd policy exactly from `PacketTunnelProvider.swift` `maybeRampAdvertisedRwnd`. Then fix the known bug: do not collapse to rwnd=4 when `outbound==0 && oldestMs==0 && highSeqAdvanced==false && recent demand`. Use a hold value of 12 instead.

**Unit tests:**
- Given healthy stats (outbound=0, replayDelta=0, flows=2), rwnd should be >= 12.
- Given replayDelta=8, rwnd should drop to floor.

**Step: run:**

```bash
cargo test --no-default-features --features ios-sync mux::rwnd
```

Expected: pass.

**Commit:** `feat: mux rwnd policy with Vaultwarden hold=12`.

---

### Task 2.4: Port send_buffer / retransmit / cwnd pacing into mux.rs

Port the Swift `maxSendsInFlight` / `sendsInFlight` cwnd budget and retransmit logic currently in `ZTLPTunnelConnection`.

**Unit tests:**
- Enqueue 100 StreamData frames, call `take_send_bytes()` repeatedly — respects cwnd budget.
- Simulate packet loss: frame not acked within RTO → retransmit appears in `take_send_bytes`.
- ACK advances cumulative → inflight entries drop.

**Step: run:**

```bash
cargo test --no-default-features --features ios-sync mux::send
```

Expected: pass.

**Commit:** `feat: mux send buffer, cwnd, retransmit`.

---

### Task 2.5: FFI — expose MuxEngine lifecycle to Swift

```rust
#[no_mangle]
pub extern "C" fn ztlp_mux_new(ctx: *mut ZtlpCryptoContext, router: *mut ZtlpPacketRouter) -> *mut ZtlpMuxEngine
#[no_mangle]
pub extern "C" fn ztlp_mux_on_utun(mux: *mut ZtlpMuxEngine, pkt: *const u8, len: usize) -> i32
#[no_mangle]
pub extern "C" fn ztlp_mux_on_udp(mux: *mut ZtlpMuxEngine, pkt: *const u8, len: usize) -> i32
#[no_mangle]
pub extern "C" fn ztlp_mux_tick(mux: *mut ZtlpMuxEngine) -> i32
#[no_mangle]
pub extern "C" fn ztlp_mux_free(mux: *mut ZtlpMuxEngine)
```

Wire mux so internally it:
- pulls bytes via `ztlp_ios_tunnel_engine_udp_send`
- writes IP packets via the utun write in IosTunnelEngine

**Step: header sync** `proto/include/ztlp.h` → `ios/ZTLP/Libraries/ztlp.h`.

**Commit:** `ffi: expose MuxEngine to iOS`.

---

### Task 2.6: Wire IosTunnelEngine to MuxEngine

Inside the Rust ingress loop:
- utun inbound packet → `mux.on_utun(pkt)` → results in send queue items
- UDP inbound packet → `mux.on_udp(pkt)` → results in utun writes
- 10ms tick → `mux.tick()` → takes send bytes and pushes them to UDP

Swift's role at this point: just call `ztlp_ios_tunnel_engine_start(fd)` and `ztlp_mux_new(ctx, router)` once. No per-packet Swift work.

**Validation:**
- Linux unit tests for mux pass.
- iOS Debug build still succeeds.

**Commit:** `feat: ingress loop drives MuxEngine end-to-end`.

---

### Task 2.7: Disable old Swift mux path behind a flag

**Files:**
- Modify: `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- Modify: `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`

Add a compile-time constant `useRustMux = true` (matching existing `useRustFdDataPlane` style). When true:
- Swift does NOT call `flushPendingAcks`.
- Swift does NOT call `setAdvertisedReceiveWindow` or rwnd policy.
- Swift does NOT maintain `sendsInFlight`.
- Swift does NOT call `ztlp_router_write_packet_sync` from its own read loop.

Leave the old code intact but unused.

**Verify Xcode build:**

```bash
ssh stevenprice@10.78.72.234 'export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin" && \
  cd ~/ztlp/ios/ZTLP && \
  xcodebuild -project ZTLP.xcodeproj -scheme ZTLP -destination "generic/platform=iOS" \
  -configuration Debug build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO 2>&1 | grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" | tail -80'
```

Expected: `BUILD SUCCEEDED`.

**Commit:** `ios: route mux through rust (phase 2 gate)`.

**Phase 2 validation on device (only after commit):**
1. `scripts/ztlp-server-preflight.sh` must be PRECHECK GREEN.
2. Ask Steve to Clean Build Folder + deploy.
3. Run benchmark → pull capture.
4. Expected:
   - Benchmark 8/8 still passes.
   - Phone log shows `Rust mux` markers (added inside MuxEngine as `ios_log("Rust mux ...")`).
   - Gateway CLIENT_ACK shows rwnd varying 8/12/16, not stuck at 4.
   - No regression vs Phase 0 capture.

If regression: roll back Task 2.7 by flipping `useRustMux = false`, investigate, do not proceed to Phase 3.

---

## Phase 3: Rust Owns Session Lifecycle

### Task 3.1: Move session health detection into Rust

**Files:**
- Create: `proto/src/session_health.rs`

Port these from `PacketTunnelProvider.swift`:
- `healthCheckInterval`, `healthSuspectThreshold`, `probeTimeoutThreshold`.
- `noProgressTicksBeforeSuspect`, `fastStuckOldestMsThreshold`.
- Probe send/receive logic.

Drive health from `mux.tick()`. When health goes dead:
- Call new `engine.mark_needs_reconnect(reason)` instead of calling Swift.

**Unit tests:**
- Simulated "no useful RX for 5s with active flows" → suspect.
- "probe response within 2s" → back to healthy.
- "probe timeout 5s" → dead.

**Commit:** `feat: rust session health detector`.

---

### Task 3.2: Rust-driven reconnect

Instead of Swift scheduling reconnect on `tunnelQueue`, `IosTunnelEngine` loop checks `needs_reconnect` flag each tick and:
1. Calls `ztlp_connect_sync` again.
2. Rebinds UDP peer to selected relay.
3. Rebuilds ZtlpCryptoContext.
4. Resets MuxEngine state (keep router state, reset streams).
5. Emits a Swift callback (action_type=253) `reconnected` with build marker so we can confirm from logs.

**Unit tests (Linux):** not feasible end-to-end without gateway. Cover the "state machine transitions" only.

**Commit:** `feat: rust-driven reconnect`.

---

### Task 3.3: Delete Swift reconnect scheduling

Remove these from `PacketTunnelProvider.swift`:
- `scheduleReconnect`
- `attemptReconnect`
- `pendingReconnectReason`
- `startHealthTimer` body (keep the stub for logging)

Everything just logs from Rust now.

**Commit:** `ios: delete swift reconnect, rust owns session lifecycle`.

**Phase 3 validation on device:**
- Benchmark passes.
- Disconnect/reconnect cycle still works (toggle VPN off/on manually).
- Session health logs come from Rust.

If regression → stop, investigate.

---

## Phase 4: Delete Swift Fat Layers

### Task 4.1: Delete ZTLPTunnelConnection.swift

Ensure nothing references it:

```bash
grep -r "ZTLPTunnelConnection" ios/ZTLP/ || true
```

Remove from Xcode target and delete file.

**Verify Xcode build:** BUILD SUCCEEDED.

**Commit:** `ios: delete ZTLPTunnelConnection.swift`.

---

### Task 4.2: Shrink PacketTunnelProvider.swift to ~250 lines

Target shape:

```swift
override func startTunnel(...) async throws {
    configureNetworkSettings(...)
    let fd = tunnelFileDescriptor ?? throw ...
    let engine = ztlp_ios_tunnel_engine_start(fd, configJSON)
    ztlp_ios_tunnel_engine_udp_bind(engine, gatewayPeer)
    ztlp_mux_new(cryptoCtx, router)
    // that's it. No timers. No ACKs. No rwnd.
}
override func stopTunnel(...) {
    ztlp_ios_tunnel_engine_free(engine)
}
```

Leave only:
- Config load
- NetworkSettings config
- utun fd discovery
- Call into Rust engine start
- Log bridging (existing `ios_log` callback)

**Verify Xcode build:** BUILD SUCCEEDED.

**Commit:** `ios: shrink PacketTunnelProvider to nebula shell (~250 lines)`.

---

### Task 4.3: Delete unused Swift files

Move to Xcode trash / remove from target:
- `ZTLPDNSResponder.swift` (DNS is in Rust now)
- `ZTLPVIPProxy.swift` (already disabled)
- `ZTLPNSClient.swift` (NS in Rust now)

Keep `TunnelConfiguration.swift`, `TunnelLogger.swift`, `PacketTunnelProvider.swift`.

**Commit:** `ios: remove defunct swift tunnel files`.

---

## Phase 5: Vaultwarden + Benchmark Validation

### Task 5.1: Run server preflight

```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Must end `PRECHECK GREEN`.

---

### Task 5.2: Ask Steve to Clean Build Folder + deploy

Steve does:
1. Xcode → Product → Clean Build Folder.
2. Run on device.
3. Connect VPN.

Do NOT redeploy gateway unless preflight failed.

---

### Task 5.3: Benchmark test 1 (pre-vault)

Steve runs benchmark, taps "Send Logs".

Me:

```bash
/home/trs/ztlp/scripts/ztlp-ios-vault-capture.sh
```

Read `summary.txt`. Acceptance: `phone_bench_ok>=1`, `gw_rto==0 or small`, rwnd values 8/12/16 (not stuck at 4).

---

### Task 5.4: Vaultwarden test 1

Steve opens Vaultwarden from the app. Waits up to 30s. Reports result.

Me:

```bash
/home/trs/ztlp/scripts/ztlp-ios-vault-capture.sh
```

Acceptance: phone log shows `WKWebView session=X didFinish`. Not `code=-999`.

---

### Task 5.5: Benchmark test 2 (post-vault)

Steve runs benchmark again without toggling VPN.

Acceptance: still 8/8 or at least matches pre-vault score.

---

### Task 5.6: Repeat Vault twice more

If all three Vault tests complete to login, and both benchmarks pass: ship.

---

## Deployment Commands Reference

**Build NE Rust lib on Steve's Mac:**

```bash
ssh stevenprice@10.78.72.234 'export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin" && \
  cd ~/ztlp/proto && \
  cargo build --release --target aarch64-apple-ios \
    --no-default-features --features ios-sync --lib \
    --target-dir target-ios-sync && \
  cp target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a \
    ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a && \
  cp include/ztlp.h ~/ztlp/ios/ZTLP/Libraries/ztlp.h'
```

**Xcode unsigned verify build:**

```bash
ssh stevenprice@10.78.72.234 '... xcodebuild ... | grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" | tail -80'
```

**Pull phone log:**

```bash
ssh stevenprice@10.78.72.234 'xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone.log'
```

**Capture everything:**

```bash
/home/trs/ztlp/scripts/ztlp-ios-vault-capture.sh
```

**Rollback everything:**

```bash
cd /home/trs/ztlp
git reset --hard v-before-nebula-collapse
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push --force origin main
# On Mac:
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git fetch && git reset --hard origin/main'
```

---

## Rules During Execution

1. Commit after every task. Never batch multiple tasks into one commit.
2. Never restart gateway/relay/NS without warning Steve first.
3. After every Rust change that affects NE, rebuild `libztlp_proto_ne.a` on Steve's Mac and Clean Build Folder before asking Steve to test.
4. After every Swift change, run the unsigned Xcode build check before asking Steve to test.
5. If a task takes longer than 15 minutes, stop and re-plan. The task was too big.
6. Phase gates are blocking: do not start Phase N+1 until Phase N's device validation passes.
7. If any on-device validation regresses, first suspect the last task, revert it, debug in isolation.
8. No "while I'm here" refactors. YAGNI.

---

## What This Plan Is NOT Doing

- Not rewriting crypto. `snow` + `chacha20poly1305` stay.
- Not rewriting the gateway. Existing Elixir stays.
- Not moving VIP termination (already moved to relay earlier).
- Not swapping to CryptoKit. Keep testable Rust crypto on Linux.
- Not touching the main app `ZTLP` target except to keep it buildable.
- Not changing iOS deployment target, Info.plist entitlements, or app-group ID.

---

## End State

- Swift NE: ~250 lines, thin shell.
- Rust: owns utun, UDP, handshake, mux, ACK/rwnd, pacing, retransmit, health, reconnect, DNS.
- Gateway: unchanged except bugs we uncover during validation.
- Vaultwarden in WKWebView: loads to login reliably.
- Benchmarks: pass 8/8 before and after Vault without manual VPN toggle.
- New Rust modules fully unit-testable on Linux, not device-only.

This ends the two-month seam-bug loop by removing the seam.
