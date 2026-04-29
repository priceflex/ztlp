# ZTLP iOS Session Health Handoff — 2026-04-29

This handoff covers the work implementing Nebula-style session health recovery for
the ZTLP iOS tunnel and the next concrete steps. Read this file end-to-end before
doing anything in the next session.

---

## 1. Why we started this work

Steve has been fighting a specific failure mode on the iOS app for weeks:

- A fresh ZTLP VPN session can run the benchmark cleanly (8/8 score).
- After opening Vaultwarden / OpenVault in the in-app WKWebView browser, the
  tunnel enters a poisoned / wedged state.
- The tunnel still looks "connected" but HTTP benchmarks hit `No response` /
  timeout, and eventually the NE is torn down.
- The only recovery was a manual VPN toggle.

Previous attempts focused on tuning: rwnd caps, queue thresholds, ACK sender
architecture, etc. After ~50 commits, the Rule of Three clearly applied: this is
not a tuning problem, it is an architectural mismatch.

The chosen direction:
**implement a Nebula-style active session-health manager instead of a blind
watchdog / blind VPN restart.** Detect sessions that are "alive but stuck" with
an encrypted probe, and recover locally (cleanup stale flows / router reset) or
re-handshake the ZTLP transport without killing the NE.

See:
- `handoff_04-28-26.md` for the prior-session plan.
- `ZTLP-IOS-OPENVAULT-HANDOFF-2026-04-29-RWND12-NEXT.md`
- `ZTLP-IOS-OPENVAULT-HANDOFF-2026-04-29.md`
- `ZTLP-IOS-RESTART-HANDOFF-2026-04-28.md`

---

## 2. What was actually implemented this session

All of the following is committed on `main`:

```
ac07c11 ios: fix frameBuffer cross-queue race in probe path
6f0ad0d ios: fix Swift build errors in probe frame handlers
6dbfdf6 ios: tighten session-health detector
61a115d ios+gateway: Nebula-style session health recovery
```

### 2.1 New proto FFI
- `ztlp_router_reset_runtime_state(router)` — clears `flows`,
  `stream_to_flow`, `outbound` queue, resets `next_stream_id=1`, preserves the
  configured service map. Used for probe-confirmed-alive recovery and for
  reconnect.
- `router_stats()` now returns extra fields:
  - `send_buf_bytes`
  - `send_buf_flows`
  - `oldest_ms`
  - `stale`
- All `proto/` tests still pass (`cargo test packet_router --lib`).

### 2.2 New gateway protocol: encrypted FRAME_PING / FRAME_PONG

In `gateway/lib/ztlp_gateway/session.ex`:

- Added frame constants:
  - `@frame_ping 0x07`
  - `@frame_pong 0x08`
- Probes are processed on the **ACK fast-path**: they bypass the in-order
  recv-window buffer, so a data gap cannot HOL-block probes.
- Logged markers: `SESSION_PING nonce=...` and `SESSION_PONG nonce=...`.
- New helper `encrypt_and_send_probe/2` for PONG send.

### 2.3 iOS session health manager

In `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`:

- Tracks:
  - `lastUsefulRxAt` — only updated when `markUsefulRx` sees payload AND the
    sequence advances (replay-only / duplicates do not count).
  - `lastOutboundDemandAt` — updated on router OpenStream / SendData / CloseStream.
  - `priorHighSeqSnapshot` + `consecutiveStuckHighSeqTicks` — catches the
    "alive but stuck" pattern where retransmits/replay still arrive but no
    forward progress is made.
  - Router stats via `parseRouterStats()` each tick.
- New low-frequency timer `healthTimer` (2s interval).
- Startup marker so we can verify the code is live on-device:
  ```
  Session health manager enabled interval=2.0s suspectRx=5.0s probeTimeout=5.0s stuckTicks=3
  ```
- Rate-limited heartbeat every 4s so we always see what the detector sees:
  ```
  Health eval: flows=N outbound=N streamMaps=N highSeq=S stuckTicks=N usefulRxAge=X.Xs outboundRecent=T/F replayDelta=N probeOutstanding=T/F
  ```
- Two independent suspect triggers, both gated by "active flows":
  1. Active flows AND `usefulRxAge >= 5s` → reason `no_useful_rx_X.Xs`.
  2. Active flows AND `highSeq` not advancing for 3 consecutive 2s ticks
     → reason `stuck_highseq_3_ticks`.
- Recovery ladder:
  - Suspect → send encrypted FRAME_PING → wait for FRAME_PONG.
  - Probe OK → `ztlp_router_cleanup_stale_flows`; if nothing to clean and
    there are still flows → `ztlp_router_reset_runtime_state`.
  - Probe timeout (5s) → `resetPacketRouterRuntimeState` + `scheduleReconnect`
    with `reason=session_health_probe_timeout`.
- `attemptReconnect()` now also resets router runtime state before bringing the
  transport back up, so a "reconnect after wedge" doesn't inherit stale mux /
  stream / queue state.

In `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`:

- New frame types in the local `ZTLPFrameType` enum: `ping = 0x07`,
  `pong = 0x08`.
- New delegate method `didReceiveProbeResponse(nonce:)`.
- `sendProbe(nonce:)` function.
- **Cross-queue race fix (commit `ac07c11`):** probe PING/PONG frames are now
  built in LOCAL byte arrays and encrypted via a new `sendEncryptedFrame()`
  helper that uses a local encrypt buffer. This avoids a data race on the
  shared `frameBuffer` instance variable:
  - `sendProbe` runs on `tunnelQueue` (from the health timer).
  - The PING handler (which sends PONG) runs on `nwQueue` (the NWConnection
    callback queue).
  - Both were previously writing into the same `frameBuffer`.
- Under Safari's 7-concurrent-stream Vaultwarden burst, the old cross-queue
  writes into `frameBuffer` corrupted frames and wedged the NE I/O path.

---

## 3. What we verified this session

### Gateway / servers
- Built `ztlp-gateway:session-health` and `ztlp-gateway:session-health-v2`
  locally, shipped via SSH pipe, restarted on `44.246.33.34` with all
  preserved env (NS, relay, backends, policies, host networking).
- Old container kept stopped as `ztlp-gateway-old` for fallback rollback.
- Verified the running gateway actually has the new probe handlers:
  ```
  ZtlpGateway.Session.module_info(:functions)
    |> Enum.filter(fn {f,_} -> Atom.to_string(f) =~ ~r/probe|ping|pong/i end)
  # => [encrypt_and_send_probe: 2, send_probe_pong: 2]
  ```
- Server preflight script (`~/ztlp/scripts/ztlp-server-preflight.sh`) returns
  `PRECHECK GREEN`.

### iOS build
- Rebuilt `libztlp_proto_ne.a` on Steve's Mac via SSH and copied the header,
  twice (once after first patch, once after the race fix).
- Xcode unsigned Release build: `** BUILD SUCCEEDED **` both times.
- Verified `ztlp_router_reset_runtime_state` symbol is present in the NE lib
  and declared in the copied header.

### On-device evidence
From the phone app-group log during the failed OpenVault test (after the
detector shipped but BEFORE the race fix):

```
04:40:52.674 Session health manager enabled interval=2.0s suspectRx=5.0s probeTimeout=5.0s stuckTicks=3
04:40:54.680 Health eval: flows=0 outbound=0 streamMaps=0 highSeq=0 stuckTicks=0 usefulRxAge=2.2s ...
04:41:04.678 Health eval: flows=0 outbound=0 streamMaps=0 highSeq=39 stuckTicks=0 usefulRxAge=3.4s outboundRecent=true ...
04:41:06.678 Session health suspect: reason=no_useful_rx_5.4s ... sending probe nonce=1777437666677
04:41:06.722 Session health probe response nonce=1777437666677
04:41:08.678 Session health suspect: reason=no_useful_rx_7.4s ... sending probe nonce=1777437668678
04:41:08.721 Session health probe response nonce=1777437668678
04:41:09.753 Mux summary gwData=40/26343B open=7 close=8 send=2/531B   # Safari fan-out
# silence for 5.7s — NE I/O wedged
04:41:15.418 VPN status changed: 5
04:41:15.782 VPN status changed: 1
```

Gateway confirmed receiving both PINGs:
```
[Session] SESSION_PING nonce=1777437666677
[Session] SESSION_PING nonce=1777437668678
```

Conclusion: the probe loop works end-to-end with ~40ms round-trip. The NE
died right after the Vaultwarden burst because of the `frameBuffer` cross-queue
race, not because of the detector logic.

---

## 4. Current state of the repo

Local working tree should be clean on `main` at `ac07c11` (or later). Only
files we may still track are the handoff / planning `*.md` files.

Local test commands that were run:
```
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml packet_router --lib
#   36 passed; 0 failed.
mix test test/ztlp_gateway/session_recovery_target_test.exs test/ztlp_gateway/session_dedup_test.exs
#   9 passed; 0 failed.
cd /home/trs/ztlp/gateway && mix compile --warnings-as-errors
#   compiled cleanly.
```

Production containers on AWS:
- `ztlp-gateway:session-health-v2` running on `44.246.33.34` (host networking).
  - Keeps prior env: `ZTLP_RELAY_SERVER=172.26.5.220:23095`,
    `ZTLP_NS_SERVER=172.26.13.85:23096`,
    `ZTLP_GATEWAY_BACKENDS=default:127.0.0.1:8080,http:127.0.0.1:8180,vault:127.0.0.1:8080`,
    `ZTLP_GATEWAY_SERVICE_NAMES=default,http,vault`,
    `ZTLP_GATEWAY_POLICIES=*:default,*:http,*:vault`.
  - `ztlp-gateway-old` is stopped, kept for rollback.
- Relay `ztlp-relay:vip` on `34.219.64.205`: unchanged.
- NS `ztlp-ns:signed-relay` on `34.217.62.46`: unchanged.

Steve's Mac (`stevenprice@10.78.72.234`):
- `~/ztlp` is synced to `origin/main` at `ac07c11` (or later).
- `ios/ZTLP/Libraries/libztlp_proto_ne.a` rebuilt from latest proto source.
- `ios/ZTLP/Libraries/ztlp.h` updated with `ztlp_router_reset_runtime_state`.
- Unsigned iOS Release build verified green from the CLI.

---

## 5. What we expect on the next phone test

After Steve does a fresh Xcode Clean Build Folder and deploys to the iPhone:

Expected phone-log markers during a healthy session:
```
Session health manager enabled interval=2.0s suspectRx=5.0s probeTimeout=5.0s stuckTicks=3
Health eval: ... (every 4s, rate-limited)
```

Expected markers during a Vaultwarden / OpenVault test:
- Benchmark pass (8/8) before the browser load.
- `Mux summary ... open=7 close=8 send=...` while Vaultwarden page loads.
- The tunnel should **NOT** die silently. The `frameBuffer` race is fixed.
- If the session actually wedges after the burst, we should see one of:
  - `Session health candidate: ... reason=no_useful_rx_5.Xs`, then
    `Session health suspect: ... sending probe nonce=...`, then either
    - `Session health probe response nonce=...` (local cleanup / reset), or
    - `Session health dead: probe timeout ...` followed by
      `Router reset runtime state removed=N reason=session_health_probe_timeout`,
      `Reconnect gen=X starting reason=session_health_probe_timeout`,
      `Reconnect gen=X succeeded via relay ...`.
  - Same markers with `reason=stuck_highseq_3_ticks` for the "alive but
    stuck" variant.
- Benchmark AFTER touching Vaultwarden should pass, with no manual VPN toggle.

Gateway-side expected markers:
- `[Session] SESSION_PING nonce=...`
- `[Session] SESSION_PONG nonce=...`
- If recovery worked, no long-lived `send_queue already overloaded` or
  `STALL: no ACK advance` lines during the relevant window.

---

## 6. How to verify / what to run

### 6.1 Pre-test server preflight
From this box:
```bash
cd /home/trs/ztlp && ./scripts/ztlp-server-preflight.sh
# expect PRECHECK GREEN before asking Steve to test
```

### 6.2 Start a phone test
1. Steve: open `/Users/stevenprice/ztlp/ios/ZTLP/ZTLP.xcodeproj` in Xcode on
   the Mac Studio.
2. Product → **Clean Build Folder** (⌘⇧K).
3. Build / run to iPhone.
4. Wait ~10s after `TUNNEL ACTIVE` appears.
5. Run benchmark (should be 8/8).
6. Open Vaultwarden / OpenVault in the in-app browser.
7. Wait until the page loads or stalls — **do NOT manually restart VPN.**
8. Run benchmark again.
9. Tap **Send Logs** on the benchmark screen.

### 6.3 Pull logs after the test
```bash
# Phone app-group log — filtered
ssh stevenprice@10.78.72.234 'xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone-next.log >/dev/null && \
  wc -l /tmp/ztlp-phone-next.log && \
  grep -E "Build:|Session health|Health eval|probe|PONG|PING|Benchmark run|Benchmark Timeout|HTTP benchmark GET failed|VPN status|ZTLP RX summary|Mux summary|Advertised rwnd|Router stats|Router reset|Router cleanup|Memory resident|Reconnect|TUNNEL|BenchUpload|failed|error" \
    /tmp/ztlp-phone-next.log | tail -400'

# Gateway logs for the same window
ssh ubuntu@44.246.33.34 "docker logs --since 10m ztlp-gateway 2>&1 | \
  grep -E 'SESSION_PING|SESSION_PONG|CLIENT_ACK.*rwnd|pacing_tick|STALL|Backpressure|send_queue|FRAME_OPEN|FRAME_CLOSE|Stream [0-9]+|ACK_LATENCY|RTO|REJECTED|unknown_session|recv_base|queue|stats' | tail -400"

# Latest benchmark records
ssh trs@10.69.95.12 "docker exec -w /rails bootstrap_web_1 bin/rails runner '
BenchmarkResult.order(created_at: :desc).limit(8).each do |b|
  puts [\"ID=#{b.id}\", b.created_at.utc.iso8601, \"score=#{b.benchmarks_passed}/#{b.benchmarks_total}\", \"mem=#{b.ne_memory_mb.inspect}\", \"replay=#{b.replay_reject_count.inspect}\", \"err=#{b.error_details.to_s[0,120]}\", \"results=#{b.individual_results.inspect[0,500]}\"].join(\" | \")
end
'"
```

---

## 7. Important pitfalls / don'ts

- **Do not restart gateway/relay/NS** without telling Steve first; it kills
  his in-progress phone benchmarks.
- **Do not `git reset --hard`** on Steve's Mac — he may have local WIP.
  If the tree is dirty, stash with a label before pulling:
  ```bash
  ssh stevenprice@10.78.72.234 "cd ~/ztlp && \
    git stash push -u -m 'pre-pull-$(date +%F-%H%M%S)' && \
    git pull origin main"
  ```
- **Do not trust `grep -a` on stripped mix-release beams** to confirm the
  container has your code. Debug strings get stripped out. Use instead:
  ```bash
  ssh ubuntu@44.246.33.34 'docker exec ztlp-gateway /app/bin/ztlp_gateway rpc \
    "ZtlpGateway.Session.module_info(:functions) |> \
       Enum.filter(fn {f,_} -> Atom.to_string(f) =~ ~r/probe|ping|pong/i end) |> \
       IO.inspect()"'
  # => should list encrypt_and_send_probe/2 and send_probe_pong/2
  ```
- **Do not probe idle tunnels.** Current code is gated on `hasActiveFlows`.
  If someone reverts that gate, we'll burn crypto/wakeups probing nothing,
  which contributes to iOS CPU-wakeup penalties.
- **Never share `frameBuffer` across queues.** The regression fixed by
  `ac07c11` was a silent NE wedge. Any new send path (control frames, rekey,
  probes, etc.) must encrypt from a LOCAL plaintext buffer into a LOCAL
  encrypt buffer via `sendEncryptedFrame()` (or equivalent).

---

## 8. Skills to load in the new session

- `ztlp-ios-performance-debugging`
- `ztlp-ios-safari-stall-debugging`
- `ztlp-ios-relay-deploy`
- `ztlp-prod-deployment`
- `systematic-debugging`
- `research-driven-root-cause-analysis`

---

## 9. Memory / user-profile notes still valid

- Steve = Steven Price, prefers to be called Steve.
- Commit identity: name "Steven Price", email "steve@techrockstars.com".
- Steve's Mac SSH: `stevenprice@10.78.72.234` with default key (not openclaw key).
- Phone UDID: `39659E7B-0554-518C-94B1-094391466C12`.
- Bootstrap: `trs@10.69.95.12`; gateway `ubuntu@44.246.33.34`;
  relay `ubuntu@34.219.64.205`; NS `ubuntu@34.217.62.46`.
- Gateway/relay/NS use `~/.ssh/id_rsa`.
- GIT_SSH_COMMAND to push to origin from this Linux box:
  `ssh -i /home/trs/openclaw_server_import/ssh/openclaw -o StrictHostKeyChecking=no`.
- rwnd cap is currently 12/10 on iOS; leave that alone.
- Always tell Steve BEFORE restarting gateway/relay/NS.

---

## 10. Definite next steps (pick up here in the new session)

1. Steve does Clean Build Folder + device deploy with the current `main`
   (`ac07c11` or later).
2. Run the validation sequence in §6.2 without any manual VPN toggle.
3. Pull logs via §6.3 and inspect:
   - Is the `Session health manager enabled ...` marker present?
   - Does `Health eval` heartbeat fire every 4s?
   - Does the NE survive the Vaultwarden burst (no silent VPN status=5)?
   - If the tunnel wedges, do we see probe → either probe response (recovery)
     or probe timeout → reconnect?
   - Does the post-Vaultwarden benchmark recover to 8/8 without manual VPN toggle?
4. If 8/8 after Vaultwarden: declare victory, update skills:
   - update `ztlp-ios-performance-debugging` and
     `ztlp-ios-safari-stall-debugging` with the session-health recovery pattern
     and the frameBuffer cross-queue race lesson.
5. If still failing: DO NOT chase tuning again. Go straight to the logs.
   - If the health marker is missing: the phone build is stale — rebuild.
   - If the health eval never fires suspect / stuck: the detector thresholds
     may need tweaking; inspect the heartbeat values and replay/highSeq.
   - If probe times out: the gateway isn't replying — check its logs for
     `SESSION_PING` and any crash / stall on that session id.
   - If NE dies silently again: look for any OTHER shared-buffer / shared-state
     between queues (ack flush timer, rekey path, etc.), similar to the
     frameBuffer race we already fixed.
