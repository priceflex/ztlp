# ZTLP Modern Flow Control — Phase B Landed

Status: **deployed, awaiting on-device verification**
Date: 2026-05-03
Predecessor: `2026-05-03-modern-flow-control-PHASE-A-LANDED.md`
Rollback tag: `v-before-byte-rwnd` → `v-after-byte-rwnd`
Commit: `9d77958` on `main`
Gateway image: `ztlp-gateway:ack-v2` (MD5 `31237063fdaa2cdf18ff874b9f6cb08e` on `Elixir.ZtlpGateway.Session.beam`)

## What shipped

**FRAME_ACK_V2 on the wire.** Client advertises its receive window in
KB (units of 1024 bytes) instead of frame count. Asymmetric: only
client→gateway direction gets V2; gateway→client ACKs stay on 0x01/SACK.

### Rust (proto/src/mux.rs)
- `FRAME_ACK_V2 = 0x10` constant + `MuxFrame::AckV2 { cumulative, window_kb }`.
- Wire: `[0x10 | cumulative_ack(8 BE) | window_kb(2 BE)]` = 11 bytes.
- Strict codec (11-byte-only decode).
- `peer_speaks_v2` sticky flag + `advertised_window_bytes` state in MuxEngine.
- `build_ack_frame` emits V2 when peer has spoken V2, V1 otherwise.
- `note_peer_sent_v2`, `peer_speaks_v2`, `advertised_window_kb`,
  `set_initial_window_kb` public API + matching FFI.
- `set_rwnd` (V1 ladder) keeps byte-window synced via
  `rwnd * RWND_V1_FRAME_SIZE_HINT (=1140)` until V2 takes over.
- `DEFAULT_INITIAL_WINDOW_KB = 16` (≈1 TCP initial-cwnd).
- `SHADOW_MAX_ENTRIES = 4096` (shadow sent-map cap, Phase A).
- **10 new Rust tests → 49/49 passing** (25 baseline → 39 Phase A → 49 Phase B).

### FFI (proto/src/ffi.rs + proto/include/ztlp.h + ios/Libraries/ztlp.h)
- `ztlp_mux_note_peer_sent_v2` / `ztlp_mux_peer_speaks_v2` / `_advertised_window_bytes` / `_advertised_window_kb` / `_set_initial_window_kb`.
- `ztlp_build_ack_v2(ack_seq, window_kb, out_buf, ...)` — standalone builder
  for Swift's legacy C-FFI ACK path.

### Gateway (gateway/lib/ztlp_gateway/session.ex)
- `@frame_ack_v2 0x10` constant alongside existing `@frame_ack 0x01`.
- New handle_tunnel_frame clause:
  ```elixir
  <<@frame_ack_v2, acked_data_seq::big-64, window_kb::big-16>>
  ```
- Conversion math: `rwnd_packets = max(1, div(window_kb * 1024, @max_payload_bytes))`
  where `@max_payload_bytes = 1140`. Feeds the existing
  `effective_window = min(cwnd, cc_max_cwnd, peer_rwnd)` math unchanged.
- Per-session state adds `peer_rwnd_bytes` + sticky `peer_uses_v2` flag.
- Fast-path ACK detection recognizes 0x10 (length == 11) so V2 bypasses
  recv-window ordering like V1 already does — no HOL blocking on ACKs.
- `CLIENT_ACK_V2` log line so you can see V2 traffic in gateway logs.
- **5 new ExUnit tests** (`gateway/test/ztlp_gateway/frame_ack_v2_test.exs`) locking
  in the wire shape: 11 bytes, 0x10 type, BE fields, byte→packet math.

### iOS Swift
- **ZTLPTunnelConnection**:
  - `ZTLPFrameType.ackV2 = 0x10`.
  - Defensive decode for 0x10 at recv path (gateway doesn't currently
    emit V2 but future-proof).
  - `useByteRwnd: Bool` toggle + `advertisedWindowKb: UInt16` state.
  - `flushPendingAcks` branches: V1 (`ztlp_build_ack_with_rwnd`) vs
    V2 (`ztlp_build_ack_v2`).
  - `setAdvertisedWindowKb(_:)` setter.
- **PacketTunnelProvider**:
  - `useByteRwnd = true` (we cut over both sides together).
  - `wireRttInstrumentationHook`: flips `conn.useByteRwnd`, calls
    `ztlp_mux_note_peer_sent_v2` so the Rust engine mirrors the upgrade
    locally, seeds `conn.advertisedWindowKb` from the engine.
  - 2s tick loop keeps `conn.advertisedWindowKb` synced with
    `ztlp_mux_advertised_window_kb(mux)`.
  - `[rtt-bdp]` log line now ends with `v2=yes/no adv_kb=N`.

## Deploy notes

### What got deployed to production (44.246.33.34)
1. Built `ztlp-gateway:ack-v2` locally using `docker build --no-cache
   -f gateway/Dockerfile -t ztlp-gateway:ack-v2 .` at the repo root
   (gateway Dockerfile uses `COPY gateway/...` paths — context MUST be
   repo root, not `gateway/`).
2. Shipped via `docker save | ssh ubuntu@44.246.33.34 'docker load'`.
3. Graceful swap pattern (avoids Erlang node-name collision on host
   networking):
   ```bash
   docker rm -f ztlp-gateway-old  # clear any prior
   docker rename ztlp-gateway ztlp-gateway-old
   docker stop ztlp-gateway-old   # release node name
   docker run -d --name ztlp-gateway --restart unless-stopped --network host \
     -e ZTLP_GATEWAY_PORT=23097 \
     -e ZTLP_NS_SERVER=172.26.13.85:23096 \
     -e ZTLP_RELAY_SERVER=172.26.5.220:23095 \
     -e "ZTLP_GATEWAY_BACKENDS=default:127.0.0.1:8080,http:127.0.0.1:8180,vault:127.0.0.1:8080" \
     -e ZTLP_GATEWAY_SERVICE_NAMES=default,http,vault \
     -e "ZTLP_GATEWAY_POLICIES=*:default,*:http,*:vault" \
     -e ZTLP_GATEWAY_METRICS_ENABLED=true -e ZTLP_GATEWAY_METRICS_PORT=9102 \
     -e ZTLP_METRICS_PORT=9102 \
     -e ZTLP_LOG_LEVEL=debug -e ZTLP_LOG_FORMAT=json \
     -e ZTLP_GATEWAY_LOG_FORMAT=json \
     -e ZTLP_GATEWAY_TLS_AUTO=false \
     -e RELEASE_COOKIE=ztlp_gateway_docker \
     ztlp-gateway:ack-v2 start
   ```
4. Verification on the running node:
   - `ns_cfg` RPC → `{{172, 26, 13, 85}, 23096}` (not 127.0.0.1 —
     correctness of `runtime.exs` NS parsing preserved).
   - `md5sum Elixir.ZtlpGateway.Session.beam` → matches locally-built
     image, proves the V2 handler is loaded.
5. Preflight script → **PRECHECK GREEN** (warnings=2 failures=0). The
   "no recent handshake activity" WARN is because the gateway restarted
   and no client is connected yet — expected.

### Mac-side iOS build
- `libztlp_proto_ne.a` + `libztlp_proto.a` rebuilt on Steve's Mac via
  the standard recipe. Sizes 27MB / 56MB.
- Unsigned xcodebuild → **CLEAN SUCCEEDED + BUILD SUCCEEDED**.

### Rollback
Both sides can rollback independently or together:

Gateway only:
```bash
ssh ubuntu@44.246.33.34 '
  docker rm -f ztlp-gateway &&
  docker rename ztlp-gateway-old ztlp-gateway &&
  docker start ztlp-gateway
'
```

Full stack (Rust + iOS + gateway source):
```bash
cd /home/trs/ztlp
git reset --hard v-before-byte-rwnd
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push --force origin main
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git fetch && git reset --hard origin/main'
# then the gateway rollback above
```

## Expected log signature

On the phone, the `[rtt-bdp]` line should now show `v2=yes adv_kb=N` as
soon as the first V2 ACK lands. The V2 flag is sticky — once true it
stays true for the session. `adv_kb` comes from
`ztlp_mux_advertised_window_kb(mux)`; expect:
- `adv_kb=16` initially (V2 default; actually 18 KB since the V1
  ladder's 16 × 1140 = 18240 bytes > 16 KB default — so the engine
  keeps the higher value)
- Rises as the V1 ladder climbs through 4/12/16 (byte-hint = rwnd × 1140)
- Once Phase D lands, autotune drives this directly.

On the gateway, `grep CLIENT_ACK_V2 gateway logs` should show all
client ACKs carrying window_kb values. `peer_uses_v2=true` in any
session debugging traces confirms the sticky flag landed.

## Device gate

1. ~~Server preflight GREEN~~ (done).
2. ~~Gateway deployed with V2 decoder~~ (done).
3. ~~Mac rebuild + Xcode build SUCCEEDED~~ (done).
4. **Pending Steve**:
   - Xcode → Clean Build Folder (⌘⇧K)
   - Deploy to phone
   - Benchmark + Vaultwarden ×3
   - Pull log
   - Pipe log to Linux; we look for `CLIENT_ACK_V2` in gateway logs,
     `[rtt-bdp] ... v2=yes adv_kb=N` in phone logs

## Gotchas discovered / reconfirmed this phase

- Gateway Dockerfile uses **repo-root** COPY paths, so `docker build`
  context must be the repo root: `docker build -f gateway/Dockerfile`.
- Erlang host-networking node-name conflict: always stop the old
  container *before* starting the new one. `docker rm -f ztlp-gateway-old`
  is critical to clean any prior failed rollback.
- `@max_payload_bytes = 1140` in gateway must stay locked-step with
  `RWND_V1_FRAME_SIZE_HINT = 1140` in Rust — the byte→packet math on
  the gateway assumes this. A future change to one must change both.
- Gateway→client ACKs still use 0x01/SACK. If later phases want
  **symmetric V2** (gateway advertising a byte window back to the
  client), the `send_ack` function at session.ex:2195 needs a new
  V2-format encoder. Today the Swift recv path decodes 0x10
  defensively so that upgrade won't need a coordinated client change.
- Gateway's `@default_peer_rwnd = 512` (packets) was always far larger
  than the iOS-side rwnd=16 cap. Phase B doesn't change that — the
  Rust engine's advertised byte-window (via `advertised_window_bytes`)
  drives what we send; the gateway converts back to packets for its
  existing cwnd math. No gateway CC behaviour change in Phase B.

## Phase C+ forward-looking

- Phase C (per-stream windows): `FRAME_MAX_STREAM_DATA = 0x11`,
  `FRAME_MAX_DATA = 0x12`. Requires per-stream ledger in both
  Rust MuxEngine and gateway `session.ex`. WKWebView parallel-stream
  starvation fix.
- Phase D (autotune): replace the V1 `RWND_FLOOR=4 / RWND_ADAPTIVE_MAX=16`
  ladder with `target_bytes = clamp(min, max, srtt * peak_goodput * safety_factor)`.
  Now that we have RTT + goodput samples from Phase A and a byte-unit
  window to drive from Phase B, this is the first phase that can
  actually widen the effective inflight without changing wire format.
- Phase E (V1 retire): only after enough fleet is on V2. Not urgent.
