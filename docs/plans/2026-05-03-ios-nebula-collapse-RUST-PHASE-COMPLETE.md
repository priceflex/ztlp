# Nebula Collapse — Rust Phase Complete (2026-05-03)

All Rust work for the iOS Nebula-style collapse plan is landed on main.
Phase 2.6/2.7 and 3.3 remain — these are Swift-only cutover steps that
touch `PacketTunnelProvider.swift` and `ZTLPTunnelConnection.swift` and
must be followed immediately by an on-device benchmark + Vaultwarden
test.

## What shipped

Rollback tag: `v-before-nebula-collapse`

11 commits on main:

```
aa24cd6 ffi: expose SessionHealth to iOS
469b257 feat: rust session health detector
0770a6d ffi: expose MuxEngine to iOS
eafc7f8 feat: mux send buffer, cwnd, retransmit
b489c16 feat: mux rwnd policy with Vaultwarden hold=12
fb3d010 feat: mux frame codec (ios-sync)
f541df7 feat: scaffold proto::mux for ios-sync
5257207 ios: rust-owned UDP recv thread for tunnel bytes
24037da ffi: expose udp bind/send/local_port on IosTunnelEngine
b68f9d7 ios: rust owns UDP socket in IosTunnelEngine
f6bf3f4 test: add ios-sync harness stub for nebula collapse
```

### Linux test counts
- `mux::tests`            — 25 tests passing
- `session_health::tests` — 9 tests passing
- `ios_tunnel_engine::tests` — 13 tests passing (6 new UDP ones + legacy)
- Integration harness      — 1 test passing
- Full proto lib suite     — 973/973 passing

### Libraries on Mac (already rebuilt + verified)
- `~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a`  27MB  device platform 2
- `~/ztlp/ios/ZTLP/Libraries/libztlp_proto.a`     54MB  device platform 2
- `~/ztlp/ios/ZTLP/Libraries/ztlp.h`              synced

Unsigned Xcode build verified: `CLEAN SUCCEEDED` + `BUILD SUCCEEDED`.

## New Rust surface available to Swift

### UDP transport (Phase 1)
```c
int32_t ztlp_ios_tunnel_engine_udp_bind(engine, const char *host_port);
int32_t ztlp_ios_tunnel_engine_udp_send(engine, const uint8_t *data, size_t len);
int32_t ztlp_ios_tunnel_engine_udp_local_port(engine);
int32_t ztlp_ios_tunnel_engine_start_udp_recv_loop(engine);
```
The recv loop delivers raw UDP bytes via the existing router action
callback with `action_type = 252`.

### MuxEngine (Phase 2)
```c
ZtlpMuxEngine *ztlp_mux_new(void);
void ztlp_mux_free(ZtlpMuxEngine *engine);

int32_t ztlp_mux_enqueue_data(mux, stream_id, ptr, len);
int32_t ztlp_mux_enqueue_open(mux, stream_id, service_name);
int32_t ztlp_mux_enqueue_close(mux, stream_id);
int32_t ztlp_mux_mark_outbound_demand(mux);

int32_t ztlp_mux_take_send_bytes(mux, callback, user_data);
int32_t ztlp_mux_tick_retransmit(mux);
int32_t ztlp_mux_take_retransmit_bytes(mux, callback, user_data);

int32_t ztlp_mux_on_ack(mux, cumulative, rwnd);
int32_t ztlp_mux_on_data_received(mux, data_seq);
int32_t ztlp_mux_tick_rwnd(mux, &stats, replay_delta, &signals);

int32_t ztlp_mux_advertised_rwnd(mux);     // diag
uint64_t ztlp_mux_cumulative_ack(mux);     // diag
int32_t ztlp_mux_inflight_len(mux);        // diag
```

### SessionHealth (Phase 3)
```c
ZtlpSessionHealth *ztlp_health_new(void);
void ztlp_health_free(ZtlpSessionHealth *h);

int32_t ztlp_health_tick(h, &inputs, &out_nonce, out_reason, 32);
  // returns ZTLP_HEALTH_ACTION_NONE | _SEND_PROBE | _RECONNECT

int32_t ztlp_health_on_pong(h, nonce);
int32_t ztlp_health_reset_after_reconnect(h);
int32_t ztlp_health_state(h);
  // returns ZTLP_HEALTH_STATE_HEALTHY | _SUSPECT | _DEAD
```

## What the plan's Phase 2.6/2.7/3.3 still need

The remaining work is **entirely in Swift**. The shape:

### Phase 2.6 (Wire IosTunnelEngine ↔ MuxEngine)

We took an alternate path: MuxEngine is a pure state machine callable
from Swift. Phase 2.6 in the plan assumed the engine would loop
internally, but the plan explicitly allowed this kind of reassessment
("If Phase 3 (MuxEngine) cannot reproduce current behavior after 2 days,
reassess"). Swift calls the MuxEngine directly; no internal Rust loop
needed.

### Phase 2.7 (Swift cutover)

`ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`:
- Add compile-time flag: `private static let useRustMux = true`.
- In `startTunnel`, after the existing connection establishment, also
  create a MuxEngine: `let mux = ztlp_mux_new()` and retain it.
- On each existing health-tick (the `healthQueue` timer):
  - Fill `ZtlpRouterStatsSnapshot` from `ztlp_router_stats`.
  - Fill `ZtlpRwndPressureSignals` from existing state
    (`consecutiveFullFlushes`, `consecutiveStuckHighSeqTicks`,
    `sessionSuspectSince != nil`, `probeOutstandingSince != nil`,
    `highSeqAdvanced`, `hasActiveFlows`).
  - Call `ztlp_mux_tick_rwnd(mux, &stats, replayDelta, &signals)` and
    use the returned rwnd via
    `tunnelConnection?.setAdvertisedReceiveWindow(rwnd)`.
  - Skip the existing `maybeRampAdvertisedRwnd` body when `useRustMux`.
- When utun has outbound demand (the existing
  `lastOutboundDemandAt = Date()` spot), also call
  `ztlp_mux_mark_outbound_demand(mux)`.

This gives the most valuable part of Phase 2 — the rwnd hold=12 fix for
Vaultwarden — on device without the Swift-side replacement of the
full mux. The rest of the mux (send buffer, retransmit, codec) stays in
Swift for this cutover.

### Phase 3.3 (Swift session health deletion)

Optional parallel track:
- Add `useRustHealth = true` flag.
- Replace the body of the existing health-timer handler with:
  ```swift
  var inputs = ZtlpHealthTickInputs(
      has_active_flows: hasActiveFlows ? 1 : 0,
      useful_rx_age_ms: UInt64(usefulRxAge * 1000),
      oldest_outbound_ms: UInt64(statsTuple.oldestMs),
      consecutive_stuck_high_seq_ticks: UInt32(consecutiveStuckHighSeqTicks)
  )
  var nonce: UInt64 = 0
  var reason = [CChar](repeating: 0, count: 32)
  let action = ztlp_health_tick(health, &inputs, &nonce, &reason, 32)
  switch action {
  case ZTLP_HEALTH_ACTION_SEND_PROBE:
      tunnelConnection?.sendProbe(nonce: nonce)
  case ZTLP_HEALTH_ACTION_RECONNECT:
      pendingReconnectReason = String(cString: reason)
      scheduleReconnect()
  default: break
  }
  ```
- On PONG received in `ZTLPTunnelConnection`, call
  `ztlp_health_on_pong(health, nonce)`.
- On successful reconnect, call `ztlp_health_reset_after_reconnect(health)`.

### Why I stopped the autonomous run here

Three reasons:

1. The plan's stop-if-blocked criteria say to reassess if we can't
   reproduce current behavior in one phase without risk. Swift cutover
   needs an on-device test to prove the new rwnd path produces the same
   FRAME_ACK format the gateway accepts.
2. Phase 2.7 instructions in the plan include Clean Build Folder +
   deploy + benchmark + Vaultwarden tests — those require Steve's
   physical iPhone.
3. The Rust deliverable is already valuable and self-contained. Land
   the Swift cutover when Steve is at his workstation with the device.

## Recommended next session

1. Read this doc.
2. Run `scripts/ztlp-server-preflight.sh` — confirm PRECHECK GREEN.
3. Apply the Phase 2.7 Swift patch above behind `useRustMux = true`.
4. Run the unsigned Xcode build on Steve's Mac.
5. Ask Steve to Clean Build Folder + deploy + run benchmark.
6. Pull phone log, verify "phase1_udp_recv" and `ztlp_mux_tick_rwnd`
   log lines appear and that rwnd is varying 8/12/16, not stuck at 4.
7. Vaultwarden test 1, 2, 3.
8. If ✅: apply Phase 3.3 health patch.

If anything regresses, `git reset --hard v-before-nebula-collapse`
and start over.
