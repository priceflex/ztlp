# iOS + Gateway Performance Handoff — 2026-05-01

## Purpose

Morning pickup note for the current iOS Rust-fd / gateway performance review.

This captures where we left off after reviewing:

- `docs/GATEWAY-REVIEW-POST-RUST-FD-AUDIT-2026-05-01.md`
- current iOS `PacketTunnelProvider.swift`
- current Rust `proto/src/ios_tunnel_engine.rs`
- current gateway `gateway/lib/ztlp_gateway/session.ex`

## Bottom Line

The gateway review doc is directionally accurate, but it should **not** be treated as permission to loosen gateway limits immediately.

The correct morning starting point is:

1. Keep gateway correctness/safety fixes.
2. Validate the Rust-fd iOS data plane under real browser/WKWebView load.
3. Tune client advertised receive window (`rwnd`) before raising gateway queue/mux limits.
4. Only loosen gateway queue/mux caps after logs prove those caps are the actual bottleneck.

## Current Big-Picture Read

The repo supports the idea that some gateway conservatism was added while protecting the older fragile Swift `packetFlow` path.

However, the Rust-fd path is still a migration-stage hybrid, not yet a proven high-throughput production data plane:

- Swift `packetFlow.readPackets` is disabled when `useRustFdDataPlane = true`.
- Rust now owns utun ingress and feeds the packet router.
- Rust dispatches router actions back through a Swift callback.
- Swift still owns transport send through `ZTLPTunnelConnection` / `NWConnection`.
- Rust fd code still contains scaffold/phase language and heavy diagnostics.

So the performance problem should be viewed as a full client/gateway control-loop issue, not just “old Swift packetFlow was weak, remove gateway limits.”

## Verified Current iOS State

File:

- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`

Important current facts:

- `useRustFdDataPlane = true`
- When true, Swift logs:
  - `Rust fd data plane requested; Swift packet I/O loop disabled`
- Swift does **not** call `startPacketLoop()` / `packetFlow.readPackets` in that mode.
- Rust engine is started with router ingress:
  - `ztlp_ios_tunnel_engine_start_router_ingress_loop(engine, router)`
- Swift registers a router action callback:
  - `ztlp_ios_tunnel_engine_set_router_action_callback(...)`

Current iOS receive-window state:

- `rwndFloor = 4`
- `rwndAdaptiveMax = 5`
- browser burst gating keeps multi-flow/WKWebView pressure at the floor.
- `ZTLPTunnelConnection.setAdvertisedReceiveWindow(_:)` clamps to `4...5`.
- ACK rwnd calculation also caps send window to `5`.

Interpretation:

The gateway usually cannot have more than 4–5 packets in flight to iOS when peer rwnd is honored. Because of that, raising gateway queue caps alone is unlikely to produce best throughput and may mostly increase latency/buffering.

## Verified Current Rust fd State

File:

- `proto/src/ios_tunnel_engine.rs`

Important current facts:

- `IosUtun` reads/writes raw utun fd with Darwin 4-byte address-family header handling.
- `start_router_ingress_loop(...)` is implemented.
- Rust read loop:
  - reads utun packets
  - parses packet metadata
  - calls `ztlp_router_write_packet_sync(...)`
  - dispatches router actions through callback
  - drains router outbound packets back to utun
- Current diagnostic markers include:
  - `close_suppression_enabled=1`
  - `marker=close_suppression_v3`
  - `Rust fd dispatch pre/post ...`
  - `Rust fd router ...`

Interpretation:

The Rust fd path is beyond pure lifecycle smoke test, but still needs live-device validation before assuming it can tolerate higher gateway fanout/queue pressure.

## Verified Current Gateway State

File:

- `gateway/lib/ztlp_gateway/session.ex`

Current queue/fanout settings:

- `@queue_high 512`
- `@queue_low 128`
- `@max_mux_streams 32`
- `@max_connecting_buffer_bytes 65_536`

Current egress gate:

```elixir
effective_window = min(min(trunc(state.cwnd), cc_max_cwnd(state)), Map.get(state, :peer_rwnd, @default_peer_rwnd))
```

Current peer rwnd support:

- default legacy rwnd: `@default_peer_rwnd 512`
- 11-byte ACK format updates `state.peer_rwnd`
- gateway logs:
  - `CLIENT_ACK data_seq=... rwnd=...`

Current enqueue behavior:

- `enqueue_stream_chunks/3` halts when `:queue.len(q) >= @queue_high`.
- This prevents backend responses from ballooning into huge gateway queues.

Current stream/fanout behavior:

- `@max_mux_streams 32` rejects new streams beyond the cap.
- connecting streams are capped at 64KB buffered early data.
- connect buffer overflow closes that stream.

Current mobile/unknown profile:

- `client_class: :mobile, interface_type: :unknown` uses conservative mobile profile:
  - initial cwnd 5
  - max cwnd 16
  - ssthresh 32
  - pacing 6ms
  - burst 2
  - initial RTO 1500ms
  - min RTO 500ms

## What To Keep

Do not remove or weaken these unless new evidence proves they are broken:

- session replacement cleanup hardening
- recovery exit when ACK reaches last sent packet
- recv-window gap recovery
- ACK fast-path / ACK handling
- peer_rwnd support
- mobile unknown RTO handling
- session health ping/pong support
- stall diagnostics / stream dump logging
- close reason logging

These are correctness or observability, not old Swift-path baggage.

## What To Re-Evaluate Later

These are plausible old-path/client-protection guardrails, but they should be tested in order, not removed blindly:

1. `@queue_high` / `@queue_low`
2. `@max_mux_streams`
3. `@max_connecting_buffer_bytes`
4. `enqueue_stream_chunks/3` halting at queue high

Important: do this only after validating Rust fd stability and client rwnd behavior.

## Likely Best Performance Path

### Step 1 — Validate Rust fd path first

Before changing gateway limits, run live iOS browser/WKWebView traffic and verify logs show:

Phone/app log expected markers:

- `Rust fd data plane requested; Swift packet I/O loop disabled`
- `Rust iOS tunnel engine scaffold started ... mode=router_ingress ...`
- `Rust router action callback registered`
- `Rust fd dispatch post actions=... open=... send=... close=... suppressed_close=...`
- `Rust fd router ... utun_write_packets=...`
- no long app-log silence during browser burst
- no repeated pathological duplicate CloseStream storm
- no hidden router outbound backlog

Gateway expected markers:

- `CLIENT_ACK ... rwnd=4|5`
- no `STALL: no ACK advance...` during browser load
- no unbounded `send_queue` growth
- no stream rejection unless actual >32 fanout occurs

### Step 2 — Tune iOS rwnd before gateway queues

The most likely immediate throughput limiter is rwnd 4–5.

Do not raise it globally.

Safer experiment sequence:

1. Keep browser burst / multi-flow at rwnd=4.
2. Allow single-flow stable download to ramp above 5 in small controlled steps.
3. Drop immediately back to floor on:
   - multiple active flows / stream maps
   - replay spike
   - router outbound backlog
   - send buffer pressure
   - old buffered flow age
   - session-health suspect/probe state
4. Test one variable at a time:
   - rwnd 6 single-flow only
   - then rwnd 8 single-flow only
   - only if stable, consider higher.

Success criteria:

- better fresh single-stream throughput
- no Vaultwarden/OpenVault regression
- browser burst still survives
- no manual VPN toggle needed after browser traffic

### Step 3 — Only then test gateway queue caps

If rwnd is still 4–5, raising `@queue_high` probably just adds buffering.

Test queue caps only if logs prove:

- client is ACKing cleanly
- rwnd has safely ramped
- send queue hits 512 while client is otherwise healthy
- backpressure is unnecessarily starving backend reads

Suggested staged test if needed:

- 512/128 baseline
- 768/192
- 1024/256

Avoid jumping back to thousands-deep queues until browser recovery is proven.

### Step 4 — Test mux stream cap only if logs show it is hit

Current cap is 32.

Do not raise unless gateway logs show:

- `max mux streams reached (32/32)`

If it is hit during valid browser workload, test small increments:

- 32 baseline
- 48
- 64

Watch memory, queue depth, and client recovery.

### Step 5 — Test connecting buffer cap last

Current cap is 64KB per connecting stream.

Only revisit if logs show:

- `exceeded connecting buffer cap`

Otherwise leave it alone.

## Recommended Morning Workflow

1. Pull latest repo state and check status.

```bash
cd /home/trs/ztlp
git status --short
git log --oneline -10 -- ios/ZTLP/ZTLPTunnel proto/src gateway/lib/ztlp_gateway/session.ex docs
```

2. Confirm Mac/Xcode source has the same Rust fd markers before asking for phone test.

```bash
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git log --oneline -5 && grep -n "useRustFdDataPlane\|close_suppression_v3\|Rust fd data plane requested" ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift proto/src/ios_tunnel_engine.rs 2>/dev/null || true'
```

3. Run server preflight before Steve tests on iPhone.

```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Must end with:

```text
PRECHECK GREEN
```

4. Capture/pull phone app-group log after test.

```bash
ssh stevenprice@10.78.72.234 'xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone.log && tail -n 300 /tmp/ztlp-phone.log'
```

5. Check gateway logs for same window.

Do not redeploy/restart gateway while Steve is testing.

Use docker logs with a since/ until window after test rather than a fragile background `docker logs -f` capture.

Useful patterns:

```bash
docker logs --since 10m ztlp-gateway 2>&1 | grep -E 'CLIENT_ACK|rwnd=|pacing_tick|Backpressure|STALL|max mux|connecting buffer|SESSION_PING|SESSION_PONG|Stream .*connected|Rust|FRAME_OPEN'
```

6. Decide next change based on evidence:

- If Rust fd markers are absent: fix build/deploy sync first.
- If Rust fd is active but app log goes silent: debug iOS fd/queue/threading before gateway tuning.
- If gateway queue grows but rwnd remains 4: tune rwnd/client pressure logic first.
- If gateway rejects streams at 32: consider staged mux cap test.
- If connecting buffer cap fires: consider staged buffer cap test.
- If none of those fire, do not change gateway caps yet.

## Open Questions

- Is the latest Mac `~/ztlp` checkout clean and synced with Linux `/home/trs/ztlp`?
- Did the last iPhone build actually include commits through the Rust fd close suppression markers?
- Under live Vaultwarden/OpenVault traffic, do we see `utun_write_packets` continue increasing from Rust fd?
- Are post-browser benchmark failures still session-health/close cleanup issues, or pure throughput limits?
- Does rwnd=5 cause pressure during browser fanout even with the newer Rust fd path?
- Is there any real evidence yet that `@queue_high 512` or `@max_mux_streams 32` is the active bottleneck?

## Suggested Update To Prior Review Doc

Add a fourth category to `docs/GATEWAY-REVIEW-POST-RUST-FD-AUDIT-2026-05-01.md`:

```text
Category 4 — Do Not Loosen Until Rust fd Is Validated

Although Swift packetFlow hot-path reads are disabled when useRustFdDataPlane=true, the current Rust fd path is still a migration-stage hybrid: Rust owns utun ingress and router interaction, but transport send crosses back through Swift callbacks, and the code still contains fd diagnostics and close-suppression markers. Gateway limits should not be relaxed solely because Rust fd is enabled. Relax them only after live device tests show stable browser-fanout behavior without hidden router backlog, CloseStream storms, gateway queue growth, or session-health recovery.
```

## Final Morning Starting Point

Start with validation, not tuning.

The next best move is to prove the current Rust fd iOS path survives real browser/WKWebView fanout while keeping gateway limits unchanged.

If stable, tune rwnd next.

Only after rwnd/client pressure is proven healthy should gateway queue/mux caps be loosened.
