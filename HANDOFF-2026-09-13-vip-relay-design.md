# HANDOFF — Coverage pass + iOS VIP relay-termination design question

Written 2026-09-13 at the end of the coverage session. Read this first in the
next session. Everything below is from real runs; nothing inferred.

## Where we left off (one paragraph)

Two coverage passes are committed on top of `8e94d04` (not pushed):
`5969499` tests pass 1, `5f37c06` five lib bug fixes, `c3a2c85` tests pass 2.
All four suites are green. While writing tests, two more real bugs surfaced
in the **iOS VIP proxy path** (bugs 6 and 7 below). Steven confirmed the
intent: the iPhone registers loopback VIPs on-device, sends every TCP
connection over ONE ZTLP session to a relay, and the relay does the TCP
fan-out / heavy network work on the phone's behalf. The relay half of that
design is half-built and the Rust half has a reconnect bug. Steven's last
words: "maybe there is a better way of doing this" — so the next session
starts with a DESIGN conversation, not a bug fix.

## Reference files (read in this order)

1. `COVERAGE-PLAN.md` — numbers, per-file gaps, all 7 bugs, next targets.
2. `docs/plans/2026-05-03-nebula-pivot-STATUS-AND-NEXT.md` — why
   congestion/pacing/send_controller are stubs; vip.rs still depends on the
   SendController stub (line ~179).
3. `docs/plans/2026-05-03-ios-nebula-collapse.md` and
   `...-RUST-PHASE-COMPLETE.md` — the iOS pivot the VIP path lives inside.
4. `docs/plans/nebula-pivot-audit/01-rust-proto.md` — "DELETE-ENTIRELY" list.
5. `docs/plans/2026-06-04-auto-reconnect-dynamic-scenarios.md` — reconnect
   behaviour; bug 7 is a reconnect bug.
6. `docs/plans/2026-05-17-GATEWAY-STALL-HANDOFF.md` and
   `2026-05-24-zone-keyed-gateway-register*.md` — gateway already has
   StreamProxy / Backend / TlsTerminator; relevant to "did the gateway take
   over the relay-termination role?"
7. `docs/ARCHITECTURE.md`, `docs/AGENT-DESIGN.md` — general.
8. Code that IS the feature:
   - `proto/src/vip.rs` (VipProxy, StreamDispatcher, mux frames
     FRAME_OPEN/DATA/CLOSE 0x06/0x00/0x05 + stream_id)
   - `proto/src/ffi.rs` ~2490-2700 (`ztlp_vip_add_service`, `ztlp_vip_start`,
     `ztlp_vip_stop`) — what the iOS app actually calls
   - `relay/lib/ztlp_relay/vip_tcp_terminator.ex`, `vip_connection.ex`,
     `vip_frame.ex`, `vip_service_table.ex` — relay half (format:
     `[conn_id:16][flags:8][payload]`, SYN/DATA/FIN/RST)
   - `relay/lib/ztlp_relay/udp_listener.ex` ~1487 (VIP intercept call site)
     and ~1657 (dst_svc_id is now a 16-byte SHA-256 hash, "Option C")
9. Tests that PIN the current (broken) behaviour, all `@tag :skip` /
   `#[ignore]` for the intended behaviour + a second test asserting the
   present failure:
   - `relay/test/ztlp_relay/vip_tcp_terminator_e2e_test.exs` (bug 6)
   - `proto/tests/vip_proxy_lifecycle_test.rs` (bug 7)
   - `relay/test/ztlp_relay/vip_connection_test.exs` (relay half, works
     when driven directly — 26 tests green)

## The two open bugs, precisely

### Bug 7 — Rust `VipProxy::start()` hot-swap split-brain (iOS reconnect) — FIXED
`proto/src/vip.rs` ~625. On a second `start()` (tunnel reconnect: cell↔wifi,
backgrounding) `self.dispatcher` is replaced with a fresh
`StreamDispatcher`, but the already-running `vip_listener_task`s captured
an `Arc` of the OLD one at spawn. New Safari connections register in the
old dispatcher; the FFI recv_loop routes tunnel data via
`proxy.dispatcher()` = the new, permanently empty one. Every
post-reconnect connection is a download black hole. `next_stream_id` is
also reset to 1, so the first new connection re-registers stream 1 in the
old dispatcher and hijacks whichever pre-swap connection held it. Proven
with a probe: `d1=1 d2=0` after swap.
Fix is mechanical: share via `Arc<RwLock<Arc<StreamDispatcher>>>` (listener
reads it per accept) or clear-in-place instead of replace; don't reset
`next_stream_id`. ~30 min TDD; the `#[ignore]`d test flips green.

### Bug 6 — relay `VipTcpTerminator` dispatch is dead code
`relay/lib/ztlp_relay/vip_tcp_terminator.ex`. Three independent facts:
1. `extract_service_name/1` reads `parsed.dst_svc_id`. Only HANDSHAKE
   packets carry it; `UdpListener` only calls `handle_vip_packet` for
   `:data_compact` packets. Service name is therefore always `""` →
   `:not_vip_service` → classic relay. Nothing is ever VIP-handled.
2. Even with a name, `dst_svc_id` is now a 16-byte SHA-256 of the service
   name (Option C, see udp_listener.ex ~1657), and the terminator decodes it
   as NUL-terminated ASCII. Can never match a registered service.
3. `route_connection/6` calls `SessionSupervisor.start_session/1`, which
   starts a `ZtlpRelay.Session` (relay peer_a/peer_b session, needs
   `:peer_a` → KeyError → `:vip_error`), NOT a `VipConnection`.
   `VipConnection.start_link/1` is referenced nowhere in `lib/`.
4. Wire-format mismatch: Rust `vip.rs` emits gateway mux frames
   (`[type:8][stream_id:32][payload]`), the relay expects
   `VipFrame` (`[conn_id:16][flags:8][payload]`). Two formats for the same
   idea. The SAST comment in `get_session_key/1` already says: "no iOS-side
   or Rust-side producer for this wire format was found in the codebase."
Conclusion: the relay-side VIP terminator was never wired end-to-end. It is
a half-built feature, not a regression.

## The design question to settle FIRST (Steven: "maybe there is a better way")

### Steven's reasoning (2026-09-13, verbatim intent)
The iPhone doesn't have the horsepower to hold many connections in memory,
so a relay should make all the connections and route results back. BUT the
relay would then hold session keys and see plaintext, so relay security
becomes the problem. He is considering **one private relay per identity**
("maybe everyone gets a private relay for themselves"). Undecided. Decision
taken for now: **park the relay-side VIP code (step 2 below), do not
delete it**, come back when the security model is chosen.

### Status after step 2 (done, committed)
- `VipTcpTerminator.handle_vip_packet/4` now really returns
  `:not_vip_service` when `ZTLP_RELAY_VIP_ENABLED` is off (the old guard was
  an `if` without `else` and never returned — disabled relays still
  decrypted/dispatched). Two tests pin it.
- `UdpListener` only calls the terminator when `Config.vip_enabled?()`, so
  the packet hot path never touches VIP code by default.
- The four VIP modules carry a PARKED banner in their moduledoc.
- Nothing deleted. Turning `ZTLP_RELAY_VIP_ENABLED=true` back on restores
  the previous (half-wired, bug-6) behaviour.

Goal (Steven's words, restated): iPhone connects to a relay; the relay
routes all connections and does all the heavy network work so the phone
only holds one UDP flow.

Options on the table, pick one before touching bug 6:

A. **Finish relay-side termination as designed.** Carry service identity in
   the VipFrame (or map session→service at HELLO), reconcile the wire format
   with `vip.rs` (one mux format, not two), make `route_connection` spawn
   `VipConnection`, wire the real Noise session key into
   `get_session_key/1` instead of the HKDF-of-PSK stopgap. Biggest work,
   keeps the relay as the TCP terminator.
B. **Let the gateway do it.** Gateway already has `Quic.StreamProxy`,
   `Backend`, `BackendPool`, `TlsTerminator`, `ServiceRouter` and speaks the
   same mux frames `vip.rs` already emits (FRAME_OPEN/DATA/CLOSE). Relay
   stays a blind SessionID forwarder (its documented job); phone → relay →
   gateway → backend. Then delete `VipTcpTerminator`/`VipConnection`/
   `VipFrame`/`VipServiceTable` from the relay (~1,200 LOC + the 4 test
   files written this session) and the `vip_*` env vars. Check whether the
   "relay does the heavy work" requirement is actually satisfied by the
   gateway sitting next to the relay.
C. **Something else entirely** (e.g. NE packet-tunnel provider on iOS with
   Nebula-style flat routing, no per-connection TCP termination anywhere).
   Steven hinted at this; explore before committing to A or B.

Questions to ask Steven at the start of the session:
- Where does the backend TCP connection physically originate today for an
  iPhone user — relay box, gateway box, or nowhere yet?
- Is the gateway deployed next to every relay the phone can pick?
- Does "heavy network work" mean TCP termination + TLS, or also DNS / HTTP
  header injection (gateway has `HttpHeaderInjector`)?
- Is Option C (hashed dst_svc_id) final? It decides how the relay/gateway
  learns which service a session is for.

## Coverage state (for whoever continues that thread)

| Component | Now | Tests | Notes |
|---|---|---|---|
| proto (lib, bins excluded) | 74.6% | 1,846 pass, 1 known-flaky | `cargo llvm-cov --no-fail-fast --ignore-filename-regex 'src/bin/'`; flaky = `quic_churn_stress_test::concurrent_reconnect_churn_is_reliable`, clear `~/.ztlp/quic_pins/*.pin` |
| ns | 69.4% | 991/991 (seeds 777, 424242) | run with `ZTLP_NS_STORAGE_MODE` UNSET |
| relay | 62.2% | 773, 1 skipped (bug 6) | |
| gateway | 64.1% | 1,092/1,092 | Docker only: `scripts/gateway-cover-docker.sh` (~8 min); exit 3 = 90% threshold, not failure; `git checkout gateway/test/fixtures/quic_handshake_vector.json` after |

Remaining big gaps: `ffi.rs` 44%, `tunnel.rs` 43.8% (both multi-day),
gateway `TlsTerminator` 0% / `Listener` 14.6% / `Backend` 36%, relay
`StatsReporter` 29% / `MeshManager` 37%, ns `Cluster` 42% / `Server` 58%.

## Fixed this session (already committed, for context)
1. relay SignalHandler: SIGUSR1 halted the node (OTP default handler).
   Now a gen_event handler forwards sigusr1/2. Verified with real `kill -USR1`.
2. relay VipConnection: FIN/RST crashed on nil session_key.
3. relay VipConnection: `:ssl.connect` raise on backend-close mid-handshake.
4. relay VipServiceTable.count/0 returned `:undefined`.
5. proto updater `extract_asset_url` skipped the first release asset.
Plus two test-only isolation fixes in ns (`yaml_config_component_auth_test`
app-env leak; `cert_issuer_test` on_exit not restarting the app) that were
the whole "75 failures" story.

## Not done / not pushed
- Nothing pushed to origin. `git log 8e94d04..HEAD` = 3 commits.
- Bug 7: FIXED (commit after 64927f7). VipProxy keeps one StreamDispatcher for its lifetime, clears it in place on hot-swap, never resets next_stream_id. 22/22 lifecycle tests, proto 1,852/1,852.
- Bug 6: PARKED behind ZTLP_RELAY_VIP_ENABLED (default off); blocked on the security design decision above.
- Clippy: 38 pre-existing `-D warnings` errors in proto lib, none in files
  touched; not addressed.
