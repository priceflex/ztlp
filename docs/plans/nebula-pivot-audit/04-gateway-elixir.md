# Nebula Pivot Audit — Section 4: Gateway (Elixir)

Branch: nebula-style-pivot. Read-only audit, written 2026-05-03 post-R4.

Goal: remove the reliability layer (data_seq / ACK / NACK / SACK / RTO / cwnd /
BBR / send_buffer / recv_window reordering / rekey / pacing / stall detector)
from the Elixir gateway so it mirrors the now-dumb-pipe iOS NE. Keep Noise XX
handshake, AEAD data plane, anti-replay (if cheap), mux stream framing
(OPEN/CLOSE/DATA and maybe PING/PONG), backend connect/read-write loop, NS
client, policy engine, TLS terminator path.

**Why this has to happen, not just "cleanup":** With the client's reliability
layer gone (R1-R4), every unacked data_seq on the gateway fires RTO and the
gateway retransmits. The client now has no ACK back-channel, so the gateway
retransmits the same data_seq forever. The client's anti-replay bitmap
correctly rejects every retransmit as `replay=N`. Result observed in the
2026-05-03 23:34 phone log:

```
23:34:53  packets=10 payload=7163B replay=1     ← one real page
23:34:54  packets=0  payload=0B   replay=20     ← RTO storm begins
23:34:55+ packets=0  payload=0B   replay=10/s   ← pathological, forever
```

Then eventually cwnd collapses on the gateway, fresh data stops flowing,
WKWebView times out. The gateway reliability layer is not harmlessly wasting
bytes — it is **actively preventing new data from moving** once any packet
is perceived lost. R5 is the functional-correctness fix, not cleanup.

---

## Rough LOC-to-remove estimate

Gateway total: 16,576 LOC across lib/. R5 target deletion: ~**6,500-8,000 LOC**
(±20%). Spread across two delete-entirely files (~1,600 LOC), the reliability
half of `session.ex` (~1,800 of 3,150 LOC), ~4 deletable sub-modules inside
`session.ex` (~600 LOC), ~1,200 LOC of reliability tests, and small
knock-on deletions in `listener.ex`, `packet.ex`, `pipeline.ex`.

`handshake.ex`, `crypto.ex`, `backend.ex`, `backend_pool.ex`, `ns_client.ex`,
`service_router.ex`, `policy_engine.ex`, `identity.ex`, `session_registry.ex`,
`listener.ex`, the TLS stack, federation, attestation, and the config/audit
plumbing all STAY as-is (or with only trivial edits).

---

## DELETE-ENTIRELY

### `gateway/lib/ztlp_gateway/bbr.ex` (309 LOC)
BBR bandwidth estimation + pacing rate calculator. Sole caller is
`session.ex:2748-2754` inside `process_cumulative_ack`. Deletion blocker:
remove `@use_bbr` + that branch.

### `gateway/test/ztlp_gateway/bbr_test.exs` (380 LOC)
Entirely dies with `bbr.ex`.

### `gateway/test/ztlp_gateway/sack_test.exs` (248 LOC)
Tests the `ZtlpGateway.Sack` sub-module inside `session.ex:1-130`. Dies with
it.

### `gateway/test/ztlp_gateway/recv_window_test.exs` (370 LOC)
Tests the `ZtlpGateway.RecvWindow` sub-module inside `session.ex:244-352`.
RecvWindow STAYS ONLY IF we decide anti-replay bitmap lives there (see
decision below). Otherwise dies with its module.

### `gateway/test/ztlp_gateway/rekey_test.exs` (327 LOC)
Tests the `ZtlpGateway.Rekey` sub-module inside `session.ex:131-243`. Rekey
goes → test goes. (Nebula has no rekey machinery on the data plane; long-term
keys get rotated at the control plane, not per-session.)

**Sub-total DELETE-ENTIRELY: 4 files, ~1,634 LOC.**

Flagged, not counted:
- **`gateway/lib/ztlp_gateway/packet.ex`** — ~60-80 LOC of ACK/NACK/FIN builders
  that disappear. Keep header parse, extract_session_id, extract_service_name,
  handshake?/data? predicates.

---

## PARTIALLY-GUT

### `gateway/lib/ztlp_gateway/session.ex` — 3,150 LOC, target ~1,000 LOC

This is the beast. Survey by line range:

STAYS (roughly):
- Module header, types, GenServer scaffolding: lines 353-715 (init, start,
  handle_packet entry, phase state machine header).
- Handshake: `handle_handshake_msg1` 1298-1328, `handle_handshake_msg3`
  1329-1441. Unchanged.
- Packet receipt dispatch (phase→handler): 706-742. Unchanged.
- `handle_data_packet` 1442-1486 minus `@frame_ack*`/`@frame_nack` branches.
- `decrypt_and_accept` 1487-1554. Keep decrypt + anti-replay check. Drop
  the ACK-fast-path branch and the window-advance dance.
- Mux stream handlers: `FRAME_OPEN` 2021-2033, `FRAME_CLOSE` 2034+, backend
  connect results 1146-1240, stream enqueue plumbing 2131-2245.
  Mux STAYS — iOS NE relay-side VIP still OPENs one mux stream per utun flow.
- Backend read-write: `handle_info({:backend_data, stream_id, data}, ...)`
  881-929, `handle_info({:tls_decrypted, ...})` 816-880. Stays — but the
  response path simplifies (no send_queue, no cwnd, just `encrypt_and_send`).
- Keepalive (FRAME_PING/PONG) 2270-2272. Stays.
- Idle timeout, `terminate/2` 1257-1292. Stays.
- Backend connect timeout `handle_info({:connect_timeout, stream_id}, ...)`
  1224-1240. Stays.
- `encrypt_and_send_stream` 2485-2581. Stays — but inlined (no pacing).

DIES:
- Entire `ZtlpGateway.Sack` submodule: lines 1-130 (~130 LOC).
- Entire `ZtlpGateway.Rekey` submodule: lines 131-243 (~113 LOC).
- Entire `ZtlpGateway.RecvWindow` submodule: lines 244-352 (~109 LOC). **If
  we keep anti-replay in session.ex inline or via a new thin `AntiReplay`
  module**, otherwise trim to just that.
- All `@frame_ack`, `@frame_ack_v2`, `@frame_nack`, `@frame_rekey` handlers
  in `handle_tunnel_frame`: lines 1804-2020 + 2079-2117 (~280 LOC).
- `process_cumulative_ack/2` and its helpers: 2722-2930+ (~250 LOC).
- `send_ack/2` 2246-2268.
- `send_queue` + pacing infra: `flush_send_queue/1..3` 2332-2416,
  `schedule_pacing_timer` 2412-2416, `handle_info(:pacing_tick, ...)` 985-
  1004, `maybe_resume_backends/1` 2281-2331 (backpressure is per-stream now,
  not queue-wide) (~250 LOC).
- Retransmit infra: `handle_info(:retransmit_check, ...)` 1005-1145, any
  per-packet retransmit helpers under that, `@retransmit_check_interval_ms`,
  `@max_retransmits`, `@max_rto_retransmit_per_tick`, RTO clamp, RTT update,
  stall detector, Karn's algo (~400 LOC).
- Rekey timer: `handle_info(:rekey_timer, ...)` 1241-1250, `do_initiate_rekey`
  2590-2621, `maybe_initiate_rekey` 2582-2589 (~60 LOC).
- Recv-gap skip: `handle_info(:recv_gap_check, ...)` 930-984,
  `cancel_recv_gap_timer` 2418 (~70 LOC).
- `deliver_recv_window` + `advance_recv_window_base` + loop 1555-1632
  (~80 LOC) — under Nebula, data packets are delivered the moment they
  decrypt, not buffered for in-order delivery.
- `pending_packets` buffering during `:awaiting_msg1/:awaiting_msg3`:
  session.ex 727-737 (~15 LOC). Safe to drop because under the Nebula pivot
  the client doesn't send fire-and-forget data until msg3 completes anyway.
  **Verify this** before deleting — re-read R2/R3 to confirm iOS NE doesn't
  race the handshake.
- Dup-ACK / fast retransmit / recovery state machine: any `in_recovery`,
  `dup_ack_count`, `recovery_cwnd`, `recovery_data_seq` references
  (~150 LOC scattered).
- Constants: `@frame_ack`, `@frame_nack`, `@frame_rekey`, `@frame_ack_v2`,
  `@initial_rto_ms`, `@min_rto_ms`, `@mobile_initial_rto_ms`,
  `@mobile_min_rto_ms`, `@max_rto_ms`, `@max_retransmits`,
  `@retransmit_check_interval_ms`, `@initial_cwnd`, `@max_cwnd`, `@min_cwnd`,
  `@min_ssthresh`, `@loss_beta`, `@queue_high`, `@queue_low`,
  `@initial_ssthresh`, `@max_rto_retransmit_per_tick`,
  `@mobile_rto_retransmit_per_tick`, `@use_bbr`, `@pacing_interval_ms`,
  `@burst_size`, `@default_peer_rwnd`, `@stall_timeout_ms`. Keep
  `@max_mux_streams`, `@max_connecting_buffer_bytes`, `@max_payload_bytes`,
  `@recv_window_size` (only if anti-replay stays), `@frame_data`, `@frame_fin`,
  `@frame_close`, `@frame_open`, `@frame_ping`, `@frame_pong`.

State map: the `state` struct currently holds ~50 fields; after R5 it drops
to ~20. Fields that die: `send_buffer`, `send_queue`, `send_seq` (kept if
outbound still numbers packets for anti-replay nonce, see decision below),
`cwnd`, `ssthresh`, `last_acked_data_seq`, `last_ack_advance_at`, `srtt_ms`,
`rttvar_ms`, `rto_ms`, `in_recovery`, `recovery_cwnd`, `recovery_data_seq`,
`dup_ack_count`, `bbr`, `pacing_timer_ref`, `retransmit_timer_ref`,
`rekey_timer_ref`, `rekey_pending`, `rekey_state`, `recv_gap_timer_ref`,
`recv_window`, `recv_window_base`, `recv_buffer`, `pending_packets`,
`backends_paused`, `peer_rwnd`.

Fields that STAY: `session_id`, `client_addr`, `udp_socket`, `service`,
`handshake`, `phase`, `i2r_key`, `r2i_key`, `static_pub`, `static_priv`,
`streams` (mux), `backend_pid` (legacy single-backend path for early msg3),
`mux_mode`, `started_at`, `bytes_in`, `bytes_out`, `idle_timer_ref`.

### `gateway/lib/ztlp_gateway/listener.ex` (196 LOC, target ~180 LOC)

Keep: UDP socket, `handle_info({:udp, ...})`, `Pipeline.admit`, session
dedup-by-addr, `start_new_session/3`.

Drop: nothing structural. The replay-storm protective code (Finding 0zz
pid-scoped SessionRegistry) STAYS — when the iOS phone's IP or port rebinds
the gateway still needs to rebuild the session cleanly. R5 doesn't remove
the session lifecycle, only the per-session reliability layer.

### `gateway/lib/ztlp_gateway/packet.ex` (566 LOC, target ~480 LOC)

Keep: magic/version check, handshake/data header parse, SessionID extract,
service-name extract, data-packet builder (`build_data`, `serialize_data_with_auth`),
handshake builders.

Drop: any helpers that serialize ACK frames or NACK frames at the packet
level. Check lines ~200-400 for `frame_ack`, `frame_nack` helpers, split
them out, delete. Estimated ~80 LOC.

### `gateway/lib/ztlp_gateway/pipeline.ex`

Keep admit() logic. Verify no branch there reads ACK-specific state. Expected
delta: 0 LOC.

---

## DECISIONS NEEDED BEFORE R5 STARTS

### D1. Anti-replay on the gateway: keep or drop?

Options:
- **Keep** (recommended): cheap bitmap, stops malicious replays from a compromised
  relay or on-path attacker. Costs ~50 LOC and one `state` field.
- **Drop**: Nebula has no anti-replay on the wire. Saves the remaining
  `recv_window` complexity entirely.

Leaning KEEP. Threat model: the relay is untrusted. If we drop anti-replay
server-side we are trusting the relay not to reflect packets back to us.
Implement as a 1024-bit sliding bitmap keyed off `packet_seq` from the header.
No buffering, no reordering, no deliver-in-order. Just accept-or-reject.

### D2. Mux stream semantics without ACKs

The current mux layer emits OPEN / CLOSE / DATA with stream_id. CLOSE today
effectively means "TCP FIN received on the backend, inform the client."
Under Nebula, CLOSE still matters — client needs to know when backend closed
so it can EOF its utun flow.

No change to mux wire format. Decision: **keep FRAME_OPEN / FRAME_CLOSE /
FRAME_DATA / FRAME_PING / FRAME_PONG**. Kill FRAME_ACK (0x01), FRAME_NACK
(0x03), FRAME_RESET (0x04 — check, may STAY for abrupt abort), FRAME_REKEY
(0x0A), FRAME_ACK_V2 (0x10).

FRAME_FIN (0x02) is the per-session FIN. Decision: **DROP**. Under Nebula,
session teardown is either idle-timeout or the client just stops sending.

### D3. Outbound `packet_seq` numbering

Currently every outbound packet gets a monotonic `send_seq`. Needed for
AEAD nonce uniqueness (nonce = `<<0::32, send_seq::little-64>>`, lines
2249 and 2489). Keep the counter, but drop `send_buffer` map keyed off it.

### D4. Backpressure

Currently `maybe_resume_backends` pauses/resumes backend reads based on
queue length. Under Nebula, there is no send queue to drain against. But
the UDP socket itself can still exhibit back-pressure (kernel send buffer
full, sendto returns EAGAIN). Decision: **per-stream** pause/resume based
on a small per-stream outbound-byte counter; when a single stream has more
than N bytes "in-flight-to-utun" (we can't actually measure this, so use
time since last ACK-less send or fixed window), pause that stream's backend.
Simpler: just let UDP drop. The client side has no complaint mechanism
under Nebula; if we overrun the utun it drops and the app-level protocol
(TLS, HTTP) retries or fails.

Leaning: **just let UDP drop**. If this proves wrong in dogfooding, add
per-stream throttle in a follow-up.

### D5. Keepalive

FRAME_PING/PONG stays, to detect dead tunnels. Interval: 30s idle. No
change.

### D6. Idle timeout

Current 5-min idle timeout STAYS. Without keepalive traffic this kills
orphaned sessions after NAT rebind.

---

## EXPECTED ARTIFACT SIZES AFTER R5

- `session.ex`: 3,150 → ~1,000 LOC
- gateway/lib total: 16,576 → ~9,000 LOC
- gateway/test total: 12,015 → ~9,500 LOC (1,325 LOC of tests die with their
  subject modules, some new tests get added for the simplified data path)

Docker image size delta: probably negligible (Elixir compilation is already
compact). The real win is cognitive/operational: no more 30s stall timeouts,
no more reconnect cascades, no more ACK-starvation debug sessions.

---

## RISKS

1. **Silent data loss:** without retransmits, any UDP packet drop on the
   gateway→client path is permanent. TLS and HTTP above MUST handle their
   own recovery. Nebula has been deployed this way for years — proves it
   works — but our TLS-terminating `tls_terminator.ex` path is unusual.
   Mitigation: run the full `ztlp-validation-suite` benchmark before and
   after, look at HTTP-level success rates, not UDP-level.

2. **Mux streams without ACKs:** FRAME_OPEN → FRAME_CLOSE ordering is no
   longer guaranteed delivered. If the iOS NE sends OPEN then CLOSE for the
   same stream_id and OPEN drops, the gateway's CLOSE arrives for a stream
   it never saw. Mitigation: make CLOSE for unknown stream_id a no-op (it
   probably already is; verify).

3. **Anti-replay window width:** if we keep anti-replay, a 1024-bit bitmap
   accommodates ~1000 packets of reorder before a legit packet is rejected.
   Under gigabit bursts this is ~10ms. If path reorder is > 10ms, raise to
   4096. Mitigation: measure in the phone log, tune before enabling.

4. **Dual-binary compatibility:** during the rollout window, there will be
   OLD iOS clients still trying to send FRAME_ACK / FRAME_REKEY to the new
   gateway. The gateway MUST log-and-drop unknown frame types, not crash or
   teardown the session. Mitigation: add a catch-all `handle_tunnel_frame(_,
   state)` that silently drops. Keep the session alive.

5. **Backend write-side flow control:** the gateway reads from backend TCP
   with `active: :once`. Currently the re-arm happens from
   `maybe_resume_backends`. After R5 the re-arm must still happen, just
   per-read, not gated on queue depth.

---

## TESTING STRATEGY

- `mix compile` clean after each R5-N task.
- `mix test` — existing tests for handshake, packet parse, policy engine,
  backend pool, NS client, service router, audit, federation, TLS should
  all remain green.
- Deleted tests: bbr_test, sack_test, rekey_test, recv_window_test — stage
  their deletions in the same commit that removes the module.
- New tests:
  - `test/ztlp_gateway/session_nebula_test.exs`: handshake + one mux OPEN
    + DATA round-trip + CLOSE, no ACKs expected on the wire.
  - `test/ztlp_gateway/anti_replay_test.exs` (if D1 = KEEP): bitmap accept/
    reject semantics.
- End-to-end:
  1. deploy new gateway to 44.246.33.34 staging image
  2. run bootstrap benchmark a few times
  3. phone log should show zero `replay=N` > 0
  4. vault loads in WKWebView without progress=0.10 stall
- Rollback plan: `docker tag ztlp-gateway:ack-v2 ztlp-gateway:rollback`
  before deploy; if R5 breaks, `docker run ...:rollback` restores in
  seconds.

---

## OPEN QUESTIONS FOR STEVE

1. D1 (anti-replay keep/drop) — leaning KEEP. Confirm?
2. D2 (FRAME_RESET) — keep for abrupt abort, or drop with FIN/REKEY/ACK? I
   lean DROP; an orphan stream on the gateway is a non-event if mux CLOSE
   is async fire-and-forget.
3. Rollout cadence — single big PR, or R5.1 (delete reliability, keep
   pacing briefly) → R5.2 (delete pacing) → R5.3 (delete BBR) incrementally?
   Incremental is safer but triples the plan-execute time. I lean
   **single PR, behind a separate branch `nebula-style-pivot-r5`**, rebased
   onto `nebula-style-pivot` after R5 lands green on device.

Once you answer 1-3 I can turn this audit into the R5 execution plan with
bite-sized tasks (R5.1 .. R5.N, same shape as R1-R4).
