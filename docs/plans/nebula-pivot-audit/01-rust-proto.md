# Nebula Pivot Audit — Section 1: Rust proto crate

Branch: nebula-style-pivot. Read-only audit.

Goal: remove the reliability layer (data_seq / ACK / NACK / SACK / RTO / cwnd /
shadow-BBR / autotune) from the Rust `proto` crate. Keep Noise handshake, AEAD
data plane, anti-replay bitmap, mux stream framing (OPEN/CLOSE/DATA/PING/PONG),
PMTUD, and session keepalive.

- **Rough LOC-to-remove total: ~8,500 LOC** (±20%). Spread across 4 delete-
  entirely files (~3,360 LOC), the reliability slice of `mux.rs` (~1,700 LOC),
  the reliability slice of `tunnel.rs` (~3,000 LOC), and reliability-only
  integration tests (~560 LOC). `packet.rs`, `session.rs`, `transport.rs` are
  effectively pure AEAD/Noise surface and contribute ~0 LOC to this delta.

---

## DELETE-ENTIRELY

Files under `proto/src/` that exist only for the reliability / congestion-control
layer. All are already feature-gated behind `tokio-runtime` in `lib.rs:80-102`.

- **proto/src/congestion.rs** — 1,959 LOC.
  AIMD/PRR/SACK scoreboard/Jacobson-Karels RTT/spurious-detect/token-bucket
  pacer. Header doc at `congestion.rs:1-17`, constants at
  `congestion.rs:19-58`, `#[cfg(test)] mod tests` at `congestion.rs:1103-1959`.
  Callers: only `proto/src/tunnel.rs` (`tunnel.rs:1176-1178`,
  `tunnel.rs:1322-1350` et al.) and `proto/tests/stress_test.rs:14`.
  Rationale: pure sender-side CC; Nebula has none of this.

- **proto/src/send_controller.rs** — 609 LOC.
  `SendController` wraps `AdvancedCongestionController` for VIP upload path:
  cwnd-gated send queue, ACK channel drain, RTT update, retransmit timer
  (`send_controller.rs:1-22`, `#[cfg(test)] mod tests` at
  `send_controller.rs:456-609`). Callers: only `proto/src/ffi.rs` (11 refs),
  `proto/src/vip.rs` (31 refs), `proto/src/tunnel.rs` (wiring). All those
  call sites need to be collapsed to direct `transport.send_data()` during
  the pivot.
  Rationale: wrapper around the file above; disappears with it.

- **proto/src/session_health.rs** — 394 LOC.
  Stall detector / probe-timeout / "needs reconnect" state machine for iOS
  (`session_health.rs:1-27`). Feature-gated `ios-sync` only
  (`session_health.rs:28`). Callers: only `proto/src/ffi.rs` (1 ref).
  Rationale: detects tunnel-reliability stalls (silent RX, oldest outbound
  age, probe timeout). Fire-and-forget UDP has nothing to stall on; keepalive
  alone is enough liveness for Nebula-style.

- **proto/src/pacing.rs** — 401 LOC.
  Despite the file-level "don't pace, just use large buffers" doc
  (`pacing.rs:1-28`), the module still ships a pacer queue + sub-batch sizing
  used by the CC path. `#[cfg(test)] mod tests` at `pacing.rs:337-401`.
  Callers: `proto/src/ffi.rs`, `proto/src/tunnel.rs`.
  Rationale: only exists to feed the retransmit / cwnd send loop. With no
  cwnd there is nothing to pace.

**Sub-total DELETE-ENTIRELY: 4 files, ~3,363 LOC** (plus their full test mods).

Possibly-also-delete (flagged, not counted):
- **proto/src/ack_socket.rs** — 299 LOC. Dedicated OS-thread ACK sender with
  dup'd socket, invented to dodge tokio scheduling starvation under heavy
  ACK load (`ack_socket.rs:1-20`). If client-side reliability ACKs go away,
  its only remaining caller shape is keepalive, which does not need a
  separate thread. Recommend a follow-up audit pass once mux.rs/tunnel.rs
  are gutted.

---

## PARTIALLY-GUT

### proto/src/mux.rs (2,814 LOC)

STAYS — mux framing + stream multiplexing core:
- `FRAME_DATA / FRAME_FIN / FRAME_CLOSE / FRAME_OPEN / FRAME_PING / FRAME_PONG`
  constants `mux.rs:39-45`.
- `MuxError`, `MuxFrame` enum + `encoded_len` / `encode` / `to_vec` / `decode`
  — `mux.rs:150-428` (note: the ACK-related arms inside `encode` at
  `mux.rs:254-293` and inside `decode` at `mux.rs:350-428` GO; DATA/FIN/OPEN/
  CLOSE/PING/PONG arms STAY).
- `StreamState`, `MuxStream` — `mux.rs:431-453`.
- `MuxEngine::new` / `next_stream_id` / `streams_len` / `queue_len` —
  `mux.rs:639-712`.
- `enqueue_outbound` / `take_send_bytes` — `mux.rs:1110-1175` (the cwnd gating
  inside these is GO; the raw framing/pop logic stays, will need a trivial
  rewrite).

GOES — reliability / CC surface:
- Reliability consts: `FRAME_ACK = 0x01` `mux.rs:40`,
  `FRAME_ACK_V2 = 0x10` `mux.rs:60`, `ACK_V2_WINDOW_UNIT_BYTES` `mux.rs:63`,
  `RWND_FLOOR / RWND_ADAPTIVE_MAX / RWND_BROWSER_BURST_TARGET /
  RWND_POST_DEMAND_HOLD` `mux.rs:66-74`, `DEFAULT_CWND / DEFAULT_RTO`
  `mux.rs:78-80`, `GOODPUT_WINDOW_BUCKETS` `mux.rs:89`, all RTT smoothing
  (`RTT_SRTT_ALPHA_*`, `RTT_RTTVAR_BETA_*`) `mux.rs:90-96`,
  `RWND_V1_FRAME_SIZE_HINT` `mux.rs:102`,
  `DEFAULT_INITIAL_WINDOW_KB` `mux.rs:108`,
  `SHADOW_MAX_ENTRIES` `mux.rs:113`, all `AUTOTUNE_*` `mux.rs:125-144`.
- `InflightPacket` `mux.rs:455-467`, `OutboundItem::AckFrame` variant
  `mux.rs:469-489`, `RouterStatsSnapshot` `mux.rs:493-505`,
  `RwndPressureSignals` `mux.rs:507-514`, `RttGoodputSnapshot` `mux.rs:516-540`,
  `GoodputBucket` `mux.rs:542-553`.
- All `cwnd / rwnd / srtt / rttvar / retransmit_buf / shadow_* / autotune_*`
  fields in `MuxEngine` — `mux.rs:562-638`.
- `advertised_rwnd` `mux.rs:686-690`, `inflight_len` `mux.rs:691-695`,
  `on_data_received` `mux.rs:714-721` (the part that feeds
  cumulative-ack state; stream delivery can stay in a trimmed form),
  `cumulative_ack` `mux.rs:723-733`, `build_ack_frame` `mux.rs:735-753`,
  `note_peer_sent_v2` `mux.rs:755-767`, `peer_speaks_v2` `mux.rs:769-773`,
  `advertised_window_bytes / _kb` `mux.rs:775-786`,
  `set_initial_window_kb` `mux.rs:788-799`,
  `set_autotune_bounds_kb / autotune_bounds_kb / autotune_target_kb /
   autotune_reason / autotune_compute_target_bytes / autotune_tick`
   `mux.rs:801-954`,
  `mark_outbound_demand` `mux.rs:955-969`,
  `tick_rwnd / tick_rwnd_v1_ladder / set_rwnd` `mux.rs:971-1108`,
  `on_cumulative_ack / on_cumulative_ack_at / observe_sent /
   observe_ack_cumulative / shadow_inflight_len` `mux.rs:1177-1311`,
  `record_rtt_sample / record_goodput_bytes / rotate_goodput_buckets /
   current_goodput_bps_inner / goodput_bps / peak_goodput_bps /
   smoothed_rtt_ms / rtt_var_ms / min_rtt_ms / latest_rtt_ms /
   rtt_samples_total / rtt_goodput_snapshot` `mux.rs:1313-1482`,
  `on_peer_rwnd` `mux.rs:1484-1489`,
  `tick_retransmit / take_retransmit_bytes / set_rto / set_cwnd / cwnd`
   `mux.rs:1491-1540`.

Estimate: ~1,700 LOC removed from mux.rs (≈60% of the file), roughly half
from code (`mux.rs:455-1540` minus stream-dispatch stubs ≈ 800 LOC) and
half from the reliability test mod (see TESTS below, ~900 LOC).

### proto/src/packet.rs (628 LOC)

`FRAME_ACK / FRAME_ACK_V2 / FRAME_DATA / FRAME_OPEN / FRAME_CLOSE / FRAME_PING
/ FRAME_PONG` do **not** live here. `rg '(FRAME_ACK|FRAME_DATA|FRAME_OPEN|
FRAME_CLOSE|FRAME_PING|FRAME_PONG|ACK_V2)' proto/src/packet.rs` → 0 hits.

This file is pure wire format: `MAGIC / VERSION / HANDSHAKE_HEADER_SIZE /
DATA_HEADER_SIZE` `packet.rs:39-48`, `MsgType` `packet.rs:53-99`,
`SessionId` `packet.rs:101-133`, `HandshakeHeader` `packet.rs:135-426`,
`DataHeader` `packet.rs:428-595`, `ZtlpPacket` `packet.rs:597-628`.

Verdict: **STAYS IN FULL.** The mux/tunnel-layer frame-type bytes live in
`mux.rs:39-60` and `tunnel.rs:131-196`. No edit needed here.

### proto/src/session.rs (205 LOC)

`rg '(data_seq|recv_window|send_buffer|retransmit|stall|rto|cwnd|ack)'
proto/src/session.rs` → only documentation hits, no code.

File is the anti-replay bitmap + the keyed `SessionState` only:
`DEFAULT_REPLAY_WINDOW / MULTIPATH_REPLAY_WINDOW` `session.rs:23-26`,
`ReplayWindow` `session.rs:32-100`, `SessionState { session_id,
peer_node_id, send_key, recv_key, send_seq, replay_window, multipath }`
`session.rs:102-162`, tests `session.rs:164-205`.

Verdict: **STAYS IN FULL.** There is no `data_seq` / `send_buffer` /
retransmit timer / stall-detector in `session.rs` — those live in
`tunnel.rs` (data_seq counter at `tunnel.rs:1251`, window-stall at
`tunnel.rs:1253-1264`, RetransmitBuffer at `tunnel.rs:551-670`).

### proto/src/transport.rs (586 LOC)

STAYS — Noise + AEAD + PMTUD core:
- `TransportNode` struct + `recv_packet / recv_batch / send_data /
   send_data_with_seq / encrypt_data / encrypt_data_with_seq /
   send_packets / send_via_relay / process_packet / max_payload_size`
  `transport.rs:33-370`.
- `BASE_PLPMTU / PROBE_SIZES / PLPMTUD_*` constants `transport.rs:372-391`.
- `PmtudPhase` `transport.rs:395-409`, `PmtudState` + impl
  `transport.rs:412-586` — uses `FRAME_PMTU_PROBE_ACK` but that's a
  PMTUD probe ACK, not a reliability ACK; stays.

GOES: nothing.

The strings `retransmit`, `retransmission` in this file are doc-comment
references to what *callers* (SendController / tunnel) do with
`send_data_with_seq`'s returned packet_seq; the function itself only hands
back a nonce-assigned seq and has no retransmit state. Keep the comments
short but the code as-is.

Verdict: **STAYS IN FULL.**

### proto/src/tunnel.rs (4,610 LOC)

This file is the TCP↔UDP bridge (`run_bridge*` family) plus the reliability
layer that wraps it. Audit surface only — not a full enumeration.

STAYS:
- Frame constants `FRAME_DATA` `tunnel.rs:131`, `FRAME_FIN` `tunnel.rs:137`,
  `FRAME_RESET` `tunnel.rs:147`, `FRAME_REJECT` `tunnel.rs:155`,
  `FRAME_RTT_PING / FRAME_RTT_PONG` `tunnel.rs:162-168`,
  `FRAME_STREAM_RESET` `tunnel.rs:188`,
  `FRAME_PMTU_PROBE / FRAME_PMTU_PROBE_ACK` `tunnel.rs:192-196`.
- `MAX_SERVICE_NAME_LEN / DEFAULT_SERVICE` `tunnel.rs:89-92`,
  `TCP_READ_BUF / MAX_SUB_BATCH / MAX_PLAINTEXT_PER_PACKET` `tunnel.rs:97-126`.
- `BridgeOutcome`, `ResetWaitResult` `tunnel.rs:200-221`.
- `send_reject` `tunnel.rs:708-756`.
- `wait_for_first_data[_channeled]` `tunnel.rs:758-929`.
- `ServiceRegistry / encode_service_name / parse_forward_arg /
   parse_forward_target / parse_local_forward` `tunnel.rs:3037-3200+`.
- `run_bridge*` outer wrappers `tunnel.rs:930-1045`; the *inner* pump
  `run_bridge_inner` `tunnel.rs:1047-2917` needs heavy surgery (see GOES)
  but its TCP read + encrypt + `udp.send_to` + TCP write flow stays.

GOES — reliability surface (the dominant mass of this file):
- Doc block describing the reliability protocol `tunnel.rs:20-56`.
- `FRAME_ACK = 0x01` `tunnel.rs:134`,
  `FRAME_NACK = 0x03` `tunnel.rs:141`,
  `FRAME_SACK = 0x05` `tunnel.rs:151`,
  `FRAME_CORRUPTION_NACK = 0x09` `tunnel.rs:173`.
- `SEND_WINDOW / ACK_EVERY_PACKETS / ACK_INTERVAL /
   REASSEMBLY_MAX_BUFFERED / REASSEMBLY_STALL_TIMEOUT /
   SENDER_ACK_TIMEOUT / SENDER_WINDOW_STALL_LIMIT /
   MAX_RTO_RETRANSMIT_CYCLES / FIN_DRAIN_TIMEOUT /
   RTT_PROBE_INTERVAL / MIN_RTO_MS / MAX_NACK_SEQS /
   RETRANSMIT_BUF_MAX` — `tunnel.rs:224-280`.
- `ReassemblyBuffer` struct + impl `tunnel.rs:289-507` (gap detection,
  `is_stalled`, `should_nack`, `missing_seqs`, `mark_nack_sent`, `has_gap`,
  `can_send_nack`). Reassembly only exists because we split a TCP byte
  stream across packets and track missing seqs for NACK. With fire-and-
  forget + mux framing, this whole type goes.
- `encode_nack_frame` `tunnel.rs:509-520`, `decode_nack_payload`
  `tunnel.rs:522-548`.
- `RetransmitEntry` `tunnel.rs:551-568`, `RetransmitBuffer`
  `tunnel.rs:570-670` (`push/get/get_with_packet_seq/send_time/
  mark_retransmitted/len/oldest_n` — all reliability).
- Inside `run_bridge_inner`: the congestion controller arcs
  `tunnel.rs:1176-1180`, retransmit bufs `tunnel.rs:1189-1192`,
  retransmit request channel `tunnel.rs:1194-1195`, PTO/RTO scaffolding
  `tunnel.rs:1209-1264`, NACK/SACK retransmit pump
  `tunnel.rs:1317-1470+`, periodic ACK sender, RTO timer, stall-exit logic.
- `send_ack` `tunnel.rs:2924-2978` and `send_sack` `tunnel.rs:2979-3036`.

Estimate: roughly `tunnel.rs:224-670` (≈450 LOC of types/consts) +
`tunnel.rs:2919-3036` (≈120 LOC of ACK/SACK senders) + ≈2,400 LOC of
inline CC/retransmit/stall code inside `run_bridge_inner`
(`tunnel.rs:1170-2910`, which is mostly reliability; TCP-read + encrypt +
sendto + decrypt + TCP-write is maybe 400-500 LOC of that span). Call it
**~3,000 LOC removed from tunnel.rs**, collapsing it toward ~1,600 LOC.

---

## TESTS

Unit-test modules inside files that are DELETE-ENTIRELY (these go with
their files, not counted separately):
- `proto/src/congestion.rs:1103-1959` (~856 LOC of RTT/SACK/PRR/spurious tests).
- `proto/src/send_controller.rs:456-609` (~153 LOC).
- `proto/src/pacing.rs:337-401` (~64 LOC).
- `proto/src/session_health.rs` — has no `#[cfg(test)]` block in-file (tests
  live in the iOS harness).

Reliability-only test blocks inside PARTIALLY-GUT files:
- `proto/src/mux.rs` — `#[cfg(test)] mod tests` starts at
  `mux.rs:1550`. Tests that go (all are reliability / CC / autotune /
  RTT / goodput / BDP / shadow-BBR / rwnd ladder / retransmit):
  `rwnd_healthy_plus_recent_demand_holds_12` l.1751,
  `rwnd_browser_replay_fast_backoff_to_floor` l.1791,
  `rwnd_router_outbound_bad_forces_floor` l.1827,
  `send_buffer_respects_cwnd` l.1851,
  `send_buffer_assigns_sequential_data_seq` l.1880,
  `open_and_close_frames_are_not_tracked_inflight` l.1904 (keep — mux),
  `retransmit_fires_after_rto` l.1921,
  `cumulative_ack_drops_everything_at_or_below` l.1956,
  `peer_rwnd_is_clamped_to_adaptive_range` l.1975,
  `rwnd_oldest_ms_alone_is_not_pressure` l.1984,
  all `rtt_*` l.2027-2114, all `goodput_*` l.2116-2167, all `bdp_*`
  l.2168-2206, `samples_total_counts_only_karn_admitted_samples` l.2207,
  `peak_goodput_is_monotonic` l.2236, all `shadow_*` l.2271-2347,
  `codec_ack_v2_*` / `codec_v1_and_v2_are_distinguishable_by_type` /
  `build_ack_frame_*` / `note_peer_sent_v2_*` / `set_initial_window_*` /
  `advertised_window_kb_rounds_up` / `v1_ladder_*` l.2348-2504,
  all `autotune_*` l.2505-2814.
  Effectively `mux.rs:1751-2814` minus ~60 LOC of OPEN/CLOSE/codec tests →
  ~1,000 LOC go. (Retained tests: frame codec roundtrip for
  DATA/OPEN/CLOSE/FIN/PING/PONG at `mux.rs:1555-1719` + the
  `open_and_close_frames_are_not_tracked_inflight` at l.1904 once the
  inflight concept is removed.)

- `proto/src/session.rs:164-205` — anti-replay tests; STAY.
- `proto/src/packet.rs` — no in-file tests; see `proto/tests/packet_tests.rs`.
- `proto/src/transport.rs` — no in-file tests that touch reliability.

Integration tests under `proto/tests/` (exclusively-reliability ones go):
- **`proto/tests/recovery_tests.rs`** — 338 LOC, mixed. GO:
  `test_reassembly_buffer_limits` l.162,
  `test_reassembly_duplicate_sequences` l.179,
  `test_nack_decode_malformed` l.276,
  `test_reassembly_out_of_order` l.298 (~100 LOC). STAY: all the
  `test_truncated_*`, `test_wrong_magic_bytes`, `test_corrupted_auth_tag`,
  `test_*_payload`, `test_pipeline_all_zeros`,
  `test_rapid_handshake_establishment`, `test_handshake_*`,
  `test_transport_send_unreachable`.
- **`proto/tests/stress_test.rs`** — 835 LOC, mixed; the reliability half
  goes entirely: `test_reassembly_*` l.29-211 (~180 LOC),
  `test_sack_ranges_under_loss` l.213, all `test_rtt_estimator_*`
  l.246-315, `test_nack_*` l.316-346, all `test_cwnd_*` l.347-446,
  `test_sack_retransmit_recovers_all_data` l.447-489. That's roughly
  `stress_test.rs:1-489` → ~460 LOC. STAY: encrypted burst tests,
  session manager capacity/cleanup, policy tests, concurrent handshakes
  (l.490-835, plus the `use ztlp_proto::congestion::...` import at
  l.14 goes away with the above).
- **`proto/tests/ack_socket_contention_tests.rs`** — 946 LOC. Despite the
  name, the one grep hit for `send_controller|congestion` is a comment at
  l.729 ("simulates cwnd opening"). The file tests whether the dedicated
  ACK-sender thread starves under contention. Whole-file verdict depends on
  whether `ack_socket.rs` survives the pivot (see its flag above). Not
  counted in the LOC delta until that decision lands.
- **`proto/tests/throughput_tests.rs`** (855 LOC) — tests GSO batching, no
  congestion/cwnd refs. STAYS.

Integration-tests sub-total GO: ~100 (recovery) + ~460 (stress) = **~560 LOC**.

---

## LOC DELTA ESTIMATE

| Bucket                                    | LOC removed |
|-------------------------------------------|------------:|
| DELETE-ENTIRELY (4 files, incl. test mods) |      3,363 |
| mux.rs reliability slice (code + tests)    |      1,700 |
| tunnel.rs reliability slice               |      3,000 |
| Integration tests (recovery+stress)        |        560 |
| **Total**                                  |  **~8,600** |

±20% → somewhere between 6,900 and 10,300 LOC removed from the Rust
`proto` crate by the client-side-only first pass. `ack_socket.rs` (+299)
and its dedicated test file (+946) are deferred to a follow-up audit.
