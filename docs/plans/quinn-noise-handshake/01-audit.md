# QUIC-Noise Handshake Phase 3: Reliability Layer Demolition Audit

## Files to Delete Entirely

- `proto/src/send_controller.rs` (609 LOC): Legacy reliability queue, retransmit tracking. Obsoleted by QUIC/Quinn streams.
- `proto/src/congestion.rs` (1959 LOC): Legacy BBR/Cubic congestion control. Obsoleted by Quinn's internal CC.
- `proto/src/recv_window.rs` (60 LOC): Legacy out-of-order receive buffer. QUIC streams provide in-order delivery.
- `proto/src/pacing.rs` (401 LOC): Legacy packet pacing. Quinn does this internally.

*Total deleted LOC: ~3029 LOC*

## Files to Partially Gut

### `proto/src/mux.rs` (2799 LOC)
- **Delete:** `MuxEngine` logic related to tracking sequence numbers, ACKs, retransmit queues, inflight calculations, and RTT/goodput tracking. The core reliability state machine is going away.
- **Keep:** `MuxFrame` and `MuxError` if they are parsed directly from the network by other systems (this needs investigation based on D1). Let's assume most of the 2800 LOC goes away.
- **Action:** Delete the reliability/ACK/retransmit logic in `MuxEngine`.

## FFI / Public API Surface Changes (`proto/src/ffi.rs`)

The `ztlp_mux_` functions are currently called by the iOS Network Extension (and potentially others) to implement the ZTLP reliability layer over UDP. We need to **stub these** during the intermediate phases until the iOS NE is rewritten to call the QUIC/Quinn equivalents (or until Quinn handles it entirely internally without iOS Ne calling tick functions).

| Symbol | File:Line | Current Purpose | Action |
|---|---|---|---|
| `ztlp_mux_new` | `ffi.rs:3951` | Allocate `MuxEngine` | STUB/KEEP (Return dummy obj) |
| `ztlp_mux_free` | `ffi.rs:3966` | Free `MuxEngine` | KEEP (Drop dummy obj) |
| `ztlp_mux_enqueue_data` | `ffi.rs:3977` | Queue data stream | STUB (Return 0/noop) |
| `ztlp_mux_enqueue_open` | `ffi.rs:4008` | Open stream | STUB (Return 0/noop) |
| `ztlp_mux_enqueue_close` | `ffi.rs:4047` | Close stream | STUB (Return 0/noop) |
| `ztlp_mux_take_send_bytes` | `ffi.rs:4073` | Yield bytes to send | STUB (Return 0 bytes/noop) |
| `ztlp_mux_tick_retransmit` | `ffi.rs:4117` | Run retransmit timers | STUB (Return 0/noop) |
| `ztlp_mux_take_retransmit_bytes`| `ffi.rs:4124` | Yield retransmits | STUB (Return 0 bytes/noop) |
| `ztlp_mux_on_ack` | `ffi.rs:4137` | Process ACK | STUB (Return 0/noop) |
| `ztlp_mux_on_data_received` | `ffi.rs:4146` | Note recv for ACK | STUB (Return 0/noop) |
| `ztlp_mux_mark_outbound_demand`| `ffi.rs:4167` | Signal demand | STUB (Return 0/noop) |
| `ztlp_mux_tick_rwnd` | `ffi.rs:4199` | Calc/send rwnd | STUB (Return 0/noop) |
| `ztlp_mux_advertised_rwnd` | `ffi.rs:4212` | Get rwnd | STUB (Return 0/noop) |
| `ztlp_mux_cumulative_ack` | `ffi.rs:4220` | Get max acked | STUB (Return 0) |
| `ztlp_mux_inflight_len` | `ffi.rs:4231` | Get inflight size | STUB (Return 0) |
| `ztlp_mux_rtt_goodput_snapshot`| `ffi.rs:4270` | Get RTT/stats | STUB (Return empty struct) |
| `ztlp_mux_observe_sent` | `ffi.rs:4286` | Shadow metrics | STUB (Return 0/noop) |
| `ztlp_mux_observe_ack_cumulative`| `ffi.rs:4301`| Shadow metrics | STUB (Return 0/noop) |
| `ztlp_mux_shadow_inflight_len` | `ffi.rs:4313` | Shadow metrics | STUB (Return 0) |
| `ztlp_mux_note_peer_sent_v2` | `ffi.rs:4324` | V2 upgrade | STUB (Return 0/noop) |
| `ztlp_mux_peer_speaks_v2` | `ffi.rs:4333` | V2 status | STUB (Return 0) |
| `ztlp_mux_advertised_window_bytes` | `ffi.rs:-` | Window | STUB (Return 0) |
| `ztlp_mux_advertised_window_kb`| `ffi.rs:-` | Window | STUB (Return 0) |
| `ztlp_mux_set_initial_window_kb`| `ffi.rs:-` | Window | STUB (Return 0/noop) |
| `ztlp_mux_set_autotune_bounds_kb`| `ffi.rs:-` | Window | STUB (Return 0/noop) |
| `ztlp_mux_autotune_target_kb` | `ffi.rs:-` | Window | STUB (Return 0) |
| `ztlp_mux_autotune_min_kb` | `ffi.rs:-` | Window | STUB (Return 0) |
| `ztlp_mux_autotune_max_kb` | `ffi.rs:-` | Window | STUB (Return 0) |
| `ztlp_mux_autotune_reason` | `ffi.rs:-` | Window | STUB (Return 0/noop) |


## Downstream Consumers

Based on grep, the `ztlp_mux_` prefix is consumed in:
- `ios/ZTLP/Libraries/ztlp.h`: C header generated for iOS
- Primary frontend: iOS Network Extension (and possibly the main iOS App).
- Elixir gateway? (Need to check if Elixir codebase uses these exact FFI names or a NIF). Not seeing `ztlp_mux_` in typical NIF names, but we should verify if the relay uses it.

## "What if only one side lands?" Impact Analysis

If we demolish the reliability layer in the `proto` crate (used by iOS and Relay) but don't convert the *other* side (e.g. Elixir gateway, or an older iOS client) to use QUIC at the exact same moment across the protocol boundary, **traffic will drop**. The old code expects `FRAME_ACK`s and retransmits; the new code won't send them.

Because QUIC operates entirely differently on the wire than our custom Mux framing + UDP ACKs, both the client and server MUST switch to QUIC simultaneously, or the deployment must route QUIC traffic on a separate UDP port (or via a new protocol multiplexing byte on the first packet).

## Open Decisions (D1, D2...)

- **D1 (Framing):** Does QUIC completely replace the `FRAME_DATA`, `FRAME_OPEN`, `FRAME_CLOSE` enum in `mux.rs`, or do we wrap QUIC payloads in these frames for parsing reasons?
- **D2 (Deployment):** If we stub `ztlp_mux_*` in FFI, the iOS client will compile but *cannot send data* the legacy way. Is the goal to replace the iOS calls to `ztlp_mux_` with Quinn C-API calls in a subsequent Swift phase, or will `ztlp_mux_enqueue_data` internally call Quinn under the hood?


## Tests that will die
- **Unit tests:** Any unit tests in `send_controller.rs`, `congestion.rs`, `recv_window.rs`, `pacing.rs`.
- **Unit tests:** `mux.rs` tests verifying sequencing, ACKs, sliding windows, retransmissions, and Autotune.
- **Integration tests:** `proto/tests/ios_tunnel_engine_harness.rs` uses `MuxEngine` / `MuxFrame`. These tests will heavily break if they simulate the custom framing sequence.

## State-struct / Context-object Shrinkage
- In `ZtlpMuxEngine` inside `ffi.rs`, the `inner: std::sync::Mutex<crate::mux::MuxEngine>` field goes away or is replaced.
- **Critical finding (`ffi.rs`):** We have a `data_seq` counter inside `ZtlpSession` that tracks standard sequence numbers. This field must be audited to ensure things like cryptographic nonces inside the Noise machine aren't accidentally tied to `data_seq`. Also, `recv_loop` in `ffi.rs` implements its own custom ACK and framing parsing (`FRAME_DATA`, `FRAME_ACK`) that will need to be deleted or rewritten entirely when Quinn handles framing natively. The `reassembly_buf` in `ffi.rs` is also completely redundant given QUIC streams.

## Open Questions

- Does the QUIC pivot require dropping the FFI entirely in a single phase, or can we return dummy (stubbed) `0` values from the `ztlp_mux_` C-APIs, verify the build passes, and then clean up the iOS code in the next phase? (Standard legacy-demolition approach suggests stubbing first, cleaning frontends second.)
- Are there any shared counters (like `send_seq`) that the crypto logic (Noise) relies on that might be deleted along with the mux reliability layer?
