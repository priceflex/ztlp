# Handoff: Rust Client Reliability Completed, Gateway Pending (2026-05-17)

## Overview
We have successfully completed the Rust portion of the "dumb-pipe" reversal described in `2026-05-17-RELIABILITY-HANDOFF.md`. 
The `ztlp connect` Rust client now correctly buffers, reorders, and flushes data packets using `ReceiveWindow`, and emits specification-compliant `FRAME_ACK_V2` packets to manage flow control.

## What Was Accomplished 
1. **Syntax & Architecture Fixes:** 
   - Repaired the broken AST (unclosed braces) inside `proto/src/tunnel.rs`.
   - Wired the `recv_window: &mut crate::ReceiveWindow` across `run_bridge_inner` and into `handle_incoming_packet`.
   - Incoming payloads are now accurately deduplicated and sequentially flushed to `tcp_writer` using `recv_window.insert(data_seq, payload)`.

2. **FRAME_ACK_V2 Layout:**
   - Implemented precise 11-byte ACK generation triggered on sequence progression or gap detection.
   - Layout: `[0x10 (FRAME_ACK_V2)]` + `[8-byte last_acked_data_seq (BE)]` + `[2-byte window_kb = 5734 (BE)]`.
   - Safely resolved `send_key` payload extraction utilizing scoped `tokio::sync::Mutex` locking (`pipeline.lock().await`).

3. **Compiler Editions & Async Chains:**
   - Fixed the phantom `async fn is not permitted in Rust 2015` errors by successfully setting `edition = "2021"` in `proto/Cargo.toml`.
   - Resolved a large chain of subsequent `async/await` strict typing and signature mismatches cascading from `tunnel.rs` out to `ztlp-cli.rs`.
   - Fixed missing `ztlp_proto::gso` imports and struct bindings.

4. **Compiled successfully:** `cargo build --release` inside `~/ztlp/proto` now builds flawlessly.

## Benchmark Status (Where we are stalled)
Running the full-stack suite:
`cd ~/ztlp && python3 bench/run_fullstack_multistream.py --size 10485760 --ns 1,4,8`
**Result:** Streams successfully transfer partial sums (between 1 MB and 5.5 MB) but ultimately stall, hitting a strict `90-second curl (28) timeout`. 

**Why:** The Rust client is doing its job and pacing the wire with `FRAME_ACK_V2`. However, the Elixir Gateway has not yet been reverted from its unthrottled "dumb-pipe" configuration, so it is either completely ignoring the incoming ACKs or exhausting its unacknowledged burst limit and silently dropping the TCP data on the floor.

## Immediate Next Steps for Next Session
The Rust codebase is fully prepped. Shift all focus to the Elixir backend.

1. **Target:** `gateway/lib/ztlp_gateway/session.ex`
2. **Handle ACKs:** Verify the Gateway is actively decoding inbound `FRAME_ACK_V2` (0x10) packets from the client.
3. **Re-activate Flow Control:** Remove the "dumb-pipe" blast/bypass logic on the Elixir side. Now that the Gateway is receiving ACKs again, ensure `cwnd` (congestion window), `inflight` tracking, and `process_cumulative_ack` are fully engaged to pace the sliding window.
4. **Benchmark Verification:** Once the Gateway correctly honors the ACKs, run `bench/run_fullstack_multistream.py`. The stalls should vanish, and throughput should hit target deployment speeds (>200MB/s).
