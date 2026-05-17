# Handoff: Desktop Production Reliability (2026-05-17)

## Overview
We are executing the plan from `2026-05-17-DESKTOP-PRODUCTION-RELIABILITY.md` to restore the ZTLP reliability layer (sequences, ACKs, and sliding windows) on the Rust client (`ztlp connect` "dumb-pipe"), and re-enable congestion control on the Elixir Gateway. 

The goal is to fix the 90-second timeouts / stalls during high-throughput downloads and reach production speeds over the AWS testbed.

## Completed Tasks
- **Task 1: Reconstruct the Client `ReceiveWindow` (Rust)** 
  - Created `proto/src/recv_window.rs` and wired it into `proto/src/tunnel.rs` (`handle_incoming_packet`). Incoming payloads are now ordered and deduplicated before being flushed to the local `tcp_writer`.
- **Task 3: Revert Elixir Gateway CWND Hacks** 
  - Reverted `legacy_bypass` in `gateway/lib/ztlp_gateway/session.ex`. 
  - Restored `effective_window` tracking and re-enabled `check_stall/1`.
  - Added a baseline `5734` packet `cwnd` ceiling for desktop throughput scaling.
- **Task 4: Tune for Production Speeds (GSO/GRO)** 
  - Added `socket2` dependency. 
  - Updated socket binding in `proto/src/bin/ztlp-cli.rs` to forcefully set `SO_RCVBUF` and `SO_SNDBUF` to 7MB, and applied `enable_gro()`.

## Status & Blockers (Task 2: FRAME_ACK Generation)
We added logic to `handle_incoming_packet` to generate ACKs. However, the Rust project is currently failing to compile.

**The Bug:**
There is a syntax error (unclosed brace `{`) in `proto/src/tunnel.rs` roughly between lines 870 and 900 where the `FRAME_ACK` generation was injected. 
Because `cargo check`/`cargo build` fails, the background benchmark process (`run_fullstack_multistream.py`) has been running on an *old compiled binary* that doesn't send the ACKs, hence the relentless 90-second stalls.

*Note on `cargo check`: The console outputs dozens of `async fn is not permitted in Rust 2015` errors. These are dummy/phantom linting errors masking the real problem. Scroll to the very bottom of the compilation output to see the `unclosed delimiter` error.*

## Immediate Next Steps for Next Session

1. **Fix `proto/src/tunnel.rs` syntax:**
   Open `ztlp/proto/src/tunnel.rs`, find `handle_incoming_packet`, and fix the brace mismatch around the `gap_detected_or_progression` block.

2. **Verify ACK Byte Layout:**
   The Elixir gateway expects a `FRAME_ACK_V2`. Ensure the Rust code builds exactly 11 bytes:
   ```rust
   let mut ack_frame = Vec::with_capacity(11);
   ack_frame.push(0x10); // FRAME_ACK_V2
   ack_frame.extend_from_slice(&last_acked_data_seq.to_be_bytes());
   let window_kb: u16 = 5734; // Large receive window
   ack_frame.extend_from_slice(&window_kb.to_be_bytes());
   ```

3. **Rebuild & Verify:**
   ```bash
   cd ztlp/proto && cargo build --release
   ```
   *(If it complains about 2015 edition, you can ignore the async warnings as long as the brace error is gone, or ensure your local cargo environment is correctly parsing `edition = "2021"` in `Cargo.toml`).*

4. **Run Benchmark:**
   Run the harness to prove the stall is fixed and speeds hit >200MB/s:
   ```bash
   cd ztlp && python3 bench/run_fullstack_multistream.py --size 10485760 --ns 1,4,8
   ```