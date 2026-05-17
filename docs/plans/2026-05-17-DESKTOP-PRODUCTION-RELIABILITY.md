# ZTLP Desktop (Linux/Windows) Production Reliability Plan

> **For Hermes:** Use `subagent-driven-development` skill to implement this plan task-by-task.

**Goal:** Get the Linux and Windows desktop endpoints (via `ztlp connect` or local proxy) running at production speeds and reliability over the real AWS full-stack testbed.

**Context & Current State:**
The recent "Nebula pivot" turned the Rust `ztlp connect` client into a "dumb-pipe" datagram proxy. It stripped out internal sequence deduplication (`ReceiveWindow`) and ACK generation (`FRAME_ACK`). We bypassed the Elixir Gateway's flow control (`cwnd`) to compensate, which led to the Gateway blindly blasting 10MB of UDP packets. This guarantees UDP packet loss across the WAN, which permanently hangs the TCP connection at the local HTTP forwarder (`curl` timeouts).

To make Linux/Windows desktop clients production-ready, we **must restore the ZTLP reliability layer** (sliding windows, ACKs, and retransmits) in the Rust client so it behaves identically to the robust gateway/iOS implementations.

---

### Task 1: Reconstruct the Client `ReceiveWindow` in Rust
**Objective:** The Rust client must be able to buffer out-of-order packets and deduplicate retransmissions before pushing data to the local TCP sockets.
**Files:** `proto/src/tunnel.rs` and/or `proto/src/recv_window.rs`
**Steps:**
1. Implement a `ReceiveWindow` struct in Rust (or restore the removed legacy code) that tracks `window_base` and buffers packets by `packet_seq`.
2. Intercept incoming `FRAME_DATA` packets in the `ztlp connect` receive loop.
3. Only yield contiguous, ordered payloads to the `std::io::Write` boundary of the local `127.0.0.1` TCP socket.

### Task 2: Implement `FRAME_ACK` Generation in Rust
**Objective:** The Rust client must explicitly acknowledge received sequence numbers so the Elixir Gateway can clear its `send_buffer`, slide its CWND, and perform targeted RTO retransmissions.
**Files:** `proto/src/tunnel.rs`
**Steps:**
1. Maintain a `last_acked_data_seq` counter on the client.
2. Upon receiving new contiguous data (or detecting a gap/duplicate indicating loss), serialize and emit a `FRAME_ACK` (or `FRAME_ACK_V2`) packet back to the Gateway.
3. Throttle/batch ACKs as needed to avoid ACK-storms.

### Task 3: Revert Elixir Gateway CWND Hacks
**Objective:** Restore the Gateway's congestion control to prevent network collapse now that the client properly acknowledges data.
**Files:** `gateway/lib/ztlp_gateway/session.ex`
**Steps:**
1. Revert the `legacy_bypass` hack from `flush_send_queue/2`.
2. Allow `window_full` logic to throttle transmission (`inflight >= effective_window`).
3. Re-enable the `check_stall/1` detection for all sessions.

### Task 4: Tune for Production Speeds (GSO/GRO)
**Objective:** Once data flows reliably, optimize the throughput bottleneck.
**Files:** `proto/src/net.rs` or `proto/src/transport.rs`
**Steps:**
1. Ensure the Rust client utilizes `UDP_SEGMENT` (GSO) and `UDP_GRO` if available on Linux, reducing syscall overhead.
2. Tune socket buffer sizes (`SO_RCVBUF` / `SO_SNDBUF`) in the Rust client to match the expected multi-megabyte window (at least 7MB).

### Task 5: Full-Stack Benchmark Certification
**Objective:** Prove reliability and production speed across the AWS testbed.
**Execution:**
1. Start Gateway, Relay, and NS on the AWS infrastructure (already active).
2. Run the full multi-stream benchmark locally:
   ```bash
   cd /home/trs/ztlp
   python3 bench/run_fullstack_multistream.py --size 10485760 --ns 1,4,8,16,32
   ```
3. **Acceptance Criteria:** `stalled=0` across all runs, aggregate MB/s approaches link/VM capacity, and all downloaded files exactly match `size` without curl timeouts.