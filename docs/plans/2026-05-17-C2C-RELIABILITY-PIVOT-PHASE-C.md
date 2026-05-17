# Phase C: Fix Client Reliability & 1 MiB Stall 

**Date:** 2026-05-17
**Status:** Relay Handshake is FIXED. Phase B (Gateway) is DIAGNOSED.

> **For Hermes:** Use `subagent-driven-development` skill to implement this plan task-by-task.

## 1. Where We Are

We successfully debugged the full-stack relay deployment:
* **Relay Dynamic Gateways** were fixed (Gateway now has the correct internal VPC IP for `ZTLP_RELAY_SERVER`, allowing `ztlp-relay` to register it and route `HELLO` packets).
* **Handshakes complete successfully** across the full AWS testbed.
* We modified the Elixir `ztlp-gateway` to bypass `cwnd` backpressure for legacy (`dumb-pipe`) clients, which eliminated the instant 1 MiB deadlocks! 

**The New Problem:**
Because the `ztlp connect` (Rust) client merged a "dumb-pipe datagram" architecture recently, the Rust client **does not send ACKs**.
Since we forced the Gateway to bypass its `cwnd` limits to compensate, the Gateway now blindly blasts 10 megabytes of UDP packets across the WAN without pacing or waiting for ACKs. 
Internet packet loss inevitably drops a few UDP packets. Since `ztlp connect` has no `recv_window` and sends no ACKs, it cannot ask for retransmissions. The local `curl` proxy receives an incomplete TCP stream and times out at 90 seconds.

## 2. Goal

To get 10 MB+ streams working reliably on the desktop `ztlp connect` bench, we **must restore an inner reliability layer** to `ztlp connect`. A dumb UDP pipe cannot transport raw TCP payload streams over a lossy WAN without an internal sliding window and ACK system. (Note: iOS already handles this via `utun` TCP).

## 3. Implementation Plan

### Task 1: Add `--reliable` flag to `ztlp connect`
**Objective:** Allow `ztlp connect` to toggle between the dumb-pipe mode and a legacy mode that utilizes strict ordering and ACKs.
**Files:**
- Modify: `proto/src/bin/ztlp-cli.rs`
**Steps:**
1. Add a `--reliable` boolean flag to the `Connect` subcommand struct.
2. Pass this configuration down to the tunnel initialization logic.

### Task 2: Re-implement `recv_window` and ACK generation in `tunnel.rs`
**Objective:** When running in `--reliable` mode, the client must buffer out-of-order packets and send `FRAME_ACK` back to the Gateway.
**Files:**
- Modify: `proto/src/tunnel.rs` (or `proto/src/mux.rs`)
**Steps:**
1. Re-introduce a `ReceiveWindow` structure (or re-activate if it still exists in the codebase) for the `dumb-pipe` / `local-forward` bridging logic.
2. In the datagram handling loop, intercept payloads: verify sequence numbers, buffer gaps, and yield ordered TCP bytes to the TCP socket writer.
3. Every N packets (or via an ACK timer), serialize a `FRAME_ACK` (or `FRAME_ACK_V2`) packet and send it to the Gateway.

### Task 3: Restore Gateway CWND and RTO logic
**Objective:** Undo the temporary unthrottled UDP blasting hack we added to Elixir in Phase B. The gateway needs its CWND window functioning properly so it doesn't overwhelm the network.
**Files:**
- Modify: `gateway/lib/ztlp_gateway/session.ex`
**Steps:**
1. Remove the `legacy_bypass` overrides in `flush_send_queue/2`.
2. Ensure the legacy backend data triggers pacing and halts when `inflight >= effective_window`.
3. Verify that `check_stall/1` remains vigilant against dead sessions.

### Task 4: Verify Fullstack Reliability
**Objective:** Prove that 10 MB multi-stream transfers complete without dropped bytes.
**Files:**
- Test: `bench/run_fullstack_multistream.py`
**Steps:**
1. Test command: `python3 bench/run_fullstack_multistream.py --size 10485760 --ns 4`
2. Validate that `stalled=0` and ALL output `got=10485760`.
3. The logs from the Gateway should smoothly show CWND scaling up, ACKs arriving from the client, and graceful teardowns.

---
*End of Plan.*