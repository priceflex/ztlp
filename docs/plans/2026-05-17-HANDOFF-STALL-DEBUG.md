# Handoff: Full-stack 1 MiB Stall Debugging & Relay Handshake Blocker
**Date:** 2026-05-17
**Goal:** Fix the 1 MiB response-side stall on the `ztlp connect` (dumb-pipe) path over the AWS full-stack testbed so we can unblock C2C streaming.

---

## 1. What We Accomplished in the Last Session
* **Gateway Instrumentation:** We injected detailed `Logger.debug` and `Logger.info` calls into `gateway/lib/ztlp_gateway/session.ex` tracking `flush_send_queue`, `encrypt_and_send_stream`, `process_cumulative_ack`, and `handle_tunnel_frame`.
* **Gateway Deployment:** We successfully built and deployed a new Docker image (`ztlp-gateway:bench-2026-05-17.v2`) to the AWS Gateway instance (`54.190.82.255`).
* **Bench Harness Fixes:** Updated `bench/run_fullstack_multistream.py` to use `--service default`, matching the Gateway's mapped `ZTLP_GATEWAY_BACKENDS`.

## 2. Current Blocker: Handshake Failing at Relay
When we run `python3 bench/run_fullstack_multistream.py --size 1048576 --ns 1`, the tunnel fails to establish. It times out waiting for `HELLO_ACK` (msg2).
* **Client Behavior:** Connects to gateway `54...` via relay `44...` for service `default`. Sends `HELLO`, retransmits 5 times, then dies.
* **Relay Behavior (`44.243.42.123`):** It correctly registers the dynamic gateways (logs `Registered dynamic gateway ... service=default addr={{172, 26, *, *}, 23097}`), but **it never logs `"Forwarding HELLO"`**.
* **Hypothesis:** The Relay isn't matching the client's incoming `HELLO` to the registered `default` service, OR the client's `ztlp connect` arguments (`GATEWAY` combined with `--relay RELAY`) are constructing a `HELLO` packet that the Relay drops or cannot parse.

## 3. Next Session Action Plan

### Phase A: Fix the Handshake Routing
1. Inspect the incoming `HELLO` packets at the Relay (`lib/ztlp_relay/udp_listener.ex` specifically `forward_hello_to_gateway`).
2. Verify why the Relay drops/ignores the packet instead of forwarding it to the private IP (`172.26...`) of the registered gateway.
3. *Alternative Trap:* Does the client need `--service bench`? Ensure the `dst_svc_id` hash matches what the relay expects. Use `debug_fullstack_single_stream.sh` to isolate.

### Phase B: Diagnose the 1 MiB Stall
1. Once the handshake survives relay routing again, the 1 MiB benchmark transfer will stall at ~513 KiB.
2. Pull the Gateway logs: `ssh ubuntu@54.190.82.255 'docker logs ztlp-gateway --tail 500' | grep '\[Session\]'`
3. Look for the newly added `[Session] flush_send_queue: queue=... inflight=... cwnd=...` and `[Session] process_cumulative_ack: acked=...` markers.
4. **Identify the Halting Point:** Does the send queue fill up? Does it stall waiting on a non-existent ACK? Does it hit a backpressure limit?

### Phase C: Fix the Gateway Path
1. The Rust client (`dumb-pipe` mode) sends NO ACKs for inner stream data. 
2. The Elixir Gateway is still applying traditional `cwnd` / reliable packet windowing logic and gets stuck.
3. Modify the Elixir Gateway (`session.ex` / `send_controller.ex`) so it treats `mux_mode == false` (dumb-pipe clients) strictly as fire-and-forget: ignore `cwnd`, disable `inflight` tracking, and just blast the UDP frames without expecting ACKs.

---
*End of Handoff.*