# Plan: Fix Browser/Vault Tunnel Crash (Mux Fan-Out & Backpressure Collapse)

## Context
When loading highly concurrent traffic like a browser through the ZTLP tunnel, the connection stalls and drops after 30 seconds. The log indicates a gateway send queue explosion (8751 items), no ACK progress, and severe NE memory pressure (20-31MB). 

## Root Cause Analysis
1. **Unbounded Mux Steam Creation:** The iOS NE `PacketTunnelProvider` reads `OpenStream` actions and blindly forwards them to the Gateway via `tunnelConnection.sendData()` without limits.
2. **Gateway Backpressure Bypass:** On the Gateway (`session.ex`), backpressure triggers at `@queue_high 256` by pausing active backend reads. *However*, newly minted streams start in an asynchronous `:connecting` state where payload data is buffered unbounded. When they connect, they all instantly flush and backend servers reply rapidly, bypassing the backpressure state and exploding the `send_queue`.
3. **ACK Starvation:** The iOS NE spends all of its CPU/memory enqueuing outbound `SendData` requests from the utun, causing it to fall behind on parsing inbound UDP packets. Consequently, it stops emitting `FRAME_ACK`s, the Gateway closes its congestion window (`cwnd`), and the session hits the 30-second STALL timeout.

## Fix Implementation Steps (For the Next Session)

### Phase 1: Gateway Backpressure Strengthening (`gateway/lib/ztlp_gateway/session.ex`)
1. **Throttle Async Connections:** Modify the `open_mux_stream` logic to reject or gracefully delay `FRAME_OPEN` if the `queue_len` is already beyond `@queue_high`.
   - *Current Bug:* Even if the queue is full, the system accepts `FRAME_OPEN`, starts a `BackendPool.checkout`, and queues boundless bytes to `stream.buffer`.
2. **Buffer Limits:** Introduce a hard cap on `stream.buffer` size during the `:connecting` state. If a client transmits too much early data before the backend connects, drop the stream to protect gateway memory.
3. **Concurrent Stream Cap:** Add a hard `@max_mux_streams` limit so browser fan-out cannot create unbounded concurrent `:connecting` + `:connected` streams before the queue high-watermark engages.
4. **Paused-On-Connect Behavior:** If `backends_paused` is already true when a backend connect completes, immediately pause reads on that backend before letting it contribute more response traffic.

### Phase 2: iOS NE Congestion / Fairness (`ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`)
1. **Paced `flushOutboundPackets`:** `processRouterActions` should not execute an infinite while loop of `tunnelConnection.sendData()` if the tunnel socket is overloaded. Limit the number of packets processed per `readPacketLoop` cycle so the runloop can breathe and process inbound UDP ACKs.
2. **Memory Monitoring check prior to stream open:** Ensure the NE `packetFlow.readPackets` pauses or drops `AF_INET` TCP SYNs if the resident memory crosses a safe threshold. (e.g. keeping it well under 15MB limits).
3. **Backpressure-Aware Action Sending:** If `tunnelConnection.sendData()` is overloaded, stop consuming more router actions in that cycle instead of firehosing additional `FRAME_OPEN`/`FRAME_DATA` blindly.

### Phase 3: Validation Protocol
1. Re-run identical Browser/Vault usage via Steve's setup. 
2. Tail the `ztlp-gateway` docker logs: ensure `send_queue` no longer explodes into 8000+.
3. Verify the Gateway's `pacing_tick` logs display `open=true` consistently and the `inflight` values drain smoothly without hitting `last_acked` stalls.
4. Confirm iOS tunnel logs show throttling/yield behavior instead of runaway router loops, and resident memory remains below the old crash range.

