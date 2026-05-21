# Diagnosis: 1 MiB Single-Stream Response-Side Stall

We successfully instrumented the gateway (Task 3) and captured the exact stall mechanics (Task 2 & 4) on the AWS testbed using `ztlp connect` via `run_fullstack_multistream.py`.

The stall is a fundamental architectural conflict between the `main` branch Rust code and the legacy Elixir gateway, exposed by the Nebula Pivot:

1. **The Rust Client is a Dumb Pipe:** `ztlp connect` on `main` runs the `run_bridge (nebula dumb-pipe)`. As per the pivot design in `proto/src/mux.rs`, the client generates and sends **ZERO** ZTLP ACKs (`acks_sent=0`). Furthermore, it has no `recv_window` to deduplicate incoming `FRAME_DATA` packets.
2. **The Gateway is Reliable:** The Elixir Gateway still implements the legacy ZTLP reliability layer. It sends packets until it fills its `cwnd` (defaulting to 64 packets, approx. 73 KiB), and then **halts** in `flush_send_queue()` waiting for ACKs.
3. **The Duplication Loop:** Since the client sends no ACKs, the gateway permanently stalls its window forwarding. It then hits its RTO timer and blindly retransmits the same 64 packets. The dumb-pipe Rust client receives these duplicates, doesn't deduplicate them, and pushes them straight into the local TCP stream to `curl`.
4. **The `~513 KiB` Symptom:** `curl` receives ~73 KiB of proper payload, followed by multiple repeats of that exact same 73 KiB chunk. Once the gateway's 30-second `STALL` timeout fires, the gateway kills the session. `curl` eventually times out at 90s having received ~500 KiB of duplicated garbage, waiting for the remainder of the 1 MiB `Content-Length`.
5. **The WAN Drop Reality:** If we strip the Gateway's reliable layer (removing `cwnd` gating) to match the Nebula pivot, the gateway easily blasts the full 1 MiB. However, on the AWS WAN, ~3-4% of UDP packets naturally drop. Because `ztlp connect` is a mere stream proxy that unwraps packets into raw TCP streams, the dropped packets create permanent holes in the HTTP response. Without an end-to-end TCP layer (like the iOS NE `utun` provides) or a ZTLP reliability layer, `curl` will always corrupt or stall on dropped datagram chunks.

## Conclusion for Task 4
We cannot fix the `run_fullstack_multistream.py` bench script for >64 KiB sizes without either:
A. Reverting the Nebula pivot on the Rust CLI client (`ztlp connect`).
B. Embedding a user-space TCP stack (like `smoltcp` or `ShadowSocks` layered protocol) inside `ztlp connect`.
