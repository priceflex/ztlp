# ZTLP-over-QUIC Adapter Plan

**Goal:** Implement a ZTLP-over-QUIC adapter while preserving the existing ZTLP MuxEngine, NodeID routing, and identity modeling. The goal is to make the `hermes_session_handoff.md` E2E scenario complete (passwordless autologin) over QUIC. All data traffic will carry the `0x5A` magic byte indicating a ZTLP frame over the QUIC stream.
**Routing mode:** α (default production path: relay 5-tuple UDP forwarding) and β (fallback: direct to gateway)
**Target:** Autologin Rails 200 over QUIC (single backend).

**Architecture:**
- handshake: Stream 0, `0x5A` magic byte framing handling `msg1/msg2/msg3` payloads of `Noise_XX`.
- data: TCP-mapped dedicated QUIC Streams, using same `0x5A` magic byte wrapping `FRAME_DATA` packets.
- `SessionId` generation: Responder generates it and sends it out-of-band or inside `msg2` payload. Note: Since we are wrapping `msg2` which doesn't originally contain `SessionId` (it is sent in the `HandshakeHeader` via UDP), we must prepend or append it to the QUIC stream, or modify the Noise payload definition.

## Phase A — Fix the Foundation

### Task A.1: Fix `HandshakeResult` and Session ID generation
The QUIC handshake currently generates unique `SessionId` values on both the initiator and responder, meaning they derive different keys and the handshake is fundamentally broken. Since UDP `HandshakeHeader` is gone, we must send the 12-byte `SessionId` from Responder to Initiator during the handshake.

**Step 1:** Modify `HandshakeResult`
- Change `HandshakeResult` to contain a single `SessionState`. (Instead of the placeholder `initiator_session` AND `responder_session`).

**Step 2:** Modify `run_responder_handshake`
- Responder generates the 12-byte `SessionId`.
- Send it right before or after `msg2` on the QUIC stream, or modify the `write_noise_frame` serialization to include an optional 12-byte `SessionId` field when `MsgType == HelloAck`. Let's just write the raw 12 bytes to the stream *before* `msg2`'s `0x5A` frame.

**Step 3:** Modify `run_initiator_handshake`
- Initiator reads the 12-byte `SessionId` from the QUIC stream right before reading `msg2`.
- Both sides now use the identical `SessionId` to call `ctx.finalize()`.

### Task A.2: Responder NodeId Verification
- In `cmd_listen` (QUIC path), remove the `NodeId([0; 16])` dummy value.
- Since `NodeId` is derived from the static public key discovered during the handshake, use the extracted public key from `HandshakeContext` OR we pass the parsed `NodeId` after the Noise state transitions.

### Task A.3: Relay Layer 1 Drops Fix
- Apply the pending `udp_listener.ex` ETS Table patch to `34.218.240.106`.

## Phase B — Add Magic-Framed Data Plane

### Task B.1: Rename `noise_frame` helpers
- Rename `read_noise_frame` / `write_noise_frame` to `read_ztlp_frame` / `write_ztlp_frame`.
- Generalize them so they can wrap generic bytes (which will be raw TCP chunk payloads).

### Task B.2: Frame Data Plane in QUIC Paths
- In `cmd_connect` and `cmd_listen`'s QUIC TCP proxy loops, replace `tokio::io::copy` with explicit `read_ztlp_frame` / `write_ztlp_frame` loops.
- All streams now use `0x5A` `| length | data` chunks.

## Phase D — Relay 5-tuple QUIC forwarding (α-routing)

### Task D.1: Relay 5-Tuple Binding
- When the Relay receives a QUIC UDP packet, it doesn't have a `SessionId` header.
- Extend `udp_listener.ex` to identify known Client IPs using the `GATEWAY_REGISTER` state, or setup a strict NAT-forwarding rule: Gateway registers, then Relay transparently echoes all UDP packets between Client-IP:Port and Gateway-IP:Port.

## Phase E — Production Rollout & E2E

### Task E.1: Gateway HTTP Injection Fix
- Change `2026-05-20T12:00:00Z` to real dynamic `SystemTime::now()` output formatted to ISO8601.

### Task E.2: Deploy to Staging and test
- Restart gateway with `--quic` features.
- Connect via `--quic`. Test autologin Rails dashboard.
