# ZTLP iOS Status — 2026-04-08 Session 4

## Current State: 8/11 → Testing Two Fixes

**Branch:** main
**Latest commits:**
- `0b4c1f6` fix: ACK fast-path — bypass recv_window HOL blocking for ACK frames
- `6c4b266` fix: activity-aware keepalive — don't kill tunnel during active data transfer
**Gateway image:** `ztlp-gateway:ack-fastpath` on 54.149.48.6

## What Was Fixed This Session

### Bug 1 (iOS): Keepalive kills tunnel during active data transfer

**Root cause:** The keepalive timer (25s) called `bridge.send()` during heavy
benchmark I/O. When the tokio send path was saturated, the send failed, which
IMMEDIATELY triggered `scheduleReconnect()`. The reconnect called
`disconnectTransport()`, tearing down the WORKING connection. The reconnect
handshake then failed (gateway rejects unknown session), cascading to 10
failures and tunnel death at ~2:45 into the benchmark.

**Evidence:**
- Gateway logs showed `REJECTED: reason=unknown_session` every 5 seconds for
  the entire benchmark duration — these were the NE's reconnect attempts
- Phone syslog: "Failed to reconnect after 10 attempts" at 14:18:45
- All data transfer was healthy (zero stalls, 129MB downloaded, cwnd=32)
  until the keepalive killed it

**Fix (PacketTunnelProvider.swift):**
- Track `lastDataActivity` from readPacketLoop/flushOutboundPackets
- When data flowed within 60s: skip keepalive send entirely (connection alive)
- When idle: require 3 consecutive failures before triggering reconnect
- Reset failure counters when real data flows
- **Commit:** `6c4b266`

### Bug 2 (Gateway): ACK head-of-line blocking causes 30s stall

**Root cause:** The phone sends re-ACKs for duplicate data via the ACK callback
socket. These re-ACKs share the same pkt_seq space as upload data (same
`send_seq_counter`). The gateway's recv_window delivers packets in-order — if
an upload data packet was lost/delayed, ALL subsequent packets (including
re-ACKs) are buffered behind the gap and never delivered to the ACK handler.

The failure mode:
1. Gateway's RTO fires, retransmits 8 oldest data_seqs per tick
2. Phone already has those data_seqs → marks as DUPLICATE
3. Phone sends re-ACK (ack_seq=44679) that would unblock the gateway
4. Re-ACK arrives at gateway with pkt_seq 6937 → goes into recv_buffer
5. But recv_window_base is stuck at 6933 (missing upload packet)
6. Re-ACK sits in buffer, never processed → gateway never sees ACK advance
7. 30 seconds pass → STALL → gateway tears down session

**Evidence:**
- Gateway: `STALL: no ACK advance for 30s inflight=32 last_acked=44647
  recv_base=6933 recovery=true`
- Phone: `DUPLICATE data_seq=44678 (expected=44680)`
- Gateway: 50+ `PKT_IN_RECOVERY` entries (re-ACKs stuck behind window gap)
- Zero `CLIENT_ACK` entries after 44647 despite phone sending re-ACKs

**Fix (session.ex — two parts):**

1. **ACK fast-path:** After decrypting a packet, check if it's an ACK frame
   (`0x01` + 8+ bytes). If so, process it immediately via `handle_tunnel_frame`
   WITHOUT waiting for in-order delivery. ACK frames carry no data — they only
   advance the send window. Added `advance_recv_window_base()` to skip ACK-only
   seq slots so they don't permanently block the window.

2. **RTO retransmit priority:** When RTO fires, prioritize retransmitting
   `last_acked + 1` (the first packet the client is missing per its cumulative
   ACK) instead of blindly sending the N lowest data_seqs. This ensures the
   actual missing packet gets retransmitted in the first tick.

**Commit:** `0b4c1f6`

## Architecture After Fixes

```
Phone recv_loop:
  recv_data → decrypt → process frame
    │
    ├─ FRAME_DATA (in-order): deliver to VIP proxy, ACK
    ├─ FRAME_DATA (duplicate): re-ACK via callback (rate-limited 20ms)
    │   └─ send_ack_frame! → NWConnection callback → gateway
    └─ Need to ACK? → callback-only path (no transport send)

Phone keepalive timer (25s):
  ├─ Data active within 60s? → SKIP (don't contend with data path)
  ├─ Data idle → send keepalive
  │   ├─ Success → reset failure counter
  │   └─ Failure → increment counter
  │       └─ 3 consecutive + no data? → scheduleReconnect()
  └─ Any real data flow → reset counter to 0

Gateway recv_window:
  packet arrives → parse → decrypt
    │
    ├─ ACK frame? → FAST PATH: process immediately
    │   └─ handle_tunnel_frame() → process_cumulative_ack()
    │       → advance last_acked → clear send_buffer
    │
    └─ Data frame? → buffer for in-order delivery
        └─ deliver_recv_window_loop() → handle_tunnel_frame()

Gateway RTO retransmit:
  timer fires → find expired packets
    │
    ├─ Priority: data_seq == last_acked+1 (most likely missing)
    └─ Fill remaining budget from lowest data_seq
```

## Gateway Deployment

```bash
# Current image
docker run -d --name ztlp-gateway --restart unless-stopped \
  --network host --env-file /etc/ztlp/gateway.env \
  ztlp-gateway:ack-fastpath

# IMPORTANT: --env-file /etc/ztlp/gateway.env is REQUIRED
# Contains: ZTLP_GATEWAY_PORT, POLICIES, BACKENDS, RELAY, NS
# Without it: wrong port, no relay registration, policy denials

# To rollback:
docker stop ztlp-gateway && docker rm ztlp-gateway
docker run -d --name ztlp-gateway --restart unless-stopped \
  --network host --env-file /etc/ztlp/gateway.env \
  ztlp-gateway:debug-logging3
```

## What's Next

### Immediate: Verify both fixes with benchmark
Run the full 11-test benchmark. Expected outcomes:
- Keepalive fix: tunnel stays alive through entire benchmark
- ACK fast-path: no 30s stalls on duplicate retransmits
- Target: 11/11 or close

### If still failing:
1. Check gateway logs for `STALL` or `REJECTED` patterns
2. Check phone syslog for `Failed to reconnect`
3. If ACK fast-path doesn't trigger: verify the re-ACK from the phone
   is actually a `0x01 + 8 byte` FRAME_ACK (not a FRAME_DATA)
4. If policy denials: ensure `--env-file /etc/ztlp/gateway.env` is passed

### Remaining known issues:
- **BELOW_BASE flood:** Phone retransmits upload packets with stale seqs
  after data transfer completes. Harmless but noisy.
- **REJECTED stale sessions:** Old session IDs (from previous VPN connections)
  still send keepalives every 5s. The NE doesn't clean up old sessions.

## Key Files Changed

- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` — keepalive + activity tracking
- `gateway/lib/ztlp_gateway/session.ex` — ACK fast-path + RTO priority

## Environment

- Steve's Mac: stevenprice@10.78.72.234
- Gateway: ubuntu@54.149.48.6 (docker: ztlp-gateway:ack-fastpath)
- Relay: ubuntu@34.219.64.205
- NS: 34.217.62.46
- Gateway env: /etc/ztlp/gateway.env
- Rust: $HOME/.cargo/bin (NOT homebrew)
- Phone UDID: 00008130-000255C11A88001C
