# TODO — ZTLP Actionable Work Items

Last updated: 2026-03-25

---

## Critical — Must Fix

_None. Both tunnel reliability issues are resolved._

---

## High Priority — Should Do Soon

### Version Bump & Release Tag
- Cut a release (v0.11.4 or v0.12.0) to mark the tunnel reliability fixes
- Update CHANGELOG.md with entries for commits `9e86f50` through `50c424d`
- Update version strings in mix.exs / Cargo.toml
- Tag and push

### NsClient Concurrency
The current NsClient is a single GenServer that serializes all identity lookups.
The 2s timeout fallback (commit `50c424d`) prevents session crashes, but under
heavy load the hex-identity fallback means policy rules keyed on human-readable
names won't match. The proper fix:

- **Option A:** Worker pool — spawn N NsClient workers, round-robin dispatch
- **Option B:** Async Task per lookup — `Task.async` inside `resolve_via_ns`,
  with a short timeout. No single-process bottleneck.
- **Option C:** Pre-warm cache — on gateway startup, bulk-fetch all known
  identities from NS and cache in ETS. Only hit NsClient for cache misses.

Recommendation: Option C (pre-warm) + Option B (async fallback for misses).

### Client-Side NACK for Stalled Streams
Currently if data_seq N is lost and there's no subsequent packet, the client
has no way to signal "I'm still waiting." It relies entirely on gateway-side
retransmit timers (RTO starting at 200ms with 1.5x backoff).

A periodic "receiver keepalive" or explicit NACK would:
- Speed recovery when the final packet(s) of a response are lost
- Reduce tail latency from RTO backoff (currently can reach ~3s)
- Complement the existing gateway ARQ rather than replace it

Implementation sketch:
- Client sends a NACK frame if no new data arrives within 500ms of the last packet
- NACK contains the highest contiguous data_seq received
- Gateway treats NACK as an immediate retransmit trigger (bypass RTO timer)

### Clean Up Debug Logging
- `Listener` reject logging (commit `50c424d`) is at `Logger.debug` — harmless
  in production but should either be kept permanently or removed
- Decision: keep it. Debug-level reject logging is valuable for diagnosing
  future session failures with zero production overhead.

---

## Medium Priority — Nice to Have

### Forward Error Correction (FEC)
Sequential reliability is 98% (49/50). The remaining ~2% is genuine internet
path loss that retransmits eventually recover, but FEC could provide:
- Zero additional RTT for recovery (XOR parity packet sent with each window)
- Better tail latency on lossy paths
- Complexity cost: ~500 lines in gateway + client

Not urgent — 98% with ARQ recovery is solid. Consider if deploying over
particularly lossy links (cellular, satellite).

### PMTU Discovery
Currently hardcoded to `@max_payload_bytes 1200` (1271 bytes on wire). This
is conservative and safe, but wastes ~15% of available MTU on typical paths.

A proper PMTU discovery mechanism would:
- Probe with increasing packet sizes (binary search)
- Detect and adapt to path MTU changes
- Start conservative (1200) and grow to the path maximum
- Requires DF-bit probing and ICMP "need to fragment" handling

Low priority — the current 1200-byte cap works everywhere and the throughput
cost is minimal for typical web traffic.

### Gateway Connection Rate Limiting
No admission rate limit on new sessions. A burst of 1000 simultaneous
handshakes would create 1000 GenServer processes. Consider:
- Token bucket for new session creation (e.g., 100/sec burst, 50/sec sustained)
- Backpressure via delayed HELLO_ACK under load
- SYN-cookie equivalent (stateless HELLO response, only allocate state on msg3)

### Relay L2 Drop Investigation
Relay stats show `dropped_l2` accumulating over time. These are session lookup
failures — packets arrive for session IDs the relay doesn't know about.
Likely causes:
- Packets arriving after session cleanup (benign, client retrying a dead session)
- Stale NAT mappings forwarding old traffic
- Not a bug, but worth monitoring. Consider logging at debug level.

---

## Low Priority — Future Work

### Test Coverage for Reliability Fixes
- Regression test: verify packets > 1200 bytes are chunked (not sent raw)
- Regression test: concurrent NsClient lookups don't crash sessions
- Load test: sustained concurrent connections (100+) over minutes

### Gateway Pacing Tuning
Current pacing interval is 2ms (`@pacing_interval_ms 2`). This was chosen
to avoid overwhelming the relay/client but hasn't been profiled. Consider:
- Adaptive pacing based on measured RTT
- Congestion-aware window sizing
- Per-session pacing (currently global timer)

### Relay Gateway Address Migration — Hardening
The relay's `handle_admitted_packet` now updates `peer_b` when a known
gateway IP sends from a new port. This self-healing is correct but could
be tightened:
- Rate limit address migrations (max 1 per session per 10s)
- Log address migrations for audit trail
- Consider requiring the gateway to signal address changes explicitly

---

## Completed (This Session — 2026-03-24/25)

- [x] Gateway ARQ: send buffer, retransmit with RTO backoff, ACK processing
- [x] Gateway paced send queue (window_size=8, 2ms interval)
- [x] Gateway drain mode (FIN triggers remaining-packets flush)
- [x] Gateway re-encrypt on retransmit (fresh nonce, no anti-replay violation)
- [x] Relay address migration (known_gateway_ips + peer_b update)
- [x] Client reassembly buffer init at seq 0
- [x] Path MTU fix: `@max_payload_bytes 1200` (1271 bytes on wire)
- [x] NsClient timeout fix: 2s timeout + graceful fallback to hex identity
- [x] 4MB UDP socket buffers on gateway listener
- [x] Reject logging on gateway listener (debug level)

## Commits
- `9e86f50` — relay address migration, gateway paced ARQ, re-encrypt retransmits
- `95ad19d` — reassembly seq 0 init + gateway drain mode
- `d554ba0` — KCP-inspired ARQ send buffer + retransmit
- `04c4d42` — cap payload to 1200 bytes for path MTU safety
- `50c424d` — prevent NsClient timeout from crashing concurrent sessions
