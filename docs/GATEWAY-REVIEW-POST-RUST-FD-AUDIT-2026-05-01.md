# Gateway Review After Rust FD Migration Work — 2026-05-01

## Purpose

This note captures the current repo-grounded reasoning for re-evaluating gateway-side tuning that may have been added to protect the older Swift `packetFlow` iOS path, and may no longer all be necessary as the iOS work shifted toward the Rust-fd-owned tunnel path.

This is a review/audit document, not a recommendation to immediately remove anything.

## Executive Summary

Yes — there are gateway-side changes from the pre-Rust-fd phase that are worth re-evaluating.

But they fall into three categories:

1. `Correctness / safety fixes` — likely still needed regardless of iOS data-plane architecture.
2. `Client-protection / browser-fanout compensations` — strongest candidates to revisit now.
3. `Observability / diagnostics` — generally safe to keep.

The most likely gateway changes to revisit are the browser-fanout / queue / mux caps, not the recovery or session-correctness fixes.

## Relevant Gateway Commits

These are the main gateway-relevant commits in the period after the older replay/RTO work and before/through the iOS Rust-fd transition:

- `1f45a37` — `fix: keep gateway send queue shallow for mobile`
- `003d061` — `gateway: exit recovery when ack reaches last sent packet`
- `7493f09` — `gateway: increase send_queue backpressure thresholds 256->2048, 64->512`
- `743fdc4` — `fix: harden gateway session replacement cleanup`
- `d9b40d3` — `fix: harden mux backpressure for iOS browser fan-out`
- `b93ccbe` — `fix: handle mobile unknown rto and detect NE interface`
- `61a115d` — `ios+gateway: Nebula-style session health recovery`

## Current Gateway State in Code

Current relevant settings in `gateway/lib/ztlp_gateway/session.ex`:

- `@queue_high 512`
- `@queue_low 128`
- `@max_mux_streams 32`
- `@max_connecting_buffer_bytes 65_536`
- `peer_rwnd` support enabled
- effective send window gated by:
  - `min(cwnd, cc_max_cwnd, peer_rwnd)`
- mobile + unknown interface profile still maps to conservative mobile RTO values

Important observation:

The current gateway is already not the earlier highly permissive queue version. Some earlier relaxations were later tightened again.

## Category 1 — Changes Probably Still Needed

These do not look like “old Swift path hacks.” They look like protocol/session correctness fixes.

### 1. Session replacement cleanup hardening
Commit:
- `743fdc4`

What it does:
- Ensures stale cleanup from an old session cannot erase/poison a replacement session that reused the same client address.

Why it likely still matters:
- This is independent of Swift `packetFlow` vs Rust fd path.
- It addresses session ownership/routing correctness.

Recommendation:
- Keep.

### 2. Recovery exit when ACK reaches last sent packet
Commit:
- `003d061`

What it does:
- Lets recovery exit cleanly once ACK state catches up to the intended target.

Why it likely still matters:
- This is recovery correctness, not a client-path-specific workaround.

Recommendation:
- Keep.

### 3. Mobile unknown RTO handling
Commit:
- `b93ccbe`
- background related: `0def454`

What it does:
- Ensures `mobile + unknown` clients use conservative mobile RTO values instead of accidentally falling into desktop-ish timing.

Why it likely still matters:
- This is still valuable whenever the client reports mobile but interface detection is unknown or imperfect.
- Not obviously tied to the old Swift-only hot path.

Recommendation:
- Probably keep.

### 4. Receiver window (`peer_rwnd`) support on the gateway
Current code behavior:
- ACKs can carry rwnd
- session state tracks `peer_rwnd`
- gateway egress uses `min(cwnd, cc_max_cwnd, peer_rwnd)`

Why it likely still matters:
- If the client advertises receive capacity, the gateway should continue honoring it.
- A healthier Rust fd path may justify different rwnd values from the client, but gateway-side support remains useful.

Recommendation:
- Keep.

## Category 2 — Best Candidates to Re-Evaluate

These are the most plausible “we added this because the old iOS path was fragile” controls.

### 1. Send queue backpressure thresholds
History:
- `7493f09` raised thresholds significantly.
- later work moved toward shallower queues again.

Current values:
- `@queue_high 512`
- `@queue_low 128`

Why revisit:
- These values were clearly tuned during a period where iOS browser traffic could destabilize badly.
- If the Rust fd path drains more reliably, the gateway may no longer need to be this conservative.
- Or the thresholds may still be correct for browser fanout independent of the client path.

Recommendation:
- Strong candidate for controlled re-testing.
- Do not remove blindly.

### 2. Max mux streams cap
Current value:
- `@max_mux_streams 32`

Why revisit:
- This is an explicit browser-fanout guardrail.
- It may have been introduced because the old client path got sick when too many streams opened concurrently.
- A stronger Rust fd path may support higher concurrency.

Risk:
- Raising/removing too early could reintroduce the original fanout collapse.

Recommendation:
- Re-evaluate carefully with controlled testing.

### 3. Connecting buffer cap
Current value:
- `@max_connecting_buffer_bytes 65_536`

Why revisit:
- This is another protective cap aimed at stream-open churn and backend buffering during connect.
- It may have been compensating for fragile client behavior under browser-style load.

Recommendation:
- Candidate to revisit after queue threshold review.

### 4. Early queue-based chunk enqueue halting
Current code:
- `enqueue_stream_chunks/3` stops enqueuing more chunks when queue length reaches `@queue_high`.

Why revisit:
- This is a strong protective behavior to prevent queue ballooning.
- It may be suppressing useful throughput more than necessary if the new iOS path can safely absorb more sustained fanout.

Recommendation:
- Audit carefully before changing.
- Good candidate for staged experiments rather than full removal.

## Category 3 — Probably Fine to Keep

These changes are mostly observability or control-plane support and do not look like likely sources of unnecessary restriction.

Examples:
- probe ping/pong support
- richer stall logging
- close reason logging
- ACK/rwnd logging
- stream dump diagnostics

Recommendation:
- Keep unless there is a concrete reason to reduce logging noise.

## Practical Interpretation

If the question is:

> “Did we add gateway restrictions mainly because the old Swift packetFlow path was weak, and should we now re-check those?”

Then the answer is:

Yes — but mostly for the browser-fanout / queue / mux-cap protections, not for the correctness fixes.

The most likely “old-path baggage” to revisit is:
- queue thresholds
- mux stream cap
- connecting buffer cap
- queue-based send truncation / shallowing behavior

The least likely to be obsolete is:
- session replacement cleanup hardening
- recovery exit fix
- mobile unknown RTO fix
- peer_rwnd support

## Suggested Review Order

If we want to review or test this safely, the best order is probably:

1. Audit current queue behavior under browser/multi-stream load
2. Re-evaluate `@queue_high` / `@queue_low`
3. Re-evaluate `@max_mux_streams`
4. Re-evaluate `@max_connecting_buffer_bytes`
5. Re-evaluate enqueue-halting behavior

And leave these alone unless strong evidence appears:
- session replacement cleanup
- recovery exit logic
- mobile unknown RTO selection
- peer_rwnd support

## Bottom Line

The repo supports the idea that there is likely some gateway conservatism left over from protecting the older iOS Swift hot path.

But the right target for re-evaluation is not the correctness logic.
The right target is the gateway’s browser-fanout and shallow-queue guardrails.

Those are the changes most likely to have become overly conservative if the Rust fd iOS path is now healthier.
