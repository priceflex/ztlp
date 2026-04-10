# Wire In AdvancedCongestionController — Task Specification

**Status:** ✅ Complete (v0.8.0, commit `167c971`)

## Overview

Replace the simple `CongestionController` in `tunnel.rs` with the `AdvancedCongestionController` from `congestion.rs`. The advanced controller provides PRR (Proportional Rate Reduction), SACK scoreboard, token bucket pacing, Eifel spurious detection, and proper Jacobson/Karels RTT — all of which are needed to handle high-loss scenarios.

## Current Architecture

### Simple CC in `tunnel.rs` (lines 611-795)
- `CongestionController` struct with fields: `cwnd`, `ssthresh`, `srtt_ms`, `rttvar_ms`, `rto_ms`, `dup_ack_count`, `state` (SlowStart/CongestionAvoidance/FastRecovery), `loss_in_rtt`, `last_loss_rtt_id`
- Methods: `new()`, `effective_window()`, `on_ack(newly_acked, ack_seq) -> AckAction`, `on_dup_ack(ack_seq) -> AckAction`, `on_loss()`, `on_corruption()`, `update_rtt(sample)`, `nack_threshold()`
- Used as `Arc<Mutex<CongestionController>>` shared between sender and receiver tasks
- Sender reads: `effective_window()`, `rto_ms`, `cwnd`, `ssthresh`, `srtt_ms`
- Sender writes: `on_loss()` (on NACK retransmit + RTO stall)
- Receiver writes: `update_rtt()`, `on_ack()`, `on_dup_ack()`, `on_corruption()`, `on_loss()` (on legacy NACK)

### Advanced CC in `congestion.rs` (lines 730-980)
- `AdvancedCongestionController` with fields: `cwnd`, `ssthresh`, `phase` (SlowStart/CongestionAvoidance/Recovery), `rtt: RttEstimator`, `pacer: TokenBucketPacer`, `spurious: SpuriousDetector`, `scoreboard: SackScoreboard`, `retransmit_tracker: RetransmitTracker`, PRR state, fast retransmit state, diagnostics
- Methods: `new()`, `effective_window()`, `on_ack(newly_acked)`, `on_loss(highest_sent_seq)`, `on_rto()`, `on_nack_received(missing_seqs) -> bool`, `on_spurious_detected()`, `update_rtt(sample)`, `gap_threshold()`, `nack_interval()`, `rto_ms()`, `srtt_ms()`, `paced_send_count(requested)`

## Changes Required

### 1. Update constants in `congestion.rs` to match v0.8 tuning

The tunnel.rs simple CC was tuned in v0.8. Apply the same tuning to `congestion.rs`:

```rust
// Change in congestion.rs:
pub const INITIAL_CWND: f64 = 10.0;      // was 64.0 — RFC 6928 IW10
pub const INITIAL_SSTHRESH: f64 = 65535.0; // was 256.0 — start unlimited
pub const MAX_RTO_MS: f64 = 4000.0;      // was 60000.0 — 4s cap
pub const SEND_WINDOW: u64 = 65535;      // was 2048 — large BDP
pub const RETRANSMIT_BUF_MAX: usize = 65536; // was 4096 — match window
```

Also update `TokenBucketPacer::new()` to use the new INITIAL_CWND value.

### 2. Replace CongestionController with AdvancedCongestionController in tunnel.rs

#### Shared state type change (line ~1271)
```rust
// Before:
let congestion: Arc<Mutex<CongestionController>> = Arc::new(Mutex::new(CongestionController::new()));

// After:
use crate::congestion::AdvancedCongestionController;
let congestion: Arc<Mutex<AdvancedCongestionController>> = Arc::new(Mutex::new(AdvancedCongestionController::new()));
```

#### Sender-side changes

**NACK loss handler** (lines ~1339, ~1414): Change `cc.on_loss()` to `cc.on_loss(Some(data_seq))` — the advanced CC needs the highest sent seq to track recovery completion.

**Window check** (line ~1508): `cc.effective_window()` — same API, no change needed.

**RTO stall** (lines ~1548-1563): Replace:
```rust
cc.on_loss();
cc.rto_ms = (cc.rto_ms * 2.0).min(MAX_RTO_MS);
```
With:
```rust
cc.on_rto();
```
The advanced CC handles backoff internally via `RttEstimator::on_rto_timeout()`.

**Stats reporting** (line ~2391): Change `cc.srtt_ms` and `cc.rto_ms` to `cc.srtt_ms()` and `cc.rto_ms()` (method calls instead of field access on the advanced CC).

#### Receiver-side changes

**RTT update** (lines ~2117, ~2234): Change `cc.update_rtt(sample)` — same API, no change.

**ACK handling** (lines ~2119-2130): Replace:
```rust
// For ACK:
let action = cc.on_ack(newly_acked, acked_seq);
// For dup ACK:
let action = cc.on_dup_ack(acked_seq);
```
With:
```rust
// For ACK:
cc.on_ack(newly_acked);
// For dup ACK: the advanced CC doesn't have on_dup_ack — it uses the SACK scoreboard instead.
// Dup ACKs in the tunnel are already handled by the NACK/SACK processing below.
```

Note: The `AckAction::FastRetransmit` return value from `on_dup_ack()` was used to trigger retransmit. With the advanced CC, fast retransmit is triggered by `on_nack_received()` returning true. Wire this up in the NACK handler.

**NACK handling** (line ~2157): Replace:
```rust
cc.on_loss();
```
With:
```rust
let should_fast_retransmit = cc.on_nack_received(&missing_seqs);
if should_fast_retransmit {
    cc.on_loss(Some(highest_sent_seq));
}
```

**SACK handling** (lines ~2234-2245): Add scoreboard update:
```rust
cc.scoreboard.update_from_sack(sack_cum_ack, &sack_ranges);
cc.on_ack(newly_acked);
```

**Corruption NACK handling** (line ~2179): The advanced CC doesn't have `on_corruption()`. Corruption NACKs should trigger retransmit WITHOUT calling `on_loss()`. Keep the current behavior — just send the retransmit request to the sender channel without touching the CC.

#### SACK scoreboard integration for retransmit

In the sender's retransmit handling, use the scoreboard to skip packets the receiver already has:
```rust
for nack_data_seq in &nack_seqs {
    // Skip if scoreboard says receiver already has it
    {
        let cc = congestion_sender.lock().await;
        if cc.scoreboard.is_acked(*nack_data_seq) {
            debug!("skipping retransmit for data_seq {} (SACK'd)", nack_data_seq);
            continue;
        }
    }
    // ... existing retransmit logic ...
}
```

#### Pacing integration

In the sender's per-packet flow control (line ~1508), add pacing:
```rust
let (effective_window, paced) = {
    let mut cc = congestion_sender.lock().await;
    let ew = cc.effective_window();
    let paced = cc.paced_send_count(remaining_chunks);
    (ew, paced)
};
// Use min(window_avail, paced) as the actual send count
```

#### Spurious detection integration

When the receiver processes an ACK for a retransmitted packet:
```rust
{
    let mut cc = congestion_receiver.lock().await;
    if cc.spurious.check_ack(acked_seq) {
        cc.on_spurious_detected();
    }
}
```

And when the sender retransmits, record it:
```rust
{
    let mut cc = congestion_sender.lock().await;
    cc.spurious.record_retransmit(*nack_data_seq, cc.srtt_ms());
}
```

### 3. Remove the old CongestionController

Delete the `CongestionController` struct, `CongestionState` enum, `AckAction` enum, and all their implementations from `tunnel.rs` (lines 611-795). Keep the constants that aren't in `congestion.rs` (like `SEND_WINDOW`, `REASSEMBLY_MAX_BUFFERED`, etc.).

Actually — **don't delete yet**. Move the old code to a `#[cfg(test)]` block or comment it out. The old tests reference it. Better: update the existing tests to use the new controller.

### 4. Update tests

The existing tunnel tests that use `CongestionController` need to be updated to use `AdvancedCongestionController`. The tests are:
- `test_congestion_slow_start` → use `AdvancedCongestionController::on_ack()`
- `test_congestion_on_loss` → use `on_loss(None)` 
- `test_congestion_rtt_estimation` → use `cc.rtt.update()` and `cc.rtt.srtt_ms()`
- `test_congestion_rto_clamping` → use `cc.rtt.update()` and `cc.rtt.rto_ms()`
- `test_congestion_effective_window_capped` → same API
- `test_congestion_nack_threshold` → use `cc.gap_threshold()` (returns Duration)
- `test_congestion_dup_ack_fast_recovery` → use `on_nack_received()` + `on_loss()`
- `test_congestion_on_corruption_no_cwnd_change` → remove (advanced CC doesn't have on_corruption)
- `test_congestion_on_loss_dedup` → use `on_loss()` dedup in Recovery phase
- `test_congestion_full_lifecycle` → rewrite using advanced CC API

### 5. Wire format — no changes

The SACK frame (0x05) and NACK frame (0x03) wire formats are already defined and used by both the tunnel and the congestion module. No wire format changes needed.

## Key API Differences

| Operation | Old `CongestionController` | New `AdvancedCongestionController` |
|-----------|---------------------------|-----------------------------------|
| Create | `CongestionController::new()` | `AdvancedCongestionController::new()` |
| Window | `cc.effective_window()` | `cc.effective_window()` ✅ same |
| ACK | `cc.on_ack(newly_acked, ack_seq) -> AckAction` | `cc.on_ack(newly_acked)` (no return) |
| Dup ACK | `cc.on_dup_ack(ack_seq) -> AckAction` | N/A — use `on_nack_received()` |
| Loss | `cc.on_loss()` | `cc.on_loss(highest_sent_seq)` |
| RTO | `cc.on_loss(); cc.rto_ms = cc.rto_ms * 2` | `cc.on_rto()` |
| Corruption | `cc.on_corruption()` (no-op) | N/A — just retransmit, skip CC |
| RTT | `cc.update_rtt(ms)` | `cc.update_rtt(ms)` ✅ same |
| Read SRTT | `cc.srtt_ms` (field) | `cc.srtt_ms()` (method) |
| Read RTO | `cc.rto_ms` (field) | `cc.rto_ms()` (method) |
| Read cwnd | `cc.cwnd` (field) | `cc.cwnd` (field) ✅ same |
| Read ssthresh | `cc.ssthresh` (field) | `cc.ssthresh` (field) ✅ same |
| NACK threshold | `cc.nack_threshold()` | `cc.gap_threshold()` (returns Duration) |
| Phase | `cc.state` (CongestionState) | `cc.phase` (CongestionPhase) |

## Execution Steps

1. `export PATH="$HOME/.cargo/bin:$PATH"`
2. First update constants in `congestion.rs` (IW10, unlimited ssthresh, 4s RTO, 65K window)
3. Then update `tunnel.rs`: replace type, update all call sites, integrate scoreboard/pacing/spurious
4. Update or rewrite tunnel CC tests  
5. `cargo fmt`
6. `cargo clippy -- -D warnings`
7. `cargo test` — all existing + updated tests must pass
8. `cd ../relay && mix test` + `cd ../ns && mix test` + `cd ../gateway && mix test`
9. Report: test counts, any issues encountered, specific changes made

## CRITICAL: Do Not Change
- Wire format (packet headers, frame types)
- Handshake code
- Reassembly buffer logic
- Pipeline/session management
- Any files outside `proto/src/tunnel.rs` and `proto/src/congestion.rs`
- Keep `FRAME_CORRUPTION_NACK` (0x09) behavior: retransmit without CC penalty

## Git
- Do NOT commit — the parent session will handle git operations
- Just make the code changes, format, and test
