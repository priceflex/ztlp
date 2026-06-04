# `ztlp connect` Auto-Reconnect Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** When the QUIC session underneath `ztlp connect` dies (gateway restart, network blip, NAT timeout), the client must rebuild the session automatically instead of leaving a zombie TCP listener that resets every fresh connection.

**Architecture:** Wrap the existing QUIC-dial + TCP-accept-loop in `cmd_connect` with a supervisor loop that detects connection loss and re-dials with exponential backoff. The TCP listener stays bound across reconnects so the user's downstream client (SSH, mstsc, etc.) sees a brief stall instead of a hard reset.

**Tech Stack:** Rust 1.85+, tokio, `quinn::Connection::closed()` for failure detection, existing `QuicEndpoint::connect_with_socket` for re-dialing.

---

## Why this is needed (the actual observed failure)

**Concrete repro from 2026-06-03:**

| Time (UTC) | Event |
|---|---|
| 2026-06-02 17:14 | Old `ztlp connect TRSDC.tech-rockstars.trs.ztlp` started on bench (PID 753656). QUIC session up, port 2298 bound. |
| 2026-06-03 12:03 | TRSDC scheduled reboot fires (`TRS Maintenance Reboot` task). |
| 2026-06-03 12:13 | `Z2LS_CHEF_STARTUP` task converges; restarts `ztlp_listener` service. |
| 2026-06-03 12:14 | New `ztlp.exe` PID on TRSDC; v0.34.8 heartbeat republishes NS records; relay re-registration resumes. |
| 2026-06-03 15:30 | User attempts `ssh -p 2298 trs\trs@127.0.0.1` → **Connection reset by peer**. |

The bench-side `ztlp connect` process never died — it just held a dead `quinn::Connection` handle. Every fresh TCP accept opened a `q_send/q_recv` stream against the dead connection, which immediately errored with `Connection("timed out")` or `closed by peer: 0`. The existing code (line 3617 in `ztlp-cli.rs`) catches this and logs *"Stop and re-run `ztlp connect` to re-establish."* — a polite admission that auto-reconnect doesn't exist yet.

**The gateway side of the system worked perfectly.** NS refresh, relay re-registration, listener restart all fired on schedule. The single broken thing is the client process.

**TRSDC reboots every 24h on schedule. Without this fix, every tunnel-using bench needs to manually re-run `ztlp connect` once per day, and any background script using the tunnel breaks silently at 04:03 PST.**

---

## What Already Exists (do not rebuild)

Greped `proto/src/` before writing this plan:

- **QUIC keepalive defaults**: `quic_transport.rs:157-161` — 15s keepalive, 60s idle ceiling. **Works correctly while the session lives**. Cannot resurrect a session torn down by the peer.
- **Mobile reconnect policy schema**: `mobile.rs:332-368` — `MobileConfig { auto_reconnect: bool, reconnect_delay_ms: u64, max_reconnect_attempts: u32 }`. Defines policy but no shared reconnect loop. iOS NE consumes these via FFI; the CLI does not.
- **Failure-backoff helper pattern**: `agent/renewal.rs:381-391` — `compute_failure_backoff(consecutive_failures: u32) -> Duration`. Linear 1-5min, then capped. Good model to follow.
- **Existing connection-died diagnostic**: `ztlp-cli.rs:3617-3624` — the comment block already names this exact failure mode. We replace the diagnostic with a real recovery path.
- **`ConnectionState` enum** with `Reconnecting = 4` (`mobile.rs:380-393`) — already designed for this state machine.

What does not exist:
- Reconnect loop wrapping `QuicEndpoint::connect_with_socket` + the TCP-accept-loop in `cmd_connect`.
- Detection of `quinn::Connection::closed()` triggering re-dial.
- TCP listener lifetime that outlives a single QUIC session.

---

## Highest Risk

**Risk: existing in-flight TCP connections during reconnect.**

When the QUIC session dies, the bench may have N open TCP connections to `127.0.0.1:2298` (e.g. an active SSH session). Each holds a `tcp::split()` half wired to a now-dead QUIC stream. Three policies:

| Policy | UX | Implementation |
|---|---|---|
| **(A) Kill open TCP, reconnect, accept fresh** | SSH user sees "Connection reset" once, has to reconnect | Easiest — drop the QUIC handle, close all open TCP, re-listen |
| **(B) Hold TCP open, stall reads/writes until new QUIC is up** | SSH user sees a freeze, then resumption (if the application tolerates it) | Hard — would need to buffer TCP↔QUIC traffic across the reconnect, and SSH does NOT tolerate a stall across the QUIC layer because the application stream context is gone |
| **(C) Best of both: reset existing TCP, accept new ones immediately** | SSH user reconnects manually but immediately; new sessions just work | Easy + honest about what we can guarantee |

**Recommendation: Policy C.** SSH (and most TCP protocols) cannot transparently survive a QUIC restart because the application-layer state (SSH session keys, RDP graphics state, HTTP/2 stream IDs) is gone with the dead QUIC stream. Pretending otherwise causes silent data corruption. Reset existing TCP, accept new ones the moment the new QUIC session is ready, and document this clearly.

**Mitigation:** before T1, write down the policy in a code comment block at the top of the new supervisor loop so the next reader doesn't second-guess it.

---

## Constraints & Out-of-Scope

**In scope:**
- Client-side `cmd_connect` supervisor loop in `proto/src/bin/ztlp-cli.rs`.
- Detection of QUIC connection death via `quinn::Connection::closed()`.
- Exponential backoff with jitter, configurable max attempts.
- Three CLI flags: `--reconnect-attempts <N>`, `--reconnect-delay-ms <N>`, `--no-reconnect`.

**Out of scope (separate work):**
- The connect-ergonomics PR (zone-append, `-L :port`, etc.) — that's `2026-06-03-connect-ergonomics.md`.
- Service-prefix names (`ssh.trsdc.<zone>`) — that's the forwards-in-SVC discussion.
- Application-layer session persistence (transparent SSH resume across QUIC restarts). Not technically possible without changes to OpenSSH; out of scope forever.

---

## Progress Tracker

> State machine: 🔲 not started → 🟡 in progress → ✅ done → ❌ blocked. Update in the same commit as each task.

| # | Task | Status | Commit SHA | Notes |
|---|---|---|---|---|
| T1 | Extract dial-and-tunnel into a function returning on session close | 🔲 | — | Pure refactor, no behavior change |
| T2 | Add `--reconnect-attempts`, `--reconnect-delay-ms`, `--no-reconnect` CLI flags | 🔲 | — | Defaults: unlimited, 1000ms initial, false |
| T3 | Wrap dial-and-tunnel in supervisor loop with exponential backoff | 🔲 | — | Honors all three flags |
| T4 | Print reconnect status to stderr (each attempt + cap reached) | 🔲 | — | Operator visibility |
| T5 | Unit tests: backoff math, max-attempts honored, no-reconnect short-circuits | 🔲 | — | |
| T6 | Integration test: kill gateway, verify client recovers within 30s | 🔲 | — | Needs test gateway harness |
| T7 | E2E validation: leave tunnel open across a manual TRSDC service restart | 🔲 | — | Live confirmation on bench |
| T8 | Doc update: `--help` text, README note, CHANGELOG entry | 🔲 | — | |
| **DONE** | All tests green, PR merged, validated against next TRSDC daily reboot | 🔲 | — | |

**Last resumed at:** _(populated on session restart)_

**Branch:** `feat/connect-auto-reconnect`

---

## Task T1: Extract dial-and-tunnel into a callable function

**Objective:** Refactor the existing connect path so the QUIC dial + TCP-accept-loop is one function that returns `Ok(DisconnectReason)` when the QUIC session ends. This is a pure refactor — no behavior change. Pre-requisite for T3.

**Files:**
- Modify: `proto/src/bin/ztlp-cli.rs` lines ~3486–3665 (the body of `cmd_connect` after `pick_quic_dial_target`)

**Step 1: Identify the slice to extract**

The function should encompass:
- Bind UDP socket (line 3489)
- Send CLIENT_ROUTE if `--service` set (lines 3512–3553)
- `QuicEndpoint::connect_with_socket` (line 3556)
- TCP listener bind (line 3574)
- Noise handshake (line 3589)
- TCP accept loop (line 3609)

It should NOT include:
- NS resolution (already done before)
- Identity loading
- Multi-candidate dial decision (already done)

**Step 2: Define the return type**

```rust
/// Reason a QUIC tunnel session ended.
#[derive(Debug, Clone)]
enum DisconnectReason {
    /// QUIC connection closed by peer (gateway restart, etc.). Recoverable.
    PeerClosed(String),
    /// QUIC connection timed out (network blip, NAT eviction). Recoverable.
    TimedOut,
    /// Initial dial failed before the tunnel was ever established. Recoverable.
    DialFailed(String),
    /// User Ctrl-C'd. NOT recoverable — exit cleanly.
    UserInterrupt,
    /// Unrecoverable error (e.g. handshake auth failure). Do not retry.
    Fatal(String),
}
```

**Step 3: Extract the function**

```rust
/// Run one QUIC tunnel session. Returns when the session ends (cleanly or not).
/// The TCP listener is bound INSIDE this function and dropped on return,
/// so the supervisor in T3 can rebind from scratch on each reconnect.
async fn run_one_tunnel(
    identity: &NodeIdentity,
    peer_addr: SocketAddr,
    node_id: [u8; 16],
    service: Option<&str>,
    bind: &str,
    local_forward: Option<&str>,
) -> Result<DisconnectReason, Box<dyn std::error::Error>> {
    // ... contents of the current lines 3488–3664 ...
}
```

**Step 4: Call site change**

Existing `cmd_connect` body after `pick_quic_dial_target`:
```rust
let reason = run_one_tunnel(&identity, peer_addr, node_id, service.as_deref(), bind, local_forward.as_deref()).await?;
match reason {
    DisconnectReason::UserInterrupt => Ok(()),
    other => {
        // T3 will replace this with a reconnect loop.
        // For T1, just propagate as an error to preserve current behavior.
        Err(format!("tunnel ended: {:?}", other).into())
    }
}
```

**Step 5: Run existing tests, verify no regressions**

```bash
cd /home/trs/ztlp/proto && cargo test --bin ztlp
```
Expected: PASS — pure refactor.

**Step 6: Manual smoke**

```bash
cargo build --bin ztlp --release
./target/release/ztlp connect TRSDC.tech-rockstars.trs.ztlp \
  --ns-server 16.147.41.195:23096 --service ssh -L 2298:127.0.0.1:22 &
sleep 5
ssh -i ~/.ssh/id_rsa -p 2298 'trs\trs'@127.0.0.1 hostname
# Expected: TRSDC
kill %1
```

**Step 7: Commit**

```bash
git add proto/src/bin/ztlp-cli.rs
git commit -m "refactor(connect): extract dial-and-tunnel into run_one_tunnel

Pure refactor in preparation for the auto-reconnect supervisor loop
(see docs/plans/2026-06-03-connect-auto-reconnect.md). No behavior
change — cmd_connect now calls run_one_tunnel once and propagates
its return as an error, matching the current 'exit on disconnect'
behavior. T3 will replace the propagation with a retry loop."
```

---

## Task T2: Add reconnect CLI flags

**Objective:** Three flags on `ztlp connect` so the supervisor in T3 is configurable per-invocation.

**Files:**
- Modify: `proto/src/bin/ztlp-cli.rs` — the `Cli::Connect` clap struct (search for `#[command(about = "Connect"` or similar)

**Step 1: Locate the Connect subcommand args**

```bash
cd /home/trs/ztlp/proto && grep -n "Connect {" src/bin/ztlp-cli.rs | head -3
```

**Step 2: Add the three flags**

```rust
/// Maximum reconnect attempts before giving up. Default: unlimited.
/// Set to 0 to disable reconnect (equivalent to --no-reconnect).
#[arg(long, default_value = "0", help = "Max reconnect attempts (0=unlimited)")]
reconnect_attempts: u32,

/// Initial delay between reconnect attempts (milliseconds).
/// Doubles each failed attempt, capped at 30s.
#[arg(long, default_value = "1000")]
reconnect_delay_ms: u64,

/// Disable reconnect entirely. Tunnel dies on first disconnect.
/// Useful for scripts that want fail-fast semantics.
#[arg(long, conflicts_with = "reconnect_attempts")]
no_reconnect: bool,
```

**Step 3: Plumb through to cmd_connect signature**

```rust
async fn cmd_connect(
    // ... existing args ...
    reconnect_attempts: u32,
    reconnect_delay_ms: u64,
    no_reconnect: bool,
) -> Result<(), Box<dyn std::error::Error>> {
```

In the dispatcher (find with `grep -n "cmd_connect(" src/bin/ztlp-cli.rs`), wire the new args through.

**Step 4: Write CLI parsing tests**

```rust
#[test]
fn connect_default_flags_enable_unlimited_reconnect() {
    let cli = Cli::parse_from(["ztlp", "connect", "foo", "--service", "ssh", "-L", ":22"]);
    if let Commands::Connect { reconnect_attempts, no_reconnect, .. } = cli.command {
        assert_eq!(reconnect_attempts, 0);  // 0 means unlimited
        assert!(!no_reconnect);
    } else {
        panic!("expected Connect");
    }
}

#[test]
fn connect_no_reconnect_flag_disables() {
    let cli = Cli::parse_from(["ztlp", "connect", "foo", "--service", "ssh", "-L", ":22", "--no-reconnect"]);
    if let Commands::Connect { no_reconnect, .. } = cli.command {
        assert!(no_reconnect);
    } else {
        panic!("expected Connect");
    }
}

#[test]
fn connect_explicit_attempts_caps_retries() {
    let cli = Cli::parse_from(["ztlp", "connect", "foo", "--service", "ssh", "-L", ":22", "--reconnect-attempts", "5"]);
    if let Commands::Connect { reconnect_attempts, .. } = cli.command {
        assert_eq!(reconnect_attempts, 5);
    } else {
        panic!("expected Connect");
    }
}
```

**Step 5: Run tests, verify pass**

```bash
cargo test --bin ztlp connect_
```

**Step 6: Commit**

```bash
git add proto/src/bin/ztlp-cli.rs
git commit -m "feat(connect): add --reconnect-attempts, --reconnect-delay-ms, --no-reconnect

Flags plumbed through to cmd_connect; supervisor loop in T3 will
consume them. Defaults: unlimited attempts, 1s initial delay, retry
enabled."
```

---

## Task T3: Supervisor loop with exponential backoff

**Objective:** Wrap `run_one_tunnel` (from T1) in a loop that consults the flags (from T2) and reconnects with backoff.

**Files:**
- Modify: `proto/src/bin/ztlp-cli.rs` cmd_connect body — replace the single-shot call with a supervisor loop

**Step 1: Write the backoff helper**

```rust
/// Compute reconnect backoff with exponential growth, capped at 30s.
/// Adds 10% jitter to avoid thundering-herd if many clients reconnect after the
/// same gateway restart.
fn compute_reconnect_delay(attempt: u32, base_ms: u64) -> Duration {
    let exp = (attempt as u32).saturating_sub(1).min(5);  // 2^5 = 32x cap
    let multiplier: u64 = 1 << exp;
    let raw_ms = base_ms.saturating_mul(multiplier);
    let capped_ms = raw_ms.min(30_000);
    // ±10% jitter
    let jitter_ms = (capped_ms / 10).max(1);
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let offset: i64 = rng.gen_range(-(jitter_ms as i64)..=jitter_ms as i64);
    let final_ms = (capped_ms as i64 + offset).max(0) as u64;
    Duration::from_millis(final_ms)
}
```

**Step 2: Write the supervisor loop**

```rust
// POLICY for in-flight TCP connections during reconnect:
//
// When the QUIC session dies, any open TCP connection on the local listener
// is reset. We do NOT attempt to transparently bridge the QUIC restart —
// the application stream context (SSH keys, RDP graphics state, etc.) is
// gone with the dead QUIC stream, and pretending otherwise causes silent
// data corruption. The user reconnects their SSH, but only after a brief
// "tunnel reestablished" stall, not a multi-minute manual ztlp-restart.

let mut attempt: u32 = 0;
loop {
    attempt += 1;

    if !no_reconnect && attempt > 1 {
        let delay = compute_reconnect_delay(attempt - 1, reconnect_delay_ms);
        eprintln!(
            "{} reconnect attempt {} (delay {}ms)…",
            c_dim("↻"),
            attempt,
            delay.as_millis()
        );
        tokio::time::sleep(delay).await;
    }

    let reason = match run_one_tunnel(
        &identity,
        peer_addr,
        node_id,
        service.as_deref(),
        bind,
        local_forward.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => DisconnectReason::DialFailed(e.to_string()),
    };

    match reason {
        DisconnectReason::UserInterrupt => {
            eprintln!("{} tunnel closed by user", c_green("✓"));
            return Ok(());
        }
        DisconnectReason::Fatal(msg) => {
            return Err(format!("fatal tunnel error: {msg}").into());
        }
        DisconnectReason::PeerClosed(_) | DisconnectReason::TimedOut | DisconnectReason::DialFailed(_) => {
            if no_reconnect {
                return Err(format!("tunnel disconnected ({:?}); --no-reconnect set", reason).into());
            }
            if reconnect_attempts > 0 && attempt >= reconnect_attempts {
                return Err(format!(
                    "tunnel disconnected after {} attempts; giving up",
                    attempt
                )
                .into());
            }
            eprintln!(
                "{} tunnel disconnected ({:?}); will retry",
                c_yellow("⚠"),
                reason
            );
            // Loop continues — next iteration will sleep then re-dial.
        }
    }
}
```

**Step 3: Detect quinn connection close inside `run_one_tunnel`**

The current code only notices the disconnect when `open_bi()` fails on a fresh TCP accept. We can do better — watch `client.closed()` in parallel with the TCP accept loop:

```rust
// Inside run_one_tunnel, after the noise handshake completes:
let client_closed_fut = client.closed();
tokio::pin!(client_closed_fut);

loop {
    tokio::select! {
        accept_res = listener.accept() => {
            match accept_res {
                Ok((tcp, addr)) => {
                    // ... existing per-connection spawn logic ...
                }
                Err(e) => {
                    return Ok(DisconnectReason::Fatal(format!("TCP accept failed: {e}")));
                }
            }
        }
        close_reason = &mut client_closed_fut => {
            // QUIC session died. Classify the close reason.
            return Ok(match close_reason {
                quinn::ConnectionError::TimedOut => DisconnectReason::TimedOut,
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::ConnectionClosed(_) => {
                    DisconnectReason::PeerClosed(format!("{:?}", close_reason))
                }
                other => DisconnectReason::Fatal(format!("{:?}", other)),
            });
        }
    }
}
```

**Step 4: Run existing tests, verify pass**

```bash
cargo test --bin ztlp
```
Expected: PASS — the supervisor changes the loop shape but each tunnel cycle still runs the original handshake + accept logic.

**Step 5: Commit**

```bash
git add proto/src/bin/ztlp-cli.rs
git commit -m "feat(connect): auto-reconnect on QUIC session loss

Wraps run_one_tunnel (T1) in a supervisor loop that detects QUIC
connection close via quinn::Connection::closed(), classifies the
reason, and re-dials with exponential backoff (1s,2s,4s,...,30s cap)
plus 10% jitter.

Honors --reconnect-attempts (0=unlimited, default), --reconnect-delay-ms
(default 1000), and --no-reconnect (fail-fast).

In-flight TCP connections are reset on reconnect — see the policy
comment block in cmd_connect for the design rationale (application
stream state cannot survive a QUIC restart)."
```

---

## Task T4: Operator visibility

**Objective:** Make reconnect attempts loud on stderr so an operator watching logs sees what's happening.

**Files:**
- Modify: `proto/src/bin/ztlp-cli.rs` — the supervisor loop messages

**Step 1: Standardize log lines**

Each reconnect event emits one stderr line in this format:

```
↻ tunnel disconnected (PeerClosed("closed by peer: 0")); attempt 2 in 2.1s
✓ tunnel reestablished after 3 attempts (12.4s total downtime)
✗ tunnel giving up after 10 attempts; --reconnect-attempts limit reached
```

**Step 2: Track total downtime**

```rust
let mut downtime_start: Option<Instant> = None;

// On disconnect:
if downtime_start.is_none() {
    downtime_start = Some(Instant::now());
}

// On successful reconnect (inside run_one_tunnel after handshake completes):
if let Some(start) = downtime_start.take() {
    eprintln!(
        "{} tunnel reestablished after {} attempts ({:.1}s downtime)",
        c_green("✓"),
        attempt,
        start.elapsed().as_secs_f64()
    );
}
```

(This requires a small refactor: `run_one_tunnel` needs to signal "handshake done" back to the supervisor. Either via an `mpsc` channel, or — simpler — pass a `&mut Option<Instant>` reference that `run_one_tunnel` clears when it gets past the handshake.)

**Step 3: Commit**

```bash
git add proto/src/bin/ztlp-cli.rs
git commit -m "feat(connect): announce reconnect attempts + downtime on stderr

Operators watching 'ztlp connect' logs now see:
  ↻ tunnel disconnected (reason); attempt N in Xs
  ✓ tunnel reestablished after N attempts (Xs downtime)
  ✗ tunnel giving up after N attempts

Downtime is wall-clock time from first disconnect to first
successful handshake, NOT cumulative attempt-delay time."
```

---

## Task T5: Unit tests for backoff and supervisor logic

**Objective:** Lock in the math and the policy decisions so future refactors don't silently regress.

**Files:**
- Modify: `proto/src/bin/ztlp-cli.rs` — `#[cfg(test)]` block

**Step 1: Test backoff math**

```rust
#[test]
fn compute_reconnect_delay_doubles_each_attempt() {
    // No jitter for determinism — test the base growth pattern.
    let base = 1000;
    let d1 = compute_reconnect_delay(1, base);
    let d2 = compute_reconnect_delay(2, base);
    let d3 = compute_reconnect_delay(3, base);
    // Within 10% jitter envelope: d1 ~= 1000ms, d2 ~= 2000ms, d3 ~= 4000ms
    assert!(d1.as_millis() >= 900 && d1.as_millis() <= 1100);
    assert!(d2.as_millis() >= 1800 && d2.as_millis() <= 2200);
    assert!(d3.as_millis() >= 3600 && d3.as_millis() <= 4400);
}

#[test]
fn compute_reconnect_delay_caps_at_30s() {
    let d = compute_reconnect_delay(20, 1000);
    assert!(d.as_millis() <= 33_000, "should be ~30s + jitter, got {}ms", d.as_millis());
    assert!(d.as_millis() >= 27_000, "should be ~30s - jitter, got {}ms", d.as_millis());
}

#[test]
fn compute_reconnect_delay_never_negative() {
    let d = compute_reconnect_delay(1, 1);
    assert!(d.as_millis() >= 0);
}
```

**Step 2: Test reason classification**

The mapping from `quinn::ConnectionError` to `DisconnectReason` is policy-critical (decides whether to retry):

```rust
#[test]
fn timed_out_is_recoverable() {
    let r = classify_close(quinn::ConnectionError::TimedOut);
    assert!(matches!(r, DisconnectReason::TimedOut));
    assert!(r.is_recoverable());
}

#[test]
fn application_closed_is_recoverable() {
    let r = classify_close(quinn::ConnectionError::ApplicationClosed(/* ... */));
    assert!(matches!(r, DisconnectReason::PeerClosed(_)));
    assert!(r.is_recoverable());
}

#[test]
fn version_mismatch_is_fatal() {
    let r = classify_close(quinn::ConnectionError::VersionMismatch);
    assert!(matches!(r, DisconnectReason::Fatal(_)));
    assert!(!r.is_recoverable());
}
```

Requires adding helper methods:
```rust
impl DisconnectReason {
    fn is_recoverable(&self) -> bool {
        !matches!(self, DisconnectReason::UserInterrupt | DisconnectReason::Fatal(_))
    }
}

fn classify_close(err: quinn::ConnectionError) -> DisconnectReason {
    match err {
        quinn::ConnectionError::TimedOut => DisconnectReason::TimedOut,
        quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::ConnectionClosed(_) => {
            DisconnectReason::PeerClosed(format!("{:?}", err))
        }
        other => DisconnectReason::Fatal(format!("{:?}", other)),
    }
}
```

**Step 3: Run tests, verify pass**

```bash
cargo test --bin ztlp compute_reconnect_delay
cargo test --bin ztlp _is_recoverable
cargo test --bin ztlp _is_fatal
```

**Step 4: Commit**

```bash
git add proto/src/bin/ztlp-cli.rs
git commit -m "test(connect): lock in backoff math and reason classification

3 backoff tests: doubling, 30s cap, never-negative.
3 classify tests: TimedOut recoverable, ApplicationClosed recoverable,
VersionMismatch fatal. Future refactors that change which quinn
errors trigger retry will fail these tests loudly."
```

---

## Task T6: Integration test — kill gateway, verify client recovers

**Objective:** Spin up a local gateway, dial it, kill it, restart it, confirm the client tunnel resumes within 30 seconds.

**Files:**
- Create: `proto/tests/auto_reconnect_integration.rs`
- Add to: `proto/Cargo.toml` `[dev-dependencies]` if `assert_cmd` or `nix` aren't already there

**Step 1: Test skeleton**

```rust
//! Integration test for ztlp connect auto-reconnect.
//!
//! Spawns a gateway listener, opens a tunnel from a client, kills the
//! gateway, restarts it, and verifies the client resumes within 30s.
//!
//! Requires: ztlp binary built (release or debug). Run with:
//!   cargo test --test auto_reconnect_integration -- --nocapture --test-threads=1

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[ignore = "slow; run with `cargo test --test auto_reconnect_integration -- --ignored`"]
fn client_recovers_from_gateway_restart() {
    // 1. Spawn gateway listener on 127.0.0.1:23095 forwarding ssh → 127.0.0.1:22
    //    (or any local TCP we can curl/nc)
    let mut gateway = Command::new("./target/debug/ztlp")
        .args(["listen", "--bind", "127.0.0.1:23095", /* ... */])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gateway");

    std::thread::sleep(Duration::from_secs(2));  // wait for bind

    // 2. Spawn client with --reconnect-attempts 5 --reconnect-delay-ms 500
    let mut client = Command::new("./target/debug/ztlp")
        .args(["connect", "127.0.0.1:23095", "--service", "ssh", "-L", "2298:127.0.0.1:22",
               "--reconnect-attempts", "5", "--reconnect-delay-ms", "500"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");

    std::thread::sleep(Duration::from_secs(3));  // wait for handshake

    // 3. Verify TCP forward works (sanity check)
    assert!(can_tcp_connect("127.0.0.1:2298"), "tunnel TCP not bound after initial connect");

    // 4. Kill the gateway
    gateway.kill().expect("kill gateway");
    gateway.wait().ok();

    // 5. Restart the gateway on the same port
    std::thread::sleep(Duration::from_secs(1));
    let mut gateway2 = Command::new("./target/debug/ztlp")
        .args(["listen", "--bind", "127.0.0.1:23095", /* ... */])
        .stderr(Stdio::piped())
        .spawn()
        .expect("respawn gateway");

    // 6. Within 30s, the client should successfully reconnect.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut reconnected = false;
    while Instant::now() < deadline {
        // Probe: try a quick TCP handshake through the tunnel.
        if probe_tunnel_works("127.0.0.1:2298") {
            reconnected = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    // Cleanup
    client.kill().ok();
    gateway2.kill().ok();

    assert!(reconnected, "client did not reconnect within 30s of gateway restart");
}

fn can_tcp_connect(addr: &str) -> bool {
    std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_millis(500),
    ).is_ok()
}

fn probe_tunnel_works(addr: &str) -> bool {
    // A TCP connect-and-close should succeed without reset if the QUIC
    // tunnel is alive on the other end. (Connection reset means dead QUIC.)
    match std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_millis(500),
    ) {
        Ok(stream) => {
            // Try to read 0 bytes — if QUIC is dead, this returns reset.
            use std::io::Read;
            let mut buf = [0u8; 1];
            let mut s = stream;
            s.set_read_timeout(Some(Duration::from_millis(100))).ok();
            !matches!(s.read(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
        }
        Err(_) => false,
    }
}
```

**Step 2: Run the integration test**

```bash
cd /home/trs/ztlp/proto
cargo build --bin ztlp
cargo test --test auto_reconnect_integration -- --ignored --nocapture
```

Expected: PASS — within 30s of the gateway restart, the probe succeeds.

**Step 3: Commit**

```bash
git add proto/tests/auto_reconnect_integration.rs
git commit -m "test(connect): integration test for auto-reconnect

Spawns gateway+client, kills gateway, restarts it, verifies client
recovers within 30s. Marked #[ignore] by default — run explicitly
with 'cargo test --test auto_reconnect_integration -- --ignored'
because it spawns subprocesses and binds ports.

Validates the full T1-T5 stack end-to-end on Linux."
```

---

## Task T7: E2E validation against the real TRSDC daily restart

**Objective:** Prove the implementation survives the actual production failure mode that motivated this plan.

**Steps (manual, observed by operator):**

```bash
# 1. Build the new ztlp client
cd /home/trs/ztlp/proto && cargo build --release --bin ztlp

# 2. Start a long-running tunnel with verbose reconnect output.
./target/release/ztlp connect TRSDC.tech-rockstars.trs.ztlp \
  --ns-server 16.147.41.195:23096 --service ssh -L 2298:127.0.0.1:22 \
  --reconnect-delay-ms 1000 \
  2>&1 | tee /tmp/ztlp-connect-overnight.log &

# 3. Wait for tomorrow's scheduled TRSDC reboot at 04:03 PST / 12:03 UTC.
#    Or, for a faster test, trigger one manually:
#      ssh -p 2298 'trs\trs'@127.0.0.1 'Restart-Service ztlp_listener'
#    (Note: this restarts only the listener, not the OS — still tests
#     the QUIC peer-restart recovery, which is the failure mode that
#     bit us today.)

# 4. After the restart, look for these markers in the log:
grep -E "(↻|✓ tunnel|⚠ tunnel)" /tmp/ztlp-connect-overnight.log

# Expected:
#   ⚠ tunnel disconnected (PeerClosed(...)); will retry
#   ↻ reconnect attempt 2 (delay ~1000ms)…
#   ✓ tunnel reestablished after 2 attempts (Xs downtime)

# 5. Verify the tunnel actually works post-recovery:
ssh -i ~/.ssh/id_rsa -p 2298 'trs\trs'@127.0.0.1 'hostname; whoami'
# Expected:
#   TRSDC
#   trs\trs
```

**Step 6: Record findings in Progress Tracker Notes column**

E.g.: `T7: validated against manual ztlp_listener restart on TRSDC 2026-06-04 03:15 UTC; client reconnected in 1.2s downtime`.

This task produces no code commits — only validation receipts.

---

## Task T8: Doc update

**Files:**
- Modify: `README.md` (or wherever connect is documented)
- Modify: `CHANGELOG.md`
- Modify: `--help` text for `ztlp connect` (auto-generated from clap docstrings — verify the new flags show up)

**Step 1: Verify --help**

```bash
./target/release/ztlp connect --help | grep -i reconnect
# Expected: 3 lines covering --reconnect-attempts, --reconnect-delay-ms, --no-reconnect
```

**Step 2: README addition**

Under the connect section, add:

```markdown
### Automatic Reconnect

`ztlp connect` automatically reconnects when the underlying QUIC tunnel is
disconnected (gateway restart, network blip, NAT timeout). The local TCP
listener stays bound across reconnect cycles. Any in-flight TCP connection
through the tunnel is reset — your downstream client (SSH, mstsc, etc.)
needs to reconnect — but new connections work as soon as the new QUIC
session is established (typically 1-3 seconds).

**Tuning:**

- `--reconnect-attempts N` — Maximum attempts (0=unlimited, the default).
- `--reconnect-delay-ms N` — Initial delay between attempts (default 1000ms).
  Doubles each failed attempt, capped at 30 seconds.
- `--no-reconnect` — Disable entirely. Tunnel dies on first disconnect.
  Useful for scripts that want fail-fast semantics.
```

**Step 3: CHANGELOG entry**

```markdown
### Added

- `ztlp connect` now automatically reconnects when the underlying QUIC tunnel
  is disconnected (gateway restart, network blip, NAT timeout). Configurable
  via `--reconnect-attempts`, `--reconnect-delay-ms`, `--no-reconnect`.
  Resolves the operational pain of having to manually re-run `ztlp connect`
  after every daily gateway restart.
```

**Step 4: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: ztlp connect auto-reconnect"
```

---

## Resume Protocol (if session interrupted)

When a new session opens this plan:

1. Read the Progress Tracker — find the last row with status ✅.
2. The next row (🔲 or 🟡) is where to resume.
3. Run `git log --oneline -10` on `feat/connect-auto-reconnect` to confirm tracker matches commit history.
4. If tracker and git disagree, **trust git** and re-update the tracker.
5. Update "Last resumed at" in the next commit.

---

## Verification Checklist (before opening PR)

- [ ] `cargo test --bin ztlp` passes (existing suite + T2 + T5 tests).
- [ ] `cargo test --test auto_reconnect_integration -- --ignored` passes locally.
- [ ] `cargo clippy --bin ztlp -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] T7 validation succeeded against TRSDC (either next daily restart or manual listener restart) — receipts in tracker Notes column.
- [ ] `--help` shows the three new flags with sensible descriptions.
- [ ] README and CHANGELOG updated.
- [ ] No new `unwrap()` / `expect()` in the reconnect path. (Operator-facing code that runs unattended for days must not panic on edge cases.)
- [ ] Reconnect loop emits a loud stderr line per attempt — verify with `--reconnect-delay-ms 100 --reconnect-attempts 3` against an unreachable peer.

---

## Open Questions for Author

1. **Default for `reconnect-attempts`: unlimited vs capped.** Unlimited means a misconfigured target retries forever; capped (say, 100) means a real outage eventually surfaces as an error exit. I lean **unlimited with loud per-attempt logging** because the failure mode "ztlp connect ran for 12 hours retrying" is easier to diagnose than "ztlp connect silently exited overnight." But a cap would be defensible.

2. **Should reconnect honor `--multi-candidate` re-evaluation?** Currently the multi-candidate dial happens once at the top of `cmd_connect` before the supervisor loop. On reconnect, should we re-run multi-candidate (in case the network topology changed — e.g. WiFi → cellular) or stick with the original peer_addr? I lean **re-run multi-candidate on every reconnect** — costs ~200ms but adapts to NAT/network changes. But this means moving NS resolution inside the supervisor loop too.

3. **Should `--no-reconnect` short-circuit before the first dial?** I.e., if the user explicitly opts out, should the first failure exit immediately, or always allow at least the initial dial to succeed? I lean **always allow the initial dial** — `--no-reconnect` is about post-establishment behavior, not initial failure.

4. **Backoff jitter range — 10% appropriate?** Larger jitter (25%) spreads retries better against thundering herd; smaller (5%) keeps reconnect tighter. The thundering-herd risk is real: if TRSDC restarts and 50 benches are connected, all 50 will see the disconnect within ~1s and try to reconnect together. 10% feels right for that scale; revisit if we see real contention at production scale.

---

## Estimated Effort

| Task | LOC | Time |
|---|---|---|
| T1 — Extract function | ~100 | 30 min |
| T2 — CLI flags | ~30 | 20 min |
| T3 — Supervisor loop | ~80 | 1.5 hr |
| T4 — Operator log lines | ~40 | 30 min |
| T5 — Unit tests | ~60 | 45 min |
| T6 — Integration test | ~120 | 2 hr |
| T7 — E2E validation | 0 (manual) | 30 min |
| T8 — Docs | ~30 | 20 min |
| **Total** | **~460** | **~6.5 hr** |

Plus ~24h elapsed time for T7 if waiting for natural TRSDC daily restart instead of manually triggering the listener.

---

## Relationship to Other Plans

- **Independent of** `2026-06-03-connect-ergonomics.md` — can land first, after, or alongside. No shared code paths.
- **Independent of** the forwards-in-SVC discussion — connect-side change only.
- **Inspired by** `mobile.rs:MobileConfig` (iOS NE) and `agent/renewal.rs:compute_failure_backoff` patterns already in the repo.
- **Validates** the v0.34.8 server-side resilience work — without this PR, the listener heartbeat does its job but operators don't see the benefit because the client process can't take advantage of a re-registered listener.
