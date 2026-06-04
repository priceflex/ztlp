# Auto-Reconnect — Dynamic Re-Resolve Scenarios (Addendum)

**Companion to:** `2026-06-03-connect-auto-reconnect.md`
**Status:** Proposed (extends the base plan)
**Author:** Hermes Agent (under Steve Price)
**Date:** 2026-06-04

## Why this addendum exists

The base auto-reconnect plan assumes the **target's address never changes** —
re-dialing simply repeats the same UDP/QUIC handshake to the same
`SocketAddr`. That assumption holds for most disconnect cases (gateway
restart, network blip, NAT eviction), but it breaks in a class of
real-world scenarios where the **gateway's reachable address changes
mid-tunnel** or where the original NS lookup result has aged out.

The user explicitly called this out — "in case ports/IP addresses change
in a dynamic connect like we have." This document enumerates the
scenarios in BDD shape (Given/When/Then), explains the design decisions
for handling each, and pins them to specific unit tests in T0 of the
implementation.

## The five scenarios

Each row of this table corresponds to a `#[tokio::test]` in T0. The tests
are written FIRST (RED), then the supervisor loop in T3+T4 makes them
pass (GREEN).

| ID | Scenario | What changes? | Recovery requires |
|---|---|---|---|
| **S1** | **Gateway restart, same IP+port** | Nothing routable changes | Re-dial only (no NS lookup needed) |
| **S2** | **Gateway moves to a new IP** | Listener's `--bind` is now `<new_ip>:<port>` | Re-resolve NS to get new SVC record |
| **S3** | **Gateway moves to a new port** | Listener restarted with `--bind <ip>:<new_port>` | Re-resolve NS to get new SVC record |
| **S4** | **NS itself is unreachable during reconnect** | NS server is down or network-partitioned | Retry NS lookup with backoff, fall back to last-known address if NS stays unreachable |
| **S5** | **NS comes back with a record pointing to a different gateway NodeID** | Original identity was rotated (re-enrollment, identity.json regenerated) | Detect NodeID change, decide whether to dial new gateway or fail (security decision — see §"NodeID mismatch policy") |

Each is a real scenario we've observed or could plausibly observe with
the current fleet:

- **S1** is the common case (TRSDC daily reboot — listener restarts on
  same `10.69.91.243:23095`).
- **S2** can fire when DHCP rotates a host's LAN address while the
  listener is restarted by Chef (DAN, CHARLY all use DHCP).
- **S3** would fire if we ever bumped the listener port (we won't
  intentionally, but reserve the option).
- **S4** is realistic — NS Mnesia migrations have caused 10-30s NS
  outages during deploys.
- **S5** is the security-sensitive case. The gateway's NodeID is its
  Ed25519 pubkey hash. A new NodeID at the same name means the gateway
  re-enrolled. From a security standpoint, this is a **different
  gateway** — the user must opt in to following it. Default: fail with
  a clear error; require `--allow-identity-change` to follow.

## Re-resolve policy

The base plan re-uses the original `peer_addr` on every reconnect attempt.
This addendum changes that to **always re-resolve through NS on every
reconnect attempt** (subject to the policies below).

### Why always re-resolve?

The original `peer_addr` is captured at the FIRST NS lookup. If the
underlying SVC record changed (S2, S3), the cached address is stale and
every reconnect attempt will fail against it. Re-resolving gives the
client current information for the same NS-resolvable cost as the first
dial (one UDP roundtrip to NS).

The cost of always re-resolving is one extra NS query per reconnect
attempt. NS lookups are cheap (single UDP packet each way, ~5-50ms
typical) compared to the QUIC dial that follows (~200-500ms typical).
Adding a cached address-only retry as an optimization is possible but
not worth the complexity — the network cost is dwarfed by the QUIC
handshake.

### When NOT to re-resolve

Two cases:

1. **`--no-resolve-on-reconnect` flag set** — operator explicitly wants
   to dial the same address every time. Useful for testing or when the
   target was specified as a raw address (`ztlp connect 10.69.91.243:23095`).
2. **Initial NS lookup was bypassed** (raw-address target) — no zone
   string in scope to re-resolve.

In both cases, the supervisor falls back to dialing the original
`peer_addr` on every retry, matching the base plan's behavior.

### When NS is temporarily down (S4)

The reconnect loop in T3 has its own backoff. NS lookup failure during
a reconnect attempt:

1. Falls back to **last-known good `peer_addr`** for the dial — better
   to try a stale address than fail outright.
2. Logs a WARN: `↻ NS lookup failed (network unreachable), retrying with
   last-known address 10.69.91.243:23095`.
3. Counts as a reconnect attempt (doesn't burn through `reconnect_attempts`
   any faster than a QUIC failure would).

If both NS AND dial fail repeatedly, the supervisor eventually hits
`--reconnect-attempts` cap and exits cleanly. The user sees `tunnel
giving up after N attempts; last error: NS lookup failed, dial against
last-known address also failed`.

### NodeID mismatch policy (S5)

The most security-sensitive case. The QUIC handshake verifies the
gateway's pubkey against the NS KEY record. If the NS KEY changes
between reconnect attempts (gateway re-enrolled, identity.json
regenerated, possibly even malicious), the new KEY won't match the
old expected NodeID we captured at first dial.

Three possible policies, ranked from most to least conservative:

| Policy | Behavior on NodeID change | Trade-off |
|---|---|---|
| **A — Fail closed** ✓ (DEFAULT) | Exit with error: `gateway identity changed; re-run ztlp connect to verify and reconnect` | Operator notices, can verify the change is legitimate |
| B — Warn-and-follow | Log a clear WARN, dial new NodeID | Lower friction; assumes re-enrollment is benign |
| C — Silent follow | No log, dial new NodeID | Hidden security event; not acceptable |

**Picked Policy A.** The original `ztlp connect` invocation explicitly
trusts a specific NodeID via the first NS lookup. If that changes, the
operator should be the one to consent. Policy A becomes Policy B when
the user passes `--allow-identity-change`. Policy C is never offered.

This matches the spirit of `StrictHostKeyChecking` in SSH — silent host
key changes are a known anti-pattern.

## Test specifications (T0 — write FIRST, watch them fail)

These are the BDD specs that go into `proto/src/bin/ztlp-cli.rs` at the
end of `mod tests` as `#[tokio::test]` functions. Pattern: each test
constructs a fake `Resolver` trait impl that returns a programmed
sequence of addresses, runs the supervisor loop against it, asserts the
expected outcome.

Why a trait-based fake resolver: NS is a network resource, can't be
exercised in unit tests. The supervisor calls `resolver.resolve(target,
ns_server)` instead of `resolve_target(...)` directly, so tests inject
a `FakeResolver` that returns `Vec<Result<(SocketAddr, NodeId)>>` in
order. Real code at the binary level wires up a `NsResolver` that
delegates to the existing `resolve_target` function. (See §"Refactor
notes" below for the trait extraction.)

### S1: Gateway restart, same IP+port

```text
Given a tunnel is running against gateway G1 at 10.69.91.243:23095 (NodeID N1)
When the QUIC session is closed by the peer
Then the supervisor:
  1. Detects the close via quinn::Connection::closed()
  2. Sleeps for the backoff delay (T2 default: 1000ms)
  3. Re-resolves NS — gets back the SAME address 10.69.91.243:23095 (N1)
  4. Re-dials and completes the QUIC handshake
  5. Resumes the TCP accept loop
And the reconnect-attempts counter is now 1
And stderr shows exactly ONE reconnect log line
```

Test name: `supervisor_recovers_from_peer_close_same_address`.

### S2: Gateway IP change

```text
Given a tunnel is running against gateway G1 at 10.69.91.243:23095 (NodeID N1)
When the QUIC session is closed by the peer
And NS now returns 10.69.91.244:23095 (same NodeID N1) for the target
Then the supervisor:
  1. Detects the close
  2. Re-resolves NS — gets back the new address 10.69.91.244:23095 (N1)
  3. Dials the NEW address (not the old one)
  4. Verifies NodeID matches — N1 == N1, no security event
  5. Completes the QUIC handshake against the new address
  6. Resumes the TCP accept loop bound to the SAME local port
And the local listener was never rebound (same TCP listener across reconnect)
```

Test name: `supervisor_follows_new_gateway_ip_when_nodeid_matches`.

### S3: Gateway port change

```text
Given a tunnel is running against 10.69.91.243:23095 (NodeID N1)
When the QUIC session is closed
And NS now returns 10.69.91.243:23097 (same NodeID N1)
Then the supervisor dials the new port and completes the handshake
```

Test name: `supervisor_follows_new_gateway_port_when_nodeid_matches`.

This is essentially identical to S2 from a recovery standpoint —
combined into one production code path. The separate test exists so a
future regression in port-handling specifically is caught.

### S4: NS unreachable during reconnect

```text
Given a tunnel is running against gateway G1
When the QUIC session is closed
And the next NS lookup returns Err(IO error: connection timed out)
Then the supervisor:
  1. Logs a WARN about NS being unreachable
  2. Falls back to the last-known peer_addr (10.69.91.243:23095)
  3. Attempts the dial against that stale address
  4. Counts the attempt against --reconnect-attempts
And when NS comes back on the NEXT attempt
Then the supervisor uses the fresh NS result
```

Test name: `supervisor_falls_back_to_stale_address_when_ns_unreachable`.

### S5: NodeID changed (re-enrollment / identity change)

```text
Given a tunnel is running against gateway G1 with NodeID N1
When the QUIC session is closed
And NS now returns 10.69.91.243:23095 (DIFFERENT NodeID N2)
And --allow-identity-change is NOT set
Then the supervisor:
  1. Detects NodeID change
  2. Returns a Fatal DisconnectReason
  3. Exits with a clear error message naming both NodeIDs
And NO dial against the new NodeID is attempted
```

Test name: `supervisor_fails_closed_on_nodeid_change_by_default`.

Plus the opt-in case:

```text
Given the same conditions as above
And --allow-identity-change IS set
Then the supervisor:
  1. Logs a WARN naming both NodeIDs
  2. Dials the new gateway with NodeID N2
  3. Completes the handshake
```

Test name: `supervisor_follows_nodeid_change_when_explicitly_allowed`.

### Negative scenarios for completeness

```text
Test: supervisor_honors_no_reconnect_flag
  Given --no-reconnect is set
  When the QUIC session closes
  Then the supervisor exits with error "tunnel disconnected; --no-reconnect set"
  And does NOT attempt a re-dial

Test: supervisor_honors_reconnect_attempts_cap
  Given --reconnect-attempts 3 is set
  When all 3 reconnect attempts fail
  Then the supervisor exits with error "tunnel disconnected after 3 attempts"

Test: supervisor_exits_cleanly_on_user_interrupt
  When the user sends SIGINT (Ctrl-C)
  Then the supervisor exits with Ok(())
  And NO reconnect attempt is made

Test: backoff_exponential_with_jitter_capped_at_30s
  Given compute_reconnect_delay(attempt, 1000) for attempt in 1..=10
  Then attempt 1 returns ~1000ms ±10%
  And attempt 2 returns ~2000ms ±10%
  And attempt 3 returns ~4000ms ±10%
  ...
  And attempt 10 returns ~30000ms ±10% (capped)
```

## Refactor notes — trait extraction for testability

The supervisor calls into NS via a trait, not a bare function. This is
the smallest invasive change that makes T0 tests possible.

```rust
#[async_trait::async_trait]
trait Resolver: Send + Sync {
    async fn resolve(&self, target: &str, ns_server: Option<&str>)
        -> Result<(SocketAddr, NodeId), Box<dyn std::error::Error>>;
}

struct NsResolver;

#[async_trait::async_trait]
impl Resolver for NsResolver {
    async fn resolve(&self, target: &str, ns_server: Option<&str>)
        -> Result<(SocketAddr, NodeId), Box<dyn std::error::Error>>
    {
        let (addr, node_id) = resolve_target(target, &ns_server.map(|s| s.to_string())).await?;
        Ok((addr, node_id.unwrap_or_else(NodeId::zero)))
    }
}

// In tests:
struct FakeResolver { results: Vec<Result<(SocketAddr, NodeId), String>> }
// ... programmable resolution results, advances cursor on each .resolve() call
```

Apply `?Sized` to any generic helpers that accept `&dyn Resolver`
callers (per `rust-cargo-pitfalls` skill #10).

## CLI flag additions (extends T2)

The base plan adds three flags. This addendum adds two more:

| Flag | Default | Purpose |
|---|---|---|
| `--no-resolve-on-reconnect` | false | Disable re-resolve on reconnect; reuse the original `peer_addr` |
| `--allow-identity-change` | false | Continue dialing if NS returns a different NodeID for the target |

Both default to the SAFE option (re-resolve enabled; identity changes
fail closed).

## Integration test (extends T6)

Replace the single integration test in the base plan with a matrix:

```rust
#[tokio::test]
async fn integration_s1_same_address() { ... }

#[tokio::test]
async fn integration_s2_ip_change() { ... }

#[tokio::test]
async fn integration_s3_port_change() { ... }

#[tokio::test]
async fn integration_s4_ns_outage_recovery() { ... }

#[tokio::test]
async fn integration_s5_nodeid_change_fails_closed() { ... }
```

Each runs against a `MockNs` + `MockGateway` harness that we'll need to
build. The mock NS responds to `lookup_addr` queries with programmable
results; the mock gateway accepts QUIC connections and can be told to
"die" mid-stream to simulate the disconnect.

Cost of the harness: probably 200-300 LOC, in a new
`proto/tests/auto_reconnect_harness.rs`. Reusable for future
network-layer tests.

## Validation criteria

Plan-level acceptance:

- [ ] All 10+ T0 unit tests pass
- [ ] Cookbook + binary integration matrix tests pass
- [ ] Live E2E: TRSDC daily reboot does NOT break the bench-side tunnel
  (validated by holding a tunnel across the 04:03 PST reboot)
- [ ] Live E2E: DAN listener restart (controlled, ~2s) does NOT break
  the bench-side tunnel
- [ ] No regression in existing `cargo test --bin ztlp` suite
- [ ] `--help` text mentions all five flags with their defaults

## Open question for implementer

**Should we keep the local TCP listener open across the QUIC restart, or
rebind it on each cycle?** The base plan says rebind (line ~150 of T1
spec). The dynamic-scenarios concern is: if we rebind, downstream
clients that already have an open TCP connection to the local port get
reset (which is fine — already documented). If we DON'T rebind, those
clients get a brief stall while the QUIC restart happens, then get a
hard reset anyway when the next packet tries to traverse the dead
stream context.

**Recommend: rebind.** Cleanest semantics, matches the policy comment
already in the base plan (line 343). The "hold open" alternative is
hard to get right (must drain all in-flight streams, must time out
gracefully) and yields no UX win because application-layer state is
gone either way.

But this is the kind of question the implementer should re-evaluate
after the first integration test fires. If reconnect happens in <1s
and the rebind causes user-visible TCP resets on every reconnect, we
might want to revisit.

## See also

- Base plan: `docs/plans/2026-06-03-connect-auto-reconnect.md`
- `proto/src/bin/ztlp-cli.rs::cmd_connect` (lines 2544-3665)
- `proto/src/bin/ztlp-cli.rs::resolve_target` (the NS lookup we'll
  delegate to from `NsResolver`)
- `rust-cargo-pitfalls` skill, pitfall #10 — `?Sized` for `&dyn Trait`
  callers
- `test-driven-development` skill — strict RED/GREEN/REFACTOR
  enforcement
