# Resilient Connectivity Implementation Plan

> **For Hermes:** Use `subagent-driven-development` skill to execute task-by-task with two-stage review. **After each task lands (RED→GREEN→commit), update the Progress Tracker table below in the SAME commit so a session restart can read this file and resume cleanly.**

**Goal:** Make `ztlp connect <name> --ns-server <addr>` "just work" through any combination of NAT, relay failure, or partial network outage. End state: a Tailscale-grade automatic decision tree (LAN → punch → primary relay → failover relays → re-query NS), all driven by NS-published metadata with relay always available as a backstop.

**Architecture:** Two parallel subsystems with shared NS plumbing.
- **Punch subsystem (H1-H10):** gateway registers its real listener socket with NS, NS coordinates simultaneous punch packets between client and gateway, relay fallback on punch timeout. Most wire protocol already exists in `proto/src/punch.rs` (1118 lines) + `ns/lib/ztlp_ns/server.ex`; missing piece is gateway-side wiring.
- **Multi-relay subsystem (R1-R3):** client queries NS for ranked relay list, runs health probes, fails over automatically. Pool implementation already exists in `proto/src/relay_pool.rs` (2188 lines) including `FailoverOrchestrator`; missing piece is NS query function + probe-task spawn + send-loop integration.

Both subsystems share the same root cause: **underscore-prefixed unused variables** in `cmd_listen` (`_ns_server`) and `cmd_connect` (`_relay_pool`) — code that was built but never wired.

**Tech Stack:** Rust (proto), Elixir (NS), Tokio async, quinn 0.11.9 (`AsyncUdpSocket` trait verified public for the H3 wrapper).

---

## Progress Tracker

> **Update this table in the same commit as each task. State machine: 🔲 not started → 🟡 in progress → ✅ done → ❌ blocked.**

| # | Task | Status | Commit SHA | Notes |
|---|---|---|---|---|
| H0 | Spike: prove quinn AsyncUdpSocket wrapper compiles | ✅ | spike-NOT-MERGED | Spike branch deleted; PunchRuntime+PunchSocket compiled clean against quinn 0.11.9. Findings: quinn::Instant is private (use std::time::Instant); RecvMeta::clone() exists so meta-compaction works without unsafe |
| H1 | PunchAgent skeleton (shared socket + NS addr) | ✅ | _commit-pending_ | RED: stub PunchAgent w/o new() fails E0599. GREEN: 883 lib tests pass, fmt+clippy clean. socket field has temporary #[allow(dead_code)] until H2 |
| H2 | PunchAgent keepalive sends PUNCH_REPORT every 25s | 🔲 | — | |
| H3 | PunchSocket — quinn AsyncUdpSocket wrapper intercepts 0x0B | 🔲 | — | **Highest risk — H0 spike must pass first** |
| H4 | Gateway-side responder sends PUNCH_BYTE to requester eps | 🔲 | — | |
| H5 | Wire --punch / --ns-server flags into ztlp listen | 🔲 | — | Removes `_ns_server` underscore prefix in cmd_listen |
| H6 | End-to-end integration test (fake NS, in-process) | 🔲 | — | |
| H7 | NS-side test that PUNCH_NOTIFY uses :learned endpoint | 🔲 | — | Elixir test |
| R1 | NS client query — query_ns_for_relays() + NS handler | 🔲 | — | New request type 0x0D LIST_RELAYS |
| R2 | Spawn probe task — drives `record_probe_success/failure` + failover_degraded/dead | 🔲 | — | |
| R3 | Replace hardcoded send_addr with relay_pool.primary() | 🔲 | — | Removes `_relay_pool` underscore prefix in cmd_connect |
| H10 | Auto-punch / auto-pool when --ns-server present, --no-punch / --no-relay-pool escape hatches | 🔲 | — | Default-on with safety valves |
| H8 | Bench validation on AWS + Steve's SD-WAN | 🔲 | — | **Requires NS restart window — bench iOS crash on restart** |
| H9 | Update docs/NAT-TRAVERSAL.md with implementation status | 🔲 | — | |
| **DONE** | All tests green, PR merged | 🔲 | — | |

**Last resumed at:** 2026-05-27 — H0 spike confirmed quinn 0.11.9 viability. Spike branch deleted; on `feature/resilient-connectivity-v0.30.12` ready to start H1.

**Branch:** `feature/resilient-connectivity-v0.30.12` (created from `main` at commit 30f3659 after plan PR #63 merged)

---

## Background — what already exists vs. what's missing

### Already exists ✅

**Punch wire protocol — fully implemented on both sides:**

- `proto/src/punch.rs` (1118 lines): full client-side punch state machine. `execute_punch` runs the dual-side punch loop. `encode_peer_endpoints_request`, `encode_punch_report`, `decode_peer_endpoints_response`, `decode_punch_notify`, `is_punch_notify`, `is_punch_packet`.
- `ns/lib/ztlp_ns/server.ex` lines 214-243, 834-901: handles `0x0A` (PEER_ENDPOINTS), `0x0C` (PUNCH_REPORT), and sends `0x0B` PUNCH_NOTIFY as side effect.
- `ns/lib/ztlp_ns/endpoint_store.ex`: stores `:learned` (NS observed source IP:port) and `:reported` (client claimed in request) endpoints.
- `ns/test/ztlp_ns/punch_protocol_test.exs`: NS-side integration tests.
- CLI plumbing: PR #62 fixed the bypass bug, so `--punch` reaches `execute_punch`.

**Relay pool — fully implemented client-side:**

- `proto/src/relay_pool.rs` (2188 lines): ranked relay list, health tracking, automatic failover.
  - `RelayPool::new(config)`, `add_relay`, `update_from_ns`, `update_from_ns_rich`
  - Health: `record_probe_success/failure`, `score`, `cmp_for_selection`
  - Failover: `failover_degraded`, `failover_dead`, `failover_candidates`, `all_candidates`
  - Backoff: 5s→10s→20s→40s→60s, 3 failures in 10min → deprioritized 5min
  - Region awareness via `gateway_region` config field
- `FailoverOrchestrator` — pool wrapper that owns the failover decision
- NS RELAY records exist: `ns/lib/ztlp_ns/record.ex:279,299` (basic + rich-stats variants used by iOS relay-side VIP)
- `ns/lib/ztlp_ns/relay_seeder.ex` — seeds initial RELAY records from `ZTLP_NS_RELAY_RECORDS` env var
- `ns/lib/ztlp_ns/registration_auth.ex:279` — relay self-registration permitted
- `ns/lib/ztlp_ns/bootstrap.ex` — static bootstrap relay list

### Missing ❌ (root causes — same anti-pattern in both subsystems)

**Punch end-to-end gaps:**

1. **Gateway never registers from its listener socket.** `cmd_listen`'s `_ns_server` arg is underscore-prefixed (unused). `ztlp ns register` uses a different ephemeral socket, so NS's learned endpoint points to a dead socket.
2. **Gateway has no PUNCH_NOTIFY handler.** Even if NS sent `0x0B`, Quinn drops it as non-QUIC.
3. **No keepalive.** NAT mappings expire (30-60s typical). NS's mapping goes stale within a minute.

**Multi-relay gaps:**

4. **Pool is built then ignored.** `cmd_connect` line 2380 creates `let _relay_pool = ... FailoverOrchestrator::new(pool)` — underscore-prefixed, never read. Send loop uses hardcoded `--relay` address.
5. **No NS query for relay discovery.** Function like `query_ns_for_relays(ns_addr, zone) -> Vec<RelayInfo>` doesn't exist. NS handler for relay-list query doesn't exist (only single-record lookups).
6. **No probe task spawned.** Pool has `probe_interval` config but nothing ticks it. `record_probe_success/failure` never called.

**Defaults gap:**

7. **`--punch` and `--relay-pool` both opt-in.** A user running `ztlp connect <name> --ns-server <addr>` doesn't get either, even though NS-resolved means NS-aware. Should be opt-out, not opt-in.

### Out of scope

- STUN-based endpoint discovery (already exists in `nat.rs`, orthogonal to NS-coordinated flow).
- Rendezvous protocol (`nat.rs`) — separate path, untouched here.
- Symmetric NAT punching (handled by relay fallback, which is the whole point of multi-relay).
- Long-lived `ztlp listen` daemon re-registering KEY/SVC records on a timer (separate concern in `FOLLOWUPS-2026-05-26.md` item 4).

---

## Sub-task overview

| Phase | Tasks | LOC est. | Risk |
|---|---|---|---|
| Punch | H0-H7 (8 tasks) | ~560 code + ~190 test | H3 highest, H0 spike de-risks |
| Multi-relay | R1-R3 (3 tasks) | ~250 code + ~100 test | low — protocol parallels punch |
| Defaults | H10 | ~30 code | low |
| Validation | H8, H9 | ops + docs | needs NS-restart window |
| **Total** | **13 tasks** | **~840 code + ~290 test** | |

**TDD discipline:** every task ships RED test → minimal GREEN → commit. Progress tracker updated in same commit.

---

## Task H0: Spike — prove quinn AsyncUdpSocket wrapper compiles

**Objective:** 30-minute throwaway branch. Build a minimum `PunchSocket: AsyncUdpSocket` that compiles + filters one byte. NOT merged. Result is a yes/no on whether H3 approach is viable.

**Files (throwaway branch `spike/quinn-wrapper`):**
- `proto/examples/quinn_wrapper_spike.rs`

**Verification:** `cargo build --example quinn_wrapper_spike` succeeds. If it doesn't, escalate to Steve before proceeding with H1.

**Tracker update:** mark H0 ✅ with `commit: spike-NOT-MERGED` and a note like "spike branch deleted after viability confirmed".

---

## Task H1: PunchAgent skeleton

**Objective:** Create `PunchAgent` struct owning a shared `Arc<UdpSocket>` clone of the gateway's listener + the NS address + the gateway's NodeId.

**Files:**
- Create: `proto/src/punch_agent.rs`
- Modify: `proto/src/lib.rs` (add `pub mod punch_agent;`)
- Test: inline `#[cfg(test)] mod tests`

**Step 1: Write failing test**

```rust
#[tokio::test]
async fn punch_agent_constructs_with_socket_and_ns_addr() {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let ns_addr: SocketAddr = "127.0.0.1:23096".parse().unwrap();
    let node_id = NodeId([0xAA; 16]);
    let agent = PunchAgent::new(sock, ns_addr, node_id);
    assert_eq!(agent.ns_addr, ns_addr);
}
```

**Step 2: Run** → fails (struct doesn't exist).

**Step 3: Implement**

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::identity::NodeId;

pub struct PunchAgent {
    pub(crate) socket: Arc<UdpSocket>,
    pub ns_addr: SocketAddr,
    pub node_id: NodeId,
}

impl PunchAgent {
    pub fn new(socket: Arc<UdpSocket>, ns_addr: SocketAddr, node_id: NodeId) -> Self {
        Self { socket, ns_addr, node_id }
    }
}
```

**Step 4: Pass** → `cargo test --lib punch_agent_constructs` → 1 passed.

**Step 5: Commit + update tracker**

```bash
git checkout -b feat/resilient-connectivity
git add proto/src/punch_agent.rs proto/src/lib.rs
# edit docs/plans/2026-05-27-resilient-connectivity-plan.md to mark H1 ✅
git add docs/plans/2026-05-27-resilient-connectivity-plan.md
git commit -m "feat(punch): H1 PunchAgent skeleton + tracker

Progress: H1 ✅"
```

---

## Task H2: Keepalive loop sends PUNCH_REPORT every 25s

**Objective:** `start_keepalive(interval)` spawns a tokio task emitting `0x0C` PUNCH_REPORT (node_id + 0 reported endpoints) every `interval`. Default 25s.

**Files:** modify `proto/src/punch_agent.rs`

**Step 1: Test (paused-time tokio runtime)**

```rust
#[tokio::test(start_paused = true)]
async fn punch_agent_sends_report_every_25s() {
    let ns_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ns_addr = ns_sock.local_addr().unwrap();
    let gw_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let node_id = NodeId([0x42; 16]);
    let agent = PunchAgent::new(gw_sock, ns_addr, node_id);
    let _h = agent.start_keepalive(Duration::from_secs(25));

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_millis(500), ns_sock.recv(&mut buf))
        .await.unwrap().unwrap();
    assert_eq!(buf[0], 0x0C);
    assert_eq!(&buf[1..17], &node_id.0[..]);

    tokio::time::advance(Duration::from_secs(25)).await;
    tokio::time::timeout(Duration::from_millis(500), ns_sock.recv(&mut buf))
        .await.expect("second keepalive").unwrap();
}
```

**Step 3: Implement** with `tokio::time::interval` + `encode_punch_report(&node_id, &[])`.

**Step 5: Commit + tracker** → mark H2 ✅.

---

## Task H3: PunchSocket — quinn AsyncUdpSocket wrapper

**Objective:** Wrap quinn's UDP socket so inbound `0x0B` PUNCH_NOTIFY packets are diverted to a tokio channel (consumed by H4 dispatcher) before Quinn sees them. `0x00` PUNCH_BYTE packets are silently dropped (they served their purpose by opening the NAT). All other packets pass through to Quinn unchanged.

**Quinn 0.11.9 trait hooks verified:**
- `quinn::Runtime::wrap_udp_socket(&self, std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>>` — runtime.rs:23
- `quinn::AsyncUdpSocket::poll_recv(...)` — runtime.rs:61

**Approach:** Implement a custom `PunchRuntime` that wraps the default `TokioRuntime`. `wrap_udp_socket` returns our `PunchSocket` (which holds the real `AsyncUdpSocket` plus the intercept channel). `poll_recv` calls inner, then filters each returned packet by `data[0]`:
- `0x0B` → push to intercept channel, **do not include in returned bufs/meta count**
- `0x00` → drop entirely
- everything else → pass through

**Files:**
- Create: `proto/src/punch_socket.rs`
- Test: `proto/tests/punch_socket_test.rs`

**Step 1: Test**

```rust
#[tokio::test]
async fn punch_socket_intercepts_notify_passes_quic() {
    let (intercept_tx, mut intercept_rx) = tokio::sync::mpsc::unbounded_channel();
    let runtime = Arc::new(PunchRuntime::new(intercept_tx));

    let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let local = std_sock.local_addr().unwrap();
    let async_sock = runtime.wrap_udp_socket(std_sock).unwrap();

    // Send a PUNCH_NOTIFY-shaped packet at the wrapped socket
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let notify = vec![0x0B; 32];
    sender.send_to(&notify, local).unwrap();

    // Send a fake QUIC packet (first byte 0xC0, typical QUIC initial)
    let quic = vec![0xC0; 64];
    sender.send_to(&quic, local).unwrap();

    // The notify should arrive on the intercept channel
    let (data, _src) = tokio::time::timeout(Duration::from_secs(1), intercept_rx.recv())
        .await.unwrap().unwrap();
    assert_eq!(data[0], 0x0B);

    // The QUIC packet should be visible via poll_recv (i.e. Quinn would see it)
    // … exact assertion depends on AsyncUdpSocket interface, see implementation
}
```

**Step 3: Implement** — full impl in plan tree, will fill in during execution after the H0 spike confirms the exact trait method signatures.

**Pitfall — Windows:** quinn's tokio runtime on Windows uses an I/O completion port path. The `AsyncUdpSocket` trait is the same, but care needed around the recv buffer layout. **Mitigation:** ship Linux/macOS gateway support in v0.30.12, file Windows-gateway as follow-up (Steve's bench is Windows, but his Mac is the *client* — clients work the same on all platforms; only gateway needs the wrapper).

**Step 5: Commit + tracker** → mark H3 ✅.

---

## Task H4: Gateway-side punch responder

**Objective:** `PunchAgent::start_dispatcher(intercept_rx)` consumes the rx channel from H3, decodes each incoming `PUNCH_NOTIFY`, extracts requester NodeId + endpoint list, and calls `respond_to_punch(socket, endpoints, 10s)` which sends `0x00` PUNCH_BYTE to each endpoint every 200ms for up to 10 seconds (or until interrupted).

**Files:**
- Modify: `proto/src/punch.rs` — add `pub async fn respond_to_punch(sock, peer_endpoints, duration)`
- Modify: `proto/src/punch_agent.rs` — `start_dispatcher`

**Step 1: Test**

```rust
#[tokio::test]
async fn respond_to_punch_sends_byte_to_each_endpoint() {
    let gw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoints = vec![peer1.local_addr().unwrap(), peer2.local_addr().unwrap()];

    tokio::spawn(async move {
        respond_to_punch(&gw, &endpoints, Duration::from_secs(1)).await.ok();
    });

    let mut b = [0u8; 4];
    let (n1, _) = tokio::time::timeout(Duration::from_secs(2), peer1.recv_from(&mut b))
        .await.unwrap().unwrap();
    assert_eq!(n1, 1);
    assert_eq!(b[0], 0x00);
    let (n2, _) = tokio::time::timeout(Duration::from_secs(2), peer2.recv_from(&mut b))
        .await.unwrap().unwrap();
    assert_eq!(b[0], 0x00);
}
```

**Step 3: Implement** with `tokio::time::interval(200ms)` × deadline loop.

**Step 5: Commit + tracker** → mark H4 ✅.

---

## Task H5: Wire --punch / --ns-server into ztlp listen

**Objective:** Remove the `_` prefix from `cmd_listen`'s `ns_server` arg. Add a `punch: bool` clap flag. When `punch && ns_server.is_some()`, build a `PunchAgent` + wrap the socket with `PunchRuntime` before handing to Quinn.

**Files:** `proto/src/bin/ztlp-cli.rs` (cmd_listen signature + clap + body)

**Step 1: Test (smoke):**

```bash
cargo build --release && ./proto/target/release/ztlp listen --help | grep -E "(punch|ns-server)"
# Expected: shows both flags
```

**Step 5: Commit + tracker** → mark H5 ✅.

---

## Task H6: End-to-end integration test (in-process fake NS)

**Objective:** Spin up a fake NS + gateway-with-PunchAgent + client-with-`--punch`, all in-process. Assert: client-to-gateway QUIC handshake succeeds without `--relay`.

**Files:** `proto/tests/punch_e2e_test.rs`

**Skeleton:**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_end_to_end_no_relay() {
    // 1. Bind fake NS that:
    //    - on 0x0A query: returns target's :learned endpoint, sends 0x0B to target
    //    - on 0x0C report: records source as :learned
    // 2. Start gateway with PunchAgent + Quinn on 127.0.0.1:0
    //    - keepalive registers gateway endpoint with NS
    // 3. Wait for NS to have learned gateway endpoint (poll up to 5s)
    // 4. Client sends 0x0A PEER_ENDPOINTS to NS
    // 5. Receive 0x0A response with gateway endpoint
    // 6. Client sends 0x00 punch + initiates QUIC handshake to that endpoint
    // 7. Assert handshake succeeds within 10s
}
```

**Step 5: Commit + tracker** → mark H6 ✅.

---

## Task H7: NS-side test for `:learned` endpoint priority

**Objective:** Add Elixir test verifying `pick_best_notify_addr/1` prefers `:learned` over `:reported` endpoints.

**Files:** `ns/test/ztlp_ns/punch_protocol_test.exs`

```elixir
describe "pick_best_notify_addr/1" do
  test "prefers learned over reported when both present" do
    target_id = :crypto.strong_rand_bytes(16)
    EndpointStore.record_endpoint(target_id, {1, 2, 3, 4}, 23095, :reported)
    EndpointStore.record_endpoint(target_id, {5, 6, 7, 8}, 56789, :learned)
    # Send PEER_ENDPOINTS, capture PUNCH_NOTIFY destination
    # Assert destination == {5,6,7,8}:56789
  end
end
```

**Step 5: Commit + tracker** → mark H7 ✅.

---

## Task R1: NS client query — list_relays

**Objective:** Add a new request type `0x0D LIST_RELAYS` that the client sends to NS, asking for "all RELAY records in zone X". NS returns a list of `RelayInfo` (address + region + load stats).

**Wire format (request):**
```
0x0D                          1 byte — request type
zone_len::8                   1 byte
zone::binary-size(zone_len)   variable
```

**Wire format (response):**
```
0x0D                          1 byte — response type
relay_count::8                1 byte
[for each relay:]
  addr_family::8              1 byte (4 or 6)
  addr::binary-4or16
  port::16
  region_len::8
  region::binary-size(region_len)
  load::8                     1 byte (0-255, 0=idle, 255=overloaded)
```

**Files:**
- Create: `proto/src/relay_discovery.rs` (`encode_list_relays_request`, `decode_list_relays_response`, async `query_ns_for_relays`)
- Modify: `ns/lib/ztlp_ns/server.ex` — add handler for `0x0D`
- Tests: inline Rust + new Elixir describe block in `ns/test/ztlp_ns/`

**Step 1 (Rust): Test**

```rust
#[test]
fn encode_list_relays_request_round_trips() {
    let req = encode_list_relays_request("z2ls-final-e2e.techrockstars.ztlp");
    assert_eq!(req[0], 0x0D);
    assert_eq!(req[1], 33);  // zone length
    assert_eq!(&req[2..], b"z2ls-final-e2e.techrockstars.ztlp");
}

#[test]
fn decode_list_relays_response_parses_three_relays() {
    let mut resp = vec![0x0D, 3];  // 3 relays
    // … push three encoded relays
    let relays = decode_list_relays_response(&resp).unwrap();
    assert_eq!(relays.len(), 3);
    assert_eq!(relays[0].region, "us-west-2");
}
```

**Step 1 (Elixir): Test**

```elixir
test "0x0D LIST_RELAYS returns zone's relays" do
  RelaySeeder.seed_relay({34, 218, 240, 106}, 23095, "us-west-2", "z2ls-final-e2e")
  req = <<0x0D, byte_size("z2ls-final-e2e")::8, "z2ls-final-e2e"::binary>>
  response = send_query(req)
  assert <<0x0D, 1::8, rest::binary>> = response  # 1 relay
  # … decode + assert addr/region
end
```

**Step 5: Commit + tracker** → mark R1 ✅. **Both Rust + Elixir sides land in same commit so the protocol can't be partially deployed.**

---

## Task R2: Spawn probe task

**Objective:** Inside `cmd_connect`'s legacy path, after building the `_relay_pool`, spawn a tokio task that ticks every `probe_interval` (default 30s). Each tick: send a PING to every relay in `pool.all_candidates()`, await PONG with 3s timeout, call `pool.record_probe_success(addr, latency)` or `pool.record_probe_failure(addr)`.

**Files:** `proto/src/bin/ztlp-cli.rs` (cmd_connect), maybe extract to `proto/src/relay_probe.rs`

**Pre-req:** the relay's PING/PONG wire format. Check `relay/` Elixir source for existing probe handlers — if PING/PONG exists, use it; otherwise spec a new relay request type.

**Step 1: Test (with fake relay)**

```rust
#[tokio::test]
async fn probe_task_records_success_on_ping_pong() {
    let fake_relay = spawn_fake_relay_pong().await;
    let pool = Arc::new(Mutex::new(RelayPool::from_addresses(
        vec![fake_relay.addr], RelayPoolConfig::default()
    )));
    let _h = spawn_probe_task(pool.clone(), Duration::from_millis(100));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let p = pool.lock().unwrap();
    let entry = p.primary_entry().unwrap();
    assert!(entry.latency_history.len() >= 2);
}
```

**Step 5: Commit + tracker** → mark R2 ✅.

---

## Task R3: Replace hardcoded send_addr with relay_pool.primary()

**Objective:** Remove the `_` prefix from `_relay_pool` in `cmd_connect`. On every handshake retry, consult `relay_pool.primary()` for current best relay. On handshake failure, call `pool.report_handshake_failure(addr)` and re-select. On handshake success, call `pool.report_handshake_success(addr, latency)`.

**Files:** `proto/src/bin/ztlp-cli.rs` cmd_connect send loop (~lines 2440-2470)

**Critical:** preserve the existing single-relay-via-`--relay` semantic — when `--relay` is pinned (not `--relay-pool`), the pool has exactly one entry and failover_enabled=false. **Existing user invocations must not change behavior.**

**Step 1: Test (regression)** — verify single-relay invocation still routes through the pool's primary (which == the pinned relay):

```rust
#[test]
fn pinned_relay_via_pool_returns_same_addr() {
    let cfg = RelayPoolConfig { failover_enabled: false, pinned_relay: Some("1.2.3.4:23095".parse().unwrap()), ..Default::default() };
    let mut pool = RelayPool::new(cfg);
    pool.add_relay("1.2.3.4:23095".parse().unwrap());
    assert_eq!(pool.primary().unwrap().to_string(), "1.2.3.4:23095");
}
```

**Step 1 (handshake feedback): Test** — verify that on a `report_handshake_failure`, the pool fails over to the next-best:

```rust
#[test]
fn handshake_failure_triggers_failover() {
    let mut pool = RelayPool::from_addresses(
        vec!["1.1.1.1:23095".parse().unwrap(), "2.2.2.2:23095".parse().unwrap()],
        RelayPoolConfig::default()
    );
    let initial = pool.primary().unwrap();
    pool.report_handshake_failure(initial);
    // After failure, primary should differ
    assert_ne!(pool.primary().unwrap(), initial);
}
```

**Step 5: Commit + tracker** → mark R3 ✅.

---

## Task H10: Auto-on with safety valves

**Objective:** When `--ns-server` is set and neither `--no-punch` nor `--no-relay-pool` is set, both subsystems activate automatically.

**Behavior:**
- `ztlp connect <name> --ns-server <addr>` → auto-punch + auto-relay-pool
- `ztlp connect <name> --ns-server <addr> --no-punch` → relay-pool only
- `ztlp connect <name> --ns-server <addr> --no-relay-pool` → punch only, pinned relay
- `ztlp connect <name> --ns-server <addr> --no-punch --no-relay-pool` → no automation, current behavior
- `ztlp connect <name>` (no NS) → unchanged (LAN-direct or pinned `--relay`)

Same on gateway: `ztlp listen --ns-server <addr>` → auto-PunchAgent unless `--no-punch`.

**Files:** `proto/src/bin/ztlp-cli.rs` clap + cmd_connect/cmd_listen flag plumbing

**Step 1: Test** — table-driven flag combinations.

**Step 5: Commit + tracker** → mark H10 ✅.

---

## Task H8: Bench validation on AWS + SD-WAN

**Objective:** Deploy v0.30.12-rc to AWS NS + Z2LS Windows gateway. Run `ztlp connect` from Steve's Mac through SD-WAN. Capture pcap. Confirm direct UDP punch path AND graceful relay fallback when punch fails.

**Pre-flight: WARN STEVE BEFORE NS RESTART.** Schedule window.

**Validation matrix:**

| Scenario | Expected outcome |
|---|---|
| Mac on Steve's home LAN → Windows on SD-WAN | punch succeeds, no relay traffic |
| Mac via cellular tether → Windows on SD-WAN | punch likely fails (carrier symmetric NAT), relay fallback engages |
| Kill primary relay mid-session | client fails over to backup relay within 10s |
| Kill NS during session | existing session continues (NS only needed for setup) |

**Steps:**

1. Build x86_64-linux release binary
2. Build Elixir NS release with R1's `0x0D` handler
3. SSH to AWS SaaS box, `docker compose pull && docker compose up -d` updated NS
4. Push gateway binary to Steve's Windows box, restart NSSM service with `--ns-server <addr>` (H10 makes punch default-on)
5. From Mac: `ztlp connect z2ls-desktop-lrc8dkh-dcc1e2.z2ls-final-e2e.techrockstars.ztlp --ns-server 16.147.41.195:23096`
6. tcpdump on both ends for: NS port 23096, relay port 23095, gateway ephemeral port
7. Assert pcap shows: PEER_ENDPOINTS, PUNCH_NOTIFY, PUNCH_BYTE both directions, then QUIC direct
8. Re-test with relay primary killed → confirm failover

**Tracker update:** mark H8 ✅ once pcap evidence captured.

---

## Task H9: Update docs/NAT-TRAVERSAL.md

**Objective:** Reflect the new working state. Add validation pcap excerpt. Link to PR.

**Files:** `docs/NAT-TRAVERSAL.md`

**Tracker update:** mark H9 ✅ → mark **DONE** ✅ → open PR.

---

## Final decision tree once all 13 tasks land

```
ztlp connect <name> --ns-server <addr>
    │
    ├─→ 1. Resolve <name> via NS → gateway node_id + SVC addr + zone's relay list
    │
    ├─→ 2. Try direct QUIC to SVC addr (5s timeout)            ← LAN-direct case
    │   ↓ fail
    ├─→ 3. NS-coordinated hole punch                            ← H1-H7
    │   ↓ timeout (10s)
    ├─→ 4. Pick best relay from pool by score (latency × load × region)
    │   ↓ try handshake (10s)
    │   ↓ fail → report_handshake_failure → failover_degraded
    │
    ├─→ 5. Try next-best relay                                  ← R1-R3
    │   ↓ exhaust all relays
    ├─→ 6. Re-query NS for fresh relay list (zone might have new relays)
    │   ↓ still no working relays
    └─→ 7. Hard error: "no reachable path to <name>"
```

Background probe task keeps health stats fresh between attempts — so step 4's "best relay" pick is informed by 30s-old PING latency, not a cold guess.

---

## Verification checklist (before opening PR)

- [ ] All 14 task commits in sequence on `feat/resilient-connectivity` (H0 not committed — spike branch)
- [ ] `cd proto && cargo test --release` → no regressions, all new tests pass
- [ ] `cd ns && mix test` → all new Elixir tests pass, no regressions
- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy --release -- -D warnings` clean
- [ ] Progress Tracker shows all 14 rows ✅
- [ ] PR description includes the H8 pcap as proof
- [ ] CodeRabbit pass review
- [ ] CI: Rust (proto), Elixir gateway/ns/relay, Interop, Performance Gate all green

---

## Risk + rollback

**Highest risk:** H3 quinn wrapper. **Mitigation:** H0 spike de-risks before H1 starts. If spike fails, escalate before sinking time.

**Second-highest risk:** H10 default-flip. **Mitigation:** safety valves (`--no-punch`, `--no-relay-pool`). Bench validates the behavior matrix before merge.

**Rollback:** Whole feature is gated by `--ns-server`. Without NS configured, neither subsystem activates. Existing `--relay`-pinned invocations unchanged.

**Bench safety:** H8 requires NS restart. Per memory: bench-iOS-crash-on-restart. Plan explicitly requires Steve approval window.

---

## Resume protocol (if session interrupted)

When a new session opens this plan:

1. Read the **Progress Tracker** table — find the last row with status ✅.
2. The next row (🔲 or 🟡) is where to resume.
3. Check `git log --oneline -5` on `feat/resilient-connectivity` to confirm tracker matches commit history.
4. If tracker and git disagree, **trust git** and re-update tracker.
5. Update "Last resumed at" line near the top of this file in the next commit.

This way, **no progress is lost on context resets**.

---

## Execution handoff

Plan complete. After this plan PR merges, I'll start with **H0 spike (30 min throwaway)**. If spike passes, I'll work through H1-H10 with `subagent-driven-development` (per-task two-stage review), updating the tracker on every commit. H8 will be paused for Steve approval; H9 closes the work.
