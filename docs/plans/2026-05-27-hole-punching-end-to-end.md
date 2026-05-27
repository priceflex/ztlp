# Hole Punching End-to-End Implementation Plan

> **For Hermes:** Use `subagent-driven-development` skill to implement task-by-task, with two-stage review per task.

**Goal:** Make `ztlp connect --punch --ns-server <NS>` actually traverse NAT between client and gateway end-to-end, with relay fallback when the punch fails.

**Architecture:**
The wire protocol (PEER_ENDPOINTS / PUNCH_NOTIFY / PUNCH_REPORT, types `0x0A` / `0x0B` / `0x0C`) is already implemented in both `proto/src/punch.rs` (Rust client) and `ns/lib/ztlp_ns/server.ex` (Elixir NS server). The missing piece is **gateway-side wiring**: the gateway never registers its public endpoint with NS from the same socket it listens on, and the gateway never reacts to incoming `PUNCH_NOTIFY` packets. We fix that with a `PunchAgent` that lives next to `cmd_listen`, sharing the QUIC listener's UDP socket, sending periodic `PUNCH_REPORT` keepalives to NS, and dispatching incoming `PUNCH_NOTIFY` packets to a punch responder.

**Tech Stack:** Rust (proto), Elixir (NS), Tokio async, existing `punch::execute_punch` for the responder side, existing `EndpointStore` GenServer on the NS side.

---

## Background — what already exists vs. what's missing

**Already exists (verified by reading code 2026-05-27):**

- `proto/src/punch.rs` (1118 lines): full client-side punch state machine. `execute_punch` runs the dual-side punch loop. `encode_peer_endpoints_request`, `encode_punch_report`, `decode_peer_endpoints_response`, `decode_punch_notify`, `is_punch_notify`, `is_punch_packet` — all present.
- `ns/lib/ztlp_ns/server.ex` lines 214-243, 834-901: handles `0x0A` (PEER_ENDPOINTS query → looks up target's known endpoints, returns response, side-effect-sends `0x0B` PUNCH_NOTIFY to the target), `0x0C` (PUNCH_REPORT — node refreshing its endpoints).
- `ns/lib/ztlp_ns/endpoint_store.ex` (referenced via `EndpointStore.record_endpoint` / `get_endpoints`): stores `:learned` (NS observed the source IP:port from inbound packet) and `:reported` (client claimed its endpoints in a PUNCH_REPORT/PEER_ENDPOINTS request) endpoints.
- `ns/test/ztlp_ns/punch_protocol_test.exs`: integration tests for the NS handler.
- CLI plumbing: `cmd_connect` calls `punch::execute_punch` when `--punch` is set (PR #62 fixed the bypass bug).

**Missing — root cause that `--punch` fails end-to-end today:**

1. **Gateway never tells NS where to find it for punching.** `cmd_listen`'s `_ns_server` argument is underscore-prefixed (unused). `ztlp ns register` uses a different ephemeral socket, so the source IP:port NS learns is meaningless for punch packets.
2. **Gateway has no PUNCH_NOTIFY handler.** Even if NS sent `0x0B` to the gateway's QUIC socket, Quinn would drop the packet because it doesn't match the QUIC header. The gateway needs to peek incoming UDP before handing to Quinn.
3. **No keepalive.** NAT mappings expire (30-60s typical). Without periodic refresh, NS's learned endpoint goes stale within a minute of the gateway booting.

**Out of scope for this plan:**
- STUN-based endpoint discovery (already exists in `nat.rs`, not part of the NS-coordinated flow).
- The Rendezvous (`nat.rs`) protocol — that's a separate orthogonal path; we leave it alone.
- Punching when client is behind symmetric NAT (handled by relay fallback, which already works).
- `ztlp listen` becoming a long-lived daemon that re-registers KEY/SVC records (separate concern, tracked in `FOLLOWUPS-2026-05-26.md` item 4).

**Out of band — fixes needed AFTER this plan lands:**
- Relay-mediated nat-assist for symmetric-NAT cases (already-existing code in `cmd_connect` legacy path lines 2440-2470 may need an audit pass once we have a working baseline).

---

## Sub-task overview

| # | Task | Files touched | LOC est. |
|---|---|---|---|
| H1 | Add `PunchAgent` skeleton with shared socket + NS address config | new `proto/src/punch_agent.rs`, `proto/src/lib.rs` | ~80 |
| H2 | Wire `PunchAgent` keepalive: send `PUNCH_REPORT` every 25s | `proto/src/punch_agent.rs` | ~50 |
| H3 | Add packet-peek dispatcher to `cmd_listen` so PUNCH_NOTIFY is intercepted before Quinn sees it | `proto/src/bin/ztlp-cli.rs` cmd_listen | ~100 |
| H4 | On PUNCH_NOTIFY receipt, gateway invokes `punch::execute_punch` from its listener socket (responder mode) | `proto/src/punch.rs` (add responder variant), `punch_agent.rs` | ~70 |
| H5 | Add `--punch` and `--ns-server` flags to `ztlp listen`, wire to `PunchAgent` | `proto/src/bin/ztlp-cli.rs` (cmd_listen signature + clap) | ~40 |
| H6 | End-to-end integration test using fake-NS + two `UdpSocket`s in same process | new `proto/tests/punch_e2e_test.rs` | ~150 |
| H7 | Add NS-side test that PUNCH_NOTIFY uses the responder's `:learned` endpoint, not just `:reported` | `ns/test/ztlp_ns/punch_protocol_test.exs` | ~40 |
| H8 | Bench validation: deploy v0.30.12 NS + gateway on AWS, run client from Mac through SD-WAN | deploy script | ops-only |
| H9 | Documentation: update `docs/NAT-TRAVERSAL.md` with implementation status table | `docs/NAT-TRAVERSAL.md` | ~30 |

**Total LOC estimate:** ~560 lines code + ~190 lines test.

**TDD discipline:** every task ships RED test → minimal GREEN → commit.

---

## Task H1: PunchAgent skeleton

**Objective:** Create a `PunchAgent` struct that owns a clone of the gateway's UDP listener socket and knows the NS server address. No behavior yet — just construction and shutdown.

**Files:**
- Create: `proto/src/punch_agent.rs`
- Modify: `proto/src/lib.rs` (add `pub mod punch_agent;`)
- Test: inline `#[cfg(test)] mod tests` in `punch_agent.rs`

**Step 1: Write failing test**

```rust
#[tokio::test]
async fn punch_agent_constructs_with_socket_and_ns_addr() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ns_addr: SocketAddr = "127.0.0.1:23096".parse().unwrap();
    let node_id = NodeId([0xAA; 16]);
    let agent = PunchAgent::new(Arc::new(sock), ns_addr, node_id);
    assert_eq!(agent.ns_addr, ns_addr);
}
```

**Step 2: Run test to verify failure**

```bash
cd proto && cargo test --lib punch_agent_constructs
# Expected: error[E0432]: unresolved import `crate::punch_agent::PunchAgent`
```

**Step 3: Write minimal implementation**

```rust
//! Gateway-side hole-punch agent: keepalives + responder dispatch.
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

**Step 4: Run test to verify pass**

```bash
cd proto && cargo test --lib punch_agent_constructs -- --nocapture
# Expected: test result: ok. 1 passed
```

**Step 5: Commit**

```bash
git checkout -b feat/hole-punch-end-to-end
git add proto/src/punch_agent.rs proto/src/lib.rs
git commit -m "feat(punch): H1 PunchAgent skeleton with shared socket + NS addr"
```

---

## Task H2: Keepalive loop sends PUNCH_REPORT every 25s

**Objective:** `PunchAgent::start()` spawns a tokio task that emits a `PUNCH_REPORT` (`0x0C` + node_id + 0 reported endpoints) every 25 seconds — fast enough to keep NAT mappings alive (30-60s typical timeout).

**Files:**
- Modify: `proto/src/punch_agent.rs`
- Test: inline (using a fake NS receiver on `127.0.0.1:0`)

**Step 1: Write failing test**

```rust
#[tokio::test(start_paused = true)]
async fn punch_agent_sends_report_every_25s() {
    // Bind a "fake NS" socket; PunchAgent's keepalive should send to it.
    let ns_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ns_addr = ns_sock.local_addr().unwrap();

    // Gateway socket
    let gw_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let node_id = NodeId([0x42; 16]);

    let agent = PunchAgent::new(Arc::new(gw_sock), ns_addr, node_id);
    let _handle = agent.start_keepalive(Duration::from_secs(25));

    // First report should be sent within 100ms of start (initial tick)
    let mut buf = [0u8; 512];
    let recv = tokio::time::timeout(Duration::from_millis(500), ns_sock.recv(&mut buf)).await;
    assert!(recv.is_ok(), "expected initial PUNCH_REPORT within 500ms");
    let n = recv.unwrap().unwrap();
    assert_eq!(buf[0], 0x0C, "first byte must be PUNCH_REPORT type");
    assert_eq!(&buf[1..17], &node_id.0[..], "node_id must follow");

    // Advance 25s and expect another report
    tokio::time::advance(Duration::from_secs(25)).await;
    let recv2 = tokio::time::timeout(Duration::from_millis(500), ns_sock.recv(&mut buf)).await;
    assert!(recv2.is_ok(), "expected second PUNCH_REPORT after 25s");
}
```

**Step 2: Run test to verify failure**

```bash
cd proto && cargo test --lib punch_agent_sends_report
# Expected: no method `start_keepalive` on `PunchAgent`
```

**Step 3: Implement minimal**

```rust
use crate::punch::encode_punch_report;
use std::time::Duration;
use tokio::task::JoinHandle;

impl PunchAgent {
    pub fn start_keepalive(self: &Self, interval: Duration) -> JoinHandle<()> {
        let sock = self.socket.clone();
        let ns_addr = self.ns_addr;
        let node_id = self.node_id;
        tokio::spawn(async move {
            // Empty endpoints — NS uses learned source addr
            let pkt = encode_punch_report(&node_id, &[]);
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if let Err(e) = sock.send_to(&pkt, ns_addr).await {
                    tracing::warn!("punch keepalive send failed: {}", e);
                }
            }
        })
    }
}
```

**Step 4: Verify pass**

```bash
cd proto && cargo test --lib punch_agent_sends_report -- --nocapture
# Expected: test result: ok
```

**Step 5: Commit**

```bash
git add proto/src/punch_agent.rs
git commit -m "feat(punch): H2 PunchAgent keepalive sends PUNCH_REPORT every 25s"
```

---

## Task H3: Packet-peek dispatcher in cmd_listen

**Objective:** When `--punch` is enabled on `ztlp listen`, intercept inbound UDP packets, route `0x0B` (PUNCH_NOTIFY) to the PunchAgent, route `0x00` (PUNCH_BYTE) silently to nowhere, and pass everything else to Quinn unchanged.

**Critical design decision:** Quinn's `bind_with_socket` takes ownership of the std socket. We need to peek before Quinn does. **Two options:**

  - **A. Wrap Quinn's runtime:** Use `quinn::Runtime` trait with a custom `AsyncUdpSocket` that filters. Heavy — requires implementing the full trait.
  - **B. Split the socket pair:** Bind one UDP socket, `try_clone` it. Give the clone to Quinn (Quinn ignores unknown packets — already true for non-QUIC bytes — verify), AND read from the original in a peek-loop. Both sockets receive *all* packets (Linux/macOS UDP semantics on same (fd-shared) socket).

Option B is simpler but has a subtle problem: with `try_clone`, both fds reference the same kernel socket; only ONE fd gets each packet (whichever recvs first). Not reliable.

  - **C. Single socket, single reader:** Read all packets on the listener task, dispatch by first byte. Inject non-punch packets back into Quinn via Quinn's `connect_with` or by maintaining our own datagram framing. **Too invasive.**

  - **D. Use Quinn's `Endpoint::wait_idle` + a recv-side filter via Quinn's `Runtime` trait.** Heavy.

  - **E. Pre-read with `recv` on a borrowed `std::net::UdpSocket` clone, dispatch punch traffic from there; tell Quinn to only listen on a SECOND port for QUIC. NS sees the punch port; client gets a SVC record pointing at the QUIC port.** Simple but means two public ports must traverse NAT — not great.

**Chosen approach (option F, new):** Replace Quinn's default async UDP socket with a thin wrapper (`quinn::AsyncUdpSocket` impl) that intercepts inbound packets in its `poll_recv` and dispatches PUNCH_NOTIFY/PUNCH_BYTE to channels owned by `PunchAgent`. All other bytes flow through to Quinn unchanged.

quinn 0.10+ exposes `quinn::Runtime::wrap_udp_socket` — we customize. This keeps **one socket, one port**, which is what NAT punching requires.

**Files:**
- Create: `proto/src/punch_socket.rs` (new wrapper type)
- Modify: `proto/src/punch_agent.rs` (add `dispatch_punch_notify(data, src)` method)
- Modify: `proto/src/bin/ztlp-cli.rs` `cmd_listen` (use `PunchSocket::wrap(std_socket)` when `--punch`)
- Test: inline + new `proto/tests/punch_socket_test.rs`

**Step 1: Write failing test (filtering behavior)**

```rust
// proto/tests/punch_socket_test.rs
#[tokio::test]
async fn punch_socket_intercepts_punch_notify_passes_through_quic() {
    // 1. Bind a UDP socket
    // 2. Wrap with PunchSocket which has a tx channel for intercepted packets
    // 3. Send a PUNCH_NOTIFY (0x0B + 16-byte node_id + 0-count + 0-len) at it
    // 4. Send a fake "QUIC" packet (0xC0 first byte, e.g.) at it
    // 5. Assert: PUNCH_NOTIFY shows up on the intercept channel; the QUIC packet shows up via Quinn-style poll_recv
}
```

**Step 2: Verify failure** — function doesn't exist.

**Step 3: Implement `PunchSocket` as a thin `quinn::AsyncUdpSocket` wrapper.**

Skeleton:

```rust
pub struct PunchSocket {
    inner: quinn::udp::UdpSocketState,  // or quinn_udp directly
    fd: std::net::UdpSocket,
    intercept_tx: tokio::sync::mpsc::UnboundedSender<(Bytes, SocketAddr)>,
}

impl quinn::AsyncUdpSocket for PunchSocket {
    fn poll_recv(&self, cx, bufs, meta) -> Poll<io::Result<usize>> {
        // call inner.recv; for each packet:
        //   if data[0] == 0x0B → forward to intercept_tx, do NOT include in returned bufs
        //   if data[0] == 0x00 → drop (punch byte, gateway uses it as keepalive only)
        //   else → include in returned bufs as normal
    }
    // delegate poll_send, local_addr, ...
}
```

**Step 4: Verify pass** — both packets dispatched correctly.

**Step 5: Commit**

```bash
git commit -m "feat(punch): H3 PunchSocket — intercept 0x0B before Quinn sees it"
```

**Pitfall:** `quinn::AsyncUdpSocket` trait may have changed across quinn versions. Verify the exact signature against the version pinned in `proto/Cargo.toml` before implementing. If quinn's trait surface is too unstable, fall back to: **two real sockets on the same port via SO_REUSEPORT (Linux/macOS only).** Windows requires Option F-prime: implement via `WSARecvFrom` with a tee. Cross-platform UDP socket-sharing in Rust is notoriously bad.

**Risk note:** Linux/macOS SO_REUSEPORT load-balances packets across listeners — no good. SO_REUSEADDR doesn't share inbound. **The quinn-wrapper approach is the only portable option.** If quinn version blocks us, escalate to Steve for a quinn-version bump rather than working around it.

---

## Task H4: Gateway-side punch responder

**Objective:** When `PunchAgent` receives a `PUNCH_NOTIFY` via H3's intercept channel, parse it (extract requester's NodeId + endpoints) and launch a responder punch — send `0x00` punch bytes to those endpoints until either Quinn sees a real QUIC handshake from one of them or 10 seconds elapse.

**Subtle point:** the responder doesn't need to do the full `execute_punch` flow — it doesn't query NS for the requester's endpoints (already provided in the notify). It just needs to **send PUNCH_BYTEs to the requester's reported endpoints** so the requester's NAT sees outbound traffic from us, opening the return path.

**Files:**
- Modify: `proto/src/punch.rs` — add `pub async fn respond_to_punch(sock, peer_endpoints, duration) -> Result<()>`
- Modify: `proto/src/punch_agent.rs` — `start_dispatcher(intercept_rx)` consumes the rx, decodes notify, calls `respond_to_punch`

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
    let (n1, _) = tokio::time::timeout(Duration::from_secs(2), peer1.recv_from(&mut b)).await.unwrap().unwrap();
    assert_eq!(n1, 1);
    assert_eq!(b[0], 0x00);
    let (n2, _) = tokio::time::timeout(Duration::from_secs(2), peer2.recv_from(&mut b)).await.unwrap().unwrap();
    assert_eq!(n2, 1);
    assert_eq!(b[0], 0x00);
}
```

**Step 2: Fail** — `respond_to_punch` doesn't exist.

**Step 3: Implement**

```rust
pub async fn respond_to_punch(
    sock: &UdpSocket,
    peer_endpoints: &[SocketAddr],
    duration: Duration,
) -> std::io::Result<()> {
    let deadline = Instant::now() + duration;
    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    while Instant::now() < deadline {
        ticker.tick().await;
        for ep in peer_endpoints {
            let _ = sock.send_to(&[PUNCH_BYTE], ep).await;
        }
    }
    Ok(())
}
```

**Step 4: Pass.**

**Step 5: Commit:** `feat(punch): H4 gateway-side responder sends PUNCH_BYTE to requester endpoints`

---

## Task H5: Wire --punch / --ns-server flags into `ztlp listen`

**Objective:** `ztlp listen --bind 0.0.0.0:23095 --punch --ns-server <addr> [...]` should construct a `PunchAgent`, wrap its socket with `PunchSocket`, hand the wrapped socket to Quinn, and start both keepalive + dispatcher.

**Files:**
- Modify: `proto/src/bin/ztlp-cli.rs`:
  - Remove the `_`-prefix from `ns_server` arg in `cmd_listen`
  - Add `punch: bool` flag to the clap definition under `Listen` subcommand
  - In the body, when `punch && ns_server.is_some()`, build the agent + wrap the socket

**Step 1: Test (integration)** — covered by H6.

**Step 5 only (this is a wiring task, no isolated unit test):**

```bash
cd proto && cargo build --release
cd /home/trs/ztlp && ./proto/target/release/ztlp listen --help | grep -A1 punch
# Expected: "--punch" flag shown
```

**Commit:** `feat(punch): H5 wire --punch and --ns-server into ztlp listen`

---

## Task H6: End-to-end integration test

**Objective:** Spin up a fake NS, a gateway with `--punch`, and a client with `--punch`, all in-process. Verify that after handshake, a real QUIC stream can flow without `--relay`.

**Files:**
- Create: `proto/tests/punch_e2e_test.rs`

This will be the largest test (~150 lines). The skeleton:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_end_to_end_no_relay() {
    // 1. Bind a fake NS that:
    //    - Handles 0x0A (PEER_ENDPOINTS): returns target's learned endpoint
    //    - On receipt, sends 0x0B PUNCH_NOTIFY to the target with requester's endpoint
    //    - Handles 0x0C (PUNCH_REPORT) — just records the source as learned
    //
    // 2. Start a gateway via PunchAgent + Quinn listening on 127.0.0.1:0
    //    - The gateway runs PunchAgent::start_keepalive + start_dispatcher
    //
    // 3. Wait until fake NS has learned the gateway's endpoint
    //
    // 4. From a client socket, send PEER_ENDPOINTS (0x0A) to fake NS asking for gateway's endpoints
    //    - Receive 0x0A response containing gateway's address
    //
    // 5. Send PUNCH_BYTE (0x00) to gateway's address, then attempt QUIC handshake
    //    - This proves the punch opened the path
    //
    // 6. Assert: client-to-gateway QUIC connection succeeds within 10s
}
```

**Commit:** `test(punch): H6 end-to-end punch via in-process fake NS`

---

## Task H7: NS-side test for `:learned` endpoint priority

**Objective:** Verify that `pick_best_notify_addr` (`ns/lib/ztlp_ns/server.ex` line 865) prefers `:learned` endpoints over `:reported` — because `:reported` is what the client *claimed*, `:learned` is the real NAT-mapped public endpoint.

**Files:**
- Modify: `ns/test/ztlp_ns/punch_protocol_test.exs` — add new `describe "pick_best_notify_addr"`

**Step 1: Test**

```elixir
describe "pick_best_notify_addr/1" do
  test "prefers learned over reported when both present" do
    target_id = :crypto.strong_rand_bytes(16)
    EndpointStore.record_endpoint(target_id, {1, 2, 3, 4}, 23095, :reported)
    EndpointStore.record_endpoint(target_id, {5, 6, 7, 8}, 56789, :learned)

    # Send a PEER_ENDPOINTS from a requester; capture the PUNCH_NOTIFY
    # destination via a packet capture / test socket.
    # Assert: PUNCH_NOTIFY sent to {5,6,7,8}:56789 (the :learned), not :reported.
  end
end
```

**Step 5: Commit:** `test(ns): H7 verify PUNCH_NOTIFY uses :learned endpoint`

---

## Task H8: Bench validation on AWS

**Objective:** Deploy v0.30.12-rc with hole-punching to AWS NS + a fresh gateway behind SD-WAN (Steve's Windows bench). Run `ztlp connect --punch --ns-server …` from his Mac. Capture pcap. Confirm direct UDP flow (no relay).

**Pre-flight:** **WARN STEVE BEFORE NS RESTART** — bench iOS will crash on restart. Schedule a window.

**Steps:**

1. Build `ztlp` x86_64-linux release binary
2. Build Elixir NS release with updated punch protocol (if any NS changes landed in H7 needed deployment)
3. SSH to AWS SaaS box, `docker compose up -d` the updated NS
4. Copy gateway binary to Steve's Windows box (via NSSM-managed location)
5. Restart `Z2LS` service with new args: `--punch --ns-server 16.147.41.195:23096`
6. From Mac: `ztlp connect z2ls-desktop-lrc8dkh-dcc1e2.z2ls-final-e2e.techrockstars.ztlp:22 --punch --ns-server 16.147.41.195:23096`
7. Run `tcpdump -i any -n 'udp port 23096 or udp portrange 23090-23100'` on both ends
8. Confirm in pcap:
   - Mac → NS: PEER_ENDPOINTS (0x0A)
   - NS → Windows-public-IP: PUNCH_NOTIFY (0x0B)
   - Windows-public-IP → Mac-public-IP: PUNCH_BYTE (0x00)
   - Mac-public-IP → Windows-public-IP: PUNCH_BYTE (0x00)
   - Quinn handshake between the two public IPs (without going through the relay)

**Verification:**
- `ztlp connect` should print "Direct connection via hole punch to <ip>:<port>"
- ssh through the tunnel should work
- relay docker logs should show **no** new tenant routing for this session

**Commit doc:** `docs(z2ls): bench-validate hole-punching e2e on v0.30.12`

---

## Task H9: Update NAT-TRAVERSAL.md

**Objective:** Replace the "current state" section with the new working state, leave the design rationale intact for future reference.

**Files:**
- Modify: `docs/NAT-TRAVERSAL.md`

**Update sections:**
- "Current State" table: change "❌ Not wired" → "✅ Working on Linux/macOS gateways, ⚠ Windows gateway needs WSARecvFrom approach (tracked in H3 pitfall)"
- Add "Validation Run 2026-MM-DD" section with pcap excerpt
- Add link to PR

**Commit:** `docs(nat): update NAT-TRAVERSAL with H1-H8 implementation status`

---

## Verification checklist (before opening PR)

- [ ] All 9 task commits in sequence on `feat/hole-punch-end-to-end`
- [ ] `cd proto && cargo test --release` → no regressions, +new tests pass
- [ ] `cd ns && mix test` → +H7 test passes, no regressions
- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy --release -- -D warnings` clean (toolchain 1.85.0)
- [ ] PR description includes the pcap from H8 as proof
- [ ] CodeRabbit pass review
- [ ] CI: Rust (proto), Elixir gateway/ns/relay, Interop, Performance Gate all green

---

## Risk + rollback

**Highest risk:** Task H3 — wrapping quinn's UDP socket. If quinn's `AsyncUdpSocket` trait doesn't support our use case on the pinned version, this entire plan stalls. **Mitigation:** spike H3 first (throwaway branch, 30 min), confirm the approach compiles, THEN proceed with H1-H2 (which are independent).

**Rollback:** All changes gated by `--punch` flag. Without the flag, `cmd_listen` behaves exactly as today. Reverting is a single PR.

**Bench safety:** H8 requires NS restart on AWS. If Steve says "don't restart yet", **stop and wait**. Bench-iOS-crash-on-restart is a hard constraint per memory.

---

## Open questions for Steve before starting

1. **Quinn version on `proto/Cargo.toml`** — anything pinned recently that might block H3? (I'll check before spiking.)
2. **Punch keepalive interval** — 25s is the standard. Any reason to go shorter for SD-WAN? (Some enterprise SD-WANs have ~15s UDP conntrack.)
3. **Should `--punch` default to `true` once H8 passes?** Or stay opt-in until v0.31.0? My recommendation: opt-in for v0.30.12, default in v0.31.0 after a week of soak.
4. **Windows gateway support** — H3 is Linux/macOS via quinn wrapper. Windows may need an SO_REUSEADDR-based fallback (or a second port). Acceptable for v0.30.12 to ship Linux/macOS only?

---

## Execution handoff

Plan saved. Ready to execute using `subagent-driven-development` skill — fresh subagent per task with two-stage review (spec compliance, then code quality). Each task is bite-sized and TDD-disciplined. Estimated 6-8 hours focused work for H1-H7 (code+test), plus H8 bench window with Steve.

**Recommended starting point:** Spike H3 first (30-min throwaway branch) to confirm the quinn-wrapper approach is viable on the pinned version. If it works, kick off H1-H9 sequentially.
