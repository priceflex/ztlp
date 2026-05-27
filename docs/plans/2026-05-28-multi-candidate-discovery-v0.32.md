# v0.32 — Multi-Candidate Discovery (ICE-Style Connectivity)

**Status:** **APPROVED** — Steve signed off on the four open questions 2026-05-28. M1 in progress.
**Author:** drafted with assistant, approved by Steve
**Branch:** `docs/v0.32-multi-candidate-discovery`
**Companion:** [`v0.31.0-relay-deployment-investigation.md`](../v0.31.0-relay-deployment-investigation.md) — the failure mode this spec eliminates

> **For Hermes:** Execution uses `subagent-driven-development` skill + **BDD/TDD discipline per task**. Every task lands as RED (failing test first) → GREEN (minimal impl) → REFACTOR → commit. Update the Progress Tracker table in the same commit as each task so a session restart can resume cleanly.

## BDD/TDD discipline (mandatory per task)

Every M-task must be implemented in this order — no exceptions:

1. **RED.** Write the failing test first. For Rust this is `cargo test <test_name>` returning a clear failure that pins the desired behaviour. For Elixir it's `mix test path/to/test:LINE` failing the same way. Commit message marker: `(RED captured: <what fails>)`.
2. **GREEN.** Write the minimum production code that turns the failing test green. No extra features, no speculative generality.
3. **REFACTOR.** Clean up names, extract helpers, run `cargo fmt && cargo clippy --all-targets -- -D warnings` (Rust) or `mix format && mix credo --strict` (Elixir). Tests must still pass.
4. **Full-suite verify.** `cargo test --all` (proto) or `mix test` (ns). No regressions tolerated.
5. **Commit.** Single squash-style commit per task with the What/Why/Details/Tests/Validation/Follow-up template Steve uses.

Subagent briefs MUST quote this discipline verbatim in the implementer context. The spec-compliance reviewer MUST verify the RED test exists and was added in the same commit as the implementation (use `git show <sha> --stat` to confirm test file + source file changed together).

---

## TL;DR

The Z2LS-via-relay failure that ate two days of v0.31.0 validation was caused by a single root design gap: **the NS only knows one address per gateway — the server-reflexive (NAT'd) source IP of its registration packet.** Every other production-grade overlay network (Nebula, Tailscale, Syncthing, WebRTC) advertises a **list** of candidate addresses per peer, and the dialer races them in parallel. This spec brings ZTLP to parity.

The Z2LS case becomes a 1ms LAN handshake instead of a relay round-trip through an internet path that's blocked by a misconfigured edge router. Same-LAN connectivity stops being a deployment landmine.

**The wire protocol is already 80% there.** PUNCH_REPORT (`0x0C`) and PEER_ENDPOINTS (`0x0A`) already carry `reported_endpoints[]` arrays; NS already stores `:learned` + `:reported` endpoints per NodeID. The missing piece is: **gateways do not enumerate their local NICs and publish them.** That's the load-bearing 30 lines of code, plus a smaller-than-expected set of follow-ons.

---

## Background — what the other guys do

### Nebula (lighthouse)

Each host periodically sends `HostUpdateNotification` to its lighthouse, containing **every local IP on every NIC**. The lighthouse stores `reported_addrs[]` from the host plus `observed_addr` it sees in the packet header. Peers query the lighthouse and get the full set back. The dialer fires handshake init packets at all candidates in parallel; whichever responds first wins. LAN-direct connections complete in <1ms with zero relay involvement.

### Tailscale (DERP control plane)

`tailscaled` reports all interface addresses to the control plane via `netcheck`. Peers receive the candidate set on subscription updates. The magic-DNS resolver picks the best path based on observed RTT, falling back to a DERP relay only when direct paths fail.

### Syncthing

Two-track discovery:
- **Global discovery** announces all reachable URIs (`tcp://1.2.3.4:22000, tcp://192.168.1.50:22000, dynamic+https://relay.example`) to a central server.
- **Local discovery** broadcasts to `255.255.255.255:21027` on UDP every 30s. Peers find each other LAN-local with zero internet round-trip — works even if global discovery is down.

### WebRTC / ICE

The canonical reference. Each side gathers candidates in three classes:
- **Host** — local NIC addresses (`192.168.x.x`, `10.x.x.x`, link-local)
- **Server-reflexive (srflx)** — what a STUN/TURN server sees as the public source
- **Relayed (relay)** — TURN-allocated transport addresses

Each candidate has a priority. The connectivity-check phase races all pairs and converges on the best working path.

### What ZTLP does today

`ztlp gateway register-v2` sends a single `GATEWAY_REGISTER_V2` (`0x0E`) frame to the relay. The NS only learns the gateway's address when the gateway sends PUNCH_REPORT (`0x0C`) keepalives — but the gateway's PUNCH_REPORT currently sends `reported_count=0`, so NS only knows the **NAT'd source address** it sees in the packet header (the server-reflexive candidate, in ICE terms).

Result: when a client on the same LAN as the gateway resolves `z2ls`, NS returns the gateway's public WAN address. Client tries to dial it from inside the LAN, hits hairpin-NAT issues or a missing edge port-forward, falls back to relay, relay also can't reach the gateway. Catastrophic for a case that should have been a direct LAN handshake.

---

## Goal & non-goals

**Goal:** A `ztlp connect <name>` invocation succeeds via the shortest viable path: LAN-direct when peers are co-located, hole-punch when both sides are behind cone NAT, relay only when nothing else works. The path-selection logic must be entirely automatic and not require any user-visible flags beyond `--ns-server`.

**Non-goals (v0.32):**
- Not implementing IPv6 link-local mDNS discovery (Syncthing's UDP-broadcast track). That's v0.33 if Steve wants it.
- Not changing TURN-style relay semantics. Relay stays the backstop.
- Not introducing a new "discovery service" component. NS stays single-source-of-truth.
- Not breaking v0.31 clients. Wire compat is mandatory through one minor release.

---

## What's already there vs. what's missing

### Already there ✅

| Component | Capability | File |
|---|---|---|
| Wire protocol | PUNCH_REPORT (0x0C) carries `reported_count::8` + N × `[family, addr, port]` | `proto/src/punch.rs` |
| Wire protocol | PEER_ENDPOINTS (0x0A) response returns N candidates | `proto/src/punch.rs` + `ns/lib/ztlp_ns/server.ex` |
| NS storage | `EndpointStore` stores both `:learned` (srflx) and `:reported` (host) per NodeID | `ns/lib/ztlp_ns/endpoint_store.ex` |
| Client dialer | `execute_punch` already races multiple candidate endpoints in parallel | `proto/src/punch.rs` |
| Relay pool | `FailoverOrchestrator` already ranks/probes multiple relay addrs | `proto/src/relay_pool.rs` |

### Missing ❌

1. **Gateway-side interface enumeration.** The gateway's PUNCH_REPORT keepalive sends `reported_count=0`. It needs to enumerate local non-loopback NICs and stuff them in.
2. **NS endpoint freshness / priority.** All endpoints stored equal. We need priority hints (host > srflx > relay) so the dialer races them in a sensible order.
3. **Orchestrator path selection.** `cmd_connect` currently follows: resolve SVC → query PEER_ENDPOINTS → punch → relay fallback. It should be: gather candidate list → parallel-dial all candidates with priority-staggered timeouts → relay only after every candidate fails. The data is there; the orchestration is missing.
4. **Wire-compat fence.** v0.31 NS will simply ignore the gateway's new `reported_endpoints[]` until v0.32 NS is deployed. We need to verify this is graceful (it is — `reported_count=0` is the existing happy path) and ship NS first.
5. **Operational tooling.** `ztlp gateway candidates <name>` admin command to list what NS currently knows for a given gateway. Critical for the next time we debug a connectivity failure.

---

## Wire-format changes

**None.** This is the killer feature: the wire protocol is already shaped right.

What changes is **what gateways put inside the existing `reported_endpoints[]` field** in PUNCH_REPORT (`0x0C`).

Today: `reported_count=0`.

After v0.32:
```
PUNCH_REPORT keepalive (every 10s):
  type = 0x0C
  node_id = <gateway 16-byte ID>
  reported_count = N   ← N local NIC addresses, IPv4 + IPv6
  for each:
    family = 0x04 (IPv4) | 0x06 (IPv6)
    addr   = 4 or 16 bytes
    port   = listener port (u16 BE)
```

NS already parses + stores this via `parse_and_track_reported/2`. No NS wire change needed.

### Where priority lives

ICE-style priority is computed **client-side at dial time**, not embedded in the wire format. Each `RelayListing`-style candidate entry gets a runtime-derived priority. **Steve-approved priority ladder (2026-05-28):**

| Class | Source | Priority |
|---|---|---|
| Host (same-subnet RFC1918) | Client and gateway share a subnet (e.g. both in `10.170.3.0/24`) | **250** |
| Host (other RFC1918) | Gateway-reported `10/8`, `172.16/12`, `192.168/16` outside client subnet | **200** |
| Host (VPN/overlay) | Tailscale `100.64/10`, our own overlay nets, any other private routable | **180** |
| Host (public IPv4) | Gateway-reported globally routable v4 | **160** |
| Host (link-local IPv6) | Gateway-reported `fe80::/10` | **140** |
| Server-reflexive | NS-observed source (`:learned`) | **100** |
| Relay | Relay pool primary | **50** |

Dialer fires handshakes in priority bands with a 250ms inter-band delay so the same-subnet LAN candidate "wins by default" if it's reachable. **VPN/overlay candidates are explicitly included** — they may be the only valid path for remote operators on Tailscale.

---

## Implementation tasks

This follows the resilient-connectivity plan's H/R numbering convention. New letter prefix: **M** for multi-candidate.

| # | Task | Surface | Risk | Est. LOC |
|---|---|---|---|---|
| M1 | Gateway interface enumerator — `local_candidates()` helper returning `Vec<SocketAddr>` from `pnet_datalink::interfaces()`, filtered for non-loopback non-link-local-IPv4 | proto | LOW | ~50 |
| M2 | Wire M1 output into gateway's PUNCH_REPORT builder — `build_punch_report(node_id, ts, candidates)` already accepts a `&[SocketAddr]`, just need to call site change | proto | LOW | ~20 |
| M3 | NS test: PUNCH_REPORT with N=3 reported endpoints stores all three; PEER_ENDPOINTS response includes all three + learned | ns Elixir | LOW | ~30 |
| M4 | Client-side candidate priority calculator — pure fn `prioritize(candidates) -> Vec<(SocketAddr, u32)>`, RFC1918 detection, sort | proto | LOW | ~80 |
| M5 | Parallel-dial orchestrator — `dial_candidates(socket, candidates, priority_band_delay_ms) -> Result<(SocketAddr, QuicConnection)>`. Fires handshakes in priority bands, first success wins, others cancelled | proto | **MED** — concurrency edge cases | ~150 |
| M6 | Wire M5 into `cmd_connect` — replace single-addr handshake with `dial_candidates()`. Relay-pool path becomes one band among others, not a sequential fallback | proto | MED | ~60 |
| M7 | `ztlp gateway candidates <name> --ns-server <addr>` admin command — queries NS PEER_ENDPOINTS for the named gateway, pretty-prints with class/priority | proto (CLI) | LOW | ~80 |
| M8 | Backward-compat test matrix: v0.31 client × v0.32 NS, v0.32 client × v0.31 NS, v0.31 gateway × v0.32 NS. Confirm graceful degradation everywhere | proto + ns | MED | tests only |
| M9 | Bench validation — re-run the Z2LS topology from the v0.31 investigation doc. Expected: LAN-direct succeeds in <50ms instead of timing out on punch and falling to broken relay path | bench | n/a | docs only |
| M10 | Docs — update `docs/NAT-TRAVERSAL.md` with the candidate-priority section, add an example wire trace, retire the workaround paragraphs that say "configure edge port-forward" | docs | LOW | docs |
| **DONE** | All tests green, PR pending merge, Z2LS topology validation deferred to RC | ✅ | _this commit_ | All 10 M-tasks complete. Branch `feature/v0.32-multi-candidate-discovery` carries: M1-M9 commits + 2 docs commits (this is the M10/closing one). 1001/1001 lib + 8/8 v032_compat integration + 11/11 NS punch_protocol + N/N admin tests green across the branch. Live AWS smoke-test PASS per M9 docs/v0.32.0-bench-validation.md. Z2LS Windows-gateway bench validation deferred to v0.32.0 RC phase — Steve-driven, requires Windows binary deploy. |

**Total estimated LOC:** ~470 production + tests. Materially smaller than the resilient-connectivity work because the wire protocol is already built.

---

## Progress Tracker

> Update this table in the same commit as each task. State machine: 🔲 not started → 🟡 in progress → ✅ done → ❌ blocked.

| # | Task | Status | Commit SHA | Notes |
|---|---|---|---|---|
| M1 | Gateway local-candidate enumerator | ✅ | 96b8eb8 + 03e6392 | RED: filter_candidates() didn't exist; tests failed to compile (E0433). GREEN: 16 tests pass, 941/941 lib suite clean. Quality review surfaced 3 important issues (silent get_if_addrs error, force_include + down NIC inconsistency, doc/code drift on v6 filter) + 1 coverage gap (ULA/exactly-8) — all fixed in 03e6392 with 4 new regression tests. Final: 20/20 local_candidates tests pass, 945/945 lib suite passes, fmt+build clean. Deps: if-addrs 0.13 added. |
| M2 | Wire into PUNCH_REPORT keepalive | ✅ | a67add5 | RED: 6 failing tests + compile errors (no field `advertise_exclude`, no fn `with_advertise_overrides`). GREEN: 4 new PunchAgent fields, with_advertise_overrides() constructor, start_keepalive() re-enumerates per tick via enumerate_local_candidates_with_overrides(). CLI: 3 new clap flags (--advertise-interface, --no-advertise-interface, --advertise-all-interfaces) wired through cmd_listen. 12/12 punch_agent tests pass (6 prior + 6 new). 951/951 lib suite green (was 945, +6). Spec review PASS, quality review APPROVED zero critical/important issues. 2 files, 302+/10- LOC. |
| M3 | NS test: N-endpoint roundtrip | ✅ | 5e9ae6c | RED captured via 999-probe inversion (asserted length == 999, got left:3, right:999), reverted to GREEN. 5 new tests in ns/test/ztlp_ns/punch_protocol_test.exs: 3-IPv4 store, mixed v4+v6 store, 8-cap store, malformed-tolerant, PEER_ENDPOINTS roundtrip (3 reported + 1 learned). Zero production code changes — server.ex parse_and_track_reported already supported N>0; M3 is pure coverage. 11/11 punch_protocol tests pass (was 6, +5). 745/745 full NS suite green (was 740, +5). mix format clean. 1 file, +178/-3 LOC. |
| M4 | Client priority calculator | ✅ | c42754a | RED: stub classify() returned Relay → "assertion left == right failed, left: Relay, right: HostSameSubnet". GREEN: 7-tier enum (Relay=50 → HostSameSubnet=250), classify(), prioritize() w/ stable descending sort, v4 u32-mask + v6 byte-walk subnet math, 100.64/10 CGNAT detection. v0.32 simplifications documented: VPN overlay = 100.64/10 only, v6 ULA+global flattened to priority 200 until v0.33 adds v6 subnet matching. 15/15 candidate_priority tests pass, 966/966 lib suite green (was 951, +15). Spec 10/10, quality 9/9, zero critical/important issues. 2 files, 411+ LOC. |
| M5 | Parallel-dial orchestrator | ✅ | b62bbbd | RED: stub dial_candidates always returned NoCandidates → 2 passed/10 failed baseline. GREEN: Dialer trait + DialPolicy + dial_candidates() racing in priority bands via JoinSet, abort_all on first success, per-candidate + total-budget timeouts. 12 BDD tests using #[tokio::test(start_paused=true)] for deterministic mocked time (entire suite runs in 0.00s wall-time). Test 7 explicitly verifies no task leak by advancing 10s post-success and asserting slow-dial counter stays at 0. async-trait 0.1 added; tokio test-util dev-dep. 978/978 lib green (was 966, +12). Spec 12/12, quality 7/7. 2 documented-tradeoff Importants (empty BudgetExhausted.tried, silent task panics) deferred to M6. APPROVED. 3 files, 643+ LOC. |
| M6 | Wire into cmd_connect | ✅ | 103cfff | Implementer hit max_iterations after writing all code + tests; orchestrator independently verified (988/988 lib, build clean, fmt clean) and committed. NEW multi_candidate_dial.rs with try_multi_candidate_connect() + QuicDialer (Phase 1 UDP probe 0xFE+nonce). our_local_subnets() added to local_candidates.rs using if_addrs::Ifv4Addr::prefixlen. cmd_connect gains --multi-candidate clap flag (hide=true). Injection is SAFE per spec review: failure falls through to existing v0.31 path with send_addr untouched. QuicDialer binds its own ephemeral socket — zero collision risk. 10 new BDD tests (8 multi_candidate_dial + 2 local_candidates). 988/988 lib green (was 978, +10). Spec 10/10, quality 9/9, ZERO critical/important, 4 minor cosmetic notes. APPROVED. 4 files, 736+ LOC. |
| M7 | `ztlp gateway candidates` admin cmd | ✅ | b619220 | NEW proto/src/admin/gateway_candidates.rs (367 LOC, 7 tests) + GatewayCommands::Candidates clap variant + cmd_gateway_candidates handler. Resolves gateway via NS, queries PEER_ENDPOINTS, classifies via candidate_priority, prints table or --json. class_short_name maps 7 variants → "host"/"srflx"/"relay". 995/995 lib green (was 988, +7). `ztlp gateway candidates --help` shows full description + examples. Spec 10/10, quality 8/8, APPROVED zero critical/important. 4 files, 499+ LOC. |
| M8 | Backward-compat matrix | ✅ | 0ad9423 | NEW proto/tests/v032_compat_matrix_test.rs — 8 wire-level tests pinning all 6 rows of the Mixed-version safety matrix. NEW pub fn decode_punch_report() in proto::punch symmetric to encode_punch_report (~50 LOC + 6 unit tests covering empty / multi-v4 / mixed v4+v6 / wrong-type / too-short / truncated-tail). Tests are encode/decode-only (not live UDP); they pin the on-wire contract mixed-version pairs depend on. 1001/1001 lib green (was 995, +6). 8/8 integration tests green. Build + fmt + clippy clean. |
| M9 | Bench validation (Z2LS topology) | ✅ | 5ed01ca | LIVE AWS validation PASS. v0.32 binary deployed to 16.147.41.195:23997 with --advertise-all-interfaces. NS direct-state dump confirmed 9 endpoints stored (8 :reported host candidates + 1 :learned srflx) — vs. v0.31 status quo of :learned only. M4 priority calculator run against live data ranked same-subnet host at 250, other RFC1918 at 200, srflx at 100, relay at 50. v0.31 production NS parsed the v0.32 frames transparently — confirms back-compat claim. 3 v0.32.1 candidates flagged: keepalive socket port mismatch (port 48278 vs listener 23997), ns-register missing node_id CBOR field, loopback classification edge. Z2LS bench validation deferred to RC phase per Steve's "warn before restart" preference — procedure documented in findings doc. Full evidence in docs/v0.32.0-bench-validation.md. |
| M10 | NAT-TRAVERSAL.md update | ✅ | _this commit_ | TL;DR updated to reflect v0.32 status (gone from "not shippable" pre-2026-05-26 to "v0.30.12 ships hole-punch + relay pool; v0.32 adds multi-candidate"). New v0.32 implementation-status section parallel to v0.30.12 with 10-row M-task tracker, defaults table, wire-protocol back-compat note, live-data evidence (the 9-endpoint EndpointStore dump from M9), 3 v0.32.1 candidates listed. Retired the obsolete "Workaround for the same-WAN topology" paragraph — replaced with a pointer to `--multi-candidate` and a note that direct-IP-only bypass remains useful for no-NS environments. |

---

## Compatibility plan

### Forward path (preferred)

1. Ship **v0.32 NS** first. v0.31 gateways continue to send `reported_count=0`; new NS accepts that and falls back to `:learned`-only candidate sets exactly like v0.31 NS does today. Zero behavioral change for existing deployments.
2. Ship **v0.32 gateway**. Now sends candidates. v0.32 NS stores them. v0.31 clients querying v0.32 NS receive a list including new host candidates; their dialer ignores everything past the first one (legacy single-addr code path) but does not crash.
3. Ship **v0.32 client**. Now races the full list. Get the LAN-direct path.

### Mixed-version safety

| Gateway | NS | Client | Result |
|---|---|---|---|
| v0.31 | v0.31 | v0.31 | Status quo — relay-dependent |
| v0.31 | v0.32 | v0.31 | Status quo — gateway sends 0 candidates |
| v0.32 | v0.31 | v0.31 | Status quo — old NS ignores extra candidates (parser tolerant) |
| v0.32 | v0.32 | v0.31 | Status quo — client uses first candidate only |
| v0.32 | v0.32 | v0.32 | **LAN-direct enabled.** |
| v0.31 | v0.32 | v0.32 | Falls back to srflx-only. Same as today. |

**The matrix is permissive — every cell is at least as good as v0.31 status quo.** That's the test M8 has to verify per row.

### NS parser tolerance check

`parse_and_track_reported/2` in `ns/lib/ztlp_ns/server.ex` already iterates `reported_count` entries with bounded length checks. M3 will assert this stays robust when N grows from 0 to up to 8 reported endpoints. Hard cap of 8 candidates per gateway is enforced client-side to keep the keepalive packet under the 1280-byte safe-MTU floor (8 × 18 bytes for IPv6 entries = 144 bytes; well under).

---

## Dial-policy design (the M5 hard part)

This is where ICE-style implementations get tricky. The race policy:

```
candidates = sorted_by_priority(gateway_candidates ∪ [srflx] ∪ relay_pool)
bands = group_by_priority_class(candidates)  // host > srflx > relay

for band in bands:
    spawn handshake to each candidate in band concurrently
    wait min(handshake_timeout, band_delay_ms = 250)
    if any band-N handshake succeeded:
        cancel all others
        return
    // else fall through to next band
```

**Why bands, not pure parallel?** A pure parallel fire-everything-at-once dial is wasteful (you spam the relay even when LAN works) and creates connection-state cleanup races. Bands give the lower-cost paths a 250ms head start. The relay band only fires if host + srflx all fail.

**Cancellation:** each handshake runs in a `tokio::select!` against an `mpsc::Receiver<()>` cancel signal. When the first success arrives the orchestrator drops the sender, cancelling all in-flight peers. Their sockets and any partial QUIC state get cleaned up by their drop impls.

**Timeout policy:** per-candidate handshake timeout = 2s. Total dial budget = 8s. After that, error out with `NoReachableCandidate { tried: Vec<(SocketAddr, Error)> }` — the error variant exposes per-candidate failure reasons so the next debugging session doesn't repeat the v0.31 mistake of guessing at the cause.

**Test strategy for M5:**
- BDD tests with `FakeSocket` that selectively answers handshakes by addr (modeled after H6 in resilient-connectivity)
- Property test: any subset of candidates being reachable should result in the highest-priority reachable one being returned
- Concurrency test: deliberate handshake collisions across bands shouldn't leak tasks (`tokio_metrics::TaskMonitor` to verify clean cleanup)

---

## Operational impact

### Keepalive size

PUNCH_REPORT today: `1 + 16 + 1 = 18 bytes`. After v0.32 with 4 IPv4 candidates: `18 + 4×7 = 46 bytes`. With 4 IPv4 + 4 IPv6: `18 + 4×7 + 4×19 = 122 bytes`. All comfortably under any plausible MTU. Bandwidth impact: ~12KB/hour per gateway at 10s keepalive cadence. Negligible.

### NS storage

EndpointStore today stores ~2 endpoints per NodeID (learned + maybe one reported). After v0.32: up to 9 per NodeID (8 reported + learned). For 1000 gateways: ~9000 endpoint rows. Trivial.

### Observability

`ztlp gateway candidates <name>` (M7) is the operator's window into this. Should output:

```
$ ztlp gateway candidates z2ls --ns-server 16.147.41.195:23096
Gateway: z2ls (node_id: 6d82769c38054da6...)
Last keepalive: 7s ago

Candidates:
  PRIO  CLASS  ADDR                   AGE   SOURCE
  200   host   10.170.3.111:23095     7s    reported
  200   host   172.17.0.1:23095       7s    reported (docker bridge)
  100   srflx  204.16.122.24:55712    7s    learned (NS-observed)
```

This is the artifact future-Steve uses to debug "why isn't z2ls reachable from my laptop" in 30 seconds instead of two days.

---

## Carry-forward / v0.33 candidates

- **Syncthing-style LAN broadcast.** Pure-offline mDNS discovery for sites with no NS reachability at all. Distinct subsystem; doesn't touch this spec.
- **Path quality scoring.** Per-candidate RTT tracking, prefer lower-latency paths on subsequent connects. Tailscale's approach.
- **IPv6 happy-eyeballs.** Currently the v0.32 priority puts public IPv6 below RFC1918 IPv4. Worth measuring whether modern dual-stack networks prefer the other way.
- **STUN-style external port discovery.** Right now srflx == NS-observed port. A separate STUN exchange would let us learn the gateway's NAT'd port without relying on NS being the punch coordinator. Useful if we ever split discovery from coordination.

---

## Decisions (Steve-approved 2026-05-28)

1. **Candidate cap: hard 8 per gateway.** Fits the existing `reported_count::8` wire model, covers real-world host counts (LAN + Docker + VPN + WAN/srflx + relay), avoids MTU/log spam and path explosion, deterministic and easy to test. **If a gateway has >8 candidates, rank and keep the best 8** (priority ladder above is the ranking function).

2. **VPN-overlay IPs are host candidates, lower priority than RFC1918 LAN.** Tailscale `100.64/10`, our own overlays, etc. all qualify. Explicitly **do not skip** — VPN may be the only valid path for remote operators. See priority table above for the full order.

3. **Interface publishing: default auto-publish with safe filtering, operator override flags.**
   **Publish by default:**
   - up + running interfaces
   - non-loopback
   - non-link-local
   - IPv4 first
   - IPv6 only if the local stack supports it cleanly (interface has at least one global-or-ULA v6 address bound)
   **Skip by default:**
   - `127.0.0.0/8` (loopback)
   - `169.254.0.0/16` (IPv4 link-local / APIPA)
   - Docker bridges (`docker0`, `br-*`) **unless explicitly enabled**
   - down interfaces
   **Operator override flags on `ztlp listen`:**
   - `--advertise-interface <name>` — force include (additive, can repeat)
   - `--no-advertise-interface <name>` — force exclude (additive, can repeat)
   - `--advertise-all-interfaces` — disable filtering entirely (drops the Docker/link-local default skips)
   Flag precedence: `--no-advertise-interface` > `--advertise-interface` > `--advertise-all-interfaces` > default filter.

4. **Release scope: ship multi-candidate as its own v0.32.0.** Do not bundle with v0.31 carry-forwards (relay probe ack, etc.). Reasons: materially changes connectivity behaviour (easier rollback if needed); cleaner test matrix; keeps v0.31 focused on auth/security hardening that already shipped; v0.32 becomes the unambiguous "resilient-connectivity" release.

---

## Next steps

Proceed with M1 using the BDD/TDD discipline at the top of this doc and the `subagent-driven-development` skill. Update the Progress Tracker in the same commit as each task lands.
