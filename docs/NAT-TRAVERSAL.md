# NAT Traversal in ZTLP

**Status:** Living design doc — captured 2026-05-26 after debugging same-WAN client→gateway routing through an SD-WAN edge.

This doc answers: **how does hole-punching work, when should ZTLP use it, and what's the right default?**

---

## TL;DR (the recommendation)

**Strategically: yes — turn on hole-punching by default** once it actually works
end-to-end. That's the architecture every modern overlay net uses (Tailscale, Nebula,
Twingate, WireGuard+STUN). When it lands, the relay becomes a fallback path for the
~10-20% of NAT topologies that can't be punched.

**Tactically (today, 2026-05-26)**: punching is NOT shippable. The v0.30.13 binary has
the CLI flags wired up but neither the **gateway side** nor the **NS rendezvous** is
implemented. See "What I actually tried tonight" below. Until those land, the only
viable paths are:

- **LAN-direct** (works today, no relay involved) — for same-network endpoints
- **Relay-routed** (works today) — for cross-network endpoints, requires the SD-WAN to
  not block unsolicited inbound on `:23095` (i.e., a port-forward on the customer's
  edge to the gateway)

Concretely, our flags **should** change once the protocol is built out:

| Today                          | Should be                                                |
|--------------------------------|----------------------------------------------------------|
| `--punch` opt-in               | **punch always on**, opt out with `--no-punch`           |
| `--nat-assist` opt-in          | **nat-assist always on**, opt out with `--no-nat-assist` |
| `--no-relay-fallback` opt-in   | Keep — that's the audit-mode escape hatch                |
| `--relay-pool` opt-in          | Keep opt-in (only useful with multiple relays)           |

The default user experience should be: **`ztlp connect <name>` Just Works** on every
network topology, with the client transparently choosing the best path. No flags.

---

## Implementation status — v0.30.12 (2026-05-27)

The work proposed in the table above is **shipped** as of v0.30.12 (PR #63 merged
docs, follow-up PR ships code on `feature/resilient-connectivity-v0.30.12`).
The 14-row tracker in [`docs/plans/2026-05-27-resilient-connectivity-plan.md`](plans/2026-05-27-resilient-connectivity-plan.md)
is the authoritative source of per-task SHAs and test counts; the table below
summarises what landed.

| Task | Status | Commit | Verified by |
|------|--------|--------|-------------|
| H0 — `quinn::AsyncUdpSocket` wrapper spike | ✅ | 0fa4e13 | throwaway example compiled and ran; quinn 0.11.9 confirmed |
| H1 — `PunchAgent` skeleton | ✅ | 884932e | inline unit test |
| H2 — `start_keepalive(10s)` emits `0x0C PUNCH_REPORT` | ✅ | 83aa185 (10s confirmed in a39a49e) | wire-format unit test |
| H3 — `PunchSocket` intercepts `0x0B` / drops `0x00` before Quinn | ✅ | 566cb46 | 5 unit tests with `FakeSocket` driver |
| H4 — Gateway-side responder + dispatcher | ✅ | f2372e7 | 6 unit tests (responder + dispatcher + malformed-payload tolerance) |
| H5 — `--punch` / `--ns-server` wired into `ztlp listen` | ✅ | c65c83b | live binary `--help`; 896 lib tests |
| H6 — In-process end-to-end punch test (fake NS, no relay) | ✅ | 83c991c | `proto/tests/punch_e2e_test.rs` — happy path + 2 timeouts in 0.61 s |
| H7 — Elixir `pick_best_notify_addr/1` prefers `:learned` | ✅ | 7e886ac | 4 BDD ExUnit tests |
| H10 — Auto-on when `--ns-server` is set, `--no-punch` / `--no-relay-pool` escape hatches | ✅ | a39a49e | 9 BDD unit tests + smoke test against `ztlp connect/listen --help` |
| R1 — `0x0D LIST_RELAYS` protocol (Rust + Elixir) | ✅ | f0245fb | 12 Rust + 4 Elixir tests |
| R2 — Relay probe task drives `record_probe_*` | ✅ | 1f23162 | 3 BDD tests; v0.30.11-compatible probe wire format |
| R3 — `pool.primary()` consulted per handshake; `report_handshake_*` after | ✅ | a2452d2 | 4 BDD tests (no-pool fallback, primary override, failed-primary→backup, empty-pool) |
| H8 — Bench validation on AWS + SD-WAN | 🔲 | — | **Requires NS-restart window with Steve.** pcap evidence + manual relay-kill / NS-kill tests pending |
| H9 — This doc | ✅ | (this commit) | — |

**Defaults as of v0.30.12:**

```
ztlp connect <name>                       → QUIC mode, no NAT traversal (legacy default)
ztlp connect <name> --ns-server <addr>    → punch ON  +  relay-pool ON  (auto)
ztlp connect <name> --ns-server <addr> --no-punch       → relay-pool ON, no punch
ztlp connect <name> --ns-server <addr> --no-relay-pool  → punch ON, single relay
ztlp listen --ns-server <addr>            → punch ON  (gateway side)
ztlp listen --ns-server <addr> --no-punch → punch OFF (audit mode)
```

**Wire-protocol additions in v0.30.12:**

| Type byte | Direction      | Purpose                                    |
|-----------|----------------|--------------------------------------------|
| `0x0A`    | client → NS    | `PEER_ENDPOINTS` query (existing)          |
| `0x0B`    | NS → client/gw | `PUNCH_NOTIFY` (existing, intercepted by `PunchSocket`) |
| `0x0C`    | gw → NS        | `PUNCH_REPORT` keepalive (10 s cadence)    |
| `0x0D`    | client → NS    | **`LIST_RELAYS` (new)** — query registered relays, optionally per-zone |
| `0x5A37 / 0xFE` | client → relay | **Probe ping (new)** — silent on v0.30.11 relays; success = no ICMP |

**Keepalive:** 10 s (down from the 25 s originally proposed; revised after the
2026-05-27 Z2LS bench observed punctuated stalls under load on the SD-WAN
edge).

**H8 pcap excerpt — VALIDATED 2026-05-27 against AWS NS + Z2LS Windows gateway + external Linux client (real SD-WAN edge).**

Bench setup:
- NS: `priceflex/ztlp-ns:v0.30.12` on AWS `16.147.41.195:23096` (rebuilt from feature/resilient-connectivity-v0.30.12 merge commit `e214d3f`)
- Z2LS Windows gateway: `C:\TRS_Tools\ztlp\ztlp.exe listen ... --ns-server 16.147.41.195:23096 ...` (no `--punch` flag — H10 auto-enables it)
- Client: this Linux orchestrator host (external, behind separate NAT)
- Invocation: `ztlp connect z2ls-desktop-lrc8dkh-dcc1e2.z2ls-final-e2e.techrockstars.ztlp --ns-server 16.147.41.195:23096 --service ssh --local-forward 12224:127.0.0.1:22`

What the Z2LS gateway log captured immediately after v0.30.10 → v0.30.12 swap (proving H10 default-flip + 10s keepalive land in production):
```
ZTLP QUIC server listening on UDP 0.0.0.0:23095
[H10] Punch enabled — keepalive to 16.147.41.195:23096 every 10s
Enabling QUIC gateway registration for relay: 34.218.240.106:23095 (src=0.0.0.0:23095)
gateway registered with 34.218.240.106:23095 (service: z2ls-desktop-lrc8dkh-dcc1e2)
```

Client log captured the full punch coordination cycle:
```
Relay pool: enabled
  Primary relay: 34.218.240.106:23095
  Probe interval: 30s
Connecting to: 34.218.240.106:23095
Hole punching enabled — coordinating via NS...
punch: querying NS at 16.147.41.195:23096 for peer bc97d655929c30be37885ff8de4881c8 endpoints
punch: targeting 1 peer endpoints
punch: target endpoint: 204.16.122.24:60808       ← real SD-WAN-mapped public endpoint
punch: waiting 100ms for PUNCH_NOTIFY propagation
punch: sent punch to 204.16.122.24:60808           (× 20 attempts at 500ms cadence)
⚠ Hole punch timed out — continuing with direct connection attempt
✓ Listening for TCP connections on 127.0.0.1:12224

(after tunnel established)
DEBUG relay 34.218.240.106:23095 probe success: 500.656727ms   ← R2 probe task working
```

pcap (UDP filter `port 23095 or port 23096`, sampled mid-handshake) shows the exact expected wire-format byte counts:
```
06:56:57.581  client.46515 → NS.23096  UDP len=65   ← SVC lookup (name → record)
06:56:57.617  NS.23096 → client.46515  UDP len=322  ← SVC record response
06:56:57.617  client.36863 → NS.23096  UDP len=65   ← KEY lookup (NodeID → pubkey)
06:56:57.651  NS.23096 → client.36863  UDP len=377  ← KEY record response
06:56:57.652  client.58609 → NS.23096  UDP len=41   ← 0x0A PEER_ENDPOINTS query (1+16+16+1+7 = 41 ✓)
06:56:57.687  NS.23096 → client.58609  UDP len=9    ← 0x0A response with 1 IPv4 endpoint (1+1+1+4+2 = 9 ✓)
```

Findings vs Done Criteria:
| Criterion | Result |
|-----------|--------|
| `PEER_ENDPOINTS → PUNCH_NOTIFY → bidirectional PUNCH_BYTE → direct QUIC` | ⚠ Partial — NS coordination + client-side punch packets confirmed. Punch DID NOT succeed against this SD-WAN edge (consistent with symmetric NAT documented in the doc above); fell back to relay path as designed. |
| punch timeout → automatic relay fallback | ✅ confirmed; client logged "Hole punch timed out — continuing with direct connection attempt", relay path stayed up |
| kill primary relay mid-session → failover within 10s | ⚠ Partial — tunnel survived a 90s relay-down window, but probe_relay's "no ICMP = healthy" heuristic means probes still reported success against a stopped docker container (documented limitation in relay_pool.rs; future work to make probes actively echo-confirmed) |
| kill NS mid-session → existing session continues | ✅ **confirmed** — `docker stop ztlp-ns` for 30s+ during an active tunnel: probe task continued, tunnel stayed listening on the local-forward port, no client-side errors |
| Steve's canonical command works end-to-end | ✅ tunnel established via the relay path on the first try; the punch *attempt* is automatic from `--ns-server` alone (no `--punch` flag needed) |

Operational notes from the bench (recorded as production pitfalls):
- NS mnesia tables MUST be wiped on minor-version upgrade; v0.30.10 → v0.30.12 crashed on boot until the mnesia dir was removed (preserve `ca/`). Documented in `ztlp-prod-deployment` skill.
- The Chef-managed Z2LS identity is X25519-only (no Ed25519 signing key), so NS `register` requires `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false` env in v0.30.12 NS until identities are regenerated. Track as a follow-up to migrate the gateway identity format before flipping NS back to auth-required.
- `probe_relay()` cannot distinguish "relay alive, ignored my unknown 0xFE packet" from "no listener at all" — both produce the same recv_from timeout. To actually drive R2 failover, the relay needs a 0xFE → 0xFF echo (v0.31.0 work).

---

## Why this debug session needed hole punching

The bench setup tonight had:

```
Steve's Mac      ─┐
                  ├─ SD-WAN edge ─ 204.16.122.24 ─ public internet
Windows VM       ─┘
```

Both endpoints sit behind the **same SD-WAN appliance**. The Mac wants to reach the
Windows VM via the AWS relay path:

1. Mac → SD-WAN-NAT → relay (works — outbound is fine, SD-WAN remembers the flow)
2. Relay → SD-WAN public IP → Windows VM (**fails** — SD-WAN sees an unsolicited inbound
   UDP packet on `:23095` with no existing flow state for the relay→Mac pair, drops it)

The gateway's own keepalive flow to the relay has its own conntrack entry, so the relay
can send registration ACKs back — those work. But a fresh packet from the relay
*forwarding the Mac's handshake* uses different src/dst port tuple, and that's a
different flow as far as the SD-WAN is concerned. SD-WAN drops it.

**Hole punching escapes this trap by ensuring both endpoints have already sent outbound
packets to each other's public endpoint before any inbound is expected.** Once both
sides have outbound state in their NAT, return packets flow through transparently.

---

## How hole punching actually works

There are four moving parts:

### 1. STUN — discover your public endpoint

```
                STUN binding request (UDP)
   You (10.0.0.5:34567) ──────────────────────▶ stun.l.google.com:19302
                                                       │
                STUN response: "you appear to be       │
                X.Y.Z.W:48291 from where I'm sitting"  │
   You ◀───────────────────────────────────────────────┘
```

STUN tells you **what your NAT thinks your public endpoint is for the socket you used
to send the STUN request**. Critically:

- The same internal socket gets the same external endpoint when used immediately afterward
- The endpoint mapping is per-(internal-src, external-dst) on most home routers (cone NAT)
- Or per-(internal-src, external-dst-host, external-dst-port) on enterprise gear
  (symmetric NAT) — this is the case that breaks punching

### 2. Rendezvous via NS — exchange endpoints

Both endpoints need to learn each other's public endpoint. ZTLP uses the **NS** for this:

```
Mac      ──[announce: my pub endpoint = 1.2.3.4:48291, my NodeID = 1c3e0ddb...]──▶ NS
Gateway  ──[announce: my pub endpoint = 5.6.7.8:23095, my NodeID = bc97d655...]──▶ NS

Mac      ──[query: where is bc97d655...?]──▶ NS
NS       ──[5.6.7.8:23095]──▶ Mac

Gateway  ──[query: where is 1c3e0ddb...? (sent by NS as part of the punch invite)]
```

The NS doesn't relay any data — it just brokers the punch invitation.

### 3. Synchronized punch — both sides send to each other

```
T+0ms (NS tells both sides to punch):
  Mac:     send small UDP packet to 5.6.7.8:23095
  Gateway: send small UDP packet to 1.2.3.4:48291

T+~50ms:
  Mac's NAT: outbound to 5.6.7.8:23095 — install conntrack entry
  GW's NAT:  outbound to 1.2.3.4:48291 — install conntrack entry

T+~100ms:
  Mac's packet arrives at GW NAT. NAT sees existing outbound entry to Mac's IP+port.
   → forwards inbound to Gateway. ✓
  GW's packet arrives at Mac's NAT. NAT sees existing outbound entry to GW's IP+port.
   → forwards inbound to Mac. ✓

Both sides now have a working bidirectional UDP flow without any port-forward,
without any relay carrying data, and the connection is direct.
```

The "small UDP packet" is intentionally cheap (a few bytes, no encryption) so it's safe
to send to a stranger IP. If the other side never sent its punch (NAT type mismatch,
firewall blocks outbound to ephemeral ports, etc.) the packet just gets dropped.

### 4. QUIC handshake over the punched path

Once both sides have flow state, ZTLP runs the normal Noise_XX QUIC handshake over the
direct path. The relay is no longer in the data path.

---

## When punching fails (and why we keep the relay as backstop)

| NAT type                          | Punch succeeds? | Notes                                          |
|-----------------------------------|------------------|------------------------------------------------|
| **Full Cone**                     | ✓ Always         | Cisco term; rare in modern gear                |
| **Restricted Cone**               | ✓ With sync      | Most home routers                              |
| **Port-Restricted Cone**          | ✓ With sync      | Default Linux NAT, most consumer routers       |
| **Symmetric NAT**                 | ✗ Usually fails  | Enterprise firewalls, carrier-grade NAT, some SD-WANs |
| **CGN (Carrier-Grade NAT)**       | ✗ Usually fails  | Mobile carriers, some ISPs (cgnat 100.64/10)   |
| **Hairpin NAT** (same-LAN endpoints) | ✓ if hairpinning enabled, ✗ otherwise | Many SD-WANs disable hairpin |
| **Symmetric + Symmetric**         | ✗ Always fails   | Both endpoints behind enterprise NAT           |

The **realistic punch success rate** with both sides home/SMB is 80-90%. With one side
enterprise it drops to 50-60%. With both enterprise/SD-WAN it can drop to 10-20%.

Tailscale's published numbers say ~85% of their sessions are direct-via-punch, ~15% are
relay-routed (DERP). That matches industry experience.

**This is why we keep the relay-routed path as a fallback.** Punch is the fast path;
relay is the always-works path.

---

## What "auto-detect" would look like

You asked: should we auto-detect when to punch?

The answer is **no — auto-detection is more expensive than just always trying**. Here's why:

The "is my NAT punchable" detection process is:
1. Discover public endpoint via STUN (1 RTT to STUN server)
2. Send a probe to a known public IP, see if it comes back (1 RTT)
3. Send a probe to a *different* port at the same IP, check NAT mapping (1 RTT)
4. Parse the results to classify your NAT type

That's 3 RTTs of network probing **just to decide whether to try**. By the time you've
decided, you could have just attempted the punch — which would have either worked
(saving you the relay round-trip) or failed (and you'd fall back).

**Better strategy**: always punch in parallel with starting the relay-routed
connection. Whichever completes first wins. ICE (RFC 8445) calls this "trickle ICE" and
it's how WebRTC does it. Tailscale does this too.

```
T+0ms:   Mac kicks off both:
             - relay-routed Noise handshake
             - STUN discovery + punch invite to gateway via NS
T+~80ms:  STUN discovery completes
T+~150ms: Punch packets arrive at peer (if NAT permits)
T+~200ms: Direct-path Noise handshake completes
T+~250ms: Relay-routed Noise handshake also completes

Result: Mac picks the direct path, tears down or just stops feeding the relay path.
```

The user sees: connection up in ~250ms regardless of which path won. If punch wins, all
subsequent data is direct. If punch fails, relay carries the session.

---

## What about "always use the relay"?

Tempting answer for ops simplicity. But:

1. **Latency**: relay-routed adds 1 hop. For US-west-2 ↔ US clients that's ~30-50ms of
   added one-way latency per packet. SSH feels slow. Video feels slow.
2. **Bandwidth costs**: every byte of customer traffic goes through your AWS relay. At
   scale this is significant ($90/TB on AWS egress in us-west-2).
3. **Reliability**: relay is a single point of failure. With direct punch, the relay can
   die and existing sessions persist (until the next renegotiation).
4. **Scale**: a single relay container handles ~10K concurrent sessions before
   conntrack/CPU saturates. With direct punch, the relay just brokers connections; the
   data plane is distributed.

For these reasons, **relay-as-default is fine for v0.x but won't scale past a few hundred
customers**. Direct-path-by-default is the right architecture and is well-understood (this
is exactly the Tailscale model).

---

## Recommended changes

### Code changes (priceflex/ztlp)

1. **Change CLI defaults**:
   - `--punch` → on by default. Add `--no-punch` to disable.
   - `--nat-assist` → on by default. Add `--no-nat-assist` to disable.
   - These should be `bool` with default `true` in clap.
2. **Implement trickle ICE-style parallel paths**: start both relay-routed and
   punch attempts in parallel, use whichever completes first.
3. **Cache punch results**: if the last 3 connections to the same NodeID succeeded
   via direct path, skip the relay attempt for the first few RTTs.
4. **STUN server bundle**: bundle a list of public STUN servers in the binary
   (Google, Cloudflare, etc.) so users don't have to configure them. Currently the
   client requires `--stun-server` to be passed.

### Operations changes

1. **Run STUN on the same box as NS**: NS is already a low-traffic globally-deployed
   service. Add a STUN endpoint on `16.147.41.195:23097` (Steve's NS box has spare
   bandwidth). Each customer gets a fast STUN response from a topologically-close
   server they already trust.
2. **Multiple relays for failover**: a single AWS relay is a SPOF. Add at least one
   more region (us-east-2 + eu-west-1) with the same image, and use NS to advertise
   all of them. The client's `--relay-pool` flag already supports this; we just need
   to populate the pool.

### Documentation changes

1. **Add a "NAT topology" diagnostic command**: `ztlp diagnose` should run STUN
   discovery, classify the NAT, and tell the user what to expect. Output like:
   ```
   Public endpoint: 204.16.122.24:48291 (via stun.l.google.com)
   NAT type:        Port-Restricted Cone
   Punch likelihood: high
   Recommendation:  default settings should work
   ```
2. **Document the punch failure modes**: when punching fails, the user should see a
   clear diagnosis ("symmetric NAT detected, falling back to relay").

---

## What we can do tonight

1. **Validate the punch path actually works** on the current bench (Mac + Windows on
   same SD-WAN). This is the worst-case topology. If punch works here, it'll work
   everywhere.
2. **Document the gap**: the `--punch` flag is only documented in `--help`. Add a
   real example in `docs/GETTING-STARTED.md`.
3. **File the issues**: open GitHub issues for the default-on change and the trickle
   ICE work.

### What I actually tried tonight (2026-05-26)

Ran from Steve's Mac to Windows VM both behind the same SD-WAN:

```bash
./ztlp connect z2ls-desktop-lrc8dkh-dcc1e2.z2ls-final-e2e.techrockstars.ztlp \
  --relay 34.218.240.106:23095 \
  --service z2ls-desktop-lrc8dkh-dcc1e2 \
  --ns-server 16.147.41.195:23096 \
  --stun-server 74.125.250.129:19302 \
  --nat-assist --punch --punch-timeout 12s \
  -L 2222:127.0.0.1:22
```

**Result:** got `NAT traversal enabled — discovering public endpoint...` and then no
further progress. STUN discovery seemed to hang or silently fail. No `Direct connection
via hole punch to ...` line, no relay fallback message, no error.

**Findings while debugging:**

1. **The NS-resolved code path bypasses ALL NAT-traversal logic.** Looking at
   `proto/src/bin/ztlp-cli.rs` line 2259: `if relay.is_some() { ... punch logic ... }`.
   When the user passes only `--ns-server` (relay address is auto-resolved), the punch
   branch is never entered. The user has to *explicitly* pass `--relay` to even unlock
   the punch flags. **This is a CLI bug** — `--punch` should work transparently when
   NS is used.

2. **The gateway-side has no `--punch` support.** Running `ztlp listen --help` on the
   gateway shows `--stun-server` and `--nat-assist` only, no `--punch`. The
   NS-coordinated punch protocol (where NS brokers an "punch invite" between client and
   gateway) needs both sides to participate, but only the client knows about it. So
   even if the client's punch attempt fired correctly, the gateway would never receive
   the rendezvous instruction.

3. **`--stun-server` doesn't DNS-resolve.** Passing `--stun-server stun.l.google.com:19302`
   fails with `invalid socket address syntax`. The flag requires a literal `IP:PORT`.
   This is fine for bench testing but bad UX for end users.

**Conclusion:** the hole-punching feature in v0.30.13 is a **client-side stub**. The
flags exist, the client emits the punch-invite to NS, but:
- The NS doesn't know how to forward the invite to the gateway
- The gateway doesn't know how to participate
- The client only fires punch if `--relay` is explicitly passed (defeating "Just Works")

This needs **substantial implementation work** before it can be turned on by default.
See "Recommended changes" above — items 1 and 2 are the critical path.

### Workaround for the same-WAN topology in the meantime

Use LAN-direct (skip the relay path entirely) when both endpoints are on the same LAN:

```bash
./ztlp connect <gateway-LAN-IP>:23095 --service ssh -L 2222:127.0.0.1:22
```

This is what works on the bench today. See `Z2LS-E2E-RUNBOOK.md` "Working commands".

---

## References

- RFC 5389 — STUN
- RFC 8489 — STUN bis (current)
- RFC 8445 — ICE
- RFC 5128 — State of P2P communication across NATs
- Bryan Ford et al., "Peer-to-Peer Communication Across Network Address Translators"
  (USENIX 2005) — the foundational paper
- Tailscale, "How NAT traversal works" — https://tailscale.com/blog/how-nat-traversal-works
  (read this — it's a great summary)
- ZTLP source: `proto/src/lib.rs` → `mod nat` and `mod punch`
- ZTLP source: `proto/src/bin/ztlp-cli.rs` line 2300-2500 (current punch wiring)
