# NS Self-Registration Heartbeat — Listener Owns Its Own NS Presence

**Status:** Proposed
**Author:** Hermes Agent (under Steve Price)
**Date:** 2026-06-01

## Problem statement

Today, ZTLP listener nodes (z2ls boxes, desktop gateways) rely on **Chef cookbook
runs** to publish their KEY and SVC records into the production Name Server
(`ZtlpNs`, Mnesia-backed Elixir service on `16.147.41.195:23096`). The recipe:

1. Computes a hash of the listener's identity + service config.
2. If the hash differs from a marker file `svc-registered.sha256`, runs
   `ztlp ns register …`.
3. Otherwise skips registration.

This architecture has three concrete failure modes observed in production:

### Failure 1 — Records expire silently every 24h

NS records carry `ttl: 86400` (24h). The cookbook only republishes on
**hash change**, so identity-stable nodes go dark every 24h after their last
converge. Affected nodes:

```
Total tech-rockstars.trs.ztlp KEY records currently in NS:  3 valid + 22 expired phantoms
Total tech-rockstars.trs.ztlp SVC records currently in NS:  0 valid + 10 expired phantoms
```

(Phantoms = records visible via `:mnesia.foldl` but evicted from primary index;
they fool inspection tooling into reporting more health than actually exists.)

### Failure 2 — Listener restart ≠ NS refresh

If `ztlp_listener` Windows Service crashes and restarts on the same config, the
SVC record is **not** republished — the hash hasn't changed, the marker is
still present, Chef skips. The relay-side route refreshes (it's keyed by live
socket); the NS-side does not. Discovery API returns Not Found for a node that
is up and reachable.

### Failure 3 — Manual NS recovery requires multi-system fix

When NS Mnesia is wiped (recent migration, schema repair, hostname fix), the
fleet does NOT self-heal. Every Chef-managed node has a stale marker file
claiming "I already registered." Recovery requires either:

- SSH-iterating every node to delete `svc-registered.sha256` + force converge,
  OR
- Cron-rotating the marker file invalidation across the fleet.

Both are out-of-band, manual, and slow.

## Proposal

**Move NS registration from a one-shot Chef step into a heartbeat task owned by
the listener process itself.** This is how Consul agents, etcd clients,
Kubernetes endpoints controllers, and Nomad workers all handle service
discovery: the **running service** publishes its own liveness.

### Architecture

```
┌─────────────────────────────────────────────┐
│           ztlp listen (process)             │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │  QUIC endpoint + relay registration  │   │  ← unchanged
│  └──────────────────────────────────────┘   │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │  NEW: ns_heartbeat_task              │   │
│  │  ─ initial publish (sync, fail-fast) │   │
│  │  ─ every 8h ± 10min jitter:          │   │
│  │      republish KEY + SVC             │   │
│  │  ─ logs each cycle (success/failure) │   │
│  └──────────────┬───────────────────────┘   │
│                 │                            │
└─────────────────┼────────────────────────────┘
                  │ UDP
                  ▼
          ┌────────────────┐
          │  ZtlpNs (NS)   │
          │  TTL=86400s    │
          └────────────────┘
```

### Heartbeat cadence

- TTL is 24h (86400s).
- Heartbeat every **8 hours** (3 publishes per TTL window — comfortably below
  the Nyquist threshold for the "miss 1, still alive" failure mode).
- ± **10 minutes of uniform random jitter** so a 1000-node fleet doesn't
  stampede NS at the top of each 8h cycle.

### Failure semantics

| Scenario | Behavior |
|---|---|
| Initial publish at startup | Synchronous. Failures **fail the listener startup** (visible in Windows service event log). |
| Heartbeat tick: NS unreachable | Logged as `WARN`. Retry on next tick. Listener keeps serving traffic. |
| Heartbeat tick: NS returns error | Logged as `WARN` with decoded error code. Retry on next tick. |
| Heartbeat tick: success | Logged as `INFO`. |
| Listener shut down cleanly | Records TTL out naturally within 24h (acceptable). |

### Chef cookbook changes

After this lands and is verified in two production fleets, Chef's
`ztlp_ns_register` resource and the `svc-registered.sha256` marker file are
**deleted**. The cookbook's responsibility shrinks to:

1. Install the `ztlp.exe` binary.
2. Drop `config.toml` (with `ns_server`, `service_name`, `zone`).
3. Drop `identity.json`.
4. Install `ztlp_listener` Windows Service.

No NS interaction. The listener handles its own presence.

### Backward compatibility (Phase 1 ship — this PR)

- `ztlp ns register` CLI subcommand **remains unchanged**. Now a thin wrapper
  around the same `ns_publish_self` helper the heartbeat uses.
- Existing Chef cookbooks continue to work — they call `ztlp ns register` once;
  meanwhile the running listener now also publishes itself every 8h.
- Belt-and-suspenders for one release. Cookbook cleanup is a follow-up PR.

### What this does NOT change

- Wire format of KEY/SVC records (CBOR layout pinned by the existing
  `ns_register_*_record_includes_node_id` tests, T3 v0.32.1).
- The `cmd_ns_register` CLI subcommand's external behavior.
- Anything in the NS server (Elixir side). Pure client refactor.
- Relay registration. That path is independent and already lives in the
  listener.

## Test plan

### Unit tests (`#[cfg(test)]` in `ztlp-cli.rs`)

1. **`ns_publish_self_validates_name_in_zone`** — rejects `foo.bar.ztlp`
   published into zone `baz.ztlp` with the existing error message.
2. **`ns_publish_self_constructs_key_packet_with_node_id`** — calls helper
   with a captured-socket NS stub, asserts the on-wire packet decodes as a
   CBOR map containing `algorithm=Ed25519`, `node_id`, `public_key`.
3. **`ns_publish_self_constructs_svc_packet_when_address_given`** — same
   stub, asserts second packet decodes as CBOR map with `address`, `node_id`,
   `zone`.
4. **`ns_publish_self_omits_svc_when_no_address`** — asserts only one packet
   is sent to the NS stub.

### Integration test (`#[tokio::test]`)

5. **`ns_heartbeat_task_republishes_on_tick`** — spawns a stub UDP echo NS,
   spawns the heartbeat task with a 1-second interval (test override), watches
   ≥3 cycles, asserts the NS stub saw ≥3 registrations.

### Pinned-contract regressions

The existing T3 tests at `ns_register_key_record_includes_node_id` and
`ns_register_svc_record_includes_node_id` MUST continue to pass — they pin the
CBOR wire shape and are the safety net for the refactor.

### Live integration confirmation

Before opening the PR for review:

1. Stand up a local NS (Elixir `mix run` on Hermes VM, port 23097).
2. Start `ztlp listen` pointed at it with `service_name`, `zone`, `ns_server`.
3. Observe in listener logs: `[ns_heartbeat] published <name> to NS @ <ts>`.
4. Query NS directly: `ztlp ns lookup <name> --ns-server 127.0.0.1:23097`
   returns the record within 1 second of listener boot.
5. Override interval to 30s; observe heartbeat re-publishes successfully on
   tick #2 and #3.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Heartbeat hammers NS at scale | 10-min jitter on each cycle smears load. 8h cadence × 1000 nodes = ~125 publishes/hr average. Well under the existing limit. |
| Listener can't publish at boot — silent failure | Initial publish is **synchronous** and aborts startup on error. Service-level alerting catches the boot failure. |
| Identity file regenerated mid-life → new KEY each heartbeat | Out of scope. Identity files are stable on production hosts (Chef-managed, immutable). |
| Mixed-version fleet during rollout | Old nodes still get registered by Chef; new nodes ALSO get registered by themselves. Idempotent — last writer wins. |
| Cookbook never cleaned up | Tracked as follow-up PR with explicit reference to this one. Both paths idempotent. |

## Out of scope (deliberately)

- Deregistration on shutdown. Records TTL out naturally; explicit
  deregistration adds wire complexity for marginal benefit.
- Heartbeat for the **agent** (`ztlp agent start`) — agent doesn't register
  itself today; that's a separate design.
- Removing the Chef recipe. Follow-up PR after this proves stable in prod.

## Estimated work

- Refactor + tests: ~1.5 hr
- Local integration confirmation: ~30 min
- PR + CI: ~1 hr
- Total: **~3 hr** (single agent session)
