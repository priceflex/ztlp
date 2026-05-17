# Handoff: ZTLP Multi-Stream Stall & Full Stack Bench

## Status as of 2026-05-17 (Phase B B1+B4 complete, root cause found and fixed)

Phase B1 (find where stalls originate) and B4 (update the diagnostic
skill) are done and on `main` as commit `c6947e0`. Phase B2 was
superseded — B1 evidence was sufficient. Phase B3 (full-stack
gateway bench) is still pending and now untangled from the loopback
stall question.

### Phase B verdict

**Root cause:** the dumb-pipe tunnel never called
`setsockopt(SO_RCVBUF / SO_SNDBUF)`. Every `UdpSocket` inherited
`net.core.rmem_default` (~200 KB - 1 MB), and the dumb-pipe has no
retransmit, so any kernel-level rcvbuf overflow becomes a permanent
transfer stall.

**Fix:** add `set_udp_buffer_sizes()` helper in `proto/src/gso.rs`,
call it from `run_bridge_inner` for both primary and demuxed recv
sockets. 7 MiB matches `rmem_max` on the standard ZTLP-tuned host.
All consumers (ztlp-cli, iOS NE FFI, Tauri desktop, relay) get it
automatically because they all flow through `run_bridge_inner`.

**Result on the 2-core VM** (`bench/run_multistream.sh`, SIZE=10 MB):

| N  | Before (MB/s / stalls) | After (MB/s / stalls) |
|----|------------------------|-----------------------|
|  1 |   117 / 0              |   166 / 0             |
|  2 |   0.3 / 1              |    69 / 0             |
|  4 |    99 / 0 (lucky)      |   108 / 0             |
|  8 |   1.3 / 5              |   144 / 0             |
| 16 |   2.6 / 7              |   190 / 0             |
| 32 |   5.2 / 11             |   214 / 0             |

`UdpRcvbufErrors` delta across the whole bench: ~1.3M → 0.

Detailed write-up: `bench/RESULTS-2026-05-17.md`.

Skill `ztlp-throughput-stall-diagnosis` updated with the resolved
multistream signature and the per-socket SO_RCVBUF root cause.

## Original Phase A handoff (2026-05-16, kept for context)

Phase A — narrowed instrumentation + benchmark scaffolding — is done and on
`main`. Phase B (the actual stall root-cause investigation) has NOT started
because it needs runtime evidence, not more code.

### What shipped (commits on main, in order)

1. `366a53a` fix(proto): set DataHeader.payload_len before computing AAD
   (single-stream 0 MB/s fix from the previous session)
2. `2b9228f` test(proto): end-to-end throughput regression for AAD desync
3. `9267ac0` bench: add multi-stream concurrent throughput probe
4. `9f5418b` docs(bench): record 2026-05-16 throughput results
5. **`94ca9da` proto: add demux-selectable throughput bench**
6. **`e91b375` Fix demux throughput benchmark bootstrap**
7. **`2c54bd0` proto: fix throughput bind and instrumentation handling**
8. **`5f4db7b` proto: validate bootstrap packets and fix rx counts**
9. **`8977830` proto: report structured packet outcome from handle_incoming_packet**

Bold = added in the Phase A session.

### What you can do now that you could not before

- `ztlp-throughput --path shared` vs `--path demux` exercise the two distinct
  bridge receive paths in `proto/src/tunnel.rs` (the original direct
  `run_bridge` vs the demuxed `run_bridge_demuxed` already used by
  `ztlp-cli`). Output prints `Bridge path:` and `Instrumentation:` so logs
  are self-describing.
- The tunnel bridge has accurate per-batch RX/TX stats. `handle_incoming_packet`
  now returns a structured `IncomingPacketOutcome { frame_kind,
  delivered_tcp_bytes, admission_rejected }`. RxBatchStats no longer
  guesses delivered bytes from raw UDP length, control frames no longer
  count as delivered payload, and dropped packets are counted as dropped.
- The lazy-connect bootstrap (`wait_for_first_data` /
  `wait_for_first_data_channeled`) now re-validates packets through
  `Pipeline::process` before accepting them, with a regression test
  (`test_wait_for_first_data_ignores_failed_admission`).
- `bridge_instrumentation_enabled()` is exposed and honours the same
  `ZTLP_DEBUG` env that `stats.rs` already uses. Setting `--debug` on
  `ztlp-throughput` now sets `ZTLP_DEBUG=1` BEFORE the tracing subscriber
  initialises, so per-batch logs actually appear.

### Verified on this VM (2-core, Linux 5.15)

- `cargo build --release --bin ztlp-throughput` clean
- `cargo test --release --test throughput_regression_test` → 123 MB/s
- `cargo test --lib test_wait_for_first_data*` → 4/4 pass
- `--path shared` 1 MB → 138 MB/s
- `--path demux` 1 MB → 17 MB/s (correct, just paying for the forwarder
  hop + per-session helper sockets; throughput is not the point of the
  demux path here — concurrency isolation is)

### Multistream stall: still reproducible, NOW DIAGNOSABLE

Latest `SIZE=10485760 bash bench/run_multistream.sh` on this VM:

```
 1 streams: aggregate=  117 MB/s   stalled=0
 2 streams: aggregate=    0.3 MB/s stalled=1   ← intermittent
 4 streams: aggregate=   99.8 MB/s stalled=0   ← also intermittent
 8 streams: aggregate=    1.3 MB/s stalled=5
16 streams: aggregate=    2.6 MB/s stalled=7
32 streams: aggregate=    5.2 MB/s stalled=3
```

The intermittent stalls at N=2/4 plus consistent stalls at N>=8 match the
"kernel UDP loopback drops + missing loss recovery" hypothesis already
documented in `ztlp-throughput-stall-diagnosis`. **The proposed Phase A
fix (port the iOS separate-ACK-socket pattern) would have been
misdirected** — the current dumb-pipe bridge does not consume ACK/NACK
frames at all (see `tunnel.rs::handle_incoming_packet` — they hit the
"reliability frames from a pre-pivot peer; ignore silently" branch). So
the iOS ACK pattern has nothing to attach to on the desktop bridge.

## Next Session Objectives (Phase B)

Phase B is **runtime evidence first**, not more code. Do not write a
separate-ACK-socket port until the evidence rules out simpler causes.

### Objective B1: Find where stalls actually originate

Run a stalled multistream config WITH instrumentation on:

```bash
cd /home/trs/ztlp
SIZE=10485760 RUST_LOG=info,ztlp_proto::stats=debug \
  bash bench/run_multistream.sh 2>&1 | tee /tmp/ms-debug.log
# Look at /tmp/ztlp-multistream/stream-*.log for per-stream final reports.
# Pick a stalled stream (one that reported 0 MB/s + 60s timeout) and
# diff its final TunnelStats against a healthy stream's.
```

Decision tree based on the diff:

- **Sender-side stall**: TX batches stop growing while RX kept going on
  the partner side. This is tokio scheduling / TCP backpressure /
  pipeline lock contention, NOT transport.
- **Receiver-side stall, packets_dropped climbing**: kernel UDP recv
  buffer overrun on the shared socket. Cheapest fix: raise SO_RCVBUF on
  the per-bridge sockets. Confirm with
  `ss -uan | grep -E 'Recv-Q|UNCONN'` during the run.
- **Both sides stop with no drops logged**: this is the case where you'd
  want loss-recovery infrastructure (NACK/SACK or a separate ACK socket).
  Only at THIS point does porting the iOS ACK architecture become a
  candidate — and even then, the dumb-pipe bridge would need a real
  receive-side reliability layer first.

### Objective B2: Single-bridge `--debug` capture

Cheaper, more focused than running 16 in parallel. Reproduce on N=2:

```bash
cd /home/trs/ztlp/proto
RUST_LOG=info,ztlp_proto::stats=debug \
  cargo run --release --bin ztlp-throughput -- \
    --mode ztlp --size 10485760 --repeat 1 --path shared --debug \
    > /tmp/single-shared.log 2>&1 &
RUST_LOG=info,ztlp_proto::stats=debug \
  cargo run --release --bin ztlp-throughput -- \
    --mode ztlp --size 10485760 --repeat 1 --path shared --debug \
    > /tmp/single-shared-2.log 2>&1 &
wait
```

Compare TunnelStats final reports between the two runs.

### Objective B3: Full-stack benchmark (still pending)

Original Objective 2 from the prior plan. NOT started.

- `ztlp-load gateway` or the `ztlp-validation-suite` skill against a
  local Elixir gateway.
- Goal: baseline `Client → Gateway (Elixir) → Relay → Server` throughput,
  contrast with loopback numbers.
- Probably better done AFTER B1/B2 so we don't conflate loopback transport
  stalls with gateway behaviour.

### Objective B4: Update the diagnostic skill

`ztlp-throughput-stall-diagnosis` already has a stub multistream
section. Once B1/B2 produce evidence, update that skill with:
- the actual TunnelStats signature of a stalled stream
- the SO_RCVBUF tuning, if that's the answer
- whether the separate-ACK pattern is or is not the fix

## Cloud VM Setup

Still on the table from the prior session: Steve has offered AWS VMs to
test real WAN behaviour. **Do not provision those yet.** The current
stall reproduces on loopback, so the bug (or the budget) lives somewhere
the kernel queue + tokio scheduler can already exhibit. WAN testing only
becomes useful once the loopback failure mode is named.

## Notes & Environment

- Working dir: `/home/trs/ztlp`
- VM: Linux 5.15 / 2-core / `10.170.3.111` or `10.69.95.x`
- UDP buffers must be tuned for any throughput work — see
  `ztlp-validation-suite` step 1b. Throughput regression test floor
  (10 MB/s) is comfortably exceeded when buffers are tuned.
- Git push: `GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw"`
  but everything in this session is already on origin/main.
- All Phase A commits authored as `Steven Price <steve@techrockstars.com>`.

## Anti-Patterns Logged This Session (do not repeat)

1. Subagent claimed a demux benchmark worked when it actually stalled.
   Parent re-ran and caught it. Lesson: never trust subagent self-reports
   on benchmarks; always rerun the command yourself.
2. First instrumentation pass infinitely-trusted UDP packet length to
   estimate delivered TCP bytes. The independent reviewer caught this.
   Now fixed via structured `IncomingPacketOutcome`.
3. Subagent ran a debug-profile `cargo test throughput_regression_test`
   and reported a false 4 MB/s failure. Re-running with `--release`
   showed 123 MB/s. Lesson: that test must be run release-only.
4. Plan as originally written said "port separate ACK socket to
   desktop/gateway bridge". The dumb-pipe bridge doesn't consume ACK
   frames at all, so that port would have built infrastructure for a
   protocol layer that isn't there. Reality-checked before coding.
