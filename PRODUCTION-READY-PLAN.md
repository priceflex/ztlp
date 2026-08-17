# ZTLP → Production-Ready Plan

> **Goal:** Make the ZTLP tunnel production-ready.
> **Status (as of 2026-08-17):** QUIC migration is ~80% done and is the *default* path.
> The remaining work is to fix the QUIC data-pump throughput stall, add regression
> tests, and re-verify end-to-end on the AWS box.
>
> This file is the single source of truth for what's left. Update the checkboxes
> as work lands. Commit it with the changes.

---

## 0. Executive Summary (the correction)

Earlier in this session I assumed the "QUIC migration (Phase 1-3)" was unbuilt and
that the ~256KB transfer stall lived in the hand-rolled raw-UDP stack (`tunnel.rs`).
**That was wrong on both counts.** Re-reading the code:

1. **The default `ztlp connect` is ALREADY the QUIC (quinn) path.** `cmd_connect`
   takes `_quic: bool` (underscored = now a no-op flag); the code comment states the
   default is the "QUIC mode path … is what works end-to-end today." The hand-rolled
   raw-UDP stack is the *legacy* fallback, entered only when you opt into
   `--relay` / `--punch` / `--nat-assist` / `--relay-pool`.
2. **The throughput stall is in the QUIC data pump**, not `tunnel.rs`. The live
   AWS benchmark (`ztlp connect … -L …`, no legacy flags) ran through the QUIC path
   and truncated >~256KB.

So the migration is essentially done. Production-readiness = **fix the QUIC data-pump
throughput bug + prove it + harden it**, not build QUIC from scratch.

---

## 1. What is already DONE (verified, do not redo)

- [x] **quinn QUIC endpoint + streams + TOFU cert verifier** — `proto/src/quic_transport.rs`
      (989 lines: `QuicEndpoint`, `QuicConnection`, `bind`/`bind_with_socket`/`connect`/
      `connect_with_socket`, `accept`/`accept_bi`/`open_bi`, `TofuCertVerifier`, ALPN
      `ztlp/1`). Compiles and binds.
- [x] **Noise_XX over QUIC stream 0** — `quic_transport::noise_stream::{run_initiator_handshake,
      run_responder_handshake, read_ztlp_frame, write_ztlp_frame}`. `MAX_FRAME_SIZE = 65536`.
- [x] **Default connect path = QUIC** — `ztlp-cli.rs` `cmd_connect` "QUIC mode" branch
      (~3679–4120): `QuicEndpoint::connect_with_socket` → `open_bi()` per TCP conn →
      `noise_stream` frame pump. Per-connection `tokio::spawn` (concurrent sessions OK).
- [x] **Gateway/listen QUIC path** — `ztlp-cli.rs` (~4794–5283): `run_responder_handshake`.
- [x] **Dedicated QUIC benchmark binaries** — `quic-server.rs`, `quic-client.rs`
      (8 × 105KB parallel streams = the Phase-5 benchmark).
- [x] **Endpoint-auth (irt-rwzo) fix + tests** — commit `23c9495` (Rust fix),
      `39b8431` (Rust regression test), `0468caa` (Elixir `EndpointAuthTest`).
      0 live rejections on the AWS box.
- [x] **Phase 0 full-stack harness** — 6-service compose stack, SSH echo PASS,
      0 endpoint-auth rejections. (commits `9124fc6`.)

## 2. The ONE blocker: QUIC data-pump throughput stall

### Evidence (reproduced live on AWS `ztlp-test` @ 34.221.165.244, 2026-08-17)
Size sweep through the live QUIC tunnel (fresh `ztlp connect -L` per size, piped-stdin ssh):

```
 32KB  → PASS  (full 32768,  md5 match)
 64KB  → PASS  (full 65536,  md5 match)
 96KB  → PASS  (full 98304,  md5 match)
128KB  → PASS  (full 131072, md5 match)
192KB  → PASS  (full 196608, md5 match)
256KB  → PASS  (full 262144, md5 match)   ← last good
512KB  → FAIL  (got 196608/524288, ssh rc 255)
768KB  → FAIL  (got 458752/786432, ssh rc 255)
1024KB → FAIL  (got 327680/1048576, ssh rc 255)
```
- Data IS flowing (client `ssh -v`: "sent 1052432, 16.8 MB/s"; tunnel logged
  repeated `TCP->QUIC Read 65000 bytes`).
- >~256KB transfers **stall and truncate** at a variable point (192/448/320KB),
  then abort (ssh rc 255). Variation = an in-flight/flow-control timing race.

### Where the pump is
`ztlp-cli.rs` ~4080–4115 (client) and the symmetric gateway-side loop:
- `read_buf = vec![0u8; 65000]` (64KB)
- `tokio::select!` between `t_read.read(&mut read_buf)` and
  `noise_stream::read_ztlp_frame(&mut q_recv)`
- each TCP chunk → one `write_ztlp_frame` (u16-length, ≤64KB) → `q_send.write_all`
- each QUIC frame → `t_write.write_all`

### Prime suspects (to confirm, in priority order)
1. **Debug `println!` on every 64KB chunk** (line ~4084, "TCP->QUIC Read {} bytes") —
   a line-buffered stdout write per chunk. Throughput tax + interleaved I/O. Remove.
2. **Head-of-line / backpressure in the `tokio::select!`** — a single `select!`
   between one read and one frame-write means if the TCP side has data but the
   QUIC `write_all` is momentarily blocked (QUIC flow control), and the QUIC side
   has nothing to read, the loop can wedge once a transfer exceeds what fits in
   flight. Need bidirectional drain (two loops / spawn) so TCP→QUIC and QUIC→TCP
   never block each other.
3. **`quinn` default flow-control / `max_concurrent_bidi_streams` / `stream_receive_window`**
   not tuned (`QuicEndpointConfig` defaults) — small transfers fit, large ones hit the
   receive window and wait.
4. **Frame framing round-trips** — `read_exact` per magic+len+payload (3 awaits per
   frame) instead of a buffered reader; adds latency per 64KB.

## 3. Work items (the actual to-do)

### P1 — Make the QUIC data pump fast + correct  (THE fix)
- [ ] **A1.** Remove the per-chunk `println!` debug lines from the QUIC data pump
      (client ~4084 and any gateway-side equivalent). Keep them behind `log::debug!`
      / a `--verbose` gate only.
- [ ] **A2.** Refactor the pump so TCP→QUIC and QUIC→TCP are **independent** (spawn a
      task per direction, or drain both fully in the loop). Goal: a 1MB+ transfer
      completes without wedging; small transfers keep working.
- [ ] **A3.** Tune `QuicEndpointConfig` (server + client): `stream_receive_window`,
      `max_concurrent_bidi_streams`, and confirm `quinn` congestion control (cubic/bbr)
      is active. Do NOT hand-roll a custom CC — use quinn's.
- [ ] **A4.** (If needed) switch the frame reader to a `BufReader` over the QUIC
      stream so the per-frame `read_exact`×3 becomes buffered reads.

### P2 — Prove it (regression + benchmark)
- [ ] **B1.** Add a Rust integration test: loopback QUIC client↔server pushing ≥1MB
      over a single stream and over 8 parallel streams; assert byte-exact md5 + a
      throughput floor (e.g. ≥50 MB/s on loopback). (Un-`#[ignore]` the existing
      `multi_stream_loopback_roundtrip` once it's real.)
- [ ] **B2.** Re-run the AWS size sweep (32KB…1MB) and the harness benchmark; all must
      PASS byte-exact. Capture the 1MB speed as the headline number.
- [ ] **B3.** Fix the benchmark's ssh exit-status handling so a clean transfer
      (rc may be 0; file verified by md5) is scored PASS on checksum, not on ssh's
      exit code alone (the current harness treats rc 255 as fail even when the file
      delivered).

### P3 — Harden / production polish
- [ ] **C1.** Re-verify endpoint-auth (irt-rwzo) still 0 rejections after P1 (the pump
      change must not regress the auth handshake on stream 0).
- [ ] **C2.** Confirm the legacy raw-UDP path (`--relay/--punch/…`) still builds and its
      existing tests pass (don't break the fallback we're deprecating).
- [ ] **C3.** Update `docs/architecture/quic-noise-handshake.md` status table: mark
      Phases 1–3 DONE (with the throughput fix), Phase 5 = B2 result.
- [ ] **C4.** Decide the legacy-UDP path's fate: keep as documented fallback, or
      deprecate + gate behind a flag with a loud warning. (Document the decision.)
- [ ] **C5.** Clean up the throwaway `.prebuilt*` fullstack files (delete or document).
- [ ] **C6.** AWS box `ztlp-test`: tear down (stop/terminate) once verified — it's
      billing on a dynamic IP. (Decision: keep only if further bench needed.)

### P4 — Release
- [ ] **D1.** Version bump + tag (per the doc, production rollout = the 0.28.0-style
      release *after* the migration; confirm the actual target version with Steven).
- [ ] **D2.** Commit cadence: each P-item as its own commit on a feature branch
      (e.g. `feature/quic-pump-throughput`), rebase to `main` when B-gates pass.

## 4. Verification gates (definition of "production-ready")

All must be true before calling it production-ready:
1. **Byte-exact throughput:** 1MB (and 10MB) file transfer through the live QUIC
   tunnel on AWS, md5-matched, >~100ms per MB (≥10 MB/s) with no truncation.
2. **Concurrency:** 8 parallel streams each carry a distinct payload end-to-end
   with no head-of-line blocking (the `quic-client` benchmark).
3. **Auth intact:** 0 endpoint-claim rejections on the live stack (irt-rwzo).
4. **Tests green:** Rust `cargo test` (lib + bin + new throughput test) and Elixir
   `mix test` (EndpointAuth + no new failures vs baseline) pass.
5. **Both paths build:** QUIC default + legacy UDP fallback both compile and their
   existing tests pass.
6. **Docs updated:** migration status table + legacy-path decision documented.

## 5. Environment / pointers

- **AWS test box:** `ztlp-test` @ `34.221.165.244` (us-west-2a, 2 vCPU/2 GB,
  dynamic IP). SSH: `ssh -i /home/trs/.ssh/ztlp-test.pem ubuntu@34.221.165.244`.
  CPU has burst; the stall is a flow-control/pump issue, not CPU-bound (small
  transfers hit 16+ MB/s on it).
- **Repo:** `/home/trs/ztlp`, remote `priceflex/ztlp` (`main`).
- **Key files:**
  - `proto/src/bin/ztlp-cli.rs` — QUIC data pump (~4055–4120 client, ~4794–5283 gateway)
  - `proto/src/quic_transport.rs` — quinn endpoint + `noise_stream` (~768–895)
  - `proto/src/bin/quic-client.rs` / `quic-server.rs` — Phase-5 benchmark binaries
    (NOTE: `quic-server.rs` hardcodes `0.0.0.0:23097` — make it take a port arg for
    isolated benching; 23097 was in use on the VM during testing.)
- **Repro scripts:** `fullstack/bench-repro.sh`, `fullstack/bench-sizes.sh`
  (untracked; keep for P2 verification).
- **Prior results:** `PHASE0-FULLSTACK-RESULTS.md` (updates 1–4: irt-rwzo fix,
  DNS-fallback, Elixir tests, benchmark root-cause).

## 6. Delegation plan (USB agents)

The fix is bounded and parallelizable. Split across agents:
- **Agent 1 (throughput fix):** P1 A1–A4 (remove debug prints, independent-direction
  pump, quinn tuning). Deliverable: builds + the AWS size sweep goes 1MB green.
- **Agent 2 (tests + bench):** P2 B1–B3 (Rust throughput integration test, AWS
  re-verify, harness scoring fix). Deliverable: test proves 1MB+ byte-exact + 8-stream
  concurrency.
- **Agent 3 (harden + docs):** P3 C1–C5 (auth re-verify, legacy-path check + decision,
  doc updates, prebuilt cleanup). Deliverable: docs updated, both paths build.
- **Coordinator (me):** P4 D1–D2 (branch, commits, version, AWS teardown decision).

Each agent gets the exact file/line references above + the size-sweep evidence so it
doesn't re-derive the root cause.

## 7. Decisions (RESOLVED by Steven, 2026-08-17)
1. **Legacy UDP path** → **DEPRECATE.** Keep it compiling through the 0.35.x release,
   but gate it behind a loud runtime warning ("legacy raw-UDP path is deprecated,
   will be removed in 0.36 — use the default QUIC path"). Document as deprecated.
   (C4 resolved.)
2. **Release version** → **0.35.x point release** on current `main` (not the 0.28.0-style
   post-migration release). (D1 resolved.)
3. **AWS box** → **KEEP until the P2 re-run**, then tear down. Also run local loopback
   bench for faster iteration. (C6 resolved.)
4. **Throughput floor** → **Tie to the measured AWS 1MB speed** as the headline, plus a
   local loopback ≥50 MB/s gate. (B1 resolved.)

**Production-ready definition (confirmed):** fix the QUIC data-pump throughput bug +
prove it (byte-exact 1MB+/10MB over AWS + 8-stream concurrency) + harden it (auth
intact, both paths build, docs updated) — NOT build QUIC from scratch (it's already
the default path).

## 7b. Delegation plan (USB agents) — DISPATCHED 2026-08-17
- **Agent 1 (throughput fix):** P1 A1–A4 (remove debug prints, independent-direction
  pump, quinn tuning). Deliverable: builds + AWS size sweep 1MB green.
- **Agent 2 (tests + bench):** P2 B1–B3 (Rust throughput integration test, AWS
  re-verify, harness scoring fix). Deliverable: 1MB+ byte-exact + 8-stream concurrency.
- **Agent 3 (harden + docs):** P3 C1–C5 (auth re-verify, legacy deprecation warning,
  doc updates, prebuilt cleanup). Deliverable: docs updated, both paths build.
- **Coordinator (me):** P4 D1–D2 (branch, commits, version, AWS teardown decision).

Each agent gets the exact file/line references above + the size-sweep evidence so it
doesn't re-derive the root cause.
