# ZTLP Test Coverage — Current State & Plan

Generated 2026-09-13 from live `cargo-llvm-cov` (Rust) and `mix test --cover`
(Elixir) runs. Updated same day after the first test-writing pass (see
"Session 1 results").

## TL;DR current numbers (after Session 1)

| Component | Tool | Line coverage | Tests | Status |
|---|---|---|---|---|
| Rust `proto` (lib only, `src/bin/` excluded) | cargo-llvm-cov | **73.5%** (was 58-59% incl. bins) | 1,823 passing, 0 failing | green |
| Elixir `ns` | mix test --cover | **60.9%** (see note) | **971/971 passing** (was 75 failing) | green |
| Elixir `relay` | mix test --cover | **62.3%** (was 56.1%) | 750 passing, 3 skipped (pinned bugs) | green |
| Elixir `gateway` | mix test --cover **in Docker** | **60.9%** | 972/972 passing | green, unblocked |

Note on ns %: the earlier 68.5% was measured with 75 red tests. 60.9% is the
number from a fully green run with a different seed; the two are not directly
comparable and the old one was inflated by tests that executed-but-failed.

Note on proto %: 73.5% is with `--ignore-filename-regex 'src/bin/'`. Operator
binaries (ztlp-cli, ztlp-fuzz, ztlp-load, ztlp-demo...) are excluded on
purpose; they are exercised by e2e/manual runs, not unit tests. Always pass
that flag so numbers stay comparable.

---

## Session 1 results (2026-09-13)

### Tests added
- `proto/tests/simulated_relay_test.rs` (31 tests) — relay.rs 0% -> **95.5%**.
  Real loopback UDP: pairing, both-direction forwarding, session isolation,
  handshake-vs-data header offsets, run() loop survives garbage, rendezvous
  register/pair/expiry/IPv6.
- `proto/tests/updater_security_test.rs` (38 tests, 2 `#[ignore]`d on a real
  bug) — updater.rs 8% -> **97.7%**. Real Ed25519 keypairs: accept valid,
  reject tampered data / tampered sig / wrong key / bad curve point / non-hex
  key; GitHub asset selection; channel matrix.
- `proto/tests/r1_stub_contract_test.rs` (13 tests) — congestion.rs, pacing.rs,
  send_controller.rs 0% -> **100%**. Pins the "inert stub" contract so a
  half-reimplementation is caught. Delete with the stubs in R2/R3.
- `relay/test/ztlp_relay/vip_service_table_test.exs` (33 tests) — 0% -> 92.3%.
- `relay/test/ztlp_relay/vip_connection_test.exs` (26 tests) — 0% -> 91.8%.
  Real loopback TCP backend + real UDP client; full lifecycle, FIN/RST both
  directions, connect refused, TLS handshake timeout, wire-format + header
  auth tag verified byte-for-byte.
- `relay/test/ztlp_relay/signal_handler_test.exs` (11 tests) — 20.8% -> 91.7%.
- `scripts/gateway-cover-docker.sh` — runs gateway `mix test --cover` inside
  the prod builder image (`hexpm/elixir:1.15.7-erlang-26.2.5`). Phase 0 = C.

### Test-only fix (applied, no lib change)
- `ns/test/ztlp_ns/yaml_config_component_auth_test.exs`: `load_and_apply`
  writes EVERY validated default (incl. `storage_mode: :disc_copies`) into
  the app env; the test only restored two keys, leaking `:disc_copies` over
  test-env `:ram_copies`. Now snapshots/restores the whole `:ztlp_ns` env.
  Reproduced before/after with `ZTLP_NS_STORAGE_MODE` unset (that env var in
  an interactive shell masks the leak). The "75 failures" were seed-order
  dependent: `--seed 0` gave 1 failure, `--seed 12345` after fix gives 0.

### Real bugs found — ALL 5 FIXED (TDD: pinned test red -> lib fix -> green)
Lib changes: `relay/lib/ztlp_relay/{signal_handler,vip_connection,vip_service_table}.ex`,
`proto/src/updater.rs`. Relay 755/755, proto updater suites 67/67, compile
`--warnings-as-errors` clean. Not yet committed.

1. **relay `SignalHandler` — SIGUSR1 halted the relay** (production-relevant).
   `:os.set_signal(:sigusr1, :handle)` only routes the signal to OTP's
   `erl_signal_server`; nothing registers a gen_event handler there, so the
   default `erl_signal_handler` runs: SIGUSR2 is swallowed (no status dump),
   SIGUSR1 calls `erlang:halt("Received SIGUSR1")`. Verified in a throwaway
   BEAM: process died with "Received SIGUSR1", crash dump written. The
   documented systemd `ExecReload` drain path kills the relay instead.
   Fix: swap in a gen_event handler that forwards `{:signal, sig}` to the
   GenServer. Test: `signal_handler_test.exs` "real OS signal delivery".

2. **relay `VipConnection` — FIN/RST to client crash when session_key is nil.**
   Data paths special-case nil key (send bare frame); `send_fin_to_client` /
   `send_rst_to_client` don't, so the first close/error path raises
   `FunctionClauseError` in `Crypto.compute_header_auth_tag/3`. Pinned by
   "backend_closed without a session_key crashes".

3. **relay `VipConnection` — TLS backend closing mid-handshake crashes
   instead of RST.** `:ssl.connect/3` raises `{badmatch, {error, einval}}`
   from `ssl:emulated_options/4` on a dead socket; only the `{:error, _}`
   return is handled, so no RST reaches the client. Also: gen_tcp-only opts
   (`:binary`, `exit_on_close:` ...) are passed to `:ssl.connect`. Pinned by
   "backend closes mid-handshake" tests.

4. **relay `VipServiceTable.count/0` returns `:undefined`** when the table
   is missing (`:ets.info/2` doesn't raise; the rescue never fires; violates
   `@spec non_neg_integer()`). Pinned by "count/0 currently leaks :undefined".

5. **proto `updater::extract_asset_url` off-by-one skips the first asset.**
   Inner search starts at the unquoted word so it always matches the NEXT
   `browser_download_url`. If the platform binary is the first/only asset,
   updater falls back to the generic `/download/<tag>/ztlp` URL. Fix: start
   inner slice one byte earlier (include the opening quote). Two `#[ignore]`
   tests in `updater_security_test.rs`.

### Environment notes added
- gateway coverage needs OTP 26+ (quicer). `scripts/gateway-cover-docker.sh`
  uses the prod Dockerfile's builder image; each run re-installs apt build
  deps (~8 min). Build cache dirs (`_build_docker`, `deps_docker`, etc.) are
  created under gateway/ and cleaned up after. The gateway test suite rewrites
  `gateway/test/fixtures/quic_handshake_vector.json` on every run — `git
  checkout` it afterwards (or investigate why a fixture is regenerated).
- gateway `mix.exs` has a 90% coverage threshold, so `mix test --cover` exits
  3 even when all tests pass. Not a test failure.
- `ZTLP_NS_STORAGE_MODE=ram` was set in the interactive shell and masked the
  ns app-env leak; unset it when reproducing env-related ns flakiness.

---

## Phase 0 — Gateway coverage: DONE (option C)

- [x] C. Run gateway coverage in the prod builder image via Docker.
      `scripts/gateway-cover-docker.sh`. 972/972, 60.88%.

---

## Phase 1 — ns test suite: DONE (green)

- [x] Full failure list captured (`--seed 0`: 1 failure, storage_mode leak).
- [x] Root-caused to app-env leak from `yaml_config_component_auth_test.exs`.
- [x] Test-only fix applied; 971/971 on seed 0 and seed 12345.
- [ ] Run 3-5 more seeds in CI to confirm no other order-dependent leaks.

---

## Phase 2 — Rust `proto`: remaining gaps (lib files, bins excluded)

| File | Coverage | Notes |
|---|---|---|
| `vip.rs` | 41.0% | VIP/service routing — weakest major file. **Next.** |
| `tunnel.rs` | 43.8% | Largest file (5k lines). |
| `ffi.rs` | 44.0% | FFI boundary — high risk. Needs harness for C-ABI calls. |
| `agent/proxy.rs` | ~50% | |
| `quic_transport.rs` | ~58% | |
| `stats.rs` | ~53% | |
| `transport.rs` | ~58% | |

- [x] relay.rs 95.5%, updater.rs 97.7%, congestion/pacing/send_controller 100%
- [ ] vip.rs raised (target: 70%+)
- [ ] ffi.rs raised (target: 70%+)
- [ ] tunnel.rs raised (target: 65%+)
- [ ] Re-run `cargo llvm-cov --ignore-filename-regex 'src/bin/' --summary-only` after each batch

---

## Phase 3 — Elixir `relay`: remaining gaps

| Module | Coverage | Notes |
|---|---|---|
| `StatsReporter` | 29.2% | |
| `SessionSupervisor` | 33.3% | |
| `VipTcpTerminator` | 34.5% | Dispatch into VipConnection — next VIP target |
| `MeshManager` | 37.0% | |
| `Config` / `UdpListener` | ~48% | Packet hot path |

- [x] VipConnection 91.8%, VipServiceTable 92.3%, SignalHandler 91.7%
- [ ] VipTcpTerminator (pairs naturally with the VipConnection harness)
- [ ] UdpListener / Config / MeshManager

---

## Phase 4 — Elixir `ns`: weakest modules (suite is now green)

| Module | Coverage | Notes |
|---|---|---|
| `Bench` | 0% | Benchmark tool — exclude or smoke-test only |
| `RelaySeeder` | ~7% | Almost entirely untested |
| `Cluster` | ~42% | |
| `Server` | ~58% | Core NS server logic — priority |

- [ ] Cover `RelaySeeder`
- [ ] Raise `Cluster` and `Server`

---

## Phase 5 — Elixir `gateway`: weakest modules (newly measurable)

| Module | Coverage | Notes |
|---|---|---|
| `TlsTerminator` | 0% | Untested entirely |
| `Bench` | 0% | Benchmark tool — exclude |
| `CertProvisioner` | 10.6% | Cert lifecycle — security-relevant |
| `Listener` | 14.6% | |
| `Backend` | 35.9% | |
| `Session` | 36.8% | |
| `Federation` | 38.1% | |
| `Cbor` | 40.7% | Codec — pure functions, easy wins |

- [ ] `Cbor` (pure codec, quick)
- [ ] `CertProvisioner` (security-relevant)
- [ ] `TlsTerminator`, `Listener`, `Session`

---

## Tooling decision: keep `mix test --cover` or add ExCoveralls?

Still open. Built-in cover was sufficient for everything above. ExCoveralls
would add per-line HTML and CI diff-coverage; it touches all three `mix.exs`.

- [ ] Decision made
