# ZTLP Test Coverage — Current State & Plan

Generated 2026-09-13 from live `cargo-llvm-cov` (Rust) and `mix test --cover`
(Elixir) runs. Updated same day after the first test-writing pass (see
"Session 1 results").

## TL;DR current numbers (after Session 2)

| Component | Tool | Line coverage | Tests | Status |
|---|---|---|---|---|
| Rust `proto` (lib only, `src/bin/` excluded) | cargo-llvm-cov | **74.6%** (S1 73.5%, start 58-59% incl. bins) | 1,846 passing, 1 known-flaky (quic pin) | green |
| Elixir `ns` | mix test --cover | **69.4%** (S1 60.9%) | **991/991** on seeds 777 + 424242 | green |
| Elixir `relay` | mix test --cover | **62.2%** (start 56.1%) | 755 + 18 new, 1 skipped (pinned bug) | green |
| Elixir `gateway` | mix test --cover **in Docker** | **64.1%** (S1 60.9%) | 1,092/1,092 | green |

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

## Session 2 results (2026-09-13, same day)

### Tests added
- `proto/tests/vip_proxy_lifecycle_test.rs` (22) — vip.rs 41% -> **91.2%**.
  Real loopback VIP listeners: accept, tunnel->TCP via StreamDispatcher,
  FIN/CLOSE sentinels, client close unregisters, concurrent stream ids,
  multi-port, bind failure, stop, update_session, no-session reject, TLS
  acceptor with rcgen cert in isolated HOME (8443), no-cert fallback.
- `relay/test/ztlp_relay/vip_tcp_terminator_e2e_test.exs` (18) — real
  encrypted compact packets end-to-end through handle_vip_packet/4.
- `gateway/test/ztlp_gateway/cbor_test.exs` (91) — Cbor 40.7% -> **100%**.
  RFC 8949 Appendix A vectors, width boundaries, deterministic map order,
  every decode error class, 200-case random round-trip.
- `gateway/test/ztlp_gateway/cert_provisioner_test.exs` (29) —
  CertProvisioner 10.6% -> **95.9%**. Fake NS UDP server speaking
  0x14 0x01/02/03 (verifies the Ed25519 request signature), full
  provisioning, dual-key storage, refresh/renew, chain-fail non-fatal,
  per-service issuance error codes, backoff ladder 30s..1h, renewal-failure
  keeps old certs, timeout, expiry classification, sweep + forced renew.
- `ns/test/ztlp_ns/relay_seeder_test.exs` (20) — RelaySeeder 7% -> **100%**.

### Test-only fix (applied)
- `ns/test/ztlp_ns/cert_issuer_test.exs` on_exit stopped `:ztlp_ns` and
  `:mnesia` and restarted neither. Any Server/Store-dependent test that ran
  after it failed with "no process" (seed 777: 11-15 failures in
  PunchProtocolTest/StoreMnesiaTest). Now restarts both, matching
  admin_test/anti_entropy_test. Seeds 777 and 424242: 991/991.

### New bugs found (NOT fixed, pinned)
6. **relay `VipTcpTerminator` — VIP dispatch is dead code in prod.** Two
   independent defects: (a) `extract_service_name/1` reads `dst_svc_id`,
   which only handshake packets carry; UdpListener only routes
   `:data_compact` packets here, so service_name is always "" and every
   packet falls back to classic relay. (b) `route_connection/6` calls
   `SessionSupervisor.start_session/1`, which starts a `ZtlpRelay.Session`
   (needs `:peer_a`) not a `VipConnection`; `VipConnection.start_link` is
   unreferenced in lib/. Pinned by two tests in
   `vip_tcp_terminator_e2e_test.exs`; the intended-behaviour test is
   `@tag :skip`. Needs a design decision (where does service identity come
   from on the data path?) before fixing.
7. **proto `VipProxy::start()` hot-swap dispatcher split-brain.** On a
   second `start()`, `self.dispatcher` is replaced but running listener
   tasks hold the OLD `Arc<StreamDispatcher>`; new connections register in
   the old one while `proxy.dispatcher()` (used by the FFI recv_loop) is
   the new, empty one -> every post-reconnect connection is a download
   black hole. Also `next_stream_id` resets to 1 so the first new connection
   hijacks stream 1's channel. `#[ignore]`d intended test + pinned test in
   `vip_proxy_lifecycle_test.rs`. Fix: share via `Arc<RwLock<Arc<..>>>` or
   clear-in-place instead of replace.

### Documented quirks pinned by tests (not bugs, but surprising)
- RelaySeeder re-seed of an existing name is `:stale_serial` (always
  serial 1): editing ZTLP_NS_RELAY_RECORDS and restarting does NOT update
  an existing record. The moduledoc example format (bare `ip:port` part
  without `address=`) seeds 0 records.
- Cbor.decode ignores trailing bytes after a complete item.

### Real bugs found in Session 1 — ALL 5 FIXED (TDD: pinned test red -> lib fix -> green)
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
| `vip.rs` | 91.2% | done S2 |
| `tunnel.rs` | 43.8% | Largest file (5k lines). |
| `ffi.rs` | 44.0% | FFI boundary — high risk. Needs harness for C-ABI calls. |
| `agent/proxy.rs` | ~50% | |
| `quic_transport.rs` | ~58% | |
| `stats.rs` | ~53% | |
| `transport.rs` | ~58% | |

- [x] relay.rs 95.5%, updater.rs 97.7%, congestion/pacing/send_controller 100%
- [x] vip.rs raised to 91.2%
- [ ] ffi.rs raised (target: 70%+)
- [ ] tunnel.rs raised (target: 65%+)
- [ ] Re-run `cargo llvm-cov --ignore-filename-regex 'src/bin/' --summary-only` after each batch

---

## Phase 3 — Elixir `relay`: remaining gaps

| Module | Coverage | Notes |
|---|---|---|
| `StatsReporter` | 29.2% | |
| `SessionSupervisor` | 33.3% | |
| `VipTcpTerminator` | ~60% (S2) | dispatch path is dead code in prod, see bug 6 |
| `MeshManager` | 37.0% | |
| `Config` / `UdpListener` | ~48% | Packet hot path |

- [x] VipConnection 91.8%, VipServiceTable 92.3%, SignalHandler 91.7%
- [x] VipTcpTerminator e2e (blocked further by bug 6)
- [ ] UdpListener / Config / MeshManager

---

## Phase 4 — Elixir `ns`: weakest modules (suite is now green)

| Module | Coverage | Notes |
|---|---|---|
| `Bench` | 0% | Benchmark tool — exclude or smoke-test only |
| `RelaySeeder` | 100% (S2) | done |
| `Cluster` | ~42% | |
| `Server` | ~58% | Core NS server logic — priority |

- [x] Cover `RelaySeeder`
- [ ] Raise `Cluster` and `Server`

---

## Phase 5 — Elixir `gateway`: weakest modules (newly measurable)

| Module | Coverage | Notes |
|---|---|---|
| `TlsTerminator` | 0% | Untested entirely |
| `Bench` | 0% | Benchmark tool — exclude |
| `CertProvisioner` | 95.9% (S2) | done |
| `Listener` | 14.6% | |
| `Backend` | 35.9% | |
| `Session` | 36.8% | |
| `Federation` | 38.1% | |
| `Cbor` | 100% (S2) | done |

- [x] `Cbor`
- [x] `CertProvisioner`
- [ ] `TlsTerminator`, `Listener`, `Session`

---

## Tooling decision: keep `mix test --cover` or add ExCoveralls?

Still open. Built-in cover was sufficient for everything above. ExCoveralls
would add per-line HTML and CI diff-coverage; it touches all three `mix.exs`.

- [ ] Decision made
