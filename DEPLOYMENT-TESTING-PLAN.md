# ZTLP Full-Stack Deployment & Verification Plan

Written after closing out all 84 security findings (see `SECURITY-TODO.md`).
This is the plan for actually standing the whole system up, exercising every
feature end-to-end, and confirming CI/CD works — not just "tests green in
isolation," which is all we have proof of today.

## Why this is needed (the honest gap)

Every fix this engagement has been verified at the **unit/component level**
in ephemeral Docker containers (`cargo test`, `mix test`, `pytest`) run
one crate/app at a time. That is real verification, but it is NOT the same
as proof that:

1. The **whole system boots together** (NS + relay + gateway + Rust
   clients + bootstrap Rails app + ztlp.net) and actually does its job —
   NAT hole-punching, relay fallback, Noise handshake, enrollment,
   certificate issuance, DNS-style resolution.
2. The **irt-rwzo fix specifically** works across the real wire, not just
   inside a single Elixir test process. The `interop/` CI suite (Suites
   1-5, `run_full_test.sh`) covers Noise handshake, pipeline headers, and
   relay forwarding — but **grep confirms zero references to 0x0A
   (PEER_ENDPOINTS), 0x0C (PUNCH_REPORT), or the new v2 signed wire
   format anywhere in `interop/`.** The exact feature the last security
   fix touched has never been exercised by a real Rust client hitting a
   real NS server. This is the single highest-priority gap.
3. `bootstrap/` (Rails) has **no CI job at all** in `.github/workflows/`.
   It has its own test suite (1226 tests, run manually in Docker this
   session) but nothing runs it automatically on push/PR.
4. The Medium/Low fixes from Batches 7-11 were verified individually;
   nothing has exercised them **together** under one running stack (e.g.
   does the new `ZTLP_NS_REQUIRE_ENDPOINT_AUTH` default of `true` break
   `docker-compose-full-stack.yml`, which currently sets
   `ZTLP_NS_REQUIRE_REGISTRATION_AUTH: "false"` but says nothing about
   the new endpoint-auth flag or ship real signed v2 packets?).
5. Two fixes were never compiler-verified at all (`hlv-ulgo`, `snn-jang`
   — Swift, no Xcode in this environment) and one was compile-verified
   but never load-tested on a real kernel (`htk-alxq` — eBPF/XDP).

## What already exists (don't rebuild these)

- `docker-compose-full-stack.yml` — NS + relay1 + relay2 + backend
  (openssh) + server + client, full NAT-punch-adjacent topology, already
  wired with healthchecks and Prometheus metrics ports. **This is the
  right skeleton for full-stack testing** — it just needs updating for
  the new endpoint-auth env var and a scenario that actually drives
  PEER_ENDPOINTS/PUNCH_REPORT.
- `.github/workflows/ci.yml` — per-app unit test jobs (rust, relay, ns,
  gateway) + an `interop` job + a `perf-gate` job, gated by a `ci-pass`
  summary job. Solid foundation; missing bootstrap and missing the
  endpoint-auth scenario in `interop`.
- `.github/workflows/release.yml` — builds Rust binaries (5 targets),
  Elixir OTP releases (relay/ns/gateway), Tauri desktop installers
  (Linux/Windows), eBPF source tarball, and publishes a GitHub Release
  on `v*` tags. This has never been dry-run this session.
- `.github/workflows/ztlp-net-tests.yml` — stdlib-only Python test job
  for the Launch app, path-scoped so it only runs on `ztlp.net/**`
  changes.
- `.github/workflows/desktop-build.yml`, `image-version-gate.yml` — not
  inspected in depth for this plan; check these still pass too.
- `interop/` — 5 test suites (31 total cases) covering Noise_XX
  handshake, pipeline header validation, edge cases, gateway E2E, and
  relay forwarding. Does NOT cover NS PEER_ENDPOINTS/PUNCH_REPORT.
- `docker-compose.yml`, `docker-compose.mesh.yml`,
  `docker-compose.federation.yml` — other topologies, not inspected in
  depth; check which of these is meant to be the "canonical" one before
  picking a target for full deployment.

## Recommended sequence

### Phase 0 — Local dry runs (fast, cheap, do first)

1. `docker-compose -f docker-compose-full-stack.yml up --build` and
   confirm all 6 services reach healthy/running state. Watch for the NS
   container: it does NOT currently set `ZTLP_NS_REQUIRE_ENDPOINT_AUTH`,
   so it will default to `true` — confirm the `server`/`client` Rust
   binaries in this compose file actually send the new v2 signed wire
   format (they should, since `punch.rs`'s encoders were fixed in a
   prior session and are used unconditionally by all real call sites —
   but this has never been confirmed against a live NS in this
   topology). If they don't, either fix the binaries or explicitly set
   `ZTLP_NS_REQUIRE_ENDPOINT_AUTH: "false"` in compose and file a
   follow-up.
2. Exercise the actual client→server SSH tunnel end to end (the compose
   file's whole point) and confirm hole-punch/relay-fallback logs show
   PEER_ENDPOINTS and PUNCH_REPORT succeeding, not silently falling
   back to unsigned/untracked mode.
3. Do the same for `docker-compose.mesh.yml` and
   `docker-compose.federation.yml` if those represent meaningfully
   different topologies (multi-NS federation, mesh routing) — these are
   exactly the kind of feature that only breaks when multiple real
   components run together.
4. Manually run the `bootstrap/` Rails app's full test suite one more
   time outside Docker-per-session ephemeral containers — ideally against
   a persistent Postgres/MySQL matching what production would use, not
   just `RAILS_ENV=test` with SQLite/whatever the default is. Confirm
   `bin/rails server` actually boots in `RAILS_ENV=production` the way
   the `bue-swlg` fix was verified this session, but now inside the
   Docker Compose network rather than a standalone container.

### Phase 1 — Close the interop test gap (the important one)

1. Add a new interop suite (`interop/ns_endpoint_auth_test.exs` server +
   a new `ztlp-endpoint-auth-interop.rs` binary, following the existing
   pattern of `ztlp-gateway-e2e.rs` / `gateway_test_server.exs`) that:
   - Spins up a real `ZtlpNs.Server` (or connects to the one in
     `docker-compose-full-stack.yml`).
   - Sends a real v2-signed PEER_ENDPOINTS request using
     `punch.rs::encode_peer_endpoints_request`, confirms it's tracked.
   - Sends a v2 PUNCH_REPORT, confirms tracking.
   - Sends a spoofed claim (different pubkey, same node_id, no prior
     registration) and confirms TOFU-pin rejection.
   - Registers a real KEY record via the 0x09 path, then sends an
     endpoint claim from an unrelated key and confirms **strict-path**
     rejection (`:not_key_owner`) — this is the actual security
     guarantee the fix provides and it has zero cross-language coverage
     right now.
   - Sends a legacy v1 (unsigned) request and confirms it still gets a
     read response but does NOT get tracked (regression guard against
     ever silently reverting to trusting v1).
2. Wire this new suite into `interop/run_full_test.sh` and
   `.github/workflows/ci.yml`'s `interop` job so it runs on every PR,
   not just locally.
3. Re-run the full `ci.yml` interop job locally (via `act` or by pushing
   to a scratch branch) to confirm it passes before merging anything
   else on top.

### Phase 2 — Add bootstrap to CI

1. Add a new `bootstrap` job to `.github/workflows/ci.yml` mirroring the
   `relay`/`ns`/`gateway` pattern but for Ruby: `ruby/setup-ruby`,
   `bundle install`, `RAILS_ENV=test bin/rails db:test:prepare` (or
   equivalent), `bin/rails test`. Use the same Postgres/MySQL service
   container pattern GitHub Actions supports if bootstrap needs a real
   DB rather than SQLite.
2. Add `bootstrap` to the `ci-pass` summary gate's `needs:` list so a
   red bootstrap suite actually blocks merges, matching how relay/ns/
   gateway/rust already work.
3. Confirm the `bue-swlg` Host-authorization fix's `config.hosts` env
   var resolution (`Socket.gethostname`, `BOOTSTRAP_HOSTS` etc.) works
   correctly inside the GitHub Actions runner environment specifically
   — CI runners have different hostnames/network setups than the local
   Docker sandbox this was verified in.

### Phase 3 — Full end-to-end feature sweep

Walk every major documented feature and confirm it works against the
live compose stack, not just unit tests. Suggested checklist (adjust
against actual docs/README as source of truth):

- [ ] Node enrollment (0x08/0x09 wire path) — new device registers,
      gets a signed KEY record, matches what `component_auth_test.exs`
      and `enrollment_test.exs` assert in isolation.
- [ ] NAT hole-punching end to end (client behind simulated NAT, via
      the compose network's bridge + iptables MASQUERADE if needed, or
      at minimum confirm the PEER_ENDPOINTS/PUNCH_REPORT flow above).
- [ ] Relay fallback when hole-punch fails (kill/block direct UDP path,
      confirm relay1/relay2 pick up the session).
- [ ] Gateway TCP bridging (the SSH backend in
      `docker-compose-full-stack.yml` is exactly this — confirm the
      full SSH session actually works, not just that the tunnel opens).
- [ ] Certificate issuance / rotation (`cert_authority.ex`, the jwj-eghu
      + xye-tnwl fix from this session — confirm PBKDF2-derived
      encrypted intermediate key actually round-trips through a real
      NS restart, not just the unit test).
- [ ] DNS-style resolution (`dns_setup.rs`, the ugx-wepq fix — confirm
      on a real macOS box if available, since the fix touches
      `/etc/resolver` and this environment can't test that natively).
- [ ] Admin API (`/admin/records`) with a real secret configured (not
      the "secret not configured, rejecting all" default seen in every
      test run's boot log this session).
- [ ] Metrics endpoints (`/metrics`, `/token_status` post-htb-ojqx-fix)
      — confirm Prometheus scraping actually gets the zone-aggregated,
      non-leaking payload in a live deployment, not just via the unit
      test's direct function call.
- [ ] ztlp.net Launch app — zone availability check, proof-of-work
      CAPTCHA, HTTPS enforcement (the ooa-bhoa fix) actually redirects
      in a real `staging`/`launch` environment deploy, not just the
      unit test's WSGI-level assertion.
- [ ] Desktop (Tauri) app — build a real installer via
      `desktop-build.yml`/`release.yml`'s desktop job and confirm it
      actually launches and can enroll/connect, not just that it
      compiles.
- [ ] macOS/iOS `EnrollmentViewModel.swift` (hlv-ulgo) — this is the
      one fix with ZERO automated verification of any kind. If there's
      any way to get this in front of a real Xcode build (even just
      `xcodebuild build` with no device, to catch compile errors), do
      it before calling deployment testing complete.
- [ ] eBPF/XDP filter (htk-alxq) — load it on a real Linux box with a
      BPF-capable kernel (`ip link set dev <iface> xdp obj ztlp_xdp.o`)
      and confirm the map-full fail-closed behavior fires under load,
      not just that it compiles.

### Phase 4 — CI/CD pipeline dry run

1. Push a scratch branch touching a trivial file in each of
   proto/relay/ns/gateway/bootstrap/ztlp.net and open a PR — confirm
   every workflow (`ci.yml`, `ztlp-net-tests.yml` if scoped,
   `image-version-gate.yml` if relevant) actually triggers and passes.
2. Cut a real pre-release tag (e.g. `v0.36.0-rc1`) on a fork or test
   remote (NOT `priceflex/ztlp` directly unless you want a real
   release) and confirm `release.yml` produces working artifacts:
   download the Linux x86_64 Rust tarball, the Elixir OTP release
   tarballs, and at minimum smoke-test that `ztlp --version` runs and
   an OTP release's `bin/ztlp_ns start` boots.
3. Confirm `desktop-build.yml`'s Tauri build still succeeds given the
   Rust/proto changes made this session (`ios_tunnel_engine.rs`'s
   `--features ios-sync` gating, the identity.rs permission fix, etc.)
   — none of these were rebuilt as part of the desktop matrix this
   session.
4. Review `image-version-gate.yml` — not inspected for this plan; check
   what it actually gates (likely container image version pinning) and
   confirm it still passes given any new Docker-related changes.

### Phase 5 — Wrap-up

1. Update `SECURITY-TODO.md`'s "Next steps" section once the Swift and
   eBPF verification gaps from Phase 3 are closed.
2. Write up results of the full-stack test pass as a short report:
   what was exercised, what passed, what didn't, and file follow-up
   issues for anything that failed under real multi-component load but
   passed in isolation (this is the most likely place to find NEW bugs
   — integration issues rarely show up in unit tests).
3. Only after all of the above is green should the live CTF box
   (`defcon-ctf-1`, 44.227.148.151) be considered for a patch rollout —
   per the standing instruction, it has not been touched this entire
   engagement and shouldn't be until there's real full-stack proof the
   fixes don't break anything.

## Effort estimate (rough)

| Phase | Effort | Risk if skipped |
|-------|--------|------------------|
| 0 (local dry run) | 1-2 hrs | Low-effort, high-value — do this first no matter what |
| 1 (interop gap) | 3-5 hrs | **Highest** — the exact security fix from this session has zero cross-language proof today |
| 2 (bootstrap CI) | 1-2 hrs | Medium — Rails app has real tests but no automated gate |
| 3 (feature sweep) | 1-2 days | Medium-high — most likely to surface real integration bugs |
| 4 (CI/CD dry run) | 2-4 hrs | Medium — release pipeline hasn't been exercised in a long time per git history |
| 5 (wrap-up) | 1 hr | Low, but don't skip the report |

## Immediate next action

Start with **Phase 0, step 1** (bring up `docker-compose-full-stack.yml`
and confirm the endpoint-auth fix works against real Rust clients) —
it's the fastest way to find out whether the irt-rwzo fix from this
session actually works outside of unit tests, which is the biggest open
question right now.
