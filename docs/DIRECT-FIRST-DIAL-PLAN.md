# Direct-First Dialing for the Agent (ZTLP)

Status: plan, not built. Written 2026-10-05 after the ChooseForce
(`www.chooseforce.ztlp`) deployment failed end to end. Steven approved the
three-part direction on 2026-10-05.

## 1. What happened

ChooseForce was put behind an Elixir gateway (`stevenprice/ztlp-gateway`) on the
ChooseForce server (LAN <APP-SERVER-LAN-IP>, behind the TRS NAT <OFFICE-NAT-IP>). The
client is the AI computer (<CLIENT-LAN-IP>), a different VLAN behind the SAME NAT.
Both talk to the new primary NS/relay on defcon-ctf-1 (<NS-PUBLIC-IP>).

Everything up to the data path works and was verified:

- `www.chooseforce.ztlp` resolves on the AI computer with one `.ztlp` NRPT rule.
- The gateway's operator key is the zone authority for `chooseforce.ztlp`; the
  NS accepts its signed SVC record (`registration_accepted`).
- The relay registers the gateway as `service=www` and accepts the agent's
  `CLIENT_ROUTE service=www`.

The data path fails: the agent gets a 504 after its 15 s first-byte deadline.
Packet capture on the ChooseForce server shows 0 packets arriving on UDP 23097.
Three UDP probes from the relay box to <OFFICE-NAT-IP>:23097 also arrived as 0.

Root causes, in order:

1. The Elixir gateway publishes exactly ONE address (`ZTLP_GATEWAY_PUBLIC_ADDR`),
   the NAT address. The NS never learns the LAN address <APP-SERVER-LAN-IP>.
2. The agent's VIP proxy (`proto/src/agent/daemon.rs`) always routes through the
   relay when one is configured. It never tries a direct endpoint.
3. The relay forwards to the gateway's advertised `ip:23097`, but the gateway sent
   its registration from an ephemeral socket (msquic owns the QUIC socket), so
   the NAT only opened THAT port. Inbound to 23097 is dropped.
4. Shared NAT: client and gateway both appear as <OFFICE-NAT-IP> to the relay, so
   even with a port forward the traffic would hairpin through the firewall.

The AI computer CAN reach the server directly: `http://<APP-SERVER-LAN-IP>/up` answered
200 in 37 ms during the investigation.

## 2. What already exists (it "used to work")

The multi-candidate / direct-first design is shipped, but only in the CLI
`ztlp connect` / `ztlp listen` path, not the agent service or the Elixir gateway.

| Capability | Module | Shipped | Used by agent? | Used by Elixir gateway? |
|---|---|---|---|---|
| Gateway enumerates all NIC addresses | `proto/src/local_candidates.rs` | v0.32 (M1) | no | no |
| SVC `addresses` field (comma list, best first; `address` stays single for old clients) | `proto/src/svc_candidates.rs` | v0.35.x | no | no |
| Client ranks candidates (same subnet > other RFC1918 > VPN > public > srflx > relay) | `proto/src/candidate_priority.rs` | v0.32 (M4) | no | n/a |
| Parallel dial with cancellation and relay fallback | `proto/src/multi_candidate_dial.rs` | v0.32 (M5) | no | n/a |
| Hole punch + relay fallback | `proto/src/punch.rs`, `punch_agent.rs` | v0.30.12 | no | no |
| `ztlp listen` publishes `address` + `addresses` | `ztlp-cli.rs compute_advertised_svc` | v0.35.x | — | — |
| `ztlp connect` resolves + ranks candidates | `ztlp-cli.rs resolve_target` | v0.35.x | — | — |

The NS needs NO change: SVC `data` is an opaque CBOR map, re-encoded verbatim
(`validate_record_data(:svc, _) -> :ok`). `svc_candidates.rs` documents the
back-compat matrix.

Known loose end (docs/NAT-TRAVERSAL.md, v0.32.1 follow-ups): v0.32 gateways
sent PUNCH_REPORT from an ephemeral socket, so reported endpoints could carry the
keepalive port, not the listener port. `compute_advertised_svc` takes
`listener_port` explicitly, so the SVC `addresses` path should carry the right
port. Verify in step A before relying on it.

## 3. The three parts (approved)

1. Gateway publishes all its addresses (private + public) in the SVC record.
2. Agent tries direct endpoints first (private first, short timeout), then relay.
3. Relay carries NAT'd gateway sessions when neither side has a direct path.

Parts 1 and 2 fix the office case (shared NAT) with no firewall change and no
hairpin. Part 3 is the general fix for remote users and is the biggest piece.

## 4. Steps, in order, each with its own test

### Step A: Rust gateway in Docker for ChooseForce (part 1, fast path)

Replace the Elixir gateway container on the ChooseForce server with the Rust
`ztlp listen` gateway, which already publishes `addresses`.

- Image: build from `proto/Dockerfile` (the CLI image). Check whether the
  release workflow already publishes one; if not, build locally and `docker
  save | ssh ... docker load` (no registry push needed for a test).
- Run: `ztlp listen --forward www:<APP-CONTAINER-IP>:3000 --ns-server
  <NS-PUBLIC-IP>:23096 --relay <NS-PUBLIC-IP>:23095 --zone chooseforce.ztlp`
  with the operator identity mounted; network `kamal`; `network_mode` must let
  it see the host's LAN address (use `--advertise-interface` or host networking,
  decide in A1).
- Needs: the operator key as a `ztlp` identity file (today it is a raw 32-byte
  hex seed in `~/ztlp-gateway/operator.key`), and the relay secret.
- Test A1 (NS): `ztlp ns lookup www.chooseforce.ztlp -t 2` shows an `addresses`
  field containing `<APP-SERVER-LAN-IP>:23097` AND the NAT address, listener port
  correct (not an ephemeral one).
- Test A2 (CLI, proves the published data is dialable): from the AI computer,
  `ztlp connect www.chooseforce.ztlp --ns-server ... --local-forward
  18080:...` then `curl http://127.0.0.1:18080/up` returns 200 and the client
  log shows the same-subnet / RFC1918 candidate won, not the relay.
- A2 passing means the agent is the only missing piece.

### Step B: Agent direct-first dial (part 2)

In `proto/src/agent/`:

- B1 `proxy::ns_resolve` reads `addresses` as well as `address` and returns a
  candidate list (`svc_candidates::resolve_candidates`). Keep `addr` as the
  best single candidate for callers that want one. Tests: CBOR fixtures with
  `address` only, both fields, malformed `addresses`.
- B2 Rank with `svc_candidates::rank_candidates(&set,
  &local_candidates::our_local_subnets())`. Tests: client on <CLIENT-LAN>/24
  ranks <APP-SERVER-LAN-IP> above <OFFICE-NAT-IP> above relay.
- B3 DONE. `connect_tunnel` (daemon.rs) is the single dial path, replacing the
  duplicated single-address bodies in `proxy_dial_phase` and
  `handle_tcp_connection_bridged` (and `dial_tunnel`, added by the splash gate).
  `dial_plan` orders the attempts (ranked direct candidates first, relay last;
  a published candidate equal to the relay collapses into the relay attempt).
  `attempt_timeout` bounds a DIRECT attempt at `DIRECT_ATTEMPT_TIMEOUT` (750 ms,
  pinned to a 250-1500 ms band by a test) ONLY when another attempt follows it;
  the relay and the final attempt of any plan are bounded by the caller's 15 s
  first-byte deadline, as before. This keeps "no relay configured" truly
  direct-only: a high-RTT WAN gateway or one lost QUIC Initial is not cut off at
  750 ms. (Found in review of PR #117.) The candidate walk is plain sequential
  dialing, not `multi_candidate_dial`'s racing orchestrator.
- B4 DONE, with a different switch than first planned: the existing
  `[tunnel] prefer_relay` (default `false` = direct first). `true` puts the
  relay first and keeps the direct candidates as the fallback. One info line per
  attempt and per winner.
- B5 DONE. Splash gate and the 15 s first-byte deadline are unchanged; the
  dial change sits inside `dial_tunnel`/`proxy_dial_phase`, below them. The
  splash and `splash_wiring_tests` suites pass with it.
- Cache: a VIP cache hit now dials the FULL ranked list. `VipEntry.peer_candidates`
  plus a per-name process-wide list (`set_peer_candidates`); `candidates_for_dial`
  honours the list only alongside a cache hit, and `gc_expired` drops it with the
  entry (stale-list bug found in self-review of PR #117).
- QUIC pin: found live while doing B6. Pins were keyed on the fixed SNI
  `localhost`, so a second gateway was rejected as a fingerprint mismatch. Pins
  are now per gateway endpoint (`pin_key_for`), and the legacy `<sni>.pin` is
  removed once per SNI per process.
- Gate: macOS `cargo check --lib --bins` (required for `proto/src/agent/**`),
  `cargo fmt --check`, clippy on touched files, full `cargo test --lib`.
- Test B6 (live) DONE: `curl http://www.chooseforce.ztlp/up` from the AI computer
  went from 504 after 15 s to 200 in ~0.1 s (23 ms on a cache hit); the agent
  log shows `tunnel active ... via Direct` for the LAN candidate and the relay
  saw no CLIENT_ROUTE for it.
- Test B7 (forced fallback) NOT YET RUN live: block the LAN candidate from the
  AI computer (temporary Windows firewall rule) and confirm the same request
  falls to the relay and behaves as before (504 until step D or a port forward
  exists). The ordering is covered by unit tests (`direct_first_plan`), but not
  yet exercised against a real dead candidate.

### Step C: Elixir gateway parity (part 1, proper)

Port candidate enumeration + `addresses` publishing to
`gateway/lib/ztlp_gateway/service_registrar.ex` so the shipped Docker image
works without the Rust swap. Mirror `compute_advertised_svc`: enumerate
interfaces (`:inet.getifaddrs`), filter like `local_candidates.rs` (drop
loopback, link-local, docker bridges unless opted in), append the relay
backstop, cap at `MAX_ADVERTISED`. ExUnit tests for the filter rules and the
wire field. Decide which image is canonical for production after C lands.

### Step D: Relay-carried gateway sessions (part 3)

For gateways behind NAT with no inbound UDP and no direct path to the client.
Two designs to evaluate before coding; write the choice into this doc:

- D-i The gateway keeps a persistent QUIC connection to the relay; the relay
  multiplexes client sessions onto it (TURN-like). Needs a relay change and a
  gateway change (both Rust and Elixir).
- D-ii The gateway sends registration FROM the QUIC listening socket so the NAT
  mapping is for 23097. Blocked today because msquic owns the socket (that is
  why `GATEWAY_REGISTER_ADDR` exists). Check whether the Rust/Quinn gateway can
  do this already (the NAT-TRAVERSAL doc says "pure-Rust mode binds the same
  socket"). If yes, D-ii is nearly free for the Rust gateway.
- Test: gateway on a NAT'd host with no port forward, client on a different
  network, request succeeds through the relay.

### Step E: Clean-up and docs

- Remove the `.ztlp`/`.trs.ztlp` test NRPT rules if the agent installs its own.
- Update `docs/NAT-TRAVERSAL.md` status table and `MULTI-ZONE-PLAN.md`.
- Add the "agent path vs CLI path" gap to the architecture notes so it is not
  rediscovered.

## 5. Open questions

- Should the agent keep the relay path warm in parallel (race) or strictly
  fall back (sequential)? `multi_candidate_dial` races in priority bands with
  250 ms gaps. Sequential is simpler to reason about; racing is faster when the
  LAN candidate is dead. Sequential was chosen for B3; revisit if B7 shows a
  noticeable stall.
- Elixir vs Rust gateway as the production image. Step A will show how much the
  Rust one lacks (TLS termination, policies, audit, admin API are Elixir-only).
- Cert issuance: the NS rejects the gateway's cert request (`unauthorized`);
  the gateway key must be allowlisted (`component_auth.allowed_keys` in the NS
  YAML config, see `demo/ns-config.yaml`). Needed for HTTPS, separate from this
  plan.
- Does the agent install a `.ztlp` NRPT rule itself for new installs? Belongs
  in MULTI-ZONE-PLAN.md.

## 6. Current live state (so nobody repeats work)

- NS + relay: defcon-ctf-1 <NS-PUBLIC-IP>, v0.35.13, `~/ztlp-trs/`,
  registration auth ON, disc_copies, hostname pinned (Mnesia).
- Zones/records on the NS: `trs.ztlp` (authority = admin@trs.ztlp key),
  `chooseforce.ztlp` (authority = gateway operator key, delegation=true),
  users `admin@trs.ztlp`, `aipc@aicomputer.trs.ztlp`, device
  `aicomputer.trs.ztlp`, SVC `www.chooseforce.ztlp` -> <OFFICE-NAT-IP>:23097.
- ChooseForce server: Elixir gateway `ztlp-gateway-trs` in `~/ztlp-gateway/`
  (zone chooseforce.ztlp, service www, backend <APP-CONTAINER-IP>:3000), operator key
  `~/ztlp-gateway/operator.key` (hex seed, owned 999:999). A stale March-2026
  container `ztlp-gateway` (exited) was left alone. Root disk grown to 390 GB.
- AI computer: enrolled in trs.ztlp as aicomputer.trs.ztlp, relay secret in
  `relay.secret`, NRPT rules `.ztlp`, `.trs.ztlp`, `.defcon.ztlp` -> 127.0.0.55.
  Demo enrollment backed up in `C:\temp\ztlp-demo-backup-20261004` and `*.bak`.
