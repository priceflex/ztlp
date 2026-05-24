# Zone-Keyed Gateway Registration — Implementation Plan (C-prime)

**Branch:** `feature/zone-keyed-gateway-register`
**Target release:** v0.30.5 (patch — preserves both `0x0A` and `0x0E` legacy paths; no wire-format breaking change to the relay's existing parsers)
**Design source:** `docs/plans/2026-05-24-zone-keyed-gateway-registration.md` (PR #43, merged `c3c78ec`)
**Author:** Hermes session 2026-05-24 evening (continuing from Steve)
**Status:** IN PROGRESS

---

## What this PR is, and what it isn't

### Is
A pragmatic, surgical patch that fixes today's **cross-tenant slug collision**
(`Tech Rockstars` + `Tech Rockstars Test` both register as `gw-tech-rockst`)
by making the Rust CLI gateway emit the **already-implemented `0x0E`
GATEWAY_REGISTER_V2 frame** (which carries an explicit `zone_id` field of
1–63 bytes), and switching the relay's routing key from the truncated
service_name to `gw:<zone_id>`.

### Is NOT
The full Ed25519 / NS-KEY-anchored auth design described in PR #43. That
work needs additional prerequisites that **do not currently exist** in the
codebase:

- `NodeIdentity` only carries X25519 keys (no Ed25519 signing key)
- `identity.json` has no `default_zone` field
- No code path publishes `bootstrap.<zone>` KEY records to NS at startup

Those gaps are tracked separately and will ship as v0.31.0 (or later).

### The architecture conflict this resolves

PR #43's design proposed a NEW wire format `0x0C` with Ed25519 signatures,
without realizing that `0x0E` GATEWAY_REGISTER_V2 (HMAC-keyed, zone-aware)
**already existed in the relay AND the Elixir gateway** (PRs #20, #21, #22).
The Rust CLI gateway — the one Launch deploys via
`priceflex/ztlp-node:hermes-quic-routing` — never picked up the V2 sender,
so all live tenants still send `0x0A` with truncated org-name slugs.

This PR closes that gap by porting the Elixir V2 sender to Rust.

---

## Step-by-step plan (numbered for commit cadence)

### Step 1 — Wire format constants + V2 builder in Rust proto (TDD)
**File:** `proto/src/bin/ztlp-cli.rs` (the existing `build_gateway_register_packet`
function is the reference point).

- Add `GATEWAY_REGISTER_V2_TYPE: u8 = 0x0E`
- Add `build_gateway_register_v2_packet(node_id, zone_id, service_name, ttl, timestamp, secret) -> Result<Vec<u8>, &'static str>`
- Signed material exactly matches the Elixir reference:
  `<<0x0E, zone_len::8, zone_id, node_id, service_padded_16, ttl::32, timestamp::64>>`
- Wire output: `<<0x5A, 0x37, 0x0E, zone_len::8, zone_id, node_id, service_padded_16, ttl::32, timestamp::64, hmac::32>>`
- Errors: `zone_len < 1 || zone_len > 63 → Err("zone_id length out of range")`

**TDD red-test first:**
- `test_v2_packet_round_trip` — build with known inputs, parse and verify field-by-field
- `test_v2_packet_rejects_zone_too_long` — 64-byte zone returns Err
- `test_v2_packet_rejects_empty_zone` — 0-byte zone returns Err
- `test_v2_packet_signed_material_matches_elixir_reference` — golden-hash check against a vector computed offline from the Elixir code

**Commit message:** `feat(proto): add 0x0E GATEWAY_REGISTER_V2 packet builder for Rust gateway`

### Step 2 — Add `--zone` flag to `ztlp listen --gateway`
**File:** `proto/src/bin/ztlp-cli.rs` (the `Listen` command struct).

- Add `#[arg(long)] zone: Option<String>` to the Listen command struct
- Add `#[arg(long)] hmac_secret_env: Option<String>` — name of an env var
  to read the per-zone HMAC secret from (matches the Elixir convention
  `ZTLP_HMAC_SECRET_<UPPER_ZONE>` but allows operator override)
- When `--zone` is provided AND a secret is loadable, the gateway sends BOTH `0x0A` (legacy, for migration) AND `0x0E` packets every interval
- When `--zone` is absent, fall back to today's behavior (V1 only) — strict backwards compat

**Commit message:** `feat(proto): ztlp listen --gateway accepts --zone for V2 register emission`

### Step 3 — Modify `spawn_relay_registration` to send V2 in parallel
**File:** `proto/src/bin/ztlp-cli.rs` (around line 3449).

- Function signature gains: `zone: Option<&str>`, `hmac_secret: Option<&[u8]>`
- Per-tick: build V1 (existing) + V2 (new, when zone+secret both available)
- Send both to the relay
- Log at debug level: `"sent gateway_register(v1+v2) zone={zone} service={svc}"`

**Tests:** add `test_spawn_v2_when_zone_present` (uses a fake UDP server,
inspects the two packets it receives per interval).

**Commit message:** `feat(proto): emit V1+V2 GATEWAY_REGISTER pair from gateway loop`

### Step 4 — Switch relay routing key to `gw:<zone_id>` for V2 registrations
**File:** `relay/lib/ztlp_relay/udp_listener.ex` (around line 614,
`do_register_gateway` callsite from `verify_gateway_register_v2`).
**File:** `relay/lib/ztlp_relay/gateway_forwarder.ex` (the
`register_dynamic_gateway/4` GenServer cast).

- V2 path calls `GatewayForwarder.register_dynamic_gateway(sender, node_id, "gw:" <> zone_id, ttl)`
  — explicitly bypassing the `service_padded_16` field for routing
- V1 path keeps existing behavior (service_name as the key)
- The forwarder's strict-routing logic at `gateway_forwarder.ex:400-401`
  already rejects requests for service names that don't match registered
  ones — colon-containing names go through the same lookup, so no change
  required to the lookup itself

**Tests:**
- New `relay/test/ztlp_relay/v2_zone_routing_test.exs`:
  - Sends V2 register with `zone_id="acme.ztlp"`, asserts
    `pick_gateway_for_service("gw:acme.ztlp")` returns the registered address
  - Sends V2 register with `zone_id="techrockstars.ztlp"` + `zone_id="techrockstars.com"`
    from two different node_ids, asserts both are independently routable
    (no collision)
  - Sends V1 register with `service_name="gw-acme"`, asserts
    `pick_gateway_for_service("gw-acme")` still works (backwards compat)

**Commit message:** `feat(relay): route V2 registrations by gw:<zone_id> key`

### Step 5 — Update `derive_zone_from_service` to handle both prefixes
**File:** `relay/lib/ztlp_relay/udp_listener.ex` (line 461).

- Add `defp derive_zone_from_service("gw:" <> rest), do: rest`
- Keep existing `defp derive_zone_from_service("gw-" <> rest), do: rest` for backcompat
- Order matters — `gw:` first since it's the new canonical form

**Tests:** small unit test adding `assert derive_zone_from_service("gw:foo.ztlp") == "foo.ztlp"`.

**Commit message:** `feat(relay): derive_zone_from_service recognizes gw:<zone> prefix`

### Step 6 — Update Launch's compose template
**File:** `ztlp.net/launch_app/app.py` (line 888, the `--service-name` arg
in the gateway compose command; line 1011, the user-facing `gw_service`
in `render_claim_page`).

- Compose command: add `--zone {row['zone']}` to the `ztlp listen` args
  AND keep `--service-name gw-{slug[:11]}` for V1 backwards-compat during
  the migration window
- `render_claim_page`: change `gw_service = f"gw-{slug[:11]}"` to
  `gw_service = f"gw:{zone}"` so the connect command tells clients to
  ask for the new zone-keyed slug

**Tests:** update `test_launch_app.py` assertions (lines 172, 221, 1073)
to check for both `--zone` and the new `gw:<zone>` service hint.

**Commit message:** `feat(launch): pass --zone to gateway and surface gw:<zone> in connect hint`

### Step 7 — Update relay README + add migration notes
**Files:**
- `relay/README.md` — document the new V2 routing key
- `docs/plans/2026-05-24-zone-keyed-gateway-register-IMPL.md` (this file)
  — flip Status: IN PROGRESS → SHIPPED at end

### Step 8 — Full test suites green
```bash
cd ~/ztlp/proto    && cargo test --lib --release
cd ~/ztlp/relay    && mix test
cd ~/ztlp/gateway  && mix test --seed 1
cd ~/ztlp/ns       && mix test
cd ~/ztlp/ztlp.net && python3 -m unittest discover tests
```

All must pass before the PR opens.

### Step 9 — CI green on push
The standard 7 checks (Rust proto, Elixir relay/ns/gateway, Performance
Gate, Interop, CI ✅) plus CodeRabbit.

### Step 10 — Tag v0.30.5 and deploy

Per Steve's "Do 2" choice this session: prod deploy after merge.
Plan:
1. Bump versions in `proto/Cargo.toml`, `relay/mix.exs`, `ns/mix.exs`,
   `gateway/mix.exs`, `ztlp.net/launch_app/app.py`, the manifest.
2. Tag `v0.30.5`, push to GitHub.
3. Build new images:
   - `priceflex/ztlp-relay:v0.30.5` (relay's `0x0E` routing change)
   - `priceflex/ztlp-node:v0.30.5` (Rust gateway's new V2 sender)
   - `ztlpnet-launch:v0.30.5` (compose template change)
4. Ship to AWS via `docker save | ssh ... docker load` pattern.
5. Recreate `ztlp-relay` on `34.218.240.106` (warn Steve — iOS bench).
6. Recreate `ztlp-launch` on `35.91.88.177`.
7. Recreate one tenant gateway as canary (`techrockstars`). Verify it
   appears in relay logs as `service=gw:techrockstars.ztlp`.
8. Recreate remaining 17 tenants if canary green.
9. Smoke test: `ztlp connect bootstrap.techrockstars.ztlp --service gw:techrockstars.ztlp`
   gets routed correctly.
10. Update `hermes_session_handoff.md` with the deploy log.

---

## Migration / safety notes

- **Zero downtime:** V1 stays on the wire from every gateway and the relay
  accepts both. Existing clients (using `gw-techrockstars` in their
  `--service` flag) keep working because the V1 registration is still
  active. New clients can opt into `gw:<zone>` for collision-safe routing.
- **No NS changes:** zero NS code touched in this PR.
- **No identity.json changes:** we don't add Ed25519 or `default_zone`
  fields — those are deferred to the v0.31.0 work.
- **Per-zone HMAC secret distribution:** existing problem (Task A in the
  handoff). For V2 frames to actually be HMAC-verified (rather than
  accepted with the staging/dev legacy fallback), Launch needs to inject
  `ZTLP_HMAC_SECRET_<ZONE>` into the gateway container's env. Not part of
  this PR — V2 frames accepted via the staging fallback are still
  better-routed than V1, even without per-zone HMAC verification, because
  the **routing key** improves regardless of whether the HMAC checks out.

## Out of scope (will become follow-up issues)

- Ed25519 signing keys in identity.json
- `default_zone` field in identity.json
- Gateway publishes `bootstrap.<zone>` KEY records to NS at startup
- Per-zone HMAC secret distribution model
- `0x0A` legacy deprecation (Phase 1/2/3 schedule in PR #43 §4)
- CLIENT_ROUTE auth tightening (PR #43 §7, deferred to v0.31.1)
