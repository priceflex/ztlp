# Cookbook: deploy per-zone HMAC secrets via NSSM env vars

**Status:** Proposed
**Author:** Hermes Agent (under Steve Price)
**Date:** 2026-06-04
**Target cookbook version:** `0.4.17` (after the notify-mismatch fix lands as `0.4.16`)
**Target ztlp binary version:** any v0.34.8+ (current floor)

## Problem statement

Every host in the fleet today emits V2 `GATEWAY_REGISTER` frames signed with a
**zero-byte HMAC** and writes `registered_unsigned: true` into its NS SVC
record. We verified this on three production hosts on 2026-06-03:

- `TRSDC.tech-rockstars.trs.ztlp` — `registered_unsigned: true`
- `z2ls-desk-8b7080.tech-rockstars.trs.ztlp` (DESKTOP-CHARLY) — same
- `dan.tech-rockstars.trs.ztlp` — same

The listener tells you why on every boot, in `ztlp-listener.err.log`:

```
⚠ --zone=tech-rockstars.trs.ztlp set but per-zone HMAC secret is empty/unset;
emitting V2 with a zero-byte HMAC. The relay's HMAC mode
(ZTLP_RELAY_HMAC_MODE=dev/staging/prod) decides whether to accept it.
Set ZTLP_HMAC_SECRET_<SLUG> to enable verified V2 emission.
```

It works because the production relay runs in lenient HMAC mode (`dev` or
`staging`), accepting unsigned frames and writing them through. The moment we
flip the relay to `prod`, every host stops registering and the fleet goes
dark.

This is the last gap between "functional ZTLP" and "trusted ZTLP." The
cookbook does not deploy the per-zone HMAC secret to any host today. There is
no field in the data bag for it and no NSSM-env wiring in
`recipes/default.rb`.

### Why this matters for multi-tenant under our zone

Tech Rockstars manages multiple customers under sub-zones of `trs.ztlp`
(today `tech-rockstars.trs.ztlp`; future `acmecorp.trs.ztlp`,
`bigcorp.trs.ztlp`, …). The V2 zone-keyed register frame carries the zone
name on the wire and the relay's `pick_gateway_for_service` routes by it
(see `references/v0.34.x-protocol-pitfalls.md` in the ztlp-prod-deployment
skill). Without a per-zone HMAC secret, **any host in any sub-zone can mint
a register packet claiming to be in any other sub-zone.** That's the
classic cross-tenant hijack the Ed25519 + per-zone HMAC boundary was
designed to prevent.

The work below is the recipe-layer half of closing that gap. The relay
already supports per-zone secrets (`relay/lib/ztlp_relay/hmac_secrets.ex`);
it just needs the secrets configured. The listener already supports them
(`proto/src/bin/ztlp-cli.rs::resolve_v2_config`); it just needs them in its
process environment.

## Proposal

Extend `cookbooks/ztlp/recipes/default.rb` (v0.4.17) to:

1. **Read a new data-bag key** `ztlp.zone_hmac_secrets` mapping zone names
   to hex/base64 secrets:

   ```yaml
   ztlp:
     zone_hmac_secrets:
       "tech-rockstars.trs.ztlp": "abc123…64hex"
       "acmecorp.trs.ztlp":        "def456…64hex"
   ```

2. **Compute the env-var name** for the host's zone using the same slugify
   rule both the listener and relay use:

   ```ruby
   def hmac_env_name_for_zone(zone)
     slug = zone.chars.map { |c| c =~ /[A-Za-z0-9]/ ? c.upcase : '_' }.join
     "ZTLP_HMAC_SECRET_#{slug}"
   end
   ```

   Mirrors `ztlp-cli.rs:4027` (Rust) and
   `relay/lib/ztlp_relay/hmac_secrets.ex:slugify_zone/1` (Elixir).

3. **Stamp the secret into NSSM's `AppEnvironmentExtra`** for
   `ztlp_listener` so the listener process inherits it on startup:

   ```ruby
   if ztlp_zone_secret
     env_name = hmac_env_name_for_zone(ztlp_zone)
     ztlp_listener_env_extra = ["#{env_name}=#{ztlp_zone_secret}"]
     # nssm set ztlp_listener AppEnvironmentExtra "<env_name>=<value>"
   end
   ```

   Bust the `listener-args.sha256` marker (line 1244) when the env-var
   value changes, so we get a delayed restart on rotation.

4. **Log a clear WARN** when `ns_self_register` is true and the host's
   zone has no secret configured. That keeps the failure mode visible
   without breaking the converge.

5. **Document the rotation procedure** in `cookbooks/ztlp/README.md`:
   set both primary and grace in the secrets map (comma-separated),
   converge fleet, switch to new-only, converge fleet, retire grace.
   See `docs/per_zone_hmac_design.md` § "Rotation flow" for the canonical
   sequence the relay expects.

### Why NSSM env extra, not a config file

Three options considered:

| Option | Pros | Cons |
|---|---|---|
| **NSSM `AppEnvironmentExtra`** ✓ | listener already looks for env var; no protocol change; rotation = nssm set + restart | secret visible to anyone with admin on the host (same trust as today's identity.json) |
| Config file (`C:\ProgramData\ZTLP\config.toml`) | could be ACL'd tighter than env vars (NTFS DACL → SYSTEM-only read) | requires Rust-side config-file support that doesn't exist yet; would land as a separate plan |
| Pull from a vault at boot | rotates without redeploy; secret never on disk | massive scope creep; no vault infra today |

**Picked NSSM env extra.** Matches what the listener already reads from
`std::env::var`. Matches what the relay reads from `System.get_env/1`.
Matches what the SaaS launch flow does for tenant containers (per the
ztlp-bootstrap-deploy skill). No protocol change needed.

ACL hardening for the data bag is already in place (encrypted at rest,
SYSTEM-decrypted at converge time — same memory note we use for
identity.json). The NSSM-config write happens as SYSTEM via Chef; the
running env var is only readable by the listener process owner (SYSTEM
by default). For a v0.4.17 ship, that trust model is identical to
today's.

## Implementation outline

### Phase 1 — Recipe support (this PR)

Files touched (estimated diff size, all in
`cookbooks/ztlp/recipes/default.rb`):

- ~line 374, after `ztlp_register_svc = …`: add
  `ztlp_zone_secrets = (ztlp_config['zone_hmac_secrets'] || {}).to_h`
- ~line 376, after `ztlp_zone = …`: resolve
  `ztlp_zone_secret = ztlp_zone_secrets[ztlp_zone]` (case-sensitive on
  zone; keys must match the zone string exactly)
- ~line 460–470 (the `node.normal['ztlp']` publish block): publish
  `node.normal['ztlp']['zone_hmac_secret_present'] = !ztlp_zone_secret.nil?`
  so Z2LS dashboards can see the state without exposing the secret
- ~line 1226 (heartbeat-enabled WARN block): add a sibling block that
  logs a WARN when `ns_self_register` is true AND no secret is configured
  for the host's zone
- ~line 1245–1280 (listener install/update ruby_block): add an
  `nssm set ztlp_listener AppEnvironmentExtra …` invocation before the
  `not_if` marker check, fold the env-extra string into the marker's
  SHA256 input so a secret rotation busts the marker and queues a delayed
  restart
- `cookbooks/ztlp/metadata.rb`: bump to `0.4.17`
- `cookbooks/ztlp/README.md`: new "Per-zone HMAC secrets" section with
  the data-bag schema, the slug rule, a rotation walkthrough, and a
  rollback procedure

Estimated cookbook delta: ~60 LOC + ~80 LOC of docs.

### Phase 2 — Relay-side secret deployment (separate PR / op)

Out of scope for the cookbook PR but blocking the cutover:

- Generate one 64-hex secret per managed sub-zone:
  ```bash
  for zone in tech-rockstars.trs.ztlp; do
    echo "ZTLP_HMAC_SECRET_$(echo "$zone" | tr 'a-z.-' 'A-Z__')=$(openssl rand -hex 32)"
  done
  ```
- Stamp them into the relay's `.env` (`~/ztlp/.env` on
  `34.218.240.106`).
- `docker compose up -d --force-recreate relay` to pick up the new env.
- ⚠ This is a relay restart. Per Steve's restart-warning convention,
  announce in chat before running and log
  `⚠ RELAY RESTART @ <UTC time>` for audit.

### Phase 3 — Cutover (separate PR)

After Phase 1 ships and Phase 2 is done:

- Add the same secrets to the data bag (encrypted-at-rest).
- Wait one converge cycle (~1h) for every host to pick them up.
- Verify via fleet audit:
  ```
  zone-inspect-ns.exs → expect registered_unsigned: false on every record
  ```
- Flip relay `ZTLP_RELAY_HMAC_MODE` from current value to `prod`.
- ⚠ Second relay restart.

### Phase 4 — Optional future hardening

- Move from NSSM env extra to a SYSTEM-owned config file at
  `C:\ProgramData\ZTLP\config.toml` once Rust gains config-file support.
- Multi-secret support for online rotation
  (`ZTLP_HMAC_SECRET_<ZONE>=primary,grace1,grace2`). Recipe already
  passes the value through verbatim, so this works without further
  changes once the data bag has multiple comma-separated secrets per zone.

## Tests

Cookbook tests (`cookbooks/ztlp/spec/unit/recipes/default_spec.rb` or
equivalent — check existing test structure):

1. Data-bag has no `zone_hmac_secrets` key → recipe sets no env extra,
   logs WARN when `ns_self_register: true`, does not break the converge.
2. Data-bag has `zone_hmac_secrets` for the host's zone → env extra is
   set with the correct env-var name and value, no WARN.
3. Data-bag has `zone_hmac_secrets` but for a DIFFERENT zone than the
   host's zone → no env extra, WARN logged.
4. Existing env extra differs from new value → marker SHA256 changes →
   listener restart queued. Idempotent on next converge (same value =
   no restart).
5. Zone slugify edge cases — uppercase zone, hyphen in zone, period in
   zone, leading/trailing punctuation. Pin against the Rust + Elixir
   slug rules. Hex output of the env-var name should match what
   `proto/src/bin/ztlp-cli.rs:4027` and
   `relay/lib/ztlp_relay/hmac_secrets.ex:slugify_zone/1` produce.

Integration validation (manual, after merge):

6. Deploy v0.4.17 cookbook to a canary host (NOT TRSDC, NOT
   DESKTOP-CHARLY — pick a quieter test host).
7. Set `ZTLP_HMAC_SECRET_TECH_ROCKSTARS_TRS_ZTLP` in the data bag.
8. Wait for the next hourly Chef converge.
9. SSH to the host, confirm `nssm get ztlp_listener AppEnvironmentExtra`
   includes the secret.
10. Confirm listener log no longer emits "per-zone HMAC secret is
    empty/unset" warning.
11. Query NS for that host's SVC record. Once Phase 2 secrets are on
    the relay AND Phase 3 mode flip is done, `registered_unsigned`
    should flip from `true` to `false`.

## Validation matrix — what we expect to see, end to end

| ztlp_register_svc | ns_self_register | zone_hmac_secrets[zone] present? | Outcome |
|---|---|---|---|
| true (default) | false (default) | – | Legacy out-of-band publish runs. No env extra set. Existing pre-migration behaviour. |
| true | true | no | Heartbeat owns NS. Listener emits zero-byte V2 HMAC. WARN logged. Relay accepts (dev/staging mode). `registered_unsigned: true` on record. Today's state. |
| true | true | yes | Heartbeat owns NS. Listener emits signed V2 HMAC. No WARN. Relay verifies. `registered_unsigned: false` on record. Target state. |
| false | true | yes | Same as above — `register_svc: false` is the cookbook-v0.4.16 workaround for fresh enrollments. Compatible with secrets. |

The third row is the eventual fleet steady state. We arrive there
incrementally: ship v0.4.17 (rows 1 and 2 unchanged, row 3 newly
available), then populate the data bag (every host moves from row 2 to
row 3), then flip relay mode to `prod` (rejects row 2 — but no hosts
should be in row 2 by then).

## Follow-up — relay-side prod-mode flip

After fleet is on row 3, flip the relay:

```bash
# In ~/ztlp/.env on 34.218.240.106
ZTLP_RELAY_HMAC_MODE=prod
```

```bash
ssh ubuntu@34.218.240.106 'cd ~/ztlp && docker compose up -d --force-recreate relay'
# ⚠ RELAY RESTART @ <utc time>
```

In `prod` mode the relay refuses any V2 frame that fails HMAC
verification. From this point forward, a host without the right secret
literally cannot register — which is the trust boundary we want.

## Open questions (please address before merge)

1. **Where exactly does the data bag live in the encrypted form?**
   The skill notes the data bag is SYSTEM-owned and encrypted at rest,
   decrypted during converge. Confirm with Steve that adding a 64-hex
   secret to the encrypted source on the Z2LS portal is the right
   distribution channel, vs. a separate secrets channel.

2. **Per-sub-zone vs top-level zone secrets.** The cookbook's
   `ztlp_ns_register_zone` logic (line 1018) squeezes the zone down to
   the rightmost-two-labels for NS register. The listener-side V2
   register uses the FULL zone string for HMAC env lookup. Confirm:
   should `tech-rockstars.trs.ztlp` and `acmecorp.trs.ztlp` share the
   same `ZTLP_HMAC_SECRET_TRS_ZTLP` (rightmost-two)? Or have separate
   `ZTLP_HMAC_SECRET_TECH_ROCKSTARS_TRS_ZTLP` and
   `ZTLP_HMAC_SECRET_ACMECORP_TRS_ZTLP` (full)? The relay reads the
   full zone string from the wire and looks up by full slug
   (`hmac_secrets.ex:259`). So the listener-side env var name must use
   the full zone too. **This means per-sub-zone secrets — which is the
   security boundary we want.** Documented for the implementer.

3. **Audit-log integration.** The cookbook today writes node attributes
   into `node.normal['ztlp']` for Z2LS observability. Should the
   secret-present state get its own
   `node.normal['ztlp']['zone_hmac_secret_present']` attribute (boolean
   only, never the secret itself) so dashboards can flag missing-secret
   hosts? **Recommended.** Already in the implementation outline above.

## See also

- `docs/per_zone_hmac_design.md` — protocol-level design of per-zone
  HMAC, slug rules, rotation flow, mode selector. Read first.
- `docs/plans/2026-05-24-zone-keyed-gateway-registration.md` — the V2
  register frame that consumes this secret. Already shipped (v0.34.x).
- `proto/src/bin/ztlp-cli.rs::resolve_v2_config` (~line 4010) — the
  listener-side lookup.
- `relay/lib/ztlp_relay/hmac_secrets.ex` — the relay-side lookup.
- `cookbooks/ztlp/recipes/default.rb` line 374-378, 460-470, 1226-1240,
  1245-1280 — the four insertion points for the recipe change.
- `ztlp-prod-deployment` skill,
  `references/v0.34.x-protocol-pitfalls.md` — why the relay's HMAC mode
  matters and what `registered_unsigned: true` really means.

## Risks & rollback

**Risk:** rolling out a bad secret value (truncated, wrong encoding)
causes every host with that secret to fail V2 emission. Listener will
log the failure and fall back to V1, which still routes today.

**Rollback:** delete the `zone_hmac_secrets` key from the data bag,
converge fleet, every host clears its NSSM env extra on next converge
and falls back to the today-state (zero-byte HMAC + `registered_unsigned:
true`). Single data-bag edit, no code change, no relay restart.

**Risk:** secret leaks via process listing (`Get-Process | Select-Object
-Property StartInfo` does NOT show env vars by default, but PowerShell
session running as Administrator with `wmi` can inspect process env on
older Windows). Treat as same trust class as identity.json on disk.

**Risk:** rotation foot-gun. Operator updates the secret without using
the comma-separated grace mechanism → listener picks up new secret on
next converge → relay still has old secret → V2 frames rejected.
**Mitigation:** README walkthrough mandates grace period; cookbook
warns when only one secret is in the comma-separated list during a
flagged rotation window. Phase 4 enhancement.
