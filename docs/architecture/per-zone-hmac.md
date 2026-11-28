# Per-Zone HMAC Secret Authentication — Design

**Status:** Phase 1 (relay-side verifier + V1 fallback) landing in v0.29.6.
**Author:** Steve Price + Hermes Agent.
**Last updated:** 2026-05-23.

This document describes the per-zone HMAC secret system that replaces the
single global `ZTLP_RELAY_REGISTRATION_SECRET` with a per-tenant key map. It
is the prod-readiness blocker for the Bootstrap workstream and for any
multi-tenant deployment where two tenants share infrastructure (relay, NS,
gateway pool) but must remain cryptographically isolated.

---

## Goals

1. **Tenant isolation.** Tenant A cannot register a gateway claiming to be
   in tenant B's zone without holding B's per-zone secret.
2. **No new external dependencies.** Secrets live in environment variables
   for v0.29.6 (`ZTLP_HMAC_SECRET_<ZONE>`). Code is structured so a future
   PR can swap in HashiCorp Vault / AWS Secrets Manager / etc. without
   touching call sites.
3. **Zero-downtime rotation.** Operators must be able to rotate a zone's
   secret without dropping in-flight registrations. Multiple active
   secrets per zone, with the first listed treated as the *primary*
   (signing) key; all listed keys are *verifying* keys.
4. **Safe migration.** Existing deployments that have no per-zone secret
   configured must continue to work in `dev` and `staging` modes (loud
   warning), but `prod` mode must reject unsigned/unmapped registrations.
5. **One spec across relay and gateway.** The signing format is identical
   on both sides; the only difference is which side holds which keys.
   Signing and verifying keys are the same value today, but the API leaves
   room to split them later (e.g., move to per-zone Ed25519 keypairs).

---

## Non-goals (deferred)

- **External secret manager.** Vault, AWS SM, GCP SM — all interesting,
  none required for v0.29.6. The `HmacSecrets` module is the integration
  point.
- **Public-key signatures.** HMAC is enough for inter-component
  registration. Per-device Ed25519 keys remain orthogonal.
- **Phase C multi-service routing.** Deferred per Steve's direction. The
  HMAC layer is designed to compose cleanly with future routing changes.

---

## Wire format

Two new frame variants are introduced. The existing V1 frames continue to
work for backward compatibility.

### GATEWAY_REGISTER_V2 (type byte `0x0E`)

```
+----------+----------+----------+----------+----------+----------+----------+----------+
| 0x5A     | 0x37     | 0x0E     | zone_len |    zone_id (zone_len bytes)             |
+----------+----------+----------+----------+----------+----------+----------+----------+
|                            node_id (16 bytes)                                         |
+----------+----------+----------+----------+----------+----------+----------+----------+
|                       service_padded (16 bytes, zero-padded)                         |
+----------+----------+----------+----------+----------+----------+----------+----------+
| ttl (4 bytes, big-endian) | timestamp (8 bytes, unix seconds, big-endian)             |
+----------+----------+----------+----------+----------+----------+----------+----------+
|                            hmac (32 bytes, HMAC-SHA256)                              |
+----------+----------+----------+----------+----------+----------+----------+----------+
```

Total length: `3 + 1 + zone_len + 16 + 16 + 4 + 8 + 32 = 80 + zone_len` bytes.
`zone_len` is constrained to `1..=63` (RFC1035 DNS label limit).

**Signed material** (what HMAC-SHA256 is computed over):

```
0x0E || zone_len (1B) || zone_id || node_id || service_padded || ttl (4B) || timestamp (8B)
```

The HMAC field itself is NOT included in the signed material. The wire
magic bytes (`0x5A 0x37`) are also NOT included — they're a framing
concern, not a payload concern.

### CLIENT_ROUTE_V2 (type byte `0x0F`)

```
+----------+----------+----------+----------+----------+----------+----------+----------+
| 0x5A     | 0x37     | 0x0F     | zone_len |    zone_id (zone_len bytes)             |
+----------+----------+----------+----------+----------+----------+----------+----------+
|                            node_id (16 bytes)                                         |
+----------+----------+----------+----------+----------+----------+----------+----------+
| svc_len  |              service_name (svc_len bytes)                                |
+----------+----------+----------+----------+----------+----------+----------+----------+
|                       timestamp (8 bytes, unix seconds, signed)                      |
+----------+----------+----------+----------+----------+----------+----------+----------+
|                            hmac (32 bytes, HMAC-SHA256)                              |
+----------+----------+----------+----------+----------+----------+----------+----------+
```

**Signed material:**

```
0x0F || zone_len (1B) || zone_id || node_id || svc_len (1B) || service_name || timestamp (8B)
```

### V1 frames (legacy, kept for backward compat)

`GATEWAY_REGISTER` (`0x0A`) and `CLIENT_ROUTE` (`0x0B`) continue to be
accepted but are subject to the V1-fallback policy described below.

---

## Zone secret storage

### Environment variable layout

Each zone has one env var. Multiple secrets are comma-separated. The
first entry is the *primary* (signing) secret; all entries are valid for
*verification*.

```
ZTLP_HMAC_SECRET_<UPCASE_ZONE> = "<primary>[,<grace1>[,<grace2>...]]"
```

Zone names are mapped to env-var suffixes by:
1. Upper-casing.
2. Replacing every non-alphanumeric character with `_`.
3. Collapsing runs of `_` into a single `_`.
4. Stripping leading/trailing `_`.

Examples:

| Zone name             | Env var suffix              |
|-----------------------|-----------------------------|
| `acme`                | `ZTLP_HMAC_SECRET_ACME`     |
| `acme.ztlp`           | `ZTLP_HMAC_SECRET_ACME_ZTLP`|
| `tech-rockstars.ztlp` | `ZTLP_HMAC_SECRET_TECH_ROCKSTARS_ZTLP` |
| `hermese2e-1779...`   | `ZTLP_HMAC_SECRET_HERMESE2E_1779___` (collisions possible — use stable zone names) |

### Secret encoding

Each comma-separated entry is one of:

- **Raw bytes (32 bytes ASCII-printable).** Used as-is.
- **Hex-encoded (64 hex chars).** Decoded to 32 raw bytes.
- **Base64-encoded (`base64:<encoded>`).** Decoded to N raw bytes
  (minimum 16, recommended 32). Useful for binary secrets generated by
  `openssl rand -base64 32`.

The same encoding rules apply per-entry within a comma-separated list,
so a primary key and grace key can be in different encodings if
necessary.

### Legacy single-secret fallback

`ZTLP_RELAY_REGISTRATION_SECRET` continues to be honored as the *default*
zone secret when no per-zone secret matches. It is used for:

- V1 frames (no `zone_id` field). Always validated against this secret
  if it's set. Otherwise governed by the mode below.
- V2 frames whose `zone_id` has no `ZTLP_HMAC_SECRET_<ZONE>` configured.
  Treated identically to the V1 fallback path.

When the legacy secret is used, a per-call WARN log is emitted in
staging mode and an ERROR is emitted (without rejecting) in prod mode
unless `ZTLP_RELAY_HMAC_LEGACY_ALLOWED=true` is explicitly set.

---

## Mode selector

```
ZTLP_RELAY_HMAC_MODE = dev | staging | prod
```

Default: `dev` (matches the historical behavior).

| Mode    | Missing per-zone secret             | Missing legacy secret           | Loud-warning logs |
|---------|-------------------------------------|---------------------------------|-------------------|
| dev     | accept (debug log)                  | accept (debug log)              | no                |
| staging | accept (WARN log per registration)  | accept (WARN log)               | yes               |
| prod    | **REJECT** (ERROR log)              | **REJECT** unless `LEGACY_ALLOWED` | yes            |

Mode is read once at boot and never re-checked. Operators wanting to
flip from staging to prod must restart the relay; this is intentional —
flipping prod-mode at runtime invalidates in-flight assumptions about
what frames have already been accepted.

---

## Rotation procedure

Goal: rotate a zone's secret without losing in-flight registrations.

1. Operator generates a new secret: `openssl rand -hex 32`.
2. Operator updates `ZTLP_HMAC_SECRET_<ZONE>` to `<new>,<old>` (NEW
   first, so it becomes the primary signing key; OLD second, so it's
   still accepted on verification).
3. Operator restarts the relay (and/or gateways) in any order. During
   the overlap window, both keys are accepted on verify.
4. Operator updates gateway-side env to use `<new>` as its primary.
5. Once all gateways are confirmed to be signing with `<new>`, operator
   removes `<old>` from the relay config: `ZTLP_HMAC_SECRET_<ZONE>` ←
   `<new>`. Restart relay.

The overlap window is determined by operator pace, not by code. There
is no automatic expiration of grace keys.

---

## Code surface

### `ZtlpRelay.HmacSecrets` (new module)

Public API:

```elixir
@type zone_id :: String.t()
@type secret  :: binary()
@type mode    :: :dev | :staging | :prod

@spec mode() :: mode()
@spec primary_secret(zone_id()) :: {:ok, secret()} | {:error, :not_configured}
@spec verifying_secrets(zone_id()) :: [secret()]
@spec legacy_secret() :: secret() | nil
@spec verify(zone_id(), signed_data :: binary(), provided_hmac :: binary()) ::
        {:ok, :primary | :grace | :legacy} | {:error, :no_secret | :bad_hmac}
```

`verify/3` is the single entry point used by both `GATEWAY_REGISTER` and
`CLIENT_ROUTE` handlers. It encapsulates:

- Looking up all verifying keys for `zone_id`.
- Falling back to the legacy single secret if no zone-specific keys
  exist, subject to mode policy.
- Trying each key with `:crypto.mac(:hmac, :sha256, ...)` in constant
  time against the provided HMAC.
- Returning which key class matched so the caller can log appropriately.

### V1 → zone_id mapping

When a V1 frame arrives, the listener derives a synthetic `zone_id` from
the `service_name` field by stripping the `gw-` prefix (current
convention) and using the remainder. This lets V1 frames participate in
the per-zone secret table without a wire-format change. Operators
running per-zone secrets MUST move to V2 frames within one release
cycle; V1 with per-zone secrets emits a deprecation WARN on every
verification.

### V2 frame handler (Phase 1.5 — LANDED in v0.29.6 / PR #21) + V2 signer (Phase 2 — LANDED in v0.29.6)

Phase 1 of this design landed the `HmacSecrets` module and the V1
fallback path (PR #20, merged 2026-05-23).

Phase 1.5 shipped the V2 wire-format additions on the **relay side**
(PR #21, merged 2026-05-23): type bytes `0x0E`
(`GATEWAY_REGISTER_V2`) and `0x0F` (`CLIENT_ROUTE_V2`) are now
dispatched by `ZtlpRelay.UdpListener.handle_info/2` to dedicated
`handle_gateway_register_v2/2` and `handle_client_route_v2/3`
clauses. Both V2 handlers parse the explicit `zone_id` field
directly out of the frame and pass it to
`HmacSecrets.verify_with_policy/3` — no service-name-derived
synthetic zone.

Phase 2 ships the V2 signer on the **gateway side**:
`ZtlpGateway.HmacSecrets` (signer-only subset of the relay's module)
reads per-zone secrets from `ZTLP_HMAC_SECRET_<UPCASE_ZONE>`, and
`ZtlpGateway.RelayRegistrar` emits V2 frames when
`ZTLP_GATEWAY_USE_V2_FRAMES=true` AND a per-zone secret is
configured for the service's derived zone. With the flag off (the
default), V1 emission is byte-identical to v0.29.5. With the flag
on but no per-zone secret for a given service, the registrar falls
back to V1 emission for that service with a loud WARN — so a
half-provisioned multi-service gateway doesn't go dark during a
partial Phase 3 rollout.

The zone derivation rule on the gateway side mirrors the relay's V1
derivation (`"gw-" <> rest` → `rest`, else service_name unchanged),
so V1 and V2 frames look up the same `ZTLP_HMAC_SECRET_<ZONE>`
slot for a given service.

---

## Test plan

1. **`hmac_secrets_test.exs`** — unit tests for `HmacSecrets`:
   - Empty env → `:not_configured` everywhere.
   - One-secret env → primary == that secret, verify against primary
     returns `{:ok, :primary}`.
   - Two-secret env → primary == first, both accepted on verify (`:primary`
     vs `:grace`).
   - Hex encoding round-trips correctly.
   - Base64 encoding round-trips correctly.
   - Zone-name slugification deterministic.
   - Mode parsing (dev/staging/prod + invalid → default + ERROR log).
   - Constant-time compare doesn't short-circuit on prefix mismatch.

2. **`udp_listener_v1_fallback_test.exs`** — integration tests using
   live `:gen_udp` sockets:
   - Mode=dev, no secret → accept unverified (existing behavior).
   - Mode=staging, no secret → accept with WARN log captured.
   - Mode=prod, no secret → reject + ERROR log.
   - Mode=prod, legacy secret set → accept on legacy match.
   - Mode=prod, per-zone secret set + matching service → accept.
   - Mode=prod, per-zone secret set + WRONG service (cross-tenant
     hijack attempt) → reject.

3. **`dynamic_registration_test.exs` (existing)** — verify all existing
   tests still pass under the new code path (no semantic change to V1
   with legacy secret).

---

## Operational checklist

When this lands in v0.29.6:

- [ ] Add `ZTLP_RELAY_HMAC_MODE=staging` to the staging relay env.
- [ ] Generate per-zone secrets for each live tenant
      (`openssl rand -hex 32` × 11).
- [ ] Update each tenant gateway's env to use its zone's secret as
      `ZTLP_RELAY_REGISTRATION_SECRET` (legacy path).
- [ ] Watch logs for "accepted via legacy secret" — should drop to zero
      as gateways re-register with their zone-specific keys.
- [ ] After 24h with no legacy-path hits, flip
      `ZTLP_RELAY_HMAC_MODE=prod` and restart.
- [ ] Prod relay (`34.219.64.205`) follows the same procedure in a
      separate change window.

---

## References

- Prior session handoff (`~/hermes_session_handoff.md`) — Task #2 (this).
- `relay/lib/ztlp_relay/udp_listener.ex:357-507` — V1 handlers.
- `relay/lib/ztlp_relay/config.ex:351-363` — current single-secret
  config function (will delegate to `HmacSecrets` for backward compat).
- `gateway/lib/ztlp_gateway/relay_registrar.ex:147-170` — gateway-side
  V1 signing (Phase 1.5 will get the V2 variant).
