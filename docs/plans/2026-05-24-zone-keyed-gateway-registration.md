# Zone-Keyed Gateway Registration

**Status:** Design proposal — pre-implementation
**Author:** Steve + agent (Hermes), 2026-05-24
**Tracking:** Discovered during Hermes Sandbox onboarding E2E debug (this session)
**Related:**
- `relay/lib/ztlp_relay/gateway_forwarder.ex` (current registration handler)
- `proto/src/bin/ztlp-cli.rs:3257-3344` (current GATEWAY_REGISTER builder)
- `docs/per_zone_hmac_design.md` (existing per-zone HMAC design — superseded by this for gateway-register specifically)
- `docs/plans/2026-05-24-z2ls-via-gateway-admin-auth.md` (Plan C / Z2LS gateway-admin auth)

---

## Problem

The relay's gateway routing table is keyed by an **unauthenticated, org-name-derived string** that doesn't include the zone. Two concrete failures we hit today:

1. **Cross-tenant slug collision.** The Launch app slugifies `organization_name` and truncates to 11 chars: `gw-{slug[:11]}`. Today's relay registration log shows:

   ```
   8C388C96…  service=gw-tech-rockst  ← "Tech Rockstars"      (zone: techrockstars.ztlp)
   EDFF66E5…  service=gw-tech-rockst  ← "Tech Rockstars Test" (zone: test.ztlp)
   ```

   Two separate tenants, same slug, same routing key. The relay accepts both registrations without complaint (the dedup key is `node_id + service_name`, not `service_name` alone). Whichever gateway's last-write wins for a given lookup, *or* the relay's existing load-balancing logic spreads client traffic across both — sending Tenant A's clients into Tenant B's gateway.

2. **No proof of right to claim the slug.** The current GATEWAY_REGISTER packet carries:

   ```
   magic | type=0x0A | node_id(16) | service_name(16, zero-padded) | ttl(4) | timestamp(8) | hmac(32, zeroed in dev)
   ```

   The `hmac` field is "zeroed in dev mode" — and in production today as well, because no shared registration secret is configured on the SaaS relay. **Any node with a ZTLP CLI can send a REGISTER packet claiming any `service_name`** and the relay will route traffic to it. There is no binding between the registering node and the zone it claims to serve.

This violates the deny-by-default + Ed25519 + per-zone HMAC + tenant-isolation expectation that the rest of the protocol enforces. NS records are zone-namespaced. Bootstrap HMACs are zone-namespaced. Gateway routing is the **only layer** that isn't, and it's the one that decides where a client's actual data plane traffic goes.

### Why not just hash the org name

Hashing `gw-{blake2s(org_name)[:12]}` removes accidental collisions between legitimate tenants but **provides zero defense against active impersonation**. An attacker who can read the public org name (or guess it — a slug truncated at 11 chars has very low entropy regardless of hash) can compute the same hash and register from their own gateway. Hashing is cosmetic; it doesn't change the security boundary.

The security boundary needs to be a **cryptographic check** that the registering node is authorised to serve the named zone.

---

## Design

### 1. Make the routing key the zone, not the org name

The relay registration slug becomes:

```
service_name = "gw:" + zone        // e.g. "gw:test.ztlp", "gw:techrockstars.ztlp"
```

Two reasons:

- **Zones are already the tenant boundary** in NS records, HMAC namespaces, Bootstrap auth, and gateway-injected admin headers. The slug should match.
- **Zone uniqueness is enforced at provisioning time** by Launch — `onboarding_requests.zone` has a unique constraint. Two tenants can't legitimately share a zone, so the slug collision is structurally prevented at the source.

The `gw:` prefix is to leave routing-key namespace headroom for future relay-managed services (e.g. `relay:`, `vip:`).

**Wire format change:** `service_name` field grows from a 16-byte zero-padded fixed-width fragment to a length-prefixed variable-width UTF-8 string. CLIENT_ROUTE already uses this shape (`svc_len::8, service::N`); GATEWAY_REGISTER should too. See §3.

### 2. Cryptographically bind registration to the zone's NS KEY

The relay accepts a registration for `gw:<zone>` **only if** the registering node proves possession of the private key corresponding to the NS KEY record at `bootstrap.<zone>`.

Concretely: the gateway signs the REGISTER payload with the Ed25519 key from its `identity.json` (the same key that's already published as the `bootstrap.<zone>` KEY record at NS). The relay:

1. Reads the signed payload's `zone` field.
2. Queries NS for `bootstrap.<zone>` KEY record. (Single UDP round-trip, ~1ms on the same VPC.)
3. Verifies the signature against the public key in that KEY record.
4. Caches the (zone → pubkey) binding with the KEY record's TTL.

If verification fails: drop the packet silently, increment a `register_unauthorised` metric. Do **not** add to routing table, do not log the rejected node_id at INFO level (would help reconnaissance).

This is the same trust model NS itself uses for zone records. We're not introducing new key material or a new CA — we're reusing the keys that already exist and are already authoritative.

### 3. Proposed new GATEWAY_REGISTER wire format

```
magic:      0x5A37           (2 bytes, big-endian)
type:       0x0C             (1 byte — GATEWAY_REGISTER v2; 0x0A stays valid during migration)
version:    0x02             (1 byte — payload format version)
node_id:    16 bytes
zone_len:   1 byte           (length of zone, 1..=255)
zone:       zone_len bytes   (UTF-8, lowercase canonical zone name)
ttl:        4 bytes          (big-endian u32)
timestamp:  8 bytes          (big-endian i64 unix seconds)
sig:        64 bytes         (Ed25519 signature over [type..timestamp])
```

Total: 2 + 1 + 1 + 16 + 1 + N + 4 + 8 + 64 = `97 + N` bytes (N = `zone_len`).

The signed range covers `[type | version | node_id | zone_len | zone | ttl | timestamp]`. Timestamp + 60s replay window is enforced by the relay (already done for v1; carry forward).

The relay derives the routing slug internally as `gw:<zone>`, so the service name doesn't need to be on the wire — it's implicit from the zone. This also prevents a node from registering one zone's traffic under another zone's slug.

### 4. Backwards compatibility & migration

The current `0x0A` packet type stays valid during the transition:

- **Phase 1 (1 release):** Ship relay + gateway with v2 (`0x0C`) support. Relay accepts both `0x0A` (legacy, unverified) and `0x0C` (verified). Gateway sends both for safety. Log a deprecation warning on every `0x0A` accept with `service_name`, `address`, and `node_id`.
- **Phase 2 (next release):** Relay rejects `0x0A` unless `ZTLP_RELAY_LEGACY_REGISTER_ALLOW=1` is set. Default-deny. Operators with un-upgraded gateways get a noisy startup warning telling them to flip the flag while they migrate.
- **Phase 3 (release after that):** Remove `0x0A` parsing entirely. Code path deleted, env var ignored.

This is the same staged-migration pattern we used for the `X-ZTLP-Client-*` header namespace split. Each phase is one cargo release apart so operators have ~2 weeks per step.

### 5. CLI-side change

Two changes to `ztlp-cli.rs`:

1. **`build_gateway_register_packet`** grows a `zone: &str` and `signing_key: &ed25519::SigningKey` parameter. The body changes from "zero the HMAC" to "Ed25519-sign the signed_payload". The 16-byte zero-padded `service_name` field is dropped from the wire (we now send length-prefixed `zone` instead).

2. **`ztlp listen --gateway`** picks up the zone from `identity.json`'s `default_zone` field (already populated by `ztlp setup --token`) or from a new `--zone <ZONE>` flag for explicit override. Without a zone the binary refuses to start with "ztlp listen requires --zone or a default_zone in identity.json".

The gateway's `identity.json` already carries the Ed25519 signing key (`static_secret_key`). No new key material is generated.

### 6. Relay-side change

`relay/lib/ztlp_relay/udp_listener.ex` — add `0x0C` packet handler that:

1. Parses the new format.
2. Looks up `bootstrap.<zone>` KEY at NS (configured `ZTLP_NS_SERVER`, same as today for inter-relay queries).
3. Verifies Ed25519 signature using `:public_key.verify/4` against the pubkey from the KEY record.
4. On success: calls `GatewayForwarder.register_dynamic_gateway/4` with `service_name = "gw:" <> zone`.
5. On failure: drops, increments `:telemetry.execute([:ztlp_relay, :register, :unauthorised], ...)`.

`relay/lib/ztlp_relay/gateway_forwarder.ex` — add cross-check in `handle_cast({:register_dynamic, ...})`: when a registration arrives for an existing `service_name` from a **different `node_id`**, log at WARN level and reject the new entry (don't silently replace). This catches both honest mistakes (operator running two gateways with the same zone) and active impersonation attempts (signature check failed somewhere — defence in depth).

### 7. CLIENT_ROUTE follow-up (separate doc)

CLIENT_ROUTE has the same trust gap — anyone can send a CLIENT_ROUTE for any service slug. Today the worst case is "you can probe which slugs exist", not "you can intercept traffic" (the actual session establishment is end-to-end Noise XX between client and gateway; the relay is a transparent forwarder, not a TLS terminator). So CLIENT_ROUTE auth is **lower priority** than GATEWAY_REGISTER auth and is deferred to a follow-up.

If we do harden CLIENT_ROUTE later, it should follow the same pattern: client signs the routing payload with its identity.json key, relay verifies against an ACL.

---

## Risks and trade-offs

### Adds an NS round-trip per registration

Every `GATEWAY_REGISTER` now requires the relay to do a NS lookup for the zone's KEY record. On the SaaS deployment NS lives in the same VPC as the relay; round-trip is sub-millisecond. The KEY record gets cached at the relay for the full NS-published TTL (currently 300s). Re-registration happens every 30s per gateway, so cache hit rate is ~99% in steady state.

If NS is unreachable, the relay can't verify new registrations — but **existing registrations stay valid until their TTL expires** (60s for gateway entries). So a brief NS outage doesn't tear down active traffic; it only blocks new gateway onboarding. This matches the existing "NS down = no new tenants, existing tenants keep working" failure mode and is consistent with operator expectations.

### What if the zone is wrong but the signature is valid

A misconfigured gateway could publish to NS under one zone but try to register at the relay under another. The relay would NS-lookup the *claimed* zone and verify the signature against *that* zone's pubkey — which would fail (different key). So this fails closed and produces a clear "register_unauthorised: signature mismatch for zone X" log line. No way for a misconfig to silently route to the wrong tenant.

### Bootstrap and client identities are different keys

Today `bootstrap.<zone>` KEY in NS holds the **gateway's** static public key (the gateway sends its own KEY register at startup). The bootstrap Rails app has a separate identity. This is fine for our purposes — the GATEWAY_REGISTER signing key is the gateway's own key, which is already what's published. Bootstrap doesn't need to be involved in relay auth.

### Migration of currently-deployed tenants

The 18 existing tenants on the SaaS host all have valid `identity.json` files with Ed25519 keys, and they've already published `bootstrap.<zone>` KEY records to NS. **No data migration needed.** When they upgrade to the v2-aware binary, they start sending `0x0C` packets and the relay accepts them on the same registration cycle (30s). Zero downtime.

### What about ngrok / public-facing NS

NS is currently reachable via ngrok on the public ztlp.net domain. The relay only queries NS internally (private VPC IP), so the ngrok exposure doesn't introduce a new attack surface — an external attacker still can't inject a fake KEY response because NS itself is trust-anchored. The KEY record signature chain stays valid regardless of transport.

---

## Implementation plan (rough sizing)

| Step | Component | Estimate |
|---|---|---|
| 1 | New wire format constants + builder in `proto/src/bin/ztlp-cli.rs` | 2 hours |
| 2 | `ztlp listen --gateway` reads zone from identity.json, signs with Ed25519 key | 1 hour |
| 3 | Relay `0x0C` parser + NS KEY lookup + signature verify | 4 hours |
| 4 | GatewayForwarder same-slug-different-node rejection logic | 1 hour |
| 5 | KEY record caching layer at relay (TTL-based) | 2 hours |
| 6 | Telemetry: `register_accepted_v2` / `register_unauthorised` / `register_legacy` counters | 1 hour |
| 7 | Unit tests for builder + parser + signature verification | 3 hours |
| 8 | Integration test: gateway boots → registers v2 → relay routes client traffic | 2 hours |
| 9 | Migrate Launch's compose templates to bake `--zone` flag explicitly for clarity (optional — defaults work) | 1 hour |
| 10 | Docs: update `docs/CLI-REF.md`, `docs/DEPLOYMENT.md`, write migration note for operators | 2 hours |

**Total: ~19 hours of focused work, ~3 days at normal pace with reviews.**

This lands as `v0.31.0` (minor bump for wire-format addition; legacy path preserved).

---

## Alternatives considered

### Alternative A: Stay with org-name slugs but add an NS-anchored signature check

Same security properties as the proposed design, but slug stays display-friendly (`gw-tech-rockst` not `gw:test.ztlp`). Rejected because:

- The slug is no longer a security key, so why pretend it's human-meaningful? Zone is the actual identity.
- Org names can be edited in Launch (operator UX feature); zone can't (it's the tenant primary key). Slugs derived from a mutable field cause subtle drift.

### Alternative B: Add registration auth at the gateway-to-relay TLS layer (mTLS)

Instead of signing the REGISTER packet, run a TLS-terminated control channel from gateway to relay and use mTLS for auth. Rejected because:

- Adds a second connection type the relay has to manage (UDP data plane + TCP/TLS control plane).
- Requires a CA + cert distribution flow. We already have Ed25519 keys distributed via NS — using them is strictly less infrastructure.
- The REGISTER packet is already a self-contained signed message in the proposed design; we don't need TLS to carry it.

### Alternative C: Drop relay-side slug routing entirely; let gateways announce via NS only

Client looks up `bootstrap.<zone>` SVC at NS, gets the gateway's `{ip, port}`, connects directly. No relay-side registration table at all.

Rejected because the relay is critical for NAT traversal — gateways behind NAT can't expose a public IP, so clients can't connect directly. The relay's job is exactly to be the rendezvous point. Removing the routing table would break the NAT case.

---

## Open questions for Steve before implementation

1. **Do you want the legacy `0x0A` path to be deny-by-default in Phase 2 immediately, or kept under an opt-in flag for a longer overlap window?** I lean toward deny-by-default — we have full control of all 18 tenants on the SaaS host plus the Z2LS Windows boxes, so the migration is observable. An optional `ZTLP_RELAY_LEGACY_REGISTER_ALLOW=1` escape hatch covers stragglers without leaving a permanent footgun.

2. **Should the slug be `gw:<zone>` (colon-separated) or `gw-<zone-with-dots-replaced>`?** Colon is cleaner protocol-wise but breaks anything that assumes service names are URL-safe. Hyphen-flattened (`gw-test-ztlp`) is uglier but more compatible. I prefer colon; happy to flip if you have a downstream consumer in mind.

3. **CLIENT_ROUTE follow-up — same release or separate?** Same release means one big design landing; separate keeps the change surface area smaller per cargo bump. I'd ship gateway auth in v0.31.0 and CLIENT_ROUTE in v0.31.1 unless you want them together.

4. **Slug-conflict policy when two valid gateways register the same zone.** Today the relay does load-balancing across all registered entries for a service. In the new world, two gateways for the same zone is *probably* a misconfig (one per tenant), but it could also be intentional HA. Default: log WARN and accept (current behaviour). Make stricter (reject second) only if you want enforced single-gateway-per-zone.

---

## Out of scope

- **Enrollment-secret architecture rework** — different blast radius (`process_enroll` at NS, not relay registration). Tracked separately; this doc deliberately doesn't touch it.
- **Bootstrap admin-pubkey rotation** — handled by Plan C / gateway-admin-auth, already merged in PR #40.
- **Inter-relay registration** (multi-relay mesh) — uses a different code path (`inter_relay.ex`) that already has separate auth via `component_auth.ex`. Not affected.
