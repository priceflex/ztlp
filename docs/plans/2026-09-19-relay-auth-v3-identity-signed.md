# Relay Authorization V3 — Identity-Signed CLIENT_ROUTE / GATEWAY_REGISTER

Date: 2026-09-19 (Sat). Status: DESIGN / NOT STARTED. Written for a fresh
session to pick up cold; nothing below assumes chat context.
Author of intent: Steven Price. "I feel like having ZTLP have permission to
use the relay would be ideal and something we should work on in the future."

Companion: /home/trs/ZTLP-MAC-PLAN-2026-09-19.md §4a (the V2 shared-secret
stopgap the Mac client ships with until V3 lands).

────────────────────────────────────────────────────────────────────
## 0. THE PROBLEM IN ONE PARAGRAPH
────────────────────────────────────────────────────────────────────
Today a client may use a relay only if it knows the zone's RELAY SECRET
(64 hex, `ZTLP_RELAY_REGISTRATION_SECRET` or per-zone
`ZTLP_HMAC_SECRET_<ZONE>`). Every CLIENT_ROUTE and GATEWAY_REGISTER frame
carries HMAC-SHA256(secret, frame). That secret is a GROUP PASSWORD: it is
identical on the relay, the gateway, and every enrolled device, it is not
in the enrollment token, and it has to be copied by hand into
`agent.toml [tunnel] relay_secret` (or `ztlp setup --relay-secret`). The
relay therefore proves "this sender knows the zone password", NOT "this
sender is the enrolled node it claims to be" — the node_id in the frame is
unauthenticated, one leaked device compromises the whole zone, and there
is no per-device revocation at the relay. It also breaks the "paste one
token and go" user story on every platform (Windows Tauri never passes it;
see desktop/src-tauri/src/tunnel.rs:113).

V3 replaces the shared HMAC with a signature made by the node's OWN
Ed25519 identity key, verified against the key the NS recorded at
enrollment. Permission to use the relay becomes a property of being an
enrolled, non-revoked ZTLP identity in the zone. No secret to copy.

────────────────────────────────────────────────────────────────────
## 1. WHAT ALREADY EXISTS (verified from source 2026-09-19, don't re-discover)
────────────────────────────────────────────────────────────────────
E1. Every identity has an Ed25519 signing key.
    proto/src/identity.rs:109-220 — `signing_key_seed: Option<Vec<u8>>`,
    auto-backfilled on load for old identities (line ~156-167),
    `identity.signing_key()` / `.verifying_key()`. Already used by
    punch.rs:171,208 and by NS endpoint claims.

E2. NS stores the node's pubkey at enrollment and can look nodes up by it.
    ns/lib/ztlp_ns/enrollment.ex:285-385 — register_device/do_register write
    a KEY record {algorithm: "Ed25519", public_key: <hex>} signed by the NS
    signing key. ns/lib/ztlp_ns/store.ex:292-301 `lookup_by_pubkey/1` via an
    Mnesia pubkey index; returns `{:error, :revoked}` for revoked keys.
    (CHECK: whether the enrolled pubkey is the X25519 static key or the
    Ed25519 verifying key — enrollment.rs sends `identity.static_public_key`
    at ztlp-cli.rs:9102 for the Bootstrap callback; confirm what the NS
    ENROLL frame's 32-byte pubkey (enrollment.ex:26,79) actually is. If it
    is X25519, V3 needs the NS to ALSO record the Ed25519 verifying key at
    enrollment — a small additive change to the ENROLL frame/record.)

E3. NS already verifies node Ed25519 signatures with ownership binding.
    ns/lib/ztlp_ns/endpoint_auth.ex:89-109 `verify_and_bind(node_id,
    timestamp, sig, pubkey)`: check_timestamp -> check_signature over
    `node_id || timestamp` -> check_ownership(node_id, pubkey) (pins the
    first pubkey seen per node_id, ETS). ns/lib/ztlp_ns/registration_auth.ex
    :128 `verify_signature(canonical, signature, pubkey)`. This is the exact
    pattern V3 lifts into the relay.

E4. Relay frame layout today (relay/lib/ztlp_relay/udp_listener.ex).
    Wire magic 0x5A 0x37 then type:
      0x0A GATEWAY_REGISTER      [16 node_id][16 service][4 ttl][8 ts][32 hmac]
      0x0E GATEWAY_REGISTER_V2   [1 zone_len][zone][16 node_id][16 svc][4 ttl][8 ts][32 hmac]
      0x0D GATEWAY_REGISTER_ADDR
      0x0B CLIENT_ROUTE          (legacy, service_name routed)
      0x0F CLIENT_ROUTE_V2       [1 zone_len][zone][16 node_id][1 svc_len][svc][8 ts signed][32 hmac]
                                 signed_data = <<0x0F, zone_len, zone, node_id, svc_len, svc, ts>>
                                 (udp_listener.ex:1069-1092)
    Verification: `ZtlpRelay.HmacSecrets.verify_with_policy(zone_id,
    signed_data, hmac)` -> {:ok, :primary|:grace|:legacy|:unverified_dev|
    :unverified_staging} | error. Mode `ZTLP_RELAY_HMAC_MODE` prod (default,
    fail-closed) | staging | dev. Design doc: docs/per_zone_hmac_design.md.
    The V1->V2 migration (docs/plans/2026-05-24-zone-keyed-gateway-
    register-IMPL.md) is the template for how a new frame type is added
    with both accepted in parallel.

E5. Client send side: proto/src/agent/daemon.rs:47-63 `set_relay_secret`
    + `build_signed_client_route` (installed once from agent.toml; two
    CLIENT_ROUTE send sites). Gateway side:
    gateway/lib/ztlp_gateway/relay_registrar.ex:301-395 builds the HMAC.
    Secret decoding rules shared by all three: 64-hex | `base64:` | raw
    (proto/src/tunnel.rs:3181 decode_relay_secret).

E6. Relay and NS are separate services; the relay has NO NS client today.
    The demo stack runs them as sibling containers on one box
    (ztlp-ns-defcon, ztlp-relay1/2-defcon, ztlp-gateway-defcon).

────────────────────────────────────────────────────────────────────
## 2. DESIGN
────────────────────────────────────────────────────────────────────
### 2.1 Principle
Authorization = "sender holds the private key of an identity that the
zone's NS has enrolled and not revoked." Exactly what zero trust should
mean here. Shared secrets remain only for relay<->gateway infra if we
choose, and even that can move to V3 (gateway has an identity too).

### 2.2 New frames (parallel to V2; V2 keeps working during migration)
  0x10 CLIENT_ROUTE_V3
    [1 zone_len][zone][16 node_id][1 svc_len][svc][8 ts (signed i64, unix
    secs)][32 ed25519_pubkey][64 ed25519_sig]
    signed_data = <<0x10, zone_len, zone, node_id, svc_len, svc, ts>>
    sig = Ed25519(node signing key, signed_data)
  0x11 GATEWAY_REGISTER_V3
    [1 zone_len][zone][16 node_id][16 svc][4 ttl][8 ts][32 pubkey][64 sig]
    signed_data = <<0x11, zone_len, zone, node_id, svc, ttl, ts>>
  (CHECK 0x10/0x11 are unused in the RELAY magic namespace. They collide
  with mux.rs FRAME_ACK_V2 = 0x10 only in a different framing namespace
  — the relay demuxes on the 0x5A 0x37 magic first, so that is fine, but
  grep relay udp_listener.ex for every accepted type before choosing.)
  The pubkey is included so the relay can verify offline first and only
  then consult authorization; it is NOT trusted by itself (see 2.3).

### 2.3 How the relay decides the pubkey is authorized — two options
  OPTION 1 — NS LOOKUP (recommended first step)
    Relay asks the zone's NS: "is pubkey P enrolled for node_id N in zone
    Z, and not revoked?" Uses the existing `Store.lookup_by_pubkey/1`
    semantics over a new NS query frame (or reuses the NS lookup wire
    already used by clients). Positive answers cached in ETS with a short
    TTL (e.g. 5 min, matching @client_route_ttl_ms); negatives cached
    briefly (30 s) to blunt spray. Revocation = NS record revoked ->
    cache expiry -> relay rejects. Needs: relay config
    `ZTLP_RELAY_NS_ADDR_<ZONE>` (or a zone->ns map) and NS reachability
    from the relay. Simple, authoritative, no new key material.
  OPTION 2 — ENROLLMENT GRANT (offline verification, later)
    At enrollment NS returns a compact grant
    {zone, node_id, pubkey, not_before, not_after} signed by the NS zone
    signing key (the same key that signs records, enrollment.ex:322-341).
    Node attaches the grant to V3 frames; relay verifies the NS signature
    with the zone's public key (config `ZTLP_RELAY_NS_PUBKEY_<ZONE>`),
    then the node signature. No runtime NS dependency; relay stays up
    when NS is down. Costs: bigger frame (~150 B), grant renewal before
    not_after, revocation only via expiry or a CRL push. Do this second,
    after Option 1 proves the model.

### 2.4 Anti-replay and binding
  - Timestamp window: same as V2 guard_timestamp (reject if |now-ts| >
    window). Keep the existing constants.
  - Ownership pin: relay pins node_id -> pubkey on first verified V3 frame
    (ETS, like NS EndpointAuth); a different pubkey for the same node_id
    is `:pubkey_mismatch` (log + reject). Cleared when NS says revoked.
  - Sender-tuple binding: unchanged — the route installed is for the
    sending UDP tuple, as today.

### 2.5 Mode policy (extends HmacSecrets.verify_with_policy classes)
  Add classes `:identity` (V3 verified + authorized) and
  `:identity_unauthorized` (sig OK, NS says unknown/revoked -> reject in
  all modes). Config `ZTLP_RELAY_AUTH_MODE` = `hmac` (today) | `both`
  (accept V2 HMAC or V3 identity; migration) | `identity` (V3 only; V2
  frames rejected with a loud warning naming the sender). Default stays
  `hmac` until every client in a zone is on a V3-capable build.

### 2.6 Client / gateway behaviour
  - Agent (daemon.rs): when `[tunnel] auth = "identity"` (new key,
    default "hmac" for now) OR when no relay_secret is configured and the
    build supports V3, send CLIENT_ROUTE_V3 signed with
    `identity.signing_key()`. Optionally send V2 AND V3 during migration
    if a secret is present (mirrors gateway V1+V2 parallel emit).
  - `ztlp setup` stops warning about a missing relay secret when V3 is
    the configured mode. The enrollment token needs no new field. THIS is
    what makes "paste one token and go" true on Windows and Mac.
  - Gateway relay_registrar.ex: emit GATEWAY_REGISTER_V3 when configured
    with an identity key (gateway already has a node identity — CHECK
    where it lives in gateway config).

### 2.7 Migration
  1. Ship relay with `ZTLP_RELAY_AUTH_MODE=both` (accept V2 + V3).
  2. Ship clients/gateway that emit V3 (and V2 if a secret exists).
  3. Watch relay logs for V2-only senders (add a counter/metric
     `ztlp_relay_route_auth_total{class=...}`).
  4. Flip zone to `identity`; delete the relay secret from agent.toml on
     all devices (or just stop distributing it).
  Defcon demo zone is the first zone to flip (one relay pair, one
  gateway, a handful of test devices).

────────────────────────────────────────────────────────────────────
## 3. WORK BREAKDOWN (TDD, tests before code; commits split tests vs impl)
────────────────────────────────────────────────────────────────────
Order chosen so every step is independently verifiable and nothing
breaks V2 users until the final flip.

W1 Spec + wire fixtures
   - Write the byte-exact V3 layouts into proto/src/tunnel.rs docs and
     docs/per_zone_hmac_design.md (new section). Generate golden test
     vectors (Rust) checked into interop/ so Elixir tests use the same
     bytes (see skill ztlp-rust-elixir-interop; the interop suite is the
     parity gate).
W2 Rust client: build_signed_client_route_v3 in daemon.rs
   - Unit tests: layout, signature verifies with verifying_key, tamper ->
     fails, ts is i64 secs. Feature-gate emit behind `[tunnel] auth`.
W3 Relay: parse + verify V3 (udp_listener.ex handle_client_route_v3)
   - Tests: golden vectors verify; bad sig rejected; stale ts rejected;
     pubkey_mismatch on pin conflict; mode matrix (hmac/both/identity).
   - Authorization stub: config-listed pubkeys first (fast path for tests
     and air-gapped relays), then W4.
W4 Relay -> NS authorization lookup (Option 1) + cache
   - NS: query frame "is pubkey P valid for node N in zone Z" (resolve E2
     CHECK first: does the NS hold the Ed25519 key? if not, extend ENROLL
     to carry it and store it in the KEY record).
   - Relay: NS client, ETS cache pos/neg TTLs, metrics.
W5 Gateway GATEWAY_REGISTER_V3 emit + relay accept
W6 CLI/UX: `ztlp setup` no secret warning under identity mode; `ztlp
   agent status` shows relay auth class; docs (CLOUD-QUICKSTART.md
   section "Forgot the relay secret?" becomes "not needed on V3 zones").
W7 Defcon demo migration: relay both -> clients V3 -> relay identity.
   Live proof: mac-llm4-0919 and a Windows device route through the
   relay with NO relay_secret in agent.toml; gateway log "handshake ok";
   relay log class=identity; then remove ZTLP_RELAY_REGISTRATION_SECRET
   from the relay container and confirm V2-only senders are rejected.
W8 Option 2 grants (later, optional).

Estimate (honest, not a promise): W1-W3 ~1 focused day, W4 ~1 day (NS
frame + relay client), W5-W7 ~1 day incl. demo migration. Real work.

────────────────────────────────────────────────────────────────────
## 4. SECURITY NOTES / THINGS TO GET RIGHT
────────────────────────────────────────────────────────────────────
- Never trust the pubkey in the frame alone; it exists only so the relay
  can verify the signature before spending an NS lookup. Authorization
  comes from NS (or an NS-signed grant).
- Rate-limit unauthenticated V3 frames per sender tuple before signature
  verification (Ed25519 verify ~50-100 µs; a spray is a CPU DoS vector).
  The relay already has rate limiting for registrations — reuse.
- Cache negative NS answers briefly; do not let a burst of unknown keys
  turn into an NS query flood.
- Keep V2 secret handling byte-identical while `both`; the existing
  relay/gateway/proto tests are the non-regression guard (Steven: Mac /
  new work must not disturb Windows and Linux which already work).
- Log the sender + class on every reject in `identity` mode so the flip
  is diagnosable from `docker logs ztlp-relay1-defcon`.

────────────────────────────────────────────────────────────────────
## 5. OPEN QUESTIONS (resolve early; they shape W4)
────────────────────────────────────────────────────────────────────
Q1 Does NS hold the node's Ed25519 verifying key or only the X25519
   static key at enrollment? (E2 CHECK.) Decides whether ENROLL grows.
Q2 Relay->NS transport: reuse the NS UDP frame family, or an HTTP admin
   API (ns/lib/ztlp_ns/admin_api.ex exists)? UDP keeps the relay's
   footprint; HTTP is easier to test. Lean UDP for parity with the rest.
Q3 Multi-zone relays: one relay serves many zones today (per-zone HMAC
   design). V3 needs zone -> NS address map in relay config. Format?
Q4 Should the gateway move to V3 in the same release, or stay on HMAC
   for one more cycle? (Fewer moving parts to flip the demo = clients
   first, gateway second.)
Q5 Steven's call: is Option 2 (offline grants) needed at all, or is
   NS-lookup-with-cache good enough for TRS's deployment shape?

────────────────────────────────────────────────────────────────────
## 6. FIRST 5 MINUTES OF THE V3 SESSION
────────────────────────────────────────────────────────────────────
1. Read this file and docs/per_zone_hmac_design.md and
   docs/plans/2026-05-24-zone-keyed-gateway-register-IMPL.md (the V2
   template).
2. Answer Q1 by reading ns/lib/ztlp_ns/enrollment.ex:20-100 and
   proto/src/enrollment.rs (what 32 bytes go on the wire).
3. Branch from main: `relay-auth-v3-identity`. Do NOT branch from
   macos-simple-direct-connect.
4. W1 golden vectors first. Ask Steven before every commit/push.
5. Repo: /home/trs/ztlp (Linux, Rust + Elixir tests run here; see skill
   ztlp-elixir-ci-debug). Demo stack for W7: Lightsail 44.240.16.59
   (ssh -i /home/trs/.ssh/ztlp-defcon-demo.pem ubuntu@44.240.16.59),
   compose ~/ztlp/demo/defcon-cloud-compose.yml.
