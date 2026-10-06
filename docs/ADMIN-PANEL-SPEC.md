# ZTLP Admin Panel: build specification

Status: SPECIFICATION, nothing built. Written 2026-10-05 after a code-level
research pass over the NS, relay, gateway, CLI, enrollment and the existing
`bootstrap/` Rails app. Every claim about existing code cites a file and line in
this repo at commit `9a42ae5`. Build in a fresh session from this document alone.

Supersedes `docs/ADMIN-PANEL-PLAN.md` (the first sketch). Several things in
that sketch turned out to be wrong once the code was read; they are corrected
here and the differences are called out in §13.

---

## 1. What this is

One Docker Compose stack (Rails 7.1 + MariaDB) that becomes the management
server for a ZTLP fleet:

- Directory: users (AD-style profile), groups, devices, like Active Directory,
  with drill-in pages to edit each.
- Enrollment: mint `ztlp://enroll/...` strings that carry the person's identity
  (username, full name, first, last, email, extra attributes) and, for now, the
  relay secret, so a user pastes one string and is fully set up.
- Gateways: register application gateways, see them, and hand each one its
  policy.
- Policy: central group/role rules that gateways enforce (groups live in the
  NS; gateways already evaluate `group:`/`role:` rules by asking the NS).
- First-admin claim: start the container, claim it with your own ZTLP key plus a
  one-time code from the container log, become the first administrator, no
  password.
- Fleet (later phases): device check-in, policy pull to agents.

Why Rails: `has_secure_password`, CSRF, strong params, Active Record
Encryption, Hotwire, a mature test harness, and we have a working Rails Docker
pattern in this repo and in other TRS apps.

Why MariaDB: requested; multi-process safe (Puma workers + a background job
runner share one DB), and matches the rest of the TRS fleet.

---

## 2. Facts about the existing system that drive the design

Each row is verified in code. "⇒" is the design consequence.

| # | Fact | Where | ⇒ |
|---|---|---|---|
| F1 | NS has USER (0x11), DEVICE (0x10), GROUP (0x12) records. USER data = `public_key, devices[], email, role(user|tech|admin)`. Extra keys are stored as-is. | `ns/lib/ztlp_ns/record.ex:396-514` | Full name, first/last, department etc. live in the panel DB, not the NS. Role stays in the NS. |
| F2 | Writes to an auth-ON NS must be **signed v2 registration (opcode 0x09)**: `<<0x09, name_len::16, name, type::8, data_len::16, cbor, sig_len::16, sig(64), pk_len::16, pubkey(32)>>`, `sig = Ed25519(<<type::8, name_len::16, name, cbor>>)`. CBOR keys sorted by `(byte_size, bytes)`. | `ns/lib/ztlp_ns/server.ex:390-412`, `registration_auth.ex:154-159`, `cbor.ex:44-54` | The panel implements this packet itself in Ruby (about 40 lines). |
| F3 | **GROUP records can only be written by a zone authority.** USER/DEVICE can also be self-written by the key in `data.public_key`. | `registration_auth.ex:333-385` | The panel must hold a zone-authority Ed25519 seed. |
| F4 | Zone authority = KEY record at a parent zone name with `data.delegation == true` whose `public_key` equals the signer. Parent chain is computed by splitting on the **first dot**, so `steve@trs.ztlp` has parent chain `["ztlp"]` only; `trs.ztlp` is NOT its parent. The NS test suite confirms this. | `registration_auth.ex:248-266`, `zone.ex:61-66`, `ns/test/ztlp_ns/group_test.exs:650,687,742` | **User and group names must be dotted, not `@` form**: `steve.users.trs.ztlp`, `admins.groups.trs.ztlp`. Then a `trs.ztlp` authority covers them. (Live prod uses `admin@trs.ztlp`; that record was self-registered, which is why it worked. The panel will not use `@` names.) |
| F5 | NS ignores client TTL. USER/DEVICE/GROUP/KEY default TTL = 86 400 s, so **identity records expire after 24 h** unless re-registered. Zone-authority writes bypass the per-`{name,type}` 60 s rate limit. | `record_defaults.ex:24-33`, `server.ex:604-606`, `registration_auth.ex:68-75` | The panel runs a re-publish job every 6 h for every record it owns. Live proof: `aicomputer.trs.ztlp` KEY, enrolled 10-04, was already gone on 10-05. |
| F6 | Listing records exists only over HTTP: `GET /admin/records?type=&zone=` on the NS metrics port (9103) with HMAC-SHA256 headers `x-ns-timestamp`, `x-ns-signature` over `"GET\n<path?query>\n<ts>\n<sha256hex(body)>"`, secret `ZTLP_NS_ADMIN_API_SECRET`. 12 req/60 s per IP by default. The UDP list opcode 0x13 was removed in v0.35.1. | `ns/lib/ztlp_ns/admin_api.ex`, `metrics_server.ex:269-271`, `config.ex:375-403` | The panel DB is the source of truth; `/admin/records` is used only for reconciliation. The TRS prod NS has no `ZTLP_NS_ADMIN_API_SECRET` set today (checked 10-05); setting one is a deploy step. |
| F7 | **The Rust CLI identity commands do not work against an auth-ON NS.** `create-user`, `link-device`, `create-group`, `group add/remove`, `revoke` send unsigned v1 packets (`0xFF 0x02 missing_pubkey`); `devices`, `ls`, `groups`, `audit` use the removed 0x13 opcode. Only `ztlp ns register` / `ztlp listen` heartbeat (`ns_publish_self`) sign correctly. | `proto/src/bin/ztlp-cli.rs:7023-7040, 10328-11461`; §3 of `/tmp/research-ns-identity.md` | Do not shell out to the CLI for identity writes. The panel speaks UDP to the NS directly. |
| F8 | Enrollment token = v1 binary `[ver=1][flags][zone][ns][relay_count][relays][gw if 0x01][callback if 0x02][max_uses::16][expires::64][nonce 16][mac 32]`, MAC = HMAC-BLAKE2s-256 over everything before the MAC, key = the 32-byte zone **enrollment secret** (`ZTLP_ENROLLMENT_SECRET` on the NS, `zone.key` on the CLI). Unknown flag bits are silently ignored by both the Rust and the Elixir parser. | `proto/src/enrollment.rs:37-79, 451-499`, `ns/lib/ztlp_ns/enrollment.ex:241-269` | New fields go in as new flag bits **between callback and max_uses**, in BOTH parsers, plus an unknown-flags check in both. |
| F9 | Enrollment (opcode 0x07) creates only a **KEY** record (plus SVC if an address is given). It never creates a DEVICE or USER record and never records an owner. `ztlp setup --owner` and `--type` are parsed but unused. | `enrollment.ex:336-408`, `ztlp-cli.rs:8908-8912` | The panel creates the DEVICE record (with owner) when the enrollment callback arrives. |
| F10 | The callback is `POST <callback_url>` form body `token_id=&node_id=&name=&pubkey_hex=`, via curl, **no auth, no signature**, and it only fires when the token came from the query-param URI form (binary tokens have no `token_id`). The query-param form sets `max_uses = 1` and, when signed, has a known Launch/Rust MAC mismatch if `callback` is present. | `ztlp-cli.rs:9429-9605`, `enrollment.rs:290-385` | The panel's new token flag carries `token_id` inside the signed binary, so binary tokens fire the callback too. The callback is authenticated by having the device sign the body with its new Ed25519 key (see §7.4). |
| F11 | The relay secret on the client is `agent.toml [tunnel] relay_secret` (inline) or `relay_secret_file` (path). `ztlp setup --relay-secret` writes it inline. There is no `relay.secret` file in the code. `setup` never modifies an existing `agent.toml`. | `proto/src/agent/config.rs:250-280`, `ztlp-cli.rs:9950-10023` | Token-carried secret is written as `relay_secret_file = "<ztlp_dir>/relay.secret"` (0600). |
| F12 | The relay secret is a per-zone group password: `ZTLP_HMAC_SECRET_<ZONE_SLUG>` on the relay (slug = upcase, non-alnum → `_`), same value on every gateway and device. Relay v3 (identity-signed, per-device) is designed but not started. | `relay/lib/ztlp_relay/hmac_secrets.ex`, `docs/plans/2026-09-19-relay-auth-v3-identity-signed.md` | Carrying it in the token is an interim measure with guardrails (§7.3). |
| F13 | **Both gateways already do central-ish policy.** Rules are per service, `allow = ["name", "*.suffix", "group:<group name>", "role:<role>", "*"]`. `group:` and `role:` are resolved **at decision time by querying the NS** (GROUP 0x12 / USER 0x11, via DEVICE 0x10 → owner). Rust: `~/.ztlp/policy.toml` (`--policy`). Elixir: `:policies` config / `ZTLP_GATEWAY_POLICIES` env / YAML. | `proto/src/policy.rs:1-35`, `ztlp-cli.rs:5125-5135`, `gateway/lib/ztlp_gateway/policy_engine.ex:8-40`, `ns_client.ex:150,321,368` | Phase 1 central policy = the panel manages GROUP membership in the NS and emits each gateway's static policy file with `group:` rules. No new gateway code needed for that. |
| F14 | Neither gateway hot-reloads policy today: the Elixir `ConfigWatcher` exists but is not in the supervision tree; the Rust gateway loads `policy.toml` once at start. | `gateway/lib/ztlp_gateway/application.ex` (no ConfigWatcher child), `ztlp-cli.rs:5237` | Policy changes that add/remove a *rule* need a gateway restart; changes to *who is in a group* take effect immediately via the NS. Design groups so that rules rarely change. Hot-reload is a later gateway change (§11). |
| F15 | The agent has a loopback IPC (`127.100.255.1:4433`, JSON lines: status, tunnels, dns_cache, flush_dns, shutdown, setup_status, enroll) and no outbound control channel, poll, or heartbeat. The `renewal` module (config hot-reload) is not wired in. | `proto/src/agent/control.rs`, `daemon.rs` | Device check-in and policy pull are new agent work (Phase 3). |
| F16 | Agent boot config (`agent.toml`): `[identity] path`, `[dns] enabled, listen, zones`, `[ns] servers`, `[tunnel] relays, relay_secret, relay_secret_file, prefer_relay`, `[renewal]`, `[log]`, `[tls] enabled, cert_dir, auto_issue`, `[gateway]` pins, `[ipc] listen`. | `proto/src/agent/config.rs:16-60` | These are the remotely-settable knobs for Phase 3. |
| F17 | Existing `bootstrap/` Rails app: good `AdminUser` (lockout, roles), `AuditLog`, `EnrollmentToken` lifecycle, QR via `rqrcode`, identity tab views, HMAC API auth, AR Encryption pattern. But: SQLite, password login, token minting is **unsigned** (legacy URI, no MAC, no Ruby BLAKE2s anywhere), `ZtlpAdmin` shells over SSH to CLI verbs that do not exist (`admin user create`), Tailwind via CDN, `COPY bin/ztlp` from an untracked file. | `/tmp/research-rails-docker.md` Part A | New app `admin/`. Copy the models/views listed in §12; do not reuse the NS/token layers. |
| F18 | Ruby 3.2 + OpenSSL 3.0.13 on this host provides `OpenSSL::Digest.new("BLAKE2s256")` and `OpenSSL::PKey.generate_key("ED25519")`. | checked 10-05 | HMAC-BLAKE2s (manual ipad/opad) and Ed25519 signing need no extra gem. |
| F19 | The `ztlp` CLI image is `stevenprice/ztlp-proto:<tag>` (`/usr/local/bin/ztlp`, no entrypoint, Debian bookworm). CI does not build it; it is pushed by hand. Release images are `stevenprice/ztlp-{ns,relay,gateway,dashboard}:<git tag>` from `release.yml`; versions are gated by `scripts/verify-image-version.sh` + `image-version-gate.yml` (hard-coded to the three Elixir components). | `proto/Dockerfile`, `.github/workflows/release.yml`, `scripts/verify-image-version.sh` | §10 adds `admin` to both. The panel only needs the CLI for `ztlp admin enroll`-free paths, so the binary is optional (used for diagnostics). |

---

## 3. Architecture

```
                         +----------------------------------------------+
  browser (admin)  --->  |  ztlp-admin (Rails 7.1, Puma)                 |
  ztlp admin claim/login |   - web UI (Hotwire, Tailwind built-in)       |
                         |   - /api/v1 (device callback, check-in)       |
                         |   - jobs: republish (6h), reconcile, gc       |
                         |   - NsClient (UDP 0x09 signed writes, 0x01    |
                         |     reads; HTTP /admin/records for lists)     |
                         |   - TokenMinter (binary token + MAC, Ruby)    |
                         +------------------+---------------------------+
                                            |                 |
                              MariaDB 11.x  |                 | UDP 23096 / HTTP 9103
                              (one DB)      v                 v
                         +--------------+        +-----------------------+
                         | admin_db     |        | ZTLP NS (Elixir)      |
                         | users,groups,|        | KEY/USER/DEVICE/GROUP |
                         | devices,     |        | records, 24h TTL      |
                         | enrollments, |        +-----------------------+
                         | gateways,    |
                         | policies,    |        relay <- HMAC_SECRET_<ZONE>
                         | admins,audit |        gateways <- policy file (§8)
                         +--------------+        agents <- token (§7)
```

Source of truth split:
- **Panel DB**: the directory (profile fields, status, who created what),
  enrollments, gateways, policies, admins, audit. Durable.
- **NS**: the signed authorization facts the rest of ZTLP reads at runtime:
  USER (role, pubkey), DEVICE (owner), GROUP (members), KEY, SVC. The panel
  re-derives every NS record from its DB and re-publishes on a schedule (F5),
  so an NS wipe is recoverable from the panel alone.

Secrets held by the panel (all AR-encrypted at rest, §9):
- Zone authority Ed25519 seed (signs NS writes; F3).
- Zone enrollment secret (32 bytes; MACs tokens; must equal the NS
  `ZTLP_ENROLLMENT_SECRET`; F8).
- Relay secret for the zone (goes into tokens; F12).
- NS admin API HMAC secret (F6).
- Per-gateway relay HMAC env value (same as relay secret for that zone).

---

## 4. First-run and administrator login

### 4.1 Claim (first boot only)

1. `docker compose up -d`. The entrypoint runs `db:prepare`, then boots.
2. If `admins` is empty, the app generates `claim_code` (32 random bytes,
   base32, grouped) and stores `sha256(claim_code)` + `expires_at = now + 24h`
   in `system_settings`. It prints to the container log:
   `ZTLP ADMIN: no administrator yet. Claim code: XXXX-XXXX-... (valid 24h)`.
3. Every page except `/claim`, `/up`, `/api/v1/*` redirects to `/claim`.
4. The operator creates their identity on their own machine with the existing
   `ztlp keygen` (identity.json holds the Ed25519 seed; `proto/src/identity.rs:109-122`)
   and runs the new CLI command:
   `ztlp admin claim https://admin.example --code XXXX-... --username steve --full-name "Steven Price" --email steve@…`
   It POSTs `{claim_code, username, full_name, first_name, last_name, email,
   pubkey_hex, timestamp, signature}` where `signature = Ed25519(sha256(canonical body))`.
   The same form is available in the browser for paste-in (pubkey + code +
   profile), signature optional in that case because the code alone already
   proves log access; the CLI path is preferred and is what the docs show.
5. Server: constant-time compare of `sha256(code)`, not expired, no admin
   exists (DB transaction + unique index on `admins.role='super_admin'` guard).
   Then: create the admin (super_admin), create the matching directory user,
   write its USER record to the NS (role `admin`), delete the claim code,
   write audit `system.claimed`. The claim window is closed permanently.
6. Lost-admin recovery: `bin/rails admin:reset_claim` inside the container
   generates a new claim code. It is a container-local command, never a web
   route.

Why a claim code: with "paste a public key" alone, whoever reaches the port
first owns the system. The code proves the operator can read the container's
log, like Vault/Gitea init.

### 4.2 Login (every time, no passwords)

Challenge-response with the admin's Ed25519 key:

1. `ztlp admin login https://admin.example` → `POST /auth/challenge {pubkey_hex}` →
   `{nonce, expires_in: 120}` (nonce stored in `login_challenges`, single use).
2. CLI signs `"ztlp-admin-login\n<host>\n<nonce>"`, `POST /auth/verify
   {pubkey_hex, nonce, signature}` → `{login_url: "https://admin.example/auth/session/<one-time-token>"}`.
3. CLI opens the browser at `login_url`; the server exchanges the one-time
   token (60 s, single use) for a session cookie and redirects to `/`.
4. Browser never touches the key. Session: cookie store, `same_site: :lax`,
   `secure: true`, 8 h idle timeout, absolute 24 h.

Browser-only fallback for admins without the CLI handy: same flow with the
signature computed client-side is NOT offered (would need the key in the
browser). Instead an admin may **enable a passkey (WebAuthn)** after first
login; this is Phase 2 (§11) using the `webauthn-ruby` gem. Until then login
requires the CLI.

Roles (`admins.role`): `super_admin` (manage admins, settings, secrets),
`admin` (everything else), `helpdesk` (enrollments, device reset, read
directory), `read_only`. Every mutating controller action has
`before_action :require_write_access` (blocks `read_only`), and settings /
admins require `super_admin`. Pattern from `bootstrap` `PoliciesController`.

---

## 5. Data model (MariaDB)

Conventions: `utf8mb4` / `utf8mb4_unicode_ci` (NOT `utf8mb4_0900_ai_ci`,
MySQL-8 only; MariaDB rejects it). Explicit short index names (64-char limit).
`bigint` PKs. Timestamps everywhere. All secret columns use
`encrypts` (AR Encryption, non-deterministic unless lookups need it).

```
zones            id, name (unique, e.g. trs.ztlp), ns_addr (host:port), ns_admin_base_url,
                 relay_addrs (json), gateway_addr,
                 authority_seed_ct (encrypts; 32B Ed25519 seed), authority_pubkey_hex,
                 enrollment_secret_ct (encrypts; 32B), relay_secret_ct (encrypts),
                 ns_admin_api_secret_ct (encrypts), last_reconciled_at
                 -- Phase 1 supports exactly one zone row; schema allows more.

admins           id, username (unique), display_name, email, role, pubkey_hex (unique),
                 user_id (fk users, nullable), last_login_at, last_login_ip, disabled_at

login_challenges id, admin_id, nonce (unique), expires_at, used_at
session_tokens   id, admin_id, token_digest (unique), expires_at, used_at

users            id, zone_id, username (unique per zone; label-safe, lowercase),
                 ns_name (unique; "<username>.users.<zone>"),
                 full_name, first_name, last_name, email, title, department, phone,
                 role (user|tech|admin; mirrors NS), status (invited|active|suspended|revoked),
                 pubkey_hex (nullable until first device enrolls or CLI create),
                 attributes (json: free-form extras), notes,
                 ns_published_at, revoked_at, revocation_reason, created_by_admin_id

groups           id, zone_id, name (unique per zone), ns_name ("<name>.groups.<zone>"),
                 description, ns_published_at
group_memberships id, group_id, user_id (unique pair), added_by_admin_id

devices          id, zone_id, name (device label), ns_name ("<name>.<zone>"),
                 user_id (owner, nullable), node_id_hex (unique), pubkey_hex (X25519 Noise static),
                 signing_pubkey_hex (Ed25519, nullable), hardware_id, platform, agent_version,
                 status (pending|enrolled|revoked|orphaned), enrolled_at, last_seen_at,
                 enrollment_id (fk), ns_published_at, revoked_at, revocation_reason

enrollments      id, zone_id, token_id (unique, 16B hex), kind (user_device|device_only),
                 user_id (nullable), device_name (nullable; null = hostname at setup),
                 embed_relay_secret (bool), identity_snapshot (json; what was put in the token),
                 max_uses, uses, expires_at, status (pending|redeemed|expired|revoked),
                 token_uri_ct (encrypts; shown once, kept for re-display by super_admin only),
                 redeemed_at, redeemed_device_id, created_by_admin_id, revoked_at, notes

gateways         id, zone_id, name (service label, e.g. www), ns_name ("<name>.<zone>" or
                 sub-zone), kind (rust_listen|elixir), host_note, backend (host:port),
                 node_id_hex, signing_pubkey_hex, status (planned|registered|online|stale),
                 last_svc_seen_at, addresses (json, from SVC), policy_rendered_at

policies         id, gateway_id, service (e.g. www), allow_rules (json array of strings:
                 "group:<ns group name>", "role:admin", "*.<zone>", "*"), position
                 -- rendered into the gateway's policy file (§8)

audit_logs       id, admin_id (nullable), action, target_type, target_id, status, details (json),
                 ip, created_at   -- index (action), (created_at), (target_type,target_id)

system_settings  key (pk), value_ct (encrypts), updated_at  -- claim_code_digest, etc.
```

Name rules (from `name_validator.ex`): labels `[a-z0-9@]([a-z0-9-@]*[a-z0-9@])?`,
≤63 chars each, total ≤253, lowercase. The panel validates `username`,
group `name` and device `name` as single labels and refuses `@`, `.` and
uppercase (normalise to lowercase on input, show the normalised value).

Why `<username>.users.<zone>` and `<group>.groups.<zone>`: F4. It also keeps
users and groups from colliding with device names.

---

## 6. NS client (Ruby, `app/services/ztlp/ns_client.rb`)

### 6.1 Canonical CBOR

Implement a minimal deterministic encoder (RFC 8949 §4.2.1): maps with text
keys sorted by `(byte_size, bytes)`, text strings (major 3), byte strings
(major 2), arrays, booleans, unsigned ints. That is all the NS record data
needs. ~60 lines. Golden-vector test it against a CBOR produced by the Elixir
encoder (`ns/lib/ztlp_ns/cbor.ex`), captured once with `mix run`.

### 6.2 Signed registration (write)

```ruby
def register(name:, type_byte:, data:, seed:)   # seed = 32B zone-authority seed
  cbor  = Cbor.encode(data)
  canon = [type_byte].pack("C") + [name.bytesize].pack("n") + name + cbor
  key   = OpenSSL::PKey.new_raw_private_key("ED25519", seed)
  sig   = key.sign(nil, canon)                      # 64 bytes
  pub   = key.raw_public_key                        # 32 bytes
  pkt   = "\x09".b + [name.bytesize].pack("n") + name + [type_byte].pack("C") +
          [cbor.bytesize].pack("n") + cbor + [sig.bytesize].pack("n") + sig +
          [pub.bytesize].pack("n") + pub
  reply = udp_roundtrip(pkt, timeout: 5)            # expect "\x06"
  raise NsError.decode(reply) if reply.getbyte(0) == 0xFF   # codes §2.6 of research
end
```

Error map (`registration_error.ex:63-74`): `0x00 unspecified, 0x01
unknown_type, 0x02 missing_pubkey, 0x03 invalid_name, 0x04 invalid_signature,
0x05 unauthorized, 0x06 key_overwrite, 0x07 revoked_pubkey, 0x08 revoked_name,
0x09 rate_limited, 0x0A invalid_data, 0x0B storage_error`. Note validator
failures such as missing `public_key` or bad `role` come back as `0x00`.

Serial = unix seconds on the NS side; two writes of the same `{name,type}` in
the same second collide (`stale_serial`, one NS-side retry). The republish job
spaces writes ≥1.1 s apart per name.

### 6.3 Records the panel writes

| Record | name | type | data |
|---|---|---|---|
| zone authority | `<zone>` | 0x01 KEY | `{algorithm:"Ed25519", node_id:"zone:<zone>", public_key:<authority hex>, delegation:true, role:"zone-authority"}`. Self-registration of a KEY whose `public_key == signer` is allowed (`registration_auth.ex:290-298`). Re-published every 6 h (TTL 24 h). If a KEY already exists at `<zone>` with a different key (prod `trs.ztlp` today: `28b688…`, the `admin@trs.ztlp` key), see §10.3 migration. |
| user | `<u>.users.<zone>` | 0x11 USER | `{public_key:<user Ed25519 hex or, until known, the authority hex>, email, role, devices:[ns names], display_name, username}` (extra keys are stored, F1; gateways ignore them) |
| group | `<g>.groups.<zone>` | 0x12 GROUP | `{members:[user ns names], description}` (≤255 members) |
| device | `<d>.<zone>` | 0x10 DEVICE | `{node_id, public_key, owner:<user ns name>, hardware_id}` |
| revoke | `revoke.<name>` | 0x05 REVOKE | `{revoked_ids:[name], reason, effective_at:"now"}` (TTL 0, never expires; purges device/group indexes) |

The KEY record for a device is created by the device itself at enrollment
(F9) and refreshed by the agent; the panel does not write device KEY records.

### 6.4 Reads

- Single record: UDP `0x01` query `<<0x01, name_len::16, name, type::8>>`
  padded to ~600 bytes (amplification cap), reply `0x02 + Record.encode`.
  Parser: canonical `type(1) name_len(2) name data_len(4) data created(8) ttl(4) serial(8)` then sig/pub.
- Lists: `GET /admin/records?type=user|device|group|key|svc&zone=<zone>` with
  HMAC headers (F6). Used by the reconcile job (§6.6) and the Gateways page
  (SVC records = live gateways and their `addresses`).

### 6.5 Republish job (every 6 h, and on demand)

For the zone: authority KEY, then every active user, group, device-with-owner.
Spaced ≥1.1 s per write. Records with `status=revoked` are not republished;
their REVOKE record is (idempotent). Marks `ns_published_at`. Failures go to
the audit log and the dashboard "NS sync" tile.

### 6.6 Reconcile job (every 30 min)

Pull `/admin/records` for user/device/group/svc. Report drift (in NS but not in
DB, in DB but missing from NS) on the dashboard; never auto-delete panel rows.
New SVC names not in `gateways` appear as "unregistered gateway" suggestions.

---

## 7. Enrollment strings with identity

### 7.1 Token format change (Rust + Elixir, same PR)

Add two flag bits, both MAC-covered, inserted after `callback_url` and before
`max_uses` (F8):

```
FLAG_HAS_IDENTITY     = 0x04
FLAG_HAS_RELAY_SECRET = 0x08

identity (if 0x04):
  u16 len + token_id (16 raw bytes)        -- so the callback fires for binary tokens (F10)
  u16 len + username
  u16 len + full_name
  u16 len + first_name
  u16 len + last_name
  u16 len + email
  u16 len + owner_ns_name                  -- "<u>.users.<zone>"
  u8 extra_count, then (u16 len key, u16 len value) × count   -- free-form attributes
relay_secret (if 0x08):
  u16 len + secret bytes (32)
```

Both parsers add: `if flags & !KNOWN_FLAGS != 0 → Malformed("unknown flags")`.
Today unknown bits are ignored, which would make an old client misparse the
rest of the token; failing closed with "update your ZTLP client" is the
correct behaviour for an old client receiving a new token.

Tests (pattern: `proto/src/enrollment.rs` tests 768-1357 and
`ns/test/ztlp_ns/enrollment_test.exs::create_token`):
round-trip with/without each flag; flipping any byte inside identity or secret
→ `InvalidMac`; flags=0x00 bytes identical to today; a golden vector shared by
Rust, Elixir and Ruby; unknown flag → Malformed; NS `process_enroll` accepts a
0x0C token and still creates the KEY record.

### 7.2 Client behaviour (`ztlp setup --token`, `setup_join`)

After the existing steps (identity, ENROLL 0x07, `config.toml`, `agent.toml`):

- If identity present: write `<ztlp_dir>/profile.json` (0600) with the
  identity fields and `owner_ns_name`; log "enrolled as <full_name>
  (<username>)". Device name default stays hostname unless `--name`.
- If relay secret present: write `<ztlp_dir>/relay.secret` (0600) and set
  `[tunnel] relay_secret_file` in the generated `agent.toml`. If `agent.toml`
  already exists (setup never rewrites it, F11) print the exact line to add.
- Callback (§7.4) fires when `token_id` is present (from either URI form).

### 7.3 Relay secret in the token: interim, with guardrails

F12 makes this a group password. Rules enforced by the panel:
- Only `kind=user_device` or `device_only` tokens with `max_uses = 1`.
- Default expiry 1 h, maximum 24 h, when `embed_relay_secret` is on.
- The token string is shown once on the result page and in the QR; stored
  encrypted; re-display requires `super_admin` and is audited.
- Never written to logs or the audit `details` (filter params `token`,
  `secret`, `relay_secret`).
- Dashboard banner "Relay access uses a shared zone secret (relay v3 not
  deployed)" until a setting flips it off.
- Rotation runbook in the UI: new relay secret on the relay as the first
  `ZTLP_HMAC_SECRET_<ZONE>` entry, old one as grace; re-enroll or push to
  devices; remove grace.

### 7.4 Callback and device creation

New authenticated callback, replacing the unauthenticated form POST (F10):

`POST /api/v1/enrollments/<token_id>/redeem`
```json
{"node_id":"<hex16>","name":"<device ns name>","noise_pubkey_hex":"<32B hex>",
 "signing_pubkey_hex":"<Ed25519 32B hex>","platform":"windows","agent_version":"0.35.16",
 "timestamp":<unix>,"signature":"<Ed25519 over sha256 of the canonical JSON without signature>"}
```
Server: token exists, `status=pending`, not expired, `uses < max_uses`;
timestamp within ±300 s; signature verifies with `signing_pubkey_hex`; then in
one transaction: `uses += 1`, status → `redeemed` if exhausted, create/upsert
`devices` row (owner = enrollment.user, `enrolled`), user `invited → active`,
set `users.pubkey_hex = signing_pubkey_hex` if null, audit. Then publish the
DEVICE record (owner) and the updated USER record (devices list) to the NS.
Reply `{"status":"redeemed","device":"<ns name>","owner":"<user ns name>"}`.
Rate limit 10/min per IP (rack-attack). Old clients still hit the legacy
`callback_url` shape; the panel also accepts `POST /api/enrollment/confirm`
(form body, unauthenticated) but only marks the enrollment `redeemed_unverified`
and creates the device as `pending` for an admin to approve.

### 7.5 UI

New enrollment → choose: existing user / new user (inline mini-form) / device
only; device name (optional); expiry; "embed relay secret" (default on, shows
the guardrail text). Result page: the `ztlp://enroll/...` string, QR (rqrcode
SVG, pattern from `bootstrap/app/services/token_generator.rb`), copyable
`ztlp setup --token "<string>"` line, Windows/Mac/Linux notes. List: pending /
redeemed / expired / revoked with filters; revoke.

Expiry sweep job every 5 min (`status pending → expired`).

---

## 8. Gateways and policy

### 8.1 Registering a gateway (what the wizard automates)

Today a Rust gateway is: identity file + `ztlp listen --zone <zone>
--ns-register-name <name> --ns-server <ns> --relay <relay> --forward
<svc>=<host:port> --policy <file>` with `HMAC_SECRET_<ZONE_SLUG>` in env, in a
container from `stevenprice/ztlp-proto` (`docs/DIRECT-FIRST-DIAL-PLAN.md`,
template in `deploy/`). It publishes KEY + SVC (with `addresses`) itself,
signed with its own key (`ns_publish_self`), and that works on auth-ON because
a KEY whose `public_key == signer` self-registers and SVC follows the KEY
owner. So the gateway does **not** need the zone authority. Its name must be
inside the zone.

Wizard "Add gateway": name, backend `host:port`, kind (Rust recommended),
host notes → the panel generates and shows: a `docker-compose.yml` (pinned
image tag from settings), a `.env` with `HMAC_SECRET_<SLUG>` filled from the
zone's relay secret (shown once), the `policy.toml` (§8.2), and the exact
`ztlp keygen` line to create the gateway identity on that host. Status flips
to `online` when the reconcile job sees the SVC record; the SVC `addresses`
are shown. (The gateway cannot be created *from* the panel over the network
in Phase 1; that needs an agent on the host, Phase 3.)

### 8.2 Policy

Policy rows render to the gateway's native format (F13):

Rust `policy.toml`:
```toml
default = "deny"
[[services]]
name = "www"
allow = ["group:staff.groups.trs.ztlp", "role:admin"]
```
Elixir: YAML `policies:` list / `ZTLP_GATEWAY_POLICIES`.

Because `group:` and `role:` are resolved by the gateway asking the NS at
request time (`ztlp-cli.rs:5125-5135`, `policy_engine.ex`, `ns_client.ex:150`),
**adding or removing a user from a group in the panel takes effect on every
gateway immediately** (bounded by the gateway's identity cache TTL). Only rule
changes need a gateway restart (F14). The UI says so on the policy page and
shows "policy file changed since gateway start" when `policy_rendered_at >
last_svc_seen_at` of the first SVC after restart.

Policy test widget: pick a device, pick a gateway → the panel walks the same
chain (DEVICE owner → USER role → GROUP members) from its DB and shows
allow/deny and which rule matched. This mirrors the gateway logic so admins
can predict access before a restart.

Default groups created at claim: `admins.groups.<zone>` (the first admin is a
member), `staff.groups.<zone>`.

---

## 9. Security

- Secrets at rest: AR Encryption with `ACTIVE_RECORD_ENCRYPTION_*` keys from
  env (pattern `bootstrap/config/environments/production.rb`), generated by
  the entrypoint on first boot and **persisted to the data volume**
  (`/data/keys.env`, 0600) so a container recreate does not lose them;
  warn loudly if they came from the volume rather than env.
- Zone authority seed: encrypted column; export only via
  `bin/rails zone:export_authority` (prints a 32B seed, audited) for the
  backup runbook in the UI. Backups of the panel without the AR keys are useless
  by design.
- Login: Ed25519 challenge-response (§4.2); passkeys Phase 2; no passwords
  anywhere. rack-attack on `/auth/*`, `/claim`, `/api/v1/*`.
- CSRF on; `config.force_ssl` and `assume_ssl` both tied to `FORCE_SSL` env
  (pitfall: `assume_ssl=true` over plain http → every POST 422; same class as
  the ZTLP agent 422 fixed in v0.35.15).
- Content-Security-Policy strict; Tailwind compiled into the image
  (`tailwindcss-rails`), not the CDN.
- `filter_parameters += [:token, :secret, :relay_secret, :seed, :signature, :code]`.
- Audit everything mutating with admin id and IP; audit viewer in UI.
- Host authorization: `ADMIN_ALLOWED_HOSTS` env.
- The panel itself can be published as `admin.<zone>` behind a ZTLP gateway
  later; Phase 1 assumes it is on a trusted network or behind an existing
  reverse proxy with TLS.

---

## 10. Repo layout, Docker, CI, release

### 10.1 Layout

```
admin/
  Dockerfile              multi-stage: ruby:3.2.7-slim (bookworm); build stage installs
                          build-essential libmariadb-dev pkg-config; precompile assets with
                          SECRET_KEY_BASE_DUMMY=1; runtime installs libmariadb3 curl;
                          optional: COPY --from=stevenprice/ztlp-proto:<tag> /usr/local/bin/ztlp
  docker-compose.yml      services: db (mariadb:11.4.<x> pinned), web (ztlp-admin), jobs
  bin/docker-entrypoint   keys bootstrap, wait-for-db, db:prepare, exec
  VERSION                 single line, e.g. 0.35.16; read by config/version.rb
  Gemfile                 rails 7.1.x, mysql2, puma, propshaft or sprockets, importmap,
                          turbo-rails, stimulus-rails, tailwindcss-rails, rqrcode,
                          solid_queue (jobs, uses the same MariaDB), rack-attack,
                          minitest, mocha
  app/services/ztlp/{cbor.rb, ns_client.rb, token_minter.rb, blake2s_hmac.rb,
                     policy_renderer.rb, gateway_bundle.rb}
  app/jobs/{republish_ns_job, reconcile_ns_job, expire_enrollments_job}
```

### 10.2 Compose (production shape)

```yaml
services:
  db:
    image: mariadb:11.4.7            # pin exact; never :latest
    command: --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci
    environment: { MARIADB_DATABASE: ztlp_admin, MARIADB_USER: ztlp_admin,
                   MARIADB_PASSWORD: ${DB_PASSWORD}, MARIADB_ROOT_PASSWORD: ${DB_ROOT_PASSWORD} }
    volumes: [ "admin_db:/var/lib/mysql" ]
    healthcheck: { test: ["CMD","healthcheck.sh","--connect","--innodb_initialized"], interval: 10s }
  web:
    image: stevenprice/ztlp-admin:v0.35.16
    depends_on: { db: { condition: service_healthy } }
    environment:
      DATABASE_URL: mysql2://ztlp_admin:${DB_PASSWORD}@db/ztlp_admin
      RAILS_ENV: production
      FORCE_SSL: "false"               # true when behind TLS
      ADMIN_ALLOWED_HOSTS: admin.example
      ZTLP_ZONE: trs.ztlp
      ZTLP_NS_ADDR: ns.example:23096
      ZTLP_NS_ADMIN_BASE_URL: http://ns.example:9103
    ports: [ "3000:3000" ]
    volumes: [ "admin_data:/data" ]    # AR keys, exported bundles
  jobs:
    image: stevenprice/ztlp-admin:v0.35.16
    command: ["bin/jobs"]              # solid_queue worker
    depends_on: [ web ]
    environment: *same as web*
volumes: { admin_db: {}, admin_data: {} }
```

Entrypoint pitfalls already known from other TRS Rails containers (apply all):
wait for the DB socket before `db:prepare`; `db:prepare` must work from an empty
volume (idempotent migrations); never `chown -R` the whole tree; Puma binds
`0.0.0.0`; `docker compose restart` does not reload `.env` (stop + up).

### 10.3 Deploy order on the TRS zone (`trs.ztlp`, NS on defcon-ctf-1)

1. Set `ZTLP_NS_ADMIN_API_SECRET` on the NS (64 hex) and restart it (F6).
2. Set `ZTLP_ENROLLMENT_SECRET` on the NS if not already (it is; copy the same
   value into the panel's zone row).
3. Start the panel, claim it.
4. Zone authority: the live `trs.ztlp` KEY is the `admin@trs.ztlp` key
   (`28b688…`, TTL 1 year, written at bootstrap). Two options, decide at build:
   (a) import that seed into the panel as the authority (the panel then owns it;
   the old CLI identity is retired), or (b) have the old key sign a new
   delegation KEY for the panel's key at `trs.ztlp` (key overwrite is allowed
   for the zone authority, `registration_auth.ex:200-225`). (a) is simpler and
   recommended since that identity exists only on one operator machine.
5. Re-create the existing records as panel objects: user `steve.users.trs.ztlp`
   (keep `admin@trs.ztlp` published too until the AI computer is re-enrolled),
   device `aicomputer.trs.ztlp` (re-enroll it with a new token so it gets an
   owner), gateway `www.chooseforce.ztlp` (import from SVC).

### 10.4 CI and release gates

- `ci.yml`: new job `admin` (ruby 3.2, MariaDB service container, `bin/rails
  test`, `bundle exec brakeman -q`, `bundle exec rubocop`). Add to `ci-pass`.
- `image-version-gate.yml` + `scripts/verify-image-version.sh`: add component
  `admin`: declared version = `admin/VERSION`, baked version =
  `docker run --rm --entrypoint cat <image> /rails/VERSION`; assert equals tag.
- `release.yml` docker matrix: `{component: admin, context: admin, image: ztlp-admin}`,
  and `{component: proto, context: proto, image: ztlp-proto}` so the CLI image
  is no longer hand-pushed.
- `release.sh`: bump `admin/VERSION` with the others.
- Public repo: no real addresses or secrets in fixtures or docs (use `10.20.x`,
  `198.51.100.x`).

---

## 11. Phases

**Phase 1, directory + enrollment + gateways (this build):**
1. Token format (Rust + Elixir + golden vector) and `setup` client changes,
   plus `ztlp admin claim` / `ztlp admin login` CLI commands. Ships as a ZTLP
   release on its own; usable without the panel via `ztlp admin enroll` flags
   (`--username --full-name --first --last --email --extra k=v --embed-relay-secret`).
2. `admin/` skeleton: compose, MariaDB, claim, key login, roles, audit, CI, image gate.
3. NsClient (CBOR, signed write, read, list) with golden tests; zone settings;
   republish + reconcile jobs.
4. Users, groups, devices CRUD + NS publish; policy test widget.
5. Enrollments UI, token minting in Ruby (HMAC-BLAKE2s), QR, authenticated
   redeem endpoint, legacy confirm endpoint, expiry sweep.
6. Gateways: registry, add-gateway bundle generator, policy renderer, SVC
   liveness from reconcile.

**Phase 2, admin convenience:** passkeys (WebAuthn), CSV import, invite email,
multiple zones, policy hot-reload in both gateways (wire `ConfigWatcher`;
Rust: watch `policy.toml` mtime) so rule changes need no restart.

**Phase 3, fleet:** agent check-in (`POST /api/v1/devices/<node>/checkin`,
signed, every 5 min: version, platform, tunnels, DNS health → `last_seen_at`,
online/offline, version drift); agent policy pull (signed JSON: `[tunnel]`
relays/prefer_relay, `[dns]` zones, pinned gateways, service allow-list)
applied via the existing IPC + config reload; remote re-enroll; gateway
deploy agent so "Add gateway" can start the container on a host; relay v3
adoption removes the relay secret from tokens.

**Phase 4:** SSO / IdP sync (Entra, Google, LDAP) into the directory;
per-resource ACLs per `docs/ACL-ARCHITECTURE.md`.

---

## 12. What to copy from `bootstrap/` (file → verdict)

COPY: `app/models/admin_user.rb` lockout logic (minus password), `audit_log.rb`
+ its controller/view, `enrollment_token.rb` status lifecycle (`use!`,
`revoke!`, `sweep_expired!`), `token_generator.rb` QR lines,
`services/ztlp/ns_admin_client.rb` (HTTP list client, HMAC canonical string),
`services/ztlp/api_authenticator.rb` (if an HMAC API is wanted later),
`test/test_helper.rb` sign-in helpers, `config/initializers/filter_parameter_logging.rb`,
production.rb hosts/SSL block, `admin/users_controller.rb` + views as the
Admins page, `lib/tasks/admin.rake` shape.
ADAPT: `identity/*` tab views and `identity_controller.rb` (drop Network),
`ztlp_users|groups|devices_controller.rb` + views, `Dockerfile` structure,
`docker-entrypoint` key bootstrap.
SKIP: SSH provisioning, machines/deployments, solid_queue 0.3 (use current),
lockbox, omniauth, `ZtlpAdmin` (wrong CLI grammar, SSH), unsigned token minting,
Tailwind CDN, `COPY bin/ztlp`.

---

## 13. Corrections to the first sketch (`ADMIN-PANEL-PLAN.md`)

- It assumed the panel writes to the NS by shelling to the CLI. The CLI
  identity commands cannot write to an auth-ON NS (F7). The panel speaks the
  signed protocol itself.
- It assumed `name@zone` user names. Those are not under the zone's authority
  (F4). Dotted names are required for the panel to create them and to create
  groups at all.
- It did not know identity records expire in 24 h (F5). The republish job is
  mandatory, not optional.
- It referred to a `relay.secret` file as if it existed; it does not (F11).
  The panel creates it and points `relay_secret_file` at it.
- It did not know gateways already evaluate `group:`/`role:` via the NS (F13),
  which makes Phase 1 central policy far smaller than planned.
- It did not know the callback is unauthenticated and only fires for query-param
  tokens (F10).

---

## 14. Open decisions for the build session

1. Zone authority migration on `trs.ztlp`: import the existing key (recommended)
   or delegate to a new one (§10.3 step 4).
2. Whether to keep publishing a USER record for each user before any device
   exists (the `public_key` is required; use the authority key as a placeholder
   until the first device's signing key arrives, or wait). Recommended:
   publish on `active` only.
3. Relay secret default: embedded by default (friction-free) vs opt-in. Spec
   says default on with the guardrails; confirm.
4. Puma + solid_queue in one container vs two (spec: two services, one image).

## 15. Verification plan (definition of done for Phase 1)

- Fresh `docker compose up` on a clean host: claim via `ztlp admin claim`,
  login via `ztlp admin login`, create group/user, mint a user+device token
  with relay secret, enroll a Windows box with `ztlp setup --token`; the device
  appears with owner and `last_seen` from the redeem; NS shows USER (dotted
  name), DEVICE (owner), GROUP; `www.chooseforce.ztlp` gateway with
  `allow=["group:staff.groups.trs.ztlp"]` returns 200 for a member and is
  denied after removing them from the group in the UI with **no gateway
  restart**.
- Kill the NS data (test NS only), run republish: all records back.
- 24 h soak: no record expired.
- Old `ztlp` (v0.35.15) given a new-format token fails with "unknown flags",
  not a misparse.
- `bin/rails test` green in CI with MariaDB; brakeman clean; image gate passes.

## Research sources (this session, 2026-10-05)

`/tmp/research-enrollment.md`, `/tmp/research-ns-identity.md`,
`/tmp/research-rails-docker.md` (subagent reports, repo-cited), live NS
record dump of `trs.ztlp`, `admin@trs.ztlp`, `aipc@aicomputer.trs.ztlp`,
`chooseforce.ztlp`, `www.chooseforce.ztlp`, and the policy/gateway code read
directly (`proto/src/policy.rs`, `gateway/lib/ztlp_gateway/{policy_engine,
ns_client,config,application}.ex`).
