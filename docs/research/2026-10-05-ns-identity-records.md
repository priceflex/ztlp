# ZTLP NS — Identity Record Write/Read Reference for an External Admin App

Source: clean checkout `/tmp/ztlp-rebase` (github.com/priceflex/ztlp). All paths relative to repo root.
All line numbers are from that checkout. Nothing was modified.

---

## 0. TL;DR for the admin app

* **Writes** go over **UDP** to the NS port (`ZTLP_NS_PORT`, default 23096) as a **signed v2 registration (opcode 0x09)**.
  Packet = `<<0x09, name_len::16, name, type_byte::8, data_len::16, data_cbor, sig_len::16, sig(64), pubkey_len::16, pubkey(32)>>`
  where `sig = Ed25519(<<type_byte::8, name_len::16, name, data_cbor>>)`. (`ns/lib/ztlp_ns/server.ex:390-412`, `registration_auth.ex:154-159`)
* **Who may write USER/DEVICE/GROUP when auth is ON** (`ZTLP_NS_REQUIRE_REGISTRATION_AUTH` unset/true, default):
  * **Zone authority** — the Ed25519 key whose lowercase-hex pubkey is stored in a KEY record at a parent zone name (e.g. `trs.ztlp`) with `data.delegation == true`. It can write ANY type under that zone and bypasses rate limiting and key-overwrite protection. (`registration_auth.ex:248-266`)
  * **Self-registration** — USER/DEVICE records may be written by the key that equals `data.public_key` (new) or the stored record's `public_key` (update). (`registration_auth.ex:333-379`)
  * **GROUP records: zone authority ONLY.** No self-registration path. (`registration_auth.ex:383-385`)
  * ⇒ **An admin app should hold the zone-authority Ed25519 seed and sign with it.** Nothing else can create groups.
* **Reads**: single record via UDP `0x01` query; **list by type/zone only via HTTP `GET /admin/records?type=&zone=`** on the metrics port (default **9103**) with HMAC headers `x-ns-timestamp` / `x-ns-signature`. The legacy UDP `0x13` list opcode was **removed in v0.35.1**.
* **The Rust CLI identity admin commands (`create-user`, `link-device`, `create-group`, `group add/remove`, `revoke`) send UNSIGNED v1 packets and therefore FAIL on an auth-ON NS** with `0xFF 0x02 missing_pubkey`. `admin devices|ls|groups|audit` still send `0x13` and get `<<0xFF>>` from a v0.35.1+ NS. See §3.

---

## 1. Record types USER (0x11), DEVICE (0x10), GROUP (0x12) — `ns/lib/ztlp_ns/record.ex`

### 1.1 Struct and type bytes
```
defstruct [:name, :type, :data, :signature, :signer_public_key, :created_at, :ttl, :serial]   # record.ex:44
@type_bytes %{key: 1, svc: 2, relay: 3, policy: 4, revoke: 5, bootstrap: 6, operator: 7,
              device: 0x10, user: 0x11, group: 0x12, ca: 0x13, cert: 0x14}                   # record.ex:64
```
`Record.type_to_byte/1` (l.69), `Record.byte_to_type/1` (l.73).

### 1.2 Canonical serialization (what NS signs when it stores)
`Record.serialize/1` (record.ex:94-105):
```
<<type_byte::8, name_len::16, name, data_len::32, data_cbor, created_at::64, ttl::32, serial::64>>
```
`data_cbor = ZtlpNs.Cbor.encode(data)` — RFC 8949 deterministic, keys sorted by `(byte_size, bytes)` (`ns/lib/ztlp_ns/cbor.ex:44-54`).
Wire form returned by queries, `Record.encode/1` (record.ex:196-203):
```
<<canonical, sig_len::16, sig, pub_len::16, pub>>
```
`Record.decode/1` (l.211-240) parses it. **Note:** the registrant does NOT build this; NS builds and signs the stored record itself with its registration key (server.ex:598-611). The registrant only signs the short registration canonical (§2.2).

### 1.3 Field tables (data map, CBOR map with text keys; all values text/hex unless noted)

| Type | Constructor | data fields (default) | Validator (called by server.ex:870-872) |
|---|---|---|---|
| DEVICE 0x10 | `Record.new_device(name, node_id, pubkey, opts)` l.396-410 | `node_id` (hex16), `public_key` (hex32), `owner` (""), `hardware_id` ("") | `validate_device/1` l.445-454: `:missing_node_id` if node_id nil/""; `:missing_public_key` if public_key nil/"" |
| USER 0x11 | `Record.new_user(name, pubkey, opts)` l.423-437 | `public_key` (hex32 Ed25519), `devices` ([]), `email` (""), `role` ("user") | `validate_user/1` l.462-471: `:missing_public_key`; `:invalid_role` unless role ∈ `["user","tech","admin"]` (role may be absent) |
| GROUP 0x12 | `Record.new_group(name, members, opts)` l.485-497 | `members` (list of user names), `description` ("") | `validate_group/1` l.505-514: `:missing_members`, `:invalid_members` (not a list), `:too_many_members` (>255) |

Doc comments: DEVICE name like `laptop-01.techrockstars.ztlp` (l.390); USER name email-style `steve@techrockstars.ztlp` (l.416); GROUP `admins@techrockstars.ztlp`, "Groups can ONLY be created/modified by zone signing key (not self-registration). Nested groups are NOT supported" (l.477-482).
Only the validator-required fields are enforced on registration; extra keys are stored as-is. NS adds `"registered_by" => <hex pubkey>` to data on authenticated registration (server.ex:603) and `"registered_unsigned" => true` on dev-mode unsigned registration (server.ex:687).

### 1.4 Name rules — `ns/lib/ztlp_ns/name_validator.ex`
* `validate/1` (l.50-67): `:empty_name` (0 bytes), `:name_too_long` (>253, `@max_name_length` l.21), `:invalid_characters` on NUL byte, then per-label check on canonicalized (lowercased) name.
* `validate_labels/1` (l.129-148): split on `.`; `:empty_label`; `:label_too_long` (>63, l.22); every label must match `@label_pattern ~r/^[a-z0-9@]([a-z0-9\-@]*[a-z0-9@])?$/` (l.25) — **`@` is allowed** inside labels, so `steve@trs.ztlp` is one label `steve@trs` + `ztlp`.
* Case-insensitive: `canonicalize/1` (l.90-92) ASCII-lowercases; Store keys on canonical name (`store.ex:134-135`) but preserves original bytes in `record.name`.
* `validate_with_suffix/2` (l.108-126): if `ZtlpNs.Config.name_suffix()` (config.ex:276, `Application.get_env(:ztlp_ns, :name_suffix)`, default nil = no check) is set, name must equal or end with `.<suffix>` else `:invalid_zone_suffix`.
* ⇒ Admin app should emit **lowercase** names; uppercase is accepted but normalized.

### 1.5 TTL / serial / expiry
* NS **ignores any client-supplied TTL/serial** — the registrant doesn't send them. NS sets `created_at = now`, `ttl = ZtlpNs.RecordDefaults.default_ttl(type)`, `serial = now (unix secs)` (server.ex:604-606).
* Defaults (`ns/lib/ztlp_ns/record_defaults.ex:24-33`): key/svc/bootstrap/device/user/group = 86 400 s; relay/policy = 3 600; revoke = 0 (never expires); unknown = 3 600.
* **USER/DEVICE/GROUP records expire after 24 h unless re-registered.** `Record.expired?/1` (record.ex:585-589): `ttl==0` never; else `now > created_at + ttl`. `Store.lookup/2` deletes expired on read (store.ex:185-188); `list_filtered` excludes expired (store.ex:284).
  ⇒ **The admin app must re-publish every identity record at least every 24 h** (e.g. every 12 h), exactly like the gateway heartbeat does for KEY/SVC.
* Serial monotonicity: `Store.do_insert/1` returns `{:error, :stale_serial}` if `existing.serial >= record.serial` (store.ex:138-140). Since serial = unix seconds, two writes in the same second collide; server retries once with `serial+1` (server.ex:632-660). A third write within the same second yields `0xFF 0x0B storage_error`.
* Capacity: `ZTLP_NS_MAX_RECORDS` (default 100 000, config.ex:38-41) → `:store_full` → `0xFF 0x00 unspecified` (not mapped in `from_internal`).

### 1.6 Indexes maintained on insert (`ns/lib/ztlp_ns/store.ex`)
* `:ztlp_ns_device_index` owner→device (l.561-583) built from DEVICE `data.owner`; `Store.lookup_devices_for_user/1` (l.323-332), `lookup_user_for_device/1` (l.341-353).
* `:ztlp_ns_group_index` member→group (l.588-613); `Store.groups_for_user/1` (l.362-370), `members_of_group/1` (l.378-386), `is_member?/2` (l.394).
* `:ztlp_ns_pubkey_index` pubkey_hex→name for KEY records only (`index_pubkey`, l.543; `lookup_by_pubkey/1` l.296-314).
* Revocation of an id also purges it from device/group indexes (server.ex:827-867).
* **These indexes are only reachable from inside the BEAM** — no UDP/HTTP opcode exposes `groups_for_user` / `lookup_devices_for_user`. See §4.

---

## 2. Registration authentication when auth is ON

### 2.1 Switch
`ZtlpNs.Config.require_registration_auth?/0` (config.ex:292-298): env `ZTLP_NS_REQUIRE_REGISTRATION_AUTH` ∈ `false|0|no` → off; unset → `Application.get_env(:ztlp_ns, :require_registration_auth, true)` → **default ON**.

### 2.2 Packet formats — `ns/lib/ztlp_ns/server.ex`
* **v2 signed** (l.390-395), accepted always:
  ```
  <<0x09, name_len::16, name::binary-size(name_len), type_byte::8, data_len::16,
    data_bin::binary-size(data_len), sig_len::16, sig::binary-size(sig_len),
    pubkey_len::16, pubkey::binary-size(pubkey_len)>>
  ```
  Must match **exactly** (no trailing bytes — the clause has no `_rest`).
* **v1 unsigned** (l.417-421): same without the pubkey trailer. With auth ON → `RegistrationError.encode(:missing_pubkey)` = `<<0xFF, 0x02>>` (l.422-425). With auth OFF → `handle_unsigned_registration/3` (l.677-…): only name + CBOR checks.
* Signature canonical: `RegistrationAuth.build_canonical/3` (registration_auth.ex:155-159) = `<<type_byte::8, name_len::16, name, data_bin>>`; verified by `verify_signature/3` (l.140-146) via `ZtlpNs.Crypto.verify` (Ed25519). `pubkey` = raw 32-byte Ed25519 verifying key.
* Reference Rust builder: `build_signed_registration_packet` `proto/src/bin/ztlp-cli.rs:7056-7103` (uses `identity.sign(&canonical)` and `identity.signing_key().verifying_key().to_bytes()`).

### 2.3 Pipeline — `handle_authenticated_registration/7` (server.ex:571-673), in order
1. `NameValidator.validate_with_suffix(name, Config.name_suffix())` → `:invalid_name` family.
2. `decode_data` CBOR (l.875-880) → `:invalid_data`.
3. `validate_record_data(type, data)` (l.870-873; device/user/group validators) → e.g. `:missing_public_key` → maps to **`:unspecified` (0x00)** because `from_internal` lacks those atoms (registration_error.ex:145-148 only lists `:invalid_data`, `:cbor_decode_failed`, `:invalid_record_data`, `:missing_required_field`). Also `:invalid_role`, `:too_many_members` → 0x00.
4. `RegistrationAuth.verify_signature` → `:invalid_signature` (0x04).
5. `RegistrationAuth.authorize(pubkey, name, type, data)` (registration_auth.ex:173-188) → `:unauthorized` (0x05).
6. `check_key_overwrite` (l.200-225) DEVICE/USER only: existing record with different `public_key` and signer not zone authority → `:key_overwrite_rejected` (0x06).
7. `check_revocation(data)` (l.234-242): `data.node_id` revoked → `:revoked` (0x07).
8. `check_name_revocation(name)` (l.119-125) → `:revoked` (0x07, note: NOT 0x08 — `from_internal(:revoked)` maps to `:revoked_pubkey`).
9. `check_rate_limit(name, type, pubkey)` → `:rate_limited` (0x09).
10. Build record, `Record.sign(record, server_priv)` with NS registration key, `Store.insert`; success reply `<<0x06>>`; audit `:registered` / `:updated`.

### 2.4 Authorization paths — `ns/lib/ztlp_ns/registration_auth.ex`
* `check_zone_authority/2` (l.248-266): computes `zone_hierarchy(name)` (l.394-399: `"a.b.c.ztlp"` → `["b.c.ztlp","c.ztlp","ztlp"]`; note the name itself is NOT included) and for each zone does `Store.lookup(zone, :key)`; authority iff `record.data.public_key == pubkey_hex and record.data.delegation == true`.
  * **`@`-name gotcha:** `Zone.parent_name/1` (zone.ex:61-66) splits on the first `.`, so `steve@trs.ztlp` → hierarchy `["ztlp"]` only. **The `@` form does not make `trs.ztlp` a parent.** Confirmed by the NS test suite: `ns/test/ztlp_ns/group_test.exs:650,687,742` all call `setup_zone_authority("ztlp")` (delegation at the TLD) to authorize `admins@zone.ztlp`. Therefore a delegation KEY at `trs.ztlp` does NOT authorize `steve@trs.ztlp`; only a delegation at `ztlp` would. For `laptop.trs.ztlp` → `["trs.ztlp","ztlp"]`, so `trs.ztlp` authority works. **Practical consequence: with user/group names in the `name@zone` form, the admin key must be the authority on the TLD `ztlp` (or whatever the last label is), OR users must be created by self-registration (signed with the user's own key), and groups cannot be created at all unless the signer is authority on the TLD label.** Verify against live data: docs/DIRECT-FIRST-DIAL-PLAN.md:206 says users `admin@trs.ztlp` exist on prod with `trs.ztlp` authority = `admin@trs.ztlp` key — consistent with self-registration of the user record plus a `trs.ztlp` KEY delegation written by the same key.
* `check_self_registration/4`: `:key` (l.276-300), `:svc` (l.302-317, needs matching KEY owner), `:relay` (l.319-327, any), `:device` (l.333-353), `:user` (l.359-379), `:group` → `{:error, :zone_authority_required}` (l.383-385), other → same (l.387-390). Any self-reg failure surfaces as `:unauthorized`.
* `ZtlpNs.ZoneAuthority` (zone_authority.ex): in-BEAM helper; `delegate/2` (l.91-114) shows the canonical delegation KEY record shape:
  `data = %{node_id: "zone:" <> child, public_key: hex, algorithm: "Ed25519", delegation: true}`, ttl 1 year, serial 1. There is **no UDP/HTTP opcode to create a delegation**; it's just a KEY registration (type 0x01) with `delegation: true` in data. Bootstrapping requires either auth OFF (gateway does this: `gateway/lib/ztlp_gateway/service_registrar.ex:418-462` sends unsigned v1 KEY with `{"delegation": true, "public_key": hex}` and comments "NS must have auth disabled for initial bootstrap, or the operator must pre-register the zone key"), or a KEY self-registration where `data.public_key == signer` (allowed by l.290-298) **and** `delegation: true` in the same data map — that is, a key can self-register itself as zone authority for any unclaimed zone name whose parent chain has no other authority. (Security note: nothing prevents this; `check_zone_authority` only checks the pubkey/flag.)
* `ZtlpNs.Zone` (zone.ex): `parent_name/1` l.61-66, `contains?/2` l.83-85.

### 2.5 Rate limiting — `check_rate_limit/3` (registration_auth.ex:68-75)
* Key = `{name, type}`; window `@rate_limit_window 60` s (l.37); ETS `:ztlp_ns_registration_rate_limit` (l.28), initialized in `application.ex:45`.
* **Zone authorities bypass** (l.69-74). Non-authority: second write to the same `{name,type}` within 60 s → `{:error, :rate_limited}` → `<<0xFF,0x09>>`.
* Legacy 2-arity `check_rate_limit(name, pubkey)` = type `:key` (l.79-81).

### 2.6 Error wire format — `ns/lib/ztlp_ns/registration_error.ex`
Reply `<<0xFF, code::8>>` (`encode/1` l.55-57). Codes (l.63-74):
`0x00 unspecified, 0x01 unknown_type, 0x02 missing_pubkey, 0x03 invalid_name, 0x04 invalid_signature, 0x05 unauthorized, 0x06 key_overwrite, 0x07 revoked_pubkey, 0x08 revoked_name, 0x09 rate_limited, 0x0A invalid_data, 0x0B storage_error`.
`from_internal/1` (l.108-155) maps internal atoms; unknown atoms → 0x00. Success = `<<0x06>>`. The Rust decoder `decode_registration_error` (ztlp-cli.rs:1946-1977) prints human text for each code.

### 2.7 NS registration (storage) signing key
`ensure_registration_key/0` (server.ex:889-918) loads/creates the Ed25519 key at `ZtlpNs.Config.identity_key_file()` (config.ex:239-248: `ZTLP_NS_IDENTITY_KEY_FILE`, default `<ZTLP_CA_DIR|ZTLP_CA_DATA_DIR>/registration_signing.key`). Every stored record's `signer_public_key` is this key, not the registrant's; the registrant pubkey is in `data.registered_by`.

---

## 3. Rust CLI admin commands — `proto/src/bin/ztlp-cli.rs`

Clap definitions at l.967-1268 (`AdminCommands`). All identity commands resolve the NS via `resolve_ns_server(ns_server, &config)` (l.12574-12585: `--ns-server` > `config.ns_server` > `127.0.0.1:23096`) and `load_config()` (l.102). `get_ztlp_dir()` (l.10081) = `~/.ztlp`.

| Command | fn / line | Flags | Packet builder | Signs with | Files read/written | `--json` | Works vs auth-ON NS? |
|---|---|---|---|---|---|---|---|
| `admin init-zone` | `cmd_admin_init_zone` 10140-10196 | `--zone`, `--secret-output` (default `~/.ztlp/zone.key`) | none (no network) | n/a | writes 64-hex **enrollment secret** to `zone.key` (0600); prints `export ZTLP_ENROLLMENT_SECRET=…` | no | n/a — **zone.key is the HMAC enrollment secret, NOT an Ed25519 zone-authority key** (despite help text calling it "zone signing key"). |
| `admin enroll` | `cmd_admin_enroll` 10200-10323 | `--zone --secret --ns-server --relay* --gateway --expires(24h) --max-uses(1) --count(1) --qr` | `EnrollmentToken::create` (proto/src/enrollment.rs) | HMAC-BLAKE2s(zone.key) | reads `zone.key` | no (prints token URI to stdout) | n/a (offline) |
| `admin create-user NAME` | `cmd_admin_create_user` 10328-10424 | `--role user|tech|admin`, `--email`, `--ns-server`, `--json` | `build_registration_packet(name, 0x11, …)` l.7025-7040 = **v1 unsigned** (sig_len 0) | nobody | generates NodeIdentity, saves `~/.ztlp/users/<name with @→_at_>.json` (0600) | yes: `{"status":"created"|"created_local_only",name,role,email,pubkey,key_file}` | **NO** → `0xFF 0x02 missing_pubkey`; CLI reports `created_local_only`. Also note `pubkey_hex = hex(identity.static_public_key)` (l.10351) = **X25519** key, not the Ed25519 signing key — even if signed, self-reg would fail the `data.public_key == signer` check. |
| `admin link-device NAME --owner U` | `cmd_admin_link_device` 10436-10507 | `--owner`, `--ns-server`, `--json` | reads KEY (0x01 query via `ns_query_raw`) to copy `node_id`/`public_key`, then `build_registration_packet(name, 0x10, …)` v1 | nobody | none | yes `{"status":"linked"|"link_failed",device,owner}` | **NO** (missing_pubkey) |
| `admin devices USER` | `cmd_admin_devices` 10510-10630 | `--ns-server --json` | UDP `<<0x13,0x01,0x10,0::16>>` (l.10533-10536) then client-side filter on `data.owner` | n/a | none | yes `{"owner","devices":[…]}` | **NO** — 0x13 removed v0.35.1 (server.ex:368-387) → `<<0xFF>>` → prints "No devices found". |
| `admin ls` | `cmd_admin_ls` 10633-10756 | `--type device|user|key|group`, `--zone`, `--ns-server`, `--json` | UDP `<<0x13,0x01,type_byte,zone_len::16,zone>>` (l.10662-10668) | n/a | none | yes `{"type","zone","records":[…]}` | **NO** (0x13 removed) |
| `admin create-group NAME` | `cmd_admin_create_group` 10795-10850 | `--description --ns-server --json` | `cbor_encode_group(desc, [])` l.6992-7014 + `build_registration_packet(name, 0x12, …)` v1 | nobody | none | yes `{"status":"created"|"create_failed",name,description,members:[]}` | **NO** (missing_pubkey; and would need zone authority anyway) |
| `admin group add G M` | `cmd_admin_group_add` 10853-10918 | `--ns-server --json` | 0x01 query type 0x12 → read-modify-write v1 0x12 | nobody | none | yes `{"status":"added"|"add_failed",group,member}` | **NO** |
| `admin group remove G M` | `cmd_admin_group_remove` 10921-11010 | same | same | nobody | none | yes `{"status":"removed"|"remove_failed"|"error",…,"was_member"}` | **NO** |
| `admin group members G` | `cmd_admin_group_members` 11013-11078 | `--ns-server --json` | 0x01 query type 0x12 (read only) | n/a | none | yes `{"group","members":[…]}` | **YES** (plain query) |
| `admin group check G U` | `cmd_admin_group_check` 11081-11143 | same | 0x01 query type 0x12 | n/a | none | yes `{"group","user","is_member"}` | **YES** |
| `admin groups` | `cmd_admin_groups` 11146-11267 | `--ns-server --json` | UDP `<<0x13,0x01,0x12,0::16>>` | n/a | none | yes `{"groups":[{name,description,members,member_count}]}` | **NO** (0x13 removed) |
| `admin revoke NAME` | `cmd_admin_revoke` 11270-11383 | `--reason --ns-server --json` | v1 0x05 REVOKE named `revoke.<name>`, data `{reason, effective_at:"now", revoked_ids:[name]}` (l.11389-11412), comment "Empty sig for dev mode" l.11300 | nobody | none | yes | **NO** |
| `admin audit` | `cmd_admin_audit` 11415-… | `--since --name --ns-server --json` | UDP `0x13 0x02/0x03` (l.11436-11461) | n/a | none | yes | **NO** (0x13 removed) |
| `admin rotate-zone-key` | 11594-11647 | `--json` | none | n/a | writes 64-byte ed25519 `SigningKey::to_bytes()` to `<state_dir>/.ztlp/zone.key` (**overwrites the hex enrollment secret with raw bytes — format conflict with init-zone/enroll**) | yes | local only; nothing re-signed despite help text (l.1237). |
| `admin export-zone-key` | 11650-… | `--format pem|hex --json` | none | n/a | reads first 32 bytes of `zone.key` as Ed25519 seed | yes | local only. |

* Comment evidence: `build_registration_packet` doc l.7023-7024 "The server ignores the client signature and re-signs with its own key, so we send a dummy 0-byte signature" (stale — true only for auth-OFF). `cmd_admin_revoke` l.11300 "Empty sig for dev mode"; l.11322 "check auth configuration". server.ex:380 states the intended migration "ztlp-cli admin {devices,ls,groups,audit} retargeted in proto/" — **not done in this checkout; no HTTP admin client exists in ztlp-cli.rs** (no `/admin/records`, `x-ns-signature`, or reqwest usage in the file).
* `ns_publish_self` (l.7156-…): the only CLI write path that works on auth-ON. Validates name ⊂ zone (l.7171), builds KEY (`{algorithm:"Ed25519", node_id, public_key: identity.signing_public_key_hex(), [address]}`) and optional SVC (`{address, node_id, zone, [addresses]}`), signs each with `build_signed_registration_packet` (l.7208, l.7267), decodes `0xFF` replies with `decode_registration_error`. Used by `ztlp ns register --name --zone --key <identity.json> --ns-server --address` (clap l.1661-1681, `cmd_ns_register` l.7368) and the listen heartbeat. Identity JSON (`proto/src/identity.rs`): `signing_key_seed` (l.122, auto-backfilled on load l.160-167), `signing_key()` l.205, `signing_public_key_hex()` l.223, `sign()` l.229.
* ⇒ For the admin app, **the CLI is not a usable write backend**; implement the v2 packet directly (Elixir/Ruby/Rust — ~30 lines).

---

## 4. Query side — how to read users/devices/groups

### 4.1 UDP (server.ex) — single-record only
* `0x01` lookup (l.171-197): `<<0x01, name_len::16, name, type_byte::8, pad…>>` → `<<0x02, Record.encode(record)>>` | `<<0x03,name_len,name,type>>` not found | `<<0x04,name_len,name>>` revoked | `<<0xFF>>` bad type. Uses `ZtlpNs.Query.lookup/2` (query.ex:37-49: Store lookup + signature verify, no chain walk). Pad the request — reply is capped at `request_size × ZTLP_NS_AMPLIFICATION_THRESHOLD` (server.ex:766-779; see ztlp-cli.rs:2558-2574). Works for type bytes 0x10/0x11/0x12.
* `0x05` lookup-by-pubkey (l.201-229): **KEY records only** (`Store.lookup_by_pubkey` → `lookup(name, :key)`), not USER.
* `0x13` admin list — **removed** (l.368-387). `Query.resolve_all/1` (query.ex:92-101) iterates types for one name but is not exposed over the wire.
* No wildcard/prefix/"all of type" UDP opcode. No opcode for `groups_for_user`, `lookup_devices_for_user`.

### 4.2 HTTP (metrics_server.ex) — the only list capability
`GET /admin/records?type=<key|svc|relay|policy|revoke|bootstrap|operator|device|user|group|ca|cert>&zone=<suffix>` (l.269-271, type map l.700-705, parser l.707-722). Response (`ZtlpNs.AdminApi.list_records/1`, admin_api.ex:259-288):
```json
{"records":[{"name","type":"user","data":{...},"created_at","ttl","serial",["pubkey_hex"]}],"count":N,"generated_at":unix}
```
Backed by `Store.list_filtered/1` (store.ex:264-287): full-table scan, zone match = `name == zone || ends_with ".zone" || ends_with "@zone"` (so `?zone=trs.ztlp` returns `steve@trs.ztlp` and `laptop.trs.ztlp`), expired excluded. No pagination.
`GET /admin/audit?since=<unix>&pattern=<glob>` (l.272-274, 523-544) → `{"entries":[{timestamp,action,name,type,details}],count,generated_at}`.
⇒ **The admin app does not need its own index for listing** — it can poll `/admin/records?type=user|device|group&zone=…` (rate-limited; see §5). It DOES need its own source of truth for the identity keys (NS stores only public keys) and for re-publishing before the 24 h TTL. Reverse lookups (devices of user, groups of user) must be derived client-side from the list (filter `data.owner`, `data.members`).

---

## 5. HTTP admin API — `ns/lib/ztlp_ns/admin_api.ex`, `admin_api/tenant_registry.ex`, `admin_api_rate_limiter.ex`

* Server: `ZtlpNs.MetricsServer` (metrics_server.ex), plain `:gen_tcp` HTTP/1.0-style, **GET only** (l.279-281 → 405 otherwise). Port `ZTLP_NS_METRICS_PORT` (default 9103, l.12, l.971), bind `ZTLP_NS_METRICS_BIND` (l.978), enable `ZTLP_NS_METRICS_ENABLED`. Other paths: `/metrics`, `/health`, `/ready`, `/token_status` (unauthenticated).
* **Read-only.** There is no write endpoint; `AdminApi` moduledoc l.3: "Authenticated read-only admin HTTP API".
* Auth scheme (admin_api.ex:7-12, 47-68): headers `x-ns-timestamp` (unix secs, ±300 s `@skew_seconds` l.17) and `x-ns-signature` = lowercase-hex HMAC-SHA256(secret, canonical) with
  `canonical = "GET\n<path_with_query>\n<timestamp>\n<sha256_hex(body)>"` (body is "" for GET → sha256("") hex). `path_with_query` is exactly the request-line path including `?…` (metrics_server.ex:361-368).
* Secret resolution `verify_request_with_registry/6` (l.105-145): try every tenant secret first (`TenantRegistry.identify_tenant/3` l.252-261, constant-time), else global `ZTLP_NS_ADMIN_API_SECRET` (`Config.load_admin_api_secret_from_env/0` config.ex:375-403: 32 raw bytes or 64-hex) → identity `:legacy`. Errors: `:no_secret`, `:missing_header`, `:stale_timestamp`, `:bad_signature`, `:bad_request` → all **401** (metrics_server.ex:385-393).
* Tenant registry env contract (tenant_registry.ex:7-9): `ZTLP_NS_ADMIN_API_TENANT_<SLUG>_SECRET`, `_ZONE_GLOB` (`*.trs.ztlp` or exact `trs.ztlp`; middle wildcards rejected at boot l.166-188), `_CIDRS` (comma-separated IPv4). Slug `^[A-Z][A-Z0-9_]*$`. Loaded once at boot (`cache_at_boot/0` l.275-279; application.ex:81), misconfig raises. Duplicate secrets across slugs refuse boot (l.70-89).
* Gate order (`handle_admin_gated/7` l.343-397): CIDR union gate (403 if registry non-empty and IP in no tenant CIDR, l.682-698) → per-IP token bucket `ZtlpNs.AdminApiRateLimiter.check/1` (429 + `Retry-After`; default `{12, 60}` = 12 req/60 s, env `ZTLP_NS_ADMIN_API_RATE_LIMIT=N/W`, config.ex:163-170, rate limiter moduledoc l.26-32) → HMAC verify (401) → identified-tenant CIDR recheck (403, l.406-429) → `AdminApi.verify_authority/2` stub (always `:ok`, admin_api.ex:224) → tenant zone-glob filtering of results (`apply_tenant_scope/2` l.641-652; audit scope l.626-633). Legacy global secret sees everything.
* Reference client: `bootstrap/app/services/ztlp/ns_admin_client.rb` (`list_records(zone:, type:, base_url:, secret:)`, env `ZTLP_NS_ADMIN_BASE_URL`, `ZTLP_NS_ADMIN_API_SECRET`). Design doc: `docs/operations/ns-admin-tenant-isolation.md`.

---

## 6. Enrollment — `ns/lib/ztlp_ns/enrollment.ex`

* Handles UDP opcode `0x07` (`Server` l.446-448 → `Enrollment.process_enroll/1` l.78-111). Request: `<<token_len::16, token, pubkey::32, node_id::16, name_len::16, name, addr_len::16, addr>>` (l.22-29). Reply `<<0x08, status>>`: 0x00 ok (+config: relay list, gateway list l.410-433), 0x01 expired, 0x02 uses exhausted, 0x03 invalid MAC, 0x04 zone mismatch, 0x05 name taken (different pubkey), 0x06 bad format / enrollment disabled (l.35-42).
* Secret: `ZTLP_ENROLLMENT_SECRET` (64 hex) read in `application.ex:52-59` → `Enrollment.set_zone_secret/1` (l.115-118, stored in `Application` env `:enrollment_secret`). **One global secret, not per-zone.** Nil → every enroll returns `0x08 0x06`.
* Token = v1 binary `<<version=1, flags, zone_len::16, zone, ns_len::16, ns_addr, relay_count::8, relays…, [gw], [callback], max_uses::16, expires_at::64, nonce::16, mac::32>>` (`parse_token/1` l.223-…); MAC = HMAC-BLAKE2s-256 (`hmac_blake2s/2` l.485-499) over everything before the MAC, matching `proto/src/enrollment.rs`.
* **The NS does not mint tokens** — the CLI (`admin enroll`) and Bootstrap do, offline, with the shared secret. NS only verifies MAC + expiry + use count.
* Use tracking: ETS `:ztlp_enrollment_tokens` keyed by nonce (l.53, `check_usage/1` l.183-…); `max_uses == 0` unlimited; zero-nonce tokens (Bootstrap query-param format) skip tracking (l.185-188). **Not persisted** — restart resets counts.
* `register_device/5` (l.303-334) + `do_register/5` (l.336-408): writes a **KEY** record `{algorithm:"Ed25519", node_id, public_key}` and optional **SVC** `{address, node_id, zone}`, signed by the NS registration key, default TTLs. **It does NOT create a DEVICE (0x10) or USER record.** Name must end with `.<token.zone>`.
  (Open question in docs/plans/2026-09-19-relay-auth-v3 §5 Q1: whether the 32-byte pubkey on the wire is X25519 or Ed25519.)
* `enrollment_log/0` (l.457-467): ETS `:ztlp_enrollment_log` of `%{name,node_id,pubkey,zone,enrolled_at}`, exposed via unauthenticated `GET /token_status` on 9103 (metrics_server.ex:265-268). In-memory only.
* ⇒ The admin app can use enrollment only to onboard devices' KEY/SVC; DEVICE/USER/GROUP records must be registered separately via §2.

---

## 7. Relay secret configuration & the V3 plan

### 7.1 Config
* `ZtlpRelay.Config.registration_secret/0` (`relay/lib/ztlp_relay/config.ex:357-363`): `ZTLP_RELAY_REGISTRATION_SECRET` env, else `Application.get_env(:ztlp_relay, :registration_secret)`, nil = unset.
* `ZtlpRelay.HmacSecrets` (`relay/lib/ztlp_relay/hmac_secrets.ex`): per-zone `ZTLP_HMAC_SECRET_<UPCASE_ZONE> = "<primary>[,<grace>…]"` (l.18; `slugify_zone/1` l.104-109: upcase, non-alnum runs → `_`, e.g. `trs.ztlp` → `TRS_ZTLP`). Each entry: raw 32 bytes | 64 hex | `base64:…` (l.23-25). First entry signs; all verify (`primary_secret/1` l.120, `verifying_secrets/1` l.136). Falls back to legacy `ZTLP_RELAY_REGISTRATION_SECRET` (`legacy_secret/0` l.157, read l.275). `verify_with_policy/3` (l.246) returns `{:ok, :primary|:grace|:legacy|:unverified_dev|:unverified_staging}`. Mode `ZTLP_RELAY_HMAC_MODE` = `prod` (default, fail-closed) | `staging` | `dev` (l.66-86). Used by `relay/lib/ztlp_relay/udp_listener.ex` for GATEWAY_REGISTER / CLIENT_ROUTE_V2 (l.435, 597, 744, 850, 1125).
* Client side: `agent.toml [tunnel] relay_secret` / `ztlp setup --relay-secret`; decoding `proto/src/tunnel.rs` `decode_relay_secret` (per plan E5). Design doc: `docs/per_zone_hmac_design.md`.

### 7.2 `docs/plans/2026-09-19-relay-auth-v3-identity-signed.md` in 10 lines
1. Status: DESIGN / NOT STARTED (2026-09-19); problem: relay access today = knowing the zone's shared HMAC secret (`ZTLP_RELAY_REGISTRATION_SECRET` / `ZTLP_HMAC_SECRET_<ZONE>`), a group password with no per-device identity or revocation, manually copied into `agent.toml`.
2. V3 goal: authorize relay use by the node's own Ed25519 identity signature, verified against the key the NS recorded at enrollment — "permission = enrolled, non-revoked ZTLP identity in the zone", no secret to copy.
3. Reuses existing pieces: `identity.signing_key()` (proto/src/identity.rs), NS `Store.lookup_by_pubkey/1`, NS `EndpointAuth.verify_and_bind` pattern, relay `HmacSecrets.verify_with_policy`.
4. New frames parallel to V2: `0x10 CLIENT_ROUTE_V3` `[zone][node_id][svc][ts][32 pubkey][64 sig]` and `0x11 GATEWAY_REGISTER_V3`; signed_data = frame prefix through ts.
5. Authorization Option 1 (first): relay asks the zone's NS "is pubkey P enrolled for node N in zone Z and not revoked?", caches positives ~5 min / negatives ~30 s; needs `ZTLP_RELAY_NS_ADDR_<ZONE>`.
6. Option 2 (later): NS-signed offline enrollment grant `{zone,node_id,pubkey,not_before,not_after}` attached to frames, verified with `ZTLP_RELAY_NS_PUBKEY_<ZONE>`.
7. Anti-replay: timestamp window as V2; node_id→pubkey TOFU pin in ETS (`:pubkey_mismatch` on conflict); route bound to sender UDP tuple.
8. New mode `ZTLP_RELAY_AUTH_MODE = hmac | both | identity` (default `hmac`), new policy classes `:identity` / `:identity_unauthorized`; agent `[tunnel] auth = "identity"`.
9. Work breakdown W1–W8 (golden vectors → Rust client → relay parse/verify → relay→NS lookup+cache → gateway V3 → CLI/UX → defcon demo migration → grants); ~3 focused days.
10. Open questions: does NS hold the Ed25519 key or only X25519 at enrollment (Q1 — decides whether ENROLL frame grows); relay→NS transport UDP vs the HTTP admin API (Q2); multi-zone NS map format (Q3); gateway timing (Q4); whether grants are needed (Q5).

---

## 8. Recommended write procedure for the admin app (derived)

1. Keep an Ed25519 **zone-authority seed** in the app. Ensure a KEY record exists at the zone apex whose `data = {algorithm:"Ed25519", node_id:"zone:<zone>", public_key:<hex>, delegation:true}` signed by that key (self-registration of a KEY where `data.public_key == signer` is allowed, registration_auth.ex:290-298; must be refreshed every 24 h because NS applies `default_ttl(:key)=86400`, NOT the 1-year TTL in `ZoneAuthority.delegate`). Because `Zone.parent_name` splits on the first `.`, names like `user@trs.ztlp` only see `ztlp` as parent → either place the delegation at the TLD label, or use dotted names (`steve.users.trs.ztlp`) so `trs.ztlp` authority applies. Verify on the live NS with `/admin/records?type=key&zone=…`.
2. For each USER/DEVICE/GROUP: CBOR-encode data with sorted keys, build `<<type_byte, name_len::16, name, cbor>>`, Ed25519-sign, send v2 0x09 packet to `ns:23096`, expect `<<0x06>>`; on `<<0xFF, code>>` map via §2.6. Avoid two writes of the same `{name,type}` in the same second (`stale_serial`).
3. Re-publish all records at ≤12 h cadence (TTL 86 400 s).
4. Read back / reconcile with `GET /admin/records?type=…&zone=…` on 9103 using HMAC headers (§5), ≤12 requests/min per IP by default.
5. Revoke via a REVOKE (0x05) record named e.g. `revoke.<name>` with `{revoked_ids:[name], reason, effective_at}` signed by the zone authority (ttl 0, never expires; also purges device/group indexes server.ex:827-843).
