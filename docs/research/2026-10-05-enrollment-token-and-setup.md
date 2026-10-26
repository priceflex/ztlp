# ZTLP Enrollment Token + `ztlp setup --token` — Technical Reference

Source checkout: `/tmp/ztlp-rebase` (branch `plan/admin-panel`, HEAD `f87f3af`).
Main crate: `proto/` (`ztlp_proto`). All line numbers refer to that checkout.
Read-only research; nothing in the repo was modified.

Related planning docs already in the tree:
- `docs/ADMIN-PANEL-PLAN.md` §3 (lines 62-93) proposes flag `0x04` (identity) and `0x08` (relay secret) as new MAC-covered, flag-gated token fields "same pattern as the existing `FLAG_HAS_CALLBACK` fix", plus an unknown-flags fail-closed check.
- `docs/plans/2026-09-19-relay-auth-v3-identity-signed.md` (relay secret as "group password"; relay v3 would remove it).

---

## 1. `EnrollmentToken` wire format — `proto/src/enrollment.rs`

### 1.1 Constants

| Constant | Value | Line | Meaning |
|---|---|---|---|
| `TOKEN_VERSION: u8` | `0x01` | 37 | only accepted version (`deserialize` rejects anything else, line 168) |
| `FLAG_HAS_GATEWAY: u8` | `0x01` | 40 | bit 0 — `gateway_addr` present |
| `FLAG_HAS_CALLBACK: u8` | `0x02` | 59 | bit 1 — `callback_url` present (added for crf-mpxh / CWE-918; comment lines 42-58) |

All three are **private** (`const`, no `pub`). Unknown flag bits are currently **ignored** by `deserialize` (there is no "unknown flags → error" check; `ADMIN-PANEL-PLAN.md:80-82` asks for one).

### 1.2 Struct (lines 62-79)

```rust
#[derive(Debug, Clone)]
pub struct EnrollmentToken {
    pub version: u8,
    pub zone: String,
    pub ns_addr: String,
    pub relay_addrs: Vec<String>,
    pub gateway_addr: Option<String>,
    pub max_uses: u16,
    pub expires_at: u64,
    pub nonce: [u8; 16],
    pub mac: [u8; 32],
    /// Token identifier (hex string from query-param URI `token` parameter).
    /// Used for enrollment confirmation callback.
    pub token_id: Option<String>,
    /// Optional callback URL for the CLI to confirm enrollment usage
    /// (populated from query-param URI `callback` parameter).
    pub callback_url: Option<String>,
}
```

`token_id` is **never serialized** to the binary form — it exists only when parsed from the query-param URI (`deserialize` sets `token_id: None`, line 261).

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum TokenValidation { Valid, Expired, InvalidMac, InvalidVersion, Malformed(String) }   // lines 82-89
```

### 1.3 Binary layout (big-endian throughout)

Produced by `serialize_without_mac()` (lines 451-499) + `serialize()` (lines 140-144, appends `mac`). Parsed by `deserialize()` (lines 158-264).

| # | Field | Encoding | Condition |
|---|---|---|---|
| 1 | `version` | `u8` = `0x01` | always |
| 2 | `flags` | `u8` (bit0 gateway, bit1 callback) | always; computed from `gateway_addr.is_some()` / `callback_url.is_some()` (lines 458-465) |
| 3 | `zone` | `u16 len` + UTF-8 bytes | always |
| 4 | `ns_addr` | `u16 len` + UTF-8 bytes (e.g. `"10.0.0.5:23096"`) | always |
| 5 | `relay_count` | `u8` (`relay_addrs.len() as u8`, line 474) | always |
| 6 | `relay_addrs[i]` | `u16 len` + UTF-8, × relay_count | always |
| 7 | `gateway_addr` | `u16 len` + UTF-8 | only if `flags & 0x01` |
| 8 | `callback_url` | `u16 len` + UTF-8 | only if `flags & 0x02` |
| 9 | `max_uses` | `u16` (0 = unlimited) | always |
| 10 | `expires_at` | `u64` unix seconds (0 = never) | always |
| 11 | `nonce` | 16 raw bytes (random, `rand::thread_rng().fill_bytes`, line 117) | always |
| 12 | `mac` | 32 raw bytes | always (appended by `serialize`) |

Length-prefix helpers: `write_len_prefixed_string(buf, s)` (lines 504-508) and `read_len_prefixed_string(data, pos)` (lines 585-604; UTF-8 validated, returns `Err("truncated length prefix")` / `"truncated string: need … at offset …"` / `"invalid UTF-8: …"`).

Any new flag-gated field must be inserted **between item 8 (`callback_url`) and item 9 (`max_uses`)** in both `serialize_without_mac` and `deserialize` to stay compatible with the Elixir NS parser (`ns/lib/ztlp_ns/enrollment.ex:241-269`), which reads gateway (0x01), then callback (0x02), then `<<max_uses::16, expires_at::64, nonce::16, _mac::32>>`. The NS parser will **misparse** any token carrying a flag it doesn't know (it has no unknown-flag check either), so a new flag requires an NS-side parser change too (that is exactly what happened with 0x02 — see comment at `enrollment.ex:250-259`).

### 1.4 MAC

- Algorithm: **HMAC-BLAKE2s-256 per RFC 2104** (ipad/opad construction, NOT BLAKE2s keyed mode). `pub fn hmac_blake2s(key, data) -> [u8;32]` at lines 624-626 delegates to `crate::admission::hmac_blake2s`. Doc comment (lines 608-623) records the historical keyed-mode bug fixed in v0.30.0 and that the Elixir side is `ZtlpNs.Enrollment.hmac_blake2s/2`.
- Key: the 32-byte zone enrollment secret (`generate_enrollment_secret()` lines 635-639; NS reads `ZTLP_ENROLLMENT_SECRET`).
- Covered bytes: **everything in items 1-11** (`serialize_without_mac()` output), i.e. version, flags, zone, ns_addr, relay list, optional gateway, optional callback, max_uses, expires_at, nonce. `create()` (lines 107-137) computes `token.mac = hmac_blake2s(secret, &token.serialize_without_mac())`.
- Verification: `validate(&self, secret: &[u8;32]) -> TokenValidation` (lines 388-411): version check → `constant_time_eq` (lines 629-632, `subtle::ConstantTimeEq`) of recomputed MAC → expiry (`expires_at > 0 && now > expires_at`).
- Elixir NS verifies over `split_mac(token_bin)` = all received bytes except the trailing 32 (`enrollment.ex:295-299`, used at `:145-163`), and only when `ZtlpNs.Config.require_registration_auth?()` is true.

### 1.5 Textual forms

| Form | Producer | Parser | Lines |
|---|---|---|---|
| base64url, no padding, of `serialize()` | `to_base64url()` (`URL_SAFE_NO_PAD`) | `from_base64url()` | 147-150 / 268-288 |
| `ztlp://enroll/<base64url>` | `to_uri()` | `from_base64url()` strips the `ztlp://enroll/` prefix | 153-155 / 277-281 |
| `ztlp://enroll/?zone=…&token=…` (query-param, "Bootstrap/Launch format") | Launch `_build_token_uri` (`ztlp.net/launch_app/app.py:~2285-2410`) / Bootstrap Rails | `from_query_param_uri()` (private) | 303-385 |

`from_base64url` dispatch rule (line 273): if the input `contains("?") && contains("token=")` → query-param parser; else base64url path.

### 1.6 Query-param URI variant — `from_query_param_uri` (lines 290-385)

Documented shape (lines 291-292):
```
ztlp://enroll/?zone=<zone>&ns=<host:port>&relay=<host:port>&token=<hex>&expires=<unix>
              [&gateway=<host:port>][&callback=<url>][&nonce=<32hex>&mac=<64hex>]
```

Parsing (lines 320-348), `pair.splitn(2,'=')`, unknown keys ignored:

| key | → field | notes |
|---|---|---|
| `zone` | `zone` | required (`"missing zone parameter"`) |
| `ns` | `ns_addr` | required (`"missing ns parameter"`) |
| `relay` | `relay_addrs.push(..)` | repeatable |
| `gateway` | `gateway_addr` | optional |
| `token` | `token_id = Some(hex)` | required (`"missing token parameter"`); Launch mints `secrets.token_hex(16)` = 32 hex chars; Bootstrap `SecureRandom.hex(8)` = 16 hex |
| `expires` | `expires_at` (`u64` parse, `"invalid expires timestamp"`) | required |
| `callback` | `callback_url = Some(percent_decode(val)?)` | optional; `percent_decode` (lines 550-574) decodes `%XX`, errors on malformed `%`, does **not** treat `+` as space |
| `nonce` | 16 bytes via `hex_decode_fixed::<16>` (lines 516-533) | must appear together with `mac`, else `Err` (lines 357-370) |
| `mac` | 32 bytes via `hex_decode_fixed::<32>` | legacy form (neither) → zeroed nonce & mac |

Fixed values set by this path: `version = TOKEN_VERSION`, `max_uses = 1` (line 378).

**Discrepancy worth knowing (factual, from reading both sides):** Launch's `_serialize_enrollment_token_for_signing` (`app.py:2414-2472`) writes `flags = 0x01 if gateway_addr else 0x00` and never writes the callback string, and its docstring at `app.py:2327-2329` says "callback … Not part of the MAC". The Rust `serialize_without_mac()` sets `0x02` and includes `callback_url` when `callback_url.is_some()`. Therefore a signed Launch URI that carries both `&callback=` and `&nonce=&mac=` reconstructs in Rust to bytes that differ from what Launch signed; `validate()` would return `InvalidMac` and an NS with `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=true` would answer `0x08 0x03`. The Rust test `test_from_query_param_uri_full_v030_10_shape_decodes_callback` (lines 1096-1115) only asserts nonce/mac are non-zero; it does not call `validate()`. The golden-vector tests (`test_signed_query_param_token_validates_against_secret`, lines 1244-1310) do not include a callback.

### 1.7 Other public helpers in the module

- `is_expired(&self) -> bool` (414-423), `expires_in_human(&self) -> String` (426-447: `never`/`expired`/`Ns`/`Nm`/`Nh`/`Nd`).
- `pub fn generate_enrollment_secret() -> [u8;32]` (635-639).
- `pub fn pin_gateway_key(config_path: &Path, key: &[u8;32])` (649-726) — appends/rewrites `pinned_gateway_keys = [...]` (base64 STANDARD) in a TOML file; used by `src/ffi.rs:3575` and `tests/pin_test.rs`.
- `pub fn parse_duration_secs(s) -> Result<u64,String>` (729-753): suffixes `d/h/m/s`, bare number = seconds.

---

## 2. `ztlp setup --token` — `proto/src/bin/ztlp-cli.rs`

### 2.1 Clap definition — `Commands::Setup` (lines 666-722)

```rust
Setup {
    #[arg(short, long)]                    token: Option<String>,        // base64url or ztlp://enroll/ URI
    #[arg(short, long)]                    name: Option<String>,         // device name (hostname default)
    #[arg(long, value_enum, default_value = "device")] r#type: SetupType, // Device | User  (enum at 1448-1453)
    #[arg(long)]                           owner: Option<String>,        // "Owner user name (for device records, e.g. steve@techrockstars.ztlp)"
    #[arg(long)]                           bind_user: bool,              // D3.T1 OS-user binding
    #[arg(short = 'y', long)]              yes: bool,
    #[arg(long)]                           force: bool,                  // re-enroll over existing identity.json (backs up)
    #[arg(long, conflicts_with = "relay_secret_file")] relay_secret: Option<String>,
    #[arg(long)]                           relay_secret_file: Option<PathBuf>,
}
```

Dispatch (lines 14289-14308):
```rust
Commands::Setup { token, name, r#type, owner, bind_user, yes, force, relay_secret, relay_secret_file }
  => match resolve_setup_relay_secret(relay_secret, relay_secret_file) {
       Err(e) => Err(e),
       Ok(relay_secret) => {
           let opts = SetupOpts { force: *force, relay_secret };
           cmd_setup(token, name, *r#type, owner, *bind_user, *yes, &opts).await
       }
  }
```

`struct SetupOpts { force: bool, relay_secret: Option<String> }` — lines 9826-9832.

### 2.2 Call chain

`cmd_setup` (8908-8974) → if `--token` given → `setup_join(token_str, name_arg, bind_user, auto_yes, opts)` (8977-9307). Interactive menu otherwise (`dialoguer::Select`), option 1 → `setup_create_network(opts.force)` (9310-9427).

Note: `cmd_setup` receives `_setup_type: SetupType` and `_owner_arg: &Option<String>` (lines 8911-8912) — **both are underscore-prefixed and unused**. `--type user` and `--owner` are accepted by clap but have no effect on the join path.

### 2.3 `setup_join` step by step (lines 8977-9307)

1. **Parse + expiry check** (8991-8996): `EnrollmentToken::from_base64url(token_str)` → `token.is_expired()` → prints zone / NS / relays / gateway / expires-in / max-uses.
2. **Device name** (9014-9031): `--name` wins; otherwise `get_hostname()` (10070-10077: `hostname::get()`, lowercased, spaces → `-`, fallback `"device"`); with `--yes` no prompt, else `dialoguer::Input` prompt "Device name" defaulting to hostname.
3. **FQDN** (9034): `full_name = format!("{}.{}", device_name, token.zone)`.
4. **Directory + paths** (9038-9044): `ztlp_dir = get_ztlp_dir()?` = `ztlp_proto::agent::config::ztlp_state_dir().join(".ztlp")` (10081-10083; `ztlp_state_dir` honours `$ZTLP_HOME`, else `dirs::home_dir()`, `src/agent/config.rs:642-649`).
   - `key_path = <ztlp_dir>/identity.json`
   - `config_path = <ztlp_dir>/config.toml`
   - `agent_config_path = <ztlp_dir>/agent.toml`
5. **Clobber guard** (9048): `guard_existing_identity(&ztlp_dir, opts.force)` (9857-9890). Without `--force` → `Err("this machine is already enrolled …")` even with `--yes`. With `--force` → renames `identity.json`, `config.toml`, `agent.toml`, `zone.key` to `<name>.<unix-ts>.bak`.
6. **Identity** (9058-9089): `NodeIdentity::generate()?`; if `--bind-user` → `identity.bound_user_sid = Some(ztlp_proto::agent::user_binding::current_user_sid()?)`; `identity.save(&key_path)` (JSON, chmod 0600 on unix — also set again at 9077-9082).
7. **Name pre-check** (9119-9128): `ns_name_is_taken_by_other_key(&token.ns_addr, &full_name, pubkey_bytes)` (9747-9760) — plain `ns_query_raw(.., type 1 /*KEY*/)` and compares `public_key` CBOR field; if taken by another key → `disambiguated_device_name(&device_name, &node_hex)` (9768-9771: appends `-<first 4 hex of node_id>`).
8. **NS registration = ENROLL 0x07** (9103-9138). This is **not** a signed v2 REGISTER (0x02) and does not use `build_registration_packet`; it is the dedicated enrollment opcode:
   ```rust
   let token_bin = token.serialize();                       // full binary incl. MAC — the query-param URI is re-serialized here
   let pubkey_bytes = identity.static_public_key.as_slice(); // X25519 Noise static pubkey (32 B)
   let node_id_bytes: &[u8;16] = identity.node_id.as_bytes();
   let addr_str = "";                                        // "Empty = no address for now"
   let enroll_body = build_enroll_packet(&token_bin, pubkey_bytes, node_id_bytes, &full_name, addr_str);
   let packet = [&[0x07u8][..], &enroll_body].concat();
   sock.send_to(&packet, ns_addr)  // UDP, 10 s timeout
   ```
   `build_enroll_packet` (9653-9686) body: `u16 token_len | token | pubkey[32] (zero-padded) | node_id[16] | u16 name_len | name | u16 addr_len | addr`.
   NS side: `ZtlpNs.Enrollment.process_enroll/1` (`ns/lib/ztlp_ns/enrollment.ex:78-108`) → `validate_token` → `register_device/5` (303-334) → `do_register/5` (336-408) which inserts a **KEY record** (`type: :key`, data `{"algorithm":"Ed25519","node_id":hex,"public_key":hex}`) signed with the NS registration key, plus an SVC record only if `addr_str` non-empty (never, from the CLI). **No DEVICE (0x10) record and no owner is written by enrollment.**
9. **Response handling** (9141-9304):
   - `0x08 0x00 <config>` → success; `parse_enroll_config(config)` (9689-9738) reads `u8 relay_count` + len-prefixed relays, then `u8 gw_count` + len-prefixed gateways (NS `build_config_response`, `enrollment.ex:410-432`).
   - `0x08 0x01` expired, `0x02` used up, `0x03` invalid MAC, `0x04` name not in zone, `0x05` name taken, `0x06` NS rejected / enrollment not configured / malformed.
10. **Writes `config.toml`** via `write_config_file(&config_path, &key_path, &token.zone, &token.ns_addr, &relay_addrs, &gateway_addrs)` (9774-9823). Content:
    ```toml
    # ZTLP Configuration — generated by `ztlp setup`
    # Zone: <zone>

    identity = "<key_path>"
    ns_server = "<ns_addr>"
    relay = "<addr>"            # or relay = ["a", "b"]; omitted when empty
    zone = "<zone>"
    gateway = "<first gateway>" # only if any
    ```
11. **Writes `agent.toml`** (9164-9186) **only if it does not already exist** (otherwise "already exists — left untouched"): `write_agent_config_file(&agent_config_path, &key_path, &token.zone, &token.ns_addr, &relay_addrs, opts.relay_secret.as_deref())` — see §3.3 for content. If `opts.relay_secret.is_none()` prints the warning "no --relay-secret given: agent.toml has no relay_secret. Fine for dev/staging relays; prod-HMAC relays will reject every route."
12. **Callback** (9189-9197): `if let Some(ref url) = token.callback_url { confirm_enrollment(url, &token, &full_name, &identity.node_id, &pubkey_hex).await }` — see §2.4.
13. `test_connectivity(&relay_addrs)` (10086+), summary, and prints the device's `static_public_key` hex for the "passwordless sign-in" claim page (9218-9248).

### 2.4 Callback to Bootstrap/Launch — `confirm_enrollment` (lines 9429-9605)

```rust
async fn confirm_enrollment(callback_url: &str, token: &EnrollmentToken, device_name: &str, node_id: &NodeId, pubkey_hex: &str)
```
- Returns immediately if `token.token_id` is `None` (9454-9457) — so **binary tokens (which never carry `token_id`) never fire the callback even if they carry `callback_url`**.
- HTTP method: **POST**, via spawning `curl` (`tokio::process::Command::new("curl")`, 9475-9500) with args `-s --max-time 60 -w "\n%{http_code}" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d <body> <callback_url>`.
- Body (9470-9473): `token_id={}&node_id={}&name={}&pubkey_hex={}` — values are **not** URL-encoded (`node_id` uses `NodeId`'s `Display`, `pubkey_hex` is `hex::encode(identity.static_public_key)`).
- **No auth and no signature** on the callback (Launch docstring `app.py:1384-1391`: "Auth: none… we only flip a status flag").
- Response handling:
  - 2xx → prints "Bootstrap confirmed token redemption (HTTP n)"; then `extract_json_string_field(body, "autobind")` (9617-9627) and branches on `"applied" | "already_bound" | "invalid" | "provisioning_incomplete" | "skipped" | other` (9524-9559).
  - 429 → `extract_json_number_field(body, "retry_after_seconds")` (9636-9650), default 60; warning only.
  - other ≥ 300 → loud warning "dashboard token may still show 'active' until the next TokenReconciler sweep".
  - curl failure / spawn failure → warning. **Never fails enrollment.**
- Expected server answers:
  - Launch (`ztlp.net/launch_app/app.py: handle_enrollment_confirm`, 1357-1614): requires `token_id` to match `^[0-9a-f]{32}$` (1422), looks up `onboarding_requests WHERE enrollment_token_uri LIKE '%token=<id>%'`, sets `enrollment_status='redeemed'`, `enrollment_redeemed_at`, `enrollment_redeemed_node_id`; optional first-bind of `pubkey_hex`; returns `200 {"status":"redeemed","name":..,"autobind":<status>[,"autobind_detail":..]}`; `400` missing/invalid token_id; `404` unknown; `429 {"error":"rate_limited","scope":"enrollment_confirm","retry_after_seconds":60}`.
  - Bootstrap Rails (`bootstrap/app/controllers/api/enrollment_controller.rb:5-65`, `POST /api/enrollment/confirm`): params `token_id`, `node_id`, `name` (ignores `pubkey_hex`); `token.use!`; `find_or_initialize_by(node_id:)` a `ztlp_devices` row (name defaults `device-<first 8 of node_id>`), sets `device.ztlp_user_id = token.ztlp_user_id` if present; returns `{status:"confirmed", token_id, current_uses, max_uses, exhausted, device_id, device_name}`; `404` / `422`.

Grep hits for "autobind"/"redeemed" in the CLI are all inside `confirm_enrollment`, its two JSON helpers, and the tests at 15086-15140.

### 2.5 Token minting side in the CLI — `ztlp admin enroll`

`AdminCommands::Enroll` (989-1025): `--zone`, `--secret <path>` (default `<ztlp_dir>/zone.key`), `--ns-server`, `--relay` (repeatable, ≥1 required), `--gateway`, `--expires` (default `24h`), `--max-uses` (default 1), `--count`, `--qr`.
`cmd_admin_enroll` (10200-10323) reads 64-hex `zone.key`, `EnrollmentToken::create(zone, ns_server, relay_addrs, gateway, max_uses, expires_at, &secret)`, prints `token.to_uri()` to stdout (optionally `qr2term`). No callback / token_id is ever minted by the CLI path.
`cmd_admin_init_zone` (10140-10196) and `create_network_files` (9906-9939) write `zone.key`.

---

## 3. Relay secret on the client today

### 3.1 Config model — `proto/src/agent/config.rs`

`pub struct TunnelConfig` (lines 192-256), relevant fields:
```rust
pub relays: RelayAddrs,                 // #[serde(alias = "relay")] — `relays = [...]` or `relay = "addr"`
pub relay_secret: Option<String>,       // line 250 — 64 hex / `base64:...` / raw; must equal relay's ZTLP_RELAY_REGISTRATION_SECRET or ZTLP_HMAC_SECRET_<ZONE>
pub relay_secret_file: Option<String>,  // line 255 — path; contents trimmed; `relay_secret` wins when both set
```
```rust
impl TunnelConfig {
    pub fn relay_secret_bytes(&self) -> Option<Vec<u8>>   // lines 260-280
}
```
`relay_secret_bytes` → `crate::tunnel::decode_relay_secret(s)` for inline; else reads file (warns `[tunnel] relay_secret_file … is empty` / `cannot read relay_secret_file`); else `None`. Defaults `None`/`None` (lines 432-433).

Decoder: `pub fn decode_relay_secret(raw: &str) -> Vec<u8>` in `proto/src/tunnel.rs:3181-3195` — trim; `base64:` prefix → STANDARD base64 decode (fallback raw); exactly 64 hex chars → 32 raw bytes; else raw ASCII bytes. Mirrors Elixir `ZtlpRelay.HmacSecrets.decode_secret/1`.

### 3.2 Runtime use

- Daemon: `proto/src/agent/daemon.rs:45-58` — `static RELAY_SECRET: RwLock<Option<Vec<u8>>>` and `pub(crate) fn set_relay_secret(secret: Option<Vec<u8>>)`. Installed once in `run_daemon` (1025-1044) from `config.tunnel.relay_secret_bytes()`; logs "relay CLIENT_ROUTE signing enabled (N-byte secret)" or warns "no [tunnel] relay_secret configured: CLIENT_ROUTE frames are unsigned". Consumed by `build_signed_client_route` (test at 2630-2656). CLIENT_ROUTE frame layout: `[magic(2) | type(1) | node_id(16) | svc_len(1) | service(N) | timestamp(8 i64 BE) | hmac(32)]` (`tunnel.rs:3197-3198`).
- `ztlp connect`: flags `--relay-secret` / `--relay-secret-file` on the connect command (lines 242-252); `resolve_relay_secret(cli_secret, cli_secret_file, agent_cfg) -> Option<Vec<u8>>` (1814-1838) precedence: CLI literal → CLI file → `agent_cfg.tunnel.relay_secret_bytes()` → `None` (unsigned). Used at 14034-14041.

### 3.3 `ztlp setup --relay-secret` / `--relay-secret-file`

- `resolve_setup_relay_secret(inline: &Option<String>, file: &Option<PathBuf>) -> Result<Option<String>>` (9835-9848): returns the **trimmed string as given** (no decoding) — inline wins; file read with `std::fs::read_to_string` and trimmed; error if the file can't be read.
- Stored in `SetupOpts.relay_secret` and written verbatim into `agent.toml` by `write_agent_config_file` (9950-10023), which refuses to overwrite an existing file (`"{} already exists; not overwriting"`), chmods 0600 on unix ("holds the relay secret"), and writes:

```toml
# ZTLP agent configuration — generated by `ztlp setup`
# Zone: <zone>

[identity]
path = "<key_path>"

[ns]
servers = ["<ns_server>"]

[tunnel]
relays = ["<relay1>", "<relay2>"]
relay_secret = "<as given>"
# — or, when None:
# relay_secret = "<64-hex shared with the relay's ZTLP_RELAY_REGISTRATION_SECRET>"  # required for prod-HMAC relays

[dns]
enabled = true
listen = "127.0.0.55:15353"      # SETUP_DEFAULT_DNS_LISTEN, line 9946
zones = ["<zone>"]

[tls]
enabled = <true iff <ztlp_dir>/ca/intermediate.pem exists>
```

- There is **no file named `relay.secret` anywhere in the code**; the only occurrence is a test temp filename (`ztlp-cli.rs:14792`). `docs/ADMIN-PANEL-PLAN.md:77` and `docs/DIRECT-FIRST-DIAL-PLAN.md:214` refer to "`relay.secret` / `relay_secret_file`" loosely; the real mechanism is `[tunnel] relay_secret` (inline) or `[tunnel] relay_secret_file` (path). A token-carried secret could either be written inline as `relay_secret = "…"` (today's `--relay-secret` behaviour) or written to a new 0600 file (e.g. `<ztlp_dir>/relay.secret`) referenced by `relay_secret_file`; the agent already supports both.
- Existing `agent.toml` is never modified by setup (hand-tuned wins), so a token-carried secret would not reach an existing config without extra logic (compare `enable_tls_in_agent_config`, 10031+, which does a surgical in-place edit of a generated file).

---

## 4. Device name and owner / user attachment

### 4.1 Name
See §2.3 steps 2-3 and 7: `--name` or `get_hostname()`; FQDN `<device>.<zone>`; `-<4 hex of node_id>` suffix via `disambiguated_device_name` on name collision with another key. NS enforces `name` ends with `.<zone>` (`enrollment.ex:307`, else `0x08 0x04`).

### 4.2 Owner — not attached at enrollment today
- `--owner` exists on `Setup` (line 689-691) but is bound to `_owner_arg` in `cmd_setup` (8912) and **never read**; `--type` → `_setup_type` (8911) likewise unused (`SetupType { Device, User }`, 1448-1453).
- The NS KEY record created by `do_register` has no owner field. Ownership lives in a separate **DEVICE record, type `0x10`**, created by `ztlp admin link-device <device> --owner <user>` → `cmd_admin_link_device` (10436-10507): looks up the KEY record (`ns_query_raw(.., 1)`), builds CBOR `{"owner", "node_id", "public_key"}` via `cbor_map`, `build_registration_packet(device_name, 0x10, &data_bin)` (a REGISTER 0x02 packet), expects NS reply byte `0x06` or `0x02`.
- Users: `ztlp admin create-user <name> --role {user|tech|admin} --email` (`AdminCommands::CreateUser`, 1037-1056) → `cmd_admin_create_user` (10328+) registers a **USER record**; `enum UserRole { User, Tech, Admin }` (1465-1480) with `role_to_str` (10427-10432) → `"user"|"tech"|"admin"`. `desktop/src-tauri/src/setup.rs:466,830` mirrors these strings. `UserRole` does **not** appear in `identity.rs`.
- Consumers of owner: gateway-side policy chain at 5125-5193 (`device_name --(DEVICE 0x10)--> owner --(GROUP 0x12)--> group`), `device_owner()` (2796-2805), `cmd_admin_devices` (10510+, filters DEVICE records by `owner`).
- Bootstrap Rails attaches a user only via its own DB: `device.ztlp_user_id = token.ztlp_user_id` in the confirm callback (`enrollment_controller.rb:43-45`).

### 4.3 OS-user binding (identity.rs / user_binding.rs) — different concept from "owner"
- `NodeIdentity` (`proto/src/identity.rs:83-123`): `node_id: NodeId`, `static_private_key: Vec<u8>` (hex), `static_public_key: Vec<u8>` (hex), `bound_user_sid: Option<String>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`, lines 96-107), `signing_key_seed: Option<Vec<u8>>` (Ed25519, lines 109-122). `generate()` 128-151, `load()` 160-172 (lazily adds a signing seed), `save()` 188-199 (chmod 0600), `signing_key()`, `signing_public_key_hex()`, `sign()`.
- `proto/src/agent/user_binding.rs`: `pub enum BindingError { Mismatch{expected,actual}, ResolutionFailed(String) }` (28-45); `pub fn current_user_sid() -> Result<String, BindingError>` (50) — Windows SID via `whoami /user /fo csv /nh`, Unix `uid:<n>` via `id -u`; `pub fn verify_user_binding(identity, current_sid)` (148-157). Enforced in `daemon.rs:581-615`.
- Set at enrollment only via `ztlp setup --bind-user` (`setup_join` 9063-9073); rejected on the create-network path (8963-8969). This records *which OS account may run the daemon*; it does not attach a ZTLP user/owner identity.

---

## 5. Existing tests to pattern a new flag-gated field after

### 5.1 Unit tests in `proto/src/enrollment.rs` (`#[cfg(test)] mod tests`, lines 757-1358)
Helper `fn test_secret() -> [u8;32]` (761-766).

| Test | Lines | What it pins |
|---|---|---|
| `test_create_and_serialize_roundtrip` | 768-792 | `create` → `serialize` → `deserialize`, all fields incl. gateway |
| `test_base64url_roundtrip` | 794-811 | `to_base64url` / `from_base64url` |
| `test_uri_roundtrip` | 813-830 | `to_uri` prefix + parse |
| `test_validate_valid_token` / `_wrong_secret` / `_expired_token` | 832-879 | `TokenValidation::{Valid,InvalidMac,Expired}` |
| `test_validate_tampered_zone` | 881-899 | byte flip in zone → `InvalidMac` (template for "new field is MAC-covered") |
| `test_multiple_relay_addrs` | 901-924 | relay_count loop |
| `test_hmac_blake2s_deterministic` / `_different_keys` | 926-943 | |
| `test_parse_duration_secs`, `test_generate_enrollment_secret` | 945-962 | |
| `test_deserialize_truncated`, `test_deserialize_wrong_version` | 964-978 | error paths |
| `test_expires_in_human` | 980-999 | |
| `test_from_query_param_uri`, `_multiple_relays`, `_with_gateway` | 1001-1025 | query-param parsing |
| `test_percent_decode_handles_callback_url_encoded_chars`, `_rejects_malformed_encoding`, `_does_not_treat_plus_as_space` | 1038-1076 | `percent_decode` |
| `test_from_query_param_uri_decodes_callback`, `_full_v030_10_shape_decodes_callback`, `_malformed_callback_rejected` | 1078-1126 | callback param |
| `test_from_query_param_uri_missing_zone` / `_missing_token` | 1128-1138 | required params |
| `test_binary_format_still_works`, `test_uri_format_still_works` | 1140-1178 | regression: old forms unaffected by new parsing |
| `test_from_query_param_uri_parses_mac_and_nonce_when_present`, `_zeros_when_absent` | 1190-1241 | signed-form params |
| `test_signed_query_param_token_validates_against_secret` | 1243-1310 | **hand-built canonical byte buffer** (version, flags=0x01, len-prefixed strings, relay_count, max_uses, expires, nonce) → `hmac_blake2s` → URI → `validate()==Valid`. This is the golden-vector pattern shared with `ns/test/ztlp_ns/enrollment_test.exs` and `ztlp.net/tests/test_launch_app.py` |
| `test_signed_query_param_token_rejects_wrong_secret` | 1312-1357 | same with flags=0x00, no relays |

Notably **absent**: a test that a token with `callback_url` round-trips through `serialize`/`deserialize` with flag `0x02`, and a test that a token with `callback_url` + signed params validates. The Elixir side does cover `0x02`: `ns/test/ztlp_ns/enrollment_test.exs` — helper `create_token(secret, opts)` (lines ~29-50 builds flags `0x01|0x02`), tests `"token with callback URL (flag 0x02) enrolls successfully"` (122), `"token with gateway AND callback (flags 0x03) parses and returns gateway"` (133), `"callback token: MAC still covers the callback bytes (tamper is rejected)"` (147).

Suggested pattern for a new flag (e.g. `FLAG_HAS_IDENTITY = 0x04`, `FLAG_HAS_RELAY_SECRET = 0x08`): add to `serialize_without_mac` / `deserialize` after callback; add tests mirroring `test_create_and_serialize_roundtrip` (field present/absent), `test_validate_tampered_zone` (flip a byte inside the new field → `InvalidMac`), `test_binary_format_still_works` (flags=0x00 bytes identical to today), a hand-built golden vector like `test_signed_query_param_token_validates_against_secret`, and an "unknown flag bits → Err" test if the fail-closed check from `ADMIN-PANEL-PLAN.md:80-82` is added. Mirror in `ns/test/ztlp_ns/enrollment_test.exs::create_token` and `ns/lib/ztlp_ns/enrollment.ex:parse_token`.

### 5.2 Setup/agent.toml tests in `proto/src/bin/ztlp-cli.rs` (`#[cfg(test)] mod tests` at 14510+)
Helper `fn fresh_tmp(label) -> PathBuf` (15225-15238).

| Test | Lines |
|---|---|
| `resolve_relay_secret_prefers_cli_then_file_then_agent_config` | 14786-14829 |
| `extract_json_string_field_handles_launch_ack` / `_handles_whitespace` / `_returns_none_for_missing_field` / `_returns_none_for_non_json_body` / `_returns_none_for_empty_body` | 15090-15129 |
| `extract_json_number_field_parses_launch_429` (+ siblings) | 15132+ |
| `guard_existing_identity_refuses_without_force_even_with_yes` / `_is_noop_when_absent` / `_force_backs_up_all_three_files` / `_force_also_backs_up_zone_key` | 15240-15309 |
| `create_network_files_refuses_when_identity_exists_without_force` / `_force_backs_up_then_writes_fresh_secret_and_identity` | 15311-15340 |
| `write_agent_config_file_enables_tls_when_ca_intermediate_exists` | 15342+ |
| `enable_tls_in_agent_config_flips_generated_false_to_true` / `_is_noop_when_file_missing_or_hand_tuned_without_tls_section` | 15371-15442 |
| `write_agent_config_file_produces_loadable_agent_config` (asserts `cfg.tunnel.relay_secret_bytes().unwrap().len() == 32` from a 64-hex secret) | 15443-15477 |
| `write_agent_config_file_without_secret_leaves_relay_secret_unset` (asserts the commented `relay_secret` hint) | 15479-15502 |
| `write_agent_config_file_refuses_to_clobber_existing` | 15504-15520 |

A test module also exists at `ztlp-cli.rs:5002` (`#[cfg(test)]`, gateway/policy area).

### 5.3 Other relevant test files
- `proto/src/agent/config.rs` tests: `tunnel_relay_secret_defaults_to_none` (897), `tunnel_relay_secret_parses_and_decodes_hex` (904), `tunnel_relay_secret_file_is_read_and_trimmed` (917); `ztlp_state_dir_*` (826, 835) use `ZTLP_HOME_TEST_LOCK` (819).
- `proto/src/tunnel.rs`: `decode_relay_secret_matches_relay_rules` (3369-3397).
- `proto/src/agent/daemon.rs`: `build_signed_client_route_uses_installed_relay_secret` (2633).
- `proto/tests/agent_user_binding_test.rs`: `test_no_binding_returns_ok`, `test_matching_binding_returns_ok`, `test_mismatched_binding_errors`, `test_identity_deserializes_without_bound_user_sid`, `test_current_user_sid_returns_something`.
- `proto/tests/pin_test.rs`: `test_pin_saved_during_enrollment` (184) etc. for `pin_gateway_key`.
- Cross-implementation: `ns/test/ztlp_ns/enrollment_test.exs`, `ztlp.net/tests/test_launch_app.py` (golden vector + `&callback=` shape, lines ~1555-1631), `bootstrap/test/controllers/api/enrollment_controller_test.rb`.

---

## 6. Quick index of names

| Symbol | File:line |
|---|---|
| `TOKEN_VERSION`, `FLAG_HAS_GATEWAY`, `FLAG_HAS_CALLBACK` | `proto/src/enrollment.rs:37,40,59` |
| `EnrollmentToken::{create,serialize,to_base64url,to_uri,deserialize,from_base64url,from_query_param_uri,validate,is_expired,expires_in_human,serialize_without_mac}` | `:107,140,147,153,158,268,303,388,414,426,451` |
| `write_len_prefixed_string`, `hex_decode_fixed`, `percent_decode`, `hex_nibble`, `read_len_prefixed_string`, `hmac_blake2s`, `constant_time_eq`, `generate_enrollment_secret`, `pin_gateway_key`, `parse_duration_secs` | `:504,516,550,576,585,624,629,635,649,729` |
| `Commands::Setup`, `SetupType`, `UserRole`, `AdminCommands::Enroll/CreateUser/LinkDevice` | `proto/src/bin/ztlp-cli.rs:675,1448,1466,989,1037,1067` |
| `cmd_setup`, `setup_join`, `setup_create_network`, `confirm_enrollment`, `extract_json_string_field`, `extract_json_number_field`, `build_enroll_packet`, `parse_enroll_config`, `ns_name_is_taken_by_other_key`, `disambiguated_device_name`, `write_config_file`, `SetupOpts`, `resolve_setup_relay_secret`, `guard_existing_identity`, `CreatedNetworkFiles`, `create_network_files`, `SETUP_DEFAULT_DNS_LISTEN`, `write_agent_config_file`, `enable_tls_in_agent_config`, `get_hostname`, `get_ztlp_dir`, `cmd_admin_init_zone`, `cmd_admin_enroll`, `cmd_admin_link_device`, `resolve_relay_secret` | `:8908,8977,9310,9447,9617,9636,9653,9689,9747,9768,9774,9826,9835,9857,9894,9906,9946,9950,10031,10070,10081,10140,10200,10436,1814` |
| `TunnelConfig`, `relay_secret`, `relay_secret_file`, `relay_secret_bytes`, `ztlp_state_dir` | `proto/src/agent/config.rs:192,250,255,260,642` |
| `decode_relay_secret` | `proto/src/tunnel.rs:3181` |
| `RELAY_SECRET`, `set_relay_secret` | `proto/src/agent/daemon.rs:51,54` |
| `NodeIdentity`, `bound_user_sid` | `proto/src/identity.rs:83,107` |
| `BindingError`, `current_user_sid`, `verify_user_binding` | `proto/src/agent/user_binding.rs:28,50,148` |
| NS: `process_enroll`, `validate_token`, `parse_token` flags handling, `register_device`, `do_register`, `build_config_response` | `ns/lib/ztlp_ns/enrollment.ex:78,145,241-269,303,336,410` |
| Launch: `handle_enrollment_confirm`, `_build_token_uri`, `_serialize_enrollment_token_for_signing` | `ztlp.net/launch_app/app.py:1357,~2285,2414` |
| Bootstrap: `Api::EnrollmentController#confirm` | `bootstrap/app/controllers/api/enrollment_controller.rb:12` |
