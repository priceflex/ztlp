# Gateway Trust via ZTLP-NS — Implementation Plan (v2)

> For the implementing session: work task by task, strict TDD (RED → GREEN → commit).
> Phase 0 is operations on live boxes: every step that touches a live box needs
> Steven's explicit OK first, one step at a time. Phases 1-6 are code on a branch
> off `main`. Do not push tags or rotate secrets without asking.

Status (2026-10-24): Phases 1-5 DONE and released as v0.36.0 code on `feat/ns-anchored-gateway-trust`.
Phase 0 (live CF gateway fixes, key backup) and the Phase 6 rollout/live proof are NOT done: they touch
live boxes and need Steven's OK per step (see "Operator rollout" below).

Deviations from v2 found while implementing (code facts, see commits):
- 2.4 `ns_cache::put(dir, raw, anchors, now)` re-verifies the raw bytes itself (no separate
  `VerifiedRecord` arg, so cache content can never disagree with what was verified). Serial watermark
  is its own file and survives expiry (replay of an older unexpired record stays refused).
- 2.5 `ns_query_verified` also rejects a genuinely signed record for a different name/type
  (`WrongRecord`). NS silent -> cached record; lower serial -> newer cached record.
- 2.6 Trusted keys live in `~/.ztlp/ns_trust.toml` (`[[server]]`), NOT `agent.toml`: `[ns] servers`
  is already a string list, `agent.toml` is template-generated + hand-tuned (NSSET would rewrite it
  hourly), and `AgentConfig::load_from_path` falls back to defaults on any parse error (would quietly
  drop strict mode). Malformed trust file = error, never "no trust". Phase 3.3/4.3 write this file.
- 3.2 NSSET = OPERATOR record (type 0x07) at the zone APEX, not `_ns.<zone>`: the NS name validator
  rejects `_`, and an SVC name could collide with a real host. OPERATOR registrations are now refused
  (signed and unsigned) so nobody can get the NS to sign a forged server list. Config:
  `ZTLP_NS_NSSET_ZONES`, `ZTLP_NS_SELF_ADDR`, `ZTLP_NS_PEERS=label=ip:port=hexkey=z1,z2;...`,
  `ZTLP_NS_NSSET_TTL`. NSSET capped at 1900 encoded bytes (client 2 KB reply budget).
- 2.5+ Records carrying `registered_unsigned=true` (dev-mode NS signs unauthenticated registrations
  with its own key) are refused as unverified: that signature vouches for nothing.
- 4.3 `ztlp setup` with a 0x10 token also does one verified lookup of the device's OWN new KEY record
  (signed by the token key, carrying its tunnel key) before writing any config: proves the server it
  enrolled with holds the key even when the NS publishes no NSSET.
- 5.3 `ztlp connect` (CLI) still dials with legacy trust (own resolution code + opt-in persistent
  endpoint path). Agent path (desktop apps, Windows service, Linux/macOS daemons) is covered.
- 4.1 Token minters: `ztlp admin enroll` (updated, `--ns-key`), `bootstrap/` (shells out to the CLI:
  pass `--ns-key` there), ztlp.net launch app (`launch_app/app.py` mints binary tokens itself, no 0x10
  yet), Z2LS (separate repo). Tokens without 0x10 keep legacy trust + WARN: follow-ups, not blockers.
- Pre-existing issues seen (not fixed here): `proto/tests/quic_handshake_vector_test.rs` rewrites
  `gateway/test/fixtures/quic_handshake_vector.json` with random keys on every `cargo test`
  (never stage it); `--no-default-features --features ios-sync` fails on `r3_pool_consult.rs` (tokio).
Code branch: `feat/ns-anchored-gateway-trust` (create from `origin/main`, v0.35.20 `b7875708`).

v2 changes vs v1: no per-gateway pin files at all (signed-record cache instead); the name-server
key arrives in the enrollment token, not with the app and not on first use; one home name server
vouches for the others through a signed server list; no fallback to weaker checks; stale-record and
replay rejection; the 3 enrolled devices are re-enrolled instead of migrated.

---

## 1. Goal

A gateway rebuild, restart, or certificate change must never require any end-user action, at any
fleet size. At the same time the client must actually authenticate the gateway (today it does not,
section 2.3).

End state, in one sentence: each device trusts exactly one key per name server, received at
enrollment; the name server signs every answer, including each gateway's current QUIC certificate
fingerprint; the client accepts a gateway only if its certificate matches a signed, unexpired record
and the TLS handshake proves the gateway holds that certificate's private key.

## 2. Verified facts (origin/main v0.35.20 + live boxes, 2026-10-22)

### 2.1 Why the ChooseForce pin broke
- CF gateway (`10.42.42.112`, container `ztlp-gateway-rust`, `~/ztlp-gateway-rust/docker-compose.yml`)
  runs image `ztlp-cli:signed-reg` = **ztlp 0.35.13**.
- Before v0.35.17 the gateway makes a fresh self-signed QUIC cert on every start
  (`quic_transport.rs::generate_ephemeral_self_signed`). Our compose recreate on 2026-10-23 05:37 UTC
  produced `7e23d6f4…`; clients had pinned `1ed9b2e9…`.
- `identity.json` is unchanged since 2026-10-05 03:58 UTC (same sha256 live and in the 2026-10-17 PBS
  backup). The QUIC cert is not derived from it; restoring backups cannot fix a pin.
- v0.35.17 (`db9aa5f8`, ZT-06): `ZTLP_QUIC_CERT_DIR=<dir>` persists `quic-cert.der` + `quic-key.der`
  (`load_or_generate_self_signed_in`).

### 2.2 Client pin today (`proto/src/quic_transport.rs`)
- `TofuCertVerifier` (~355): trust on first use, pin file `$HOME/.ztlp/quic_pins/<key>.pin` (hex
  SHA-256 of the leaf DER), key from `pin_key_for_service(remote, sni, relayed_service)`. macOS daemon
  HOME is `/Library/Application Support/ZTLP`; the Windows service uses the SYSTEM profile.
- `verify_or_pin` (~544): mismatch = hard fail with "delete the pin". No expiry, no recovery.
- Dial sites: `QuicEndpoint::connect_with_socket_for_service` (~902) builds the verifier. Callers:
  `agent/daemon.rs:3236` (agent: desktop apps + Windows service) and `bin/ztlp-cli.rs:4277` (`ztlp connect`).

### 2.3 SECURITY GAP (fix first): the pin proves nothing today
`verify_tls12_signature`/`verify_tls13_signature` (~595-610) return `assertion()` unconditionally. The
TLS 1.3 CertificateVerify signature is the only proof the server holds the cert's private key. The
cert is public (every client sees it), so an on-path attacker can present the pinned cert, sign the
handshake with their own key, and pass the pin check. Nothing else catches it:
- Data frames after the handshake are plaintext `0x5A|len|bytes` inside QUIC TLS; Noise only
  authenticates the client and binds the session.
- Desktop clients never check the gateway's Noise static key (`handshake.rs::verify_gateway_pin` is
  only called from the iOS FFI).
- Noise is not bound to the TLS channel: a MITM can terminate QUIC on both sides and relay Noise
  untouched, so the real gateway still sees the real client while the MITM reads all data.

### 2.4 Name server facts (`ns/lib/ztlp_ns/`)
- Registration `0x09` (`ztlp-cli.rs::build_signed_registration_packet` ~7064): signed by the gateway
  over `type|name_len|name|data`. SVC data: `address`, `node_id`, `zone`, optional `addresses` (~7255).
- NS verifies the registrant signature + zone authority (`server.ex:~580`), adds
  `registered_by=<registrant pubkey hex>`, and re-signs the stored record with the NS registration key
  (`Record.sign(record, server_priv)`, `server.ex:~620`). The registrant's own signature is not kept.
- NS key persisted: `Config.identity_key_file/0` → `<ca_data_dir>/registration_signing.key`
  (`ZTLP_NS_IDENTITY_KEY_FILE` override). Stable across restarts.
- Query `0x01` → `<<0x02, Record.encode(record)>>`; `encode = canonical || sig_len::16 || sig ||
  pub_len::16 || pub`; `canonical = type::8 | name_len::16 | name | data_len::32 | cbor | created_at::64
  | ttl::32 | serial::64` (`record.ex:94`, `:196`). CBOR keys sorted. The NS caps a reply at 8× the
  query size; the client pads queries to 256 B (2 KB budget).
- Replication (`anti_entropy.ex:237-248`): replicated records keep their ORIGINAL signature and are
  rejected unless `Record.verify` passes; higher serial wins. So replicas serve records signed by the
  home key. A replica needs its own trusted key only if it accepts new registrations itself.
- The NS already authors records itself using the registration key (`relay_seeder.ex`). The server
  list in Phase 3 follows that pattern.
- Elixir gateway already verifies NS records against `ZTLP_GATEWAY_TRUST_ANCHORS=label:hexpubkey`
  (`gateway/lib/ztlp_gateway/config.ex:168`). **The Rust client has no record verification at all**:
  `agent/proxy.rs::ns_query_raw` (~284) strips the reply to bare CBOR and drops the signature.
- Live: TRS primary NS `44.227.148.151` (`ztlp-ns:v0.35.19`, `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=true`);
  customer-fleet NS `44.230.7.100`. A device may belong to several name servers.

### 2.5 Enrollment facts
- Token flag bits (`proto/src/enrollment.rs:40-70` / `ns/lib/ztlp_ns/enrollment.ex:272-304`):
  `0x01` gateway addr, `0x02` callback URL, `0x08` relay secret. `0x04`/`0x10` unused. Both parsers
  must learn any new flag together (the `0x02` skew broke enrollment once; see the skill).
- ENROLL `0x07` request / `0x08` reply. Success reply: `<<0x08, 0x00, relay_count::8, relays...,
  gateway_count::8, gateways...>>` (`enrollment.ex:40-54`). Not signed; the transport is plain UDP.
- Agent check-in: hourly, signed by the device's enrolled signing key (`agent/ns_checkin.rs`, v0.35.19+).

### 2.6 Carry-forward observations
- CF compose passes `--admin-pubkey-email fe0f39312fd8f9a4c986=steve@techrockstars.com`: 20 hex chars,
  not a 64-hex X25519 key. Probably truncated; it would break the `/ztlp/who` SSO email header.
- Enrolled ChooseForce devices: `~/customer-records/chooseforce-ztlp-clients/tracker.md`
  (heidys-macbook-air-2 enrolled, carina-macbook-air pending) plus Steven's Macs. Three devices total.

## 3. Design

### 3.1 Trust chain
```
enrollment token (out of band: email / QR / Chef)  -->  home NS key  (the device's only root)
home NS signs:
   SVC www.chooseforce.ztlp   data.quic_cert_sha256 = <hex>, data.registered_by = <gateway pubkey>
   NSSET _ns.<zone>           list of {addr, pubkey, zones[]} for replicas / other servers
client dial:
   1. record signature verifies against a trusted NS key for that zone     (Phase 2)
   2. record unexpired (created_at + ttl > now) and serial >= last seen    (Phase 2)
   3. TLS CertificateVerify really verified against the presented cert     (Phase 1)
   4. sha256(leaf) == data.quic_cert_sha256                                 (Phase 5)
   mismatch -> one fresh lookup (cache bypass) -> else hard fail, no fallback
```

### 3.2 What a device stores
| Item | Lifetime | Source |
|---|---|---|
| Trusted NS keys: `[[server]] addr, key, zones, home` in `~/.ztlp/ns_trust.toml` (see status note) | permanent (updated by signed NSSET) | enrollment token (home), NSSET records (others) |
| Signed-record cache `~/.ztlp/ns_cache/<name>.<type>.rec` (raw `Record.encode` bytes) | until `created_at + ttl`; replaced by higher serial | every verified lookup |
| `~/.ztlp/quic_pins/*.pin` | **removed** for gateways with a published fingerprint; legacy only | n/a |

### 3.3 Decision rules (pure function, Phase 5)
Inputs: `record` (`Verified{fp, expired?, serial}` / `Unverified` / `None`), `presented` (leaf sha256),
`strict` (true when the device has ANY trusted key for the zone).

| record | strict | Decision |
|---|---|---|
| Verified, unexpired, fp == presented | any | ACCEPT; cache the record |
| Verified, fp != presented | any | REJECT `NsMismatch` (caller: one fresh lookup, then fail) |
| Verified but expired | any | treat as `Unverified` |
| Unverified / None | true | REJECT `UnverifiedAnswer` (no fallback, ever) |
| Unverified / None | false (no trusted key: legacy device) | legacy TOFU pin behavior, unchanged |

`strict` is derived, not configurable. There is no switch that re-enables the weak path on a device
that has a trusted key.

### 3.4 Where the NS key comes from
1. **Enrollment token, flag `0x10` `FLAG_HAS_NS_KEY`**, 32 raw bytes, covered by the token MAC.
   Minted by `ztlp admin enroll` (and any other minter: Z2LS, desktop app — inventory in task 4.1).
   The client holds the key before touching the network. During enrollment the ENROLL reply and the
   first lookups must verify against it, or enrollment fails.
2. **NSSET record** `_ns.<zone>` (type SVC-style, reserved name, authored by the NS itself like
   `relay_seeder`): `{"servers":[{"addr":"ip:port","pubkey":"<hex>","zones":["<zone>",...]}],
   "serial":N}`. Signed by the home key. Clients verify with the home key, then trust the listed
   keys for the listed zones only. Refreshed at enrollment and by the hourly check-in. Removing a
   server from the list removes its trust fleet-wide within an hour.
3. **Rotation of the home key**: publish an NSSET signed by the old key that lists the new key; clients
   switch; retire the old one in a later NSSET. No re-enrollment. Re-enrollment is the fallback if the
   old key is compromised.
4. **Separate organizations' name servers** get their own key through their own token. The home server
   cannot vouch for zones it is not authoritative for (NS-side check in task 3.2).
5. **No trust on first use anywhere.** The 3 currently enrolled devices are re-enrolled with new tokens.

### 3.5 Compatibility matrix
| Gateway | Client | Result |
|---|---|---|
| old (no fp published) | new, token with key | strict: SVC record verifies but has no fp → ACCEPT on TLS-verified cert, legacy pin as cache (documented interim; fleet upgrade removes it) |
| new | old client | ignores unknown CBOR key; legacy pins; still gets Phase 1 if updated |
| new + `ZTLP_QUIC_CERT_DIR` | new | stable cert; zero re-pins |
| new, ephemeral cert | new | fp republished at every start; clients follow after re-registration (retry path, task 5.4) |
| old token (no 0x10) | new client | legacy mode (`strict=false`) + WARN at every start; re-enroll to fix |

NS code changes: NSSET seeder + zone-scope check (Phase 3), token flag parse (Phase 4), optional
signed NSSET in the ENROLL reply (Phase 4). SVC data passthrough needs no change (proved in task 3.1).

## 4. Phase 0: stop the bleeding (operations, every step needs Steven's OK)

### Task 0.1 Read-only pre-checks
```bash
ssh trs@10.42.42.112 'docker exec ztlp-gateway-rust ztlp --version; docker exec ztlp-gateway-rust env | grep -c QUIC_CERT; ls -la ~/ztlp-gateway-rust/'
```
Expected: `ztlp 0.35.13`, `0`, no `quic-cert.der`. Resolve the truncated `--admin-pubkey-email` (2.6):
get Steven's Mac tunnel X25519 key and confirm the full 64-hex value.

### Task 0.2 Build the v0.35.20 gateway image
```bash
cd ~/projects/ztlp-quic-pin-ns && git checkout v0.35.20   # read proto/Dockerfile header for the build context first
docker build -t ztlp-cli:v0.35.20 -f proto/Dockerfile proto
docker run --rm --entrypoint ztlp ztlp-cli:v0.35.20 --version      # expect ztlp 0.35.20
docker save ztlp-cli:v0.35.20 | ssh trs@10.42.42.112 docker load
```

### Task 0.3 Compose change (show the exact diff before saving)
`image: ztlp-cli:v0.35.20`; add `ZTLP_QUIC_CERT_DIR: "/data"` under `environment:`; fix
`--admin-pubkey-email` if truncated. `cp docker-compose.yml docker-compose.yml.bak-pre-0.35.20` first.
Container runs as `1000:1000` with `./:/data` RW, so it can create the cert files.

### Task 0.4 Recreate the gateway (needs a window, ~10 s outage)
```bash
cd ~/ztlp-gateway-rust && docker compose up -d && sleep 5 && docker logs --tail 30 ztlp-gateway-rust
sha256sum quic-cert.der; docker compose restart; sleep 5; sha256sum quic-cert.der   # identical
```

### Task 0.5 Last manual re-pin (Steven's Macs, heidys-macbook-air-2)
`sudo rm "/Library/Application Support/ZTLP/.ztlp/quic_pins/localhost_10_42_42_112_23097.pin"` (plus any
relayed-pin variant for `www`), then `https://www.chooseforce.ztlp/ztlp/who` in a real browser. Record in
the tracker. After Phase 6 ships these devices are re-enrolled anyway (3.4 item 5).

### Task 0.6 Back up gateway key material outside the VM
`identity.json`, `quic-cert.der`, `quic-key.der` → the secret store Steven names (ask). PBS covers
them inside VM 296 weekly. Also back up the NS registration key
(`registration_signing.key` on `44.227.148.151`) the same way: after this plan it is the fleet's root.

### Task 0.7 Fleet audit (read-only) → `docs/QUIC-PIN-FLEET-AUDIT.md`
Every Rust `ztlp listen --gateway` (CF `.112`, blitz `10.69.95.12`, others), the Elixir
`ztlp-gateway-trs` (`ZTLP_GATEWAY_QUIC_DATA_DIR=/var/lib/ztlp/gateway`: confirm the volume persists
and the cert survives a restart), and the Windows endpoint listeners (gateways too; operators pin them;
version spread from Z2LS). Record version, cert persistence, restart-survival. Per-box fixes are
separate approved steps.

## 5. Phase 1: make the TLS signature check real (client, security)

Files: `proto/src/quic_transport.rs` (`TofuCertVerifier` impl; tests in `mod tofu_tests` ~1153).

### Task 1.1 RED: forged CertificateVerify rejected
```rust
#[test]
fn tls13_signature_from_a_different_key_is_rejected() {
    use rustls::client::danger::ServerCertVerifier;
    let real = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let attacker = rcgen::KeyPair::generate().unwrap();
    let cert: CertificateDer<'static> = real.cert.der().clone();
    let msg = b"tls13 transcript stand-in";
    let sig = sign_with(&attacker, msg);   // helper: ECDSA P-256 over msg; check rcgen 0.13 / provider API first
    let dss = rustls::DigitallySignedStruct::new(rustls::SignatureScheme::ECDSA_NISTP256_SHA256, sig);
    let v = TofuCertVerifier::with_pin_dir("sig.example", tempfile::tempdir().unwrap().path().to_path_buf());
    assert!(v.verify_tls13_signature(msg, &cert, &dss).is_err());
}
```
Run: `cd proto && cargo test --lib quic_transport::tokio_endpoint::tofu_tests::tls13_signature`
Expected: FAIL (returns `assertion()` today).

### Task 1.2 RED: genuine signature accepted (same, signed with `real.key_pair`, `is_ok()`). Regression guard.

### Task 1.3 GREEN
```rust
fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &rustls::DigitallySignedStruct)
    -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls13_signature(m, c, d, &self.algs())
}
fn verify_tls12_signature(/* same shape */) { rustls::crypto::verify_tls12_signature(m, c, d, &self.algs()) }
fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { self.algs().supported_schemes() }
// algs(): rustls::crypto::CryptoProvider::get_default().expect("ensure_crypto ran").signature_verification_algorithms
```
Rewrite the "intentionally a no-op" comment block.

### Task 1.4 Loopback test
Tokio test: server endpoint with `load_or_generate_self_signed_in(tmp)`, client with a fresh pin dir,
connect twice. Both succeed. Proves the provider accepts rcgen's default ECDSA P-256 leaf. Then
`cargo test --lib quic_transport` and `cargo test` (crate) all green.

### Task 1.5 Commit: `fix(quic): verify TLS CertificateVerify in TofuCertVerifier (pin now proves key possession)`

## 6. Phase 2: NS record verification + signed-record cache (client)

New module `proto/src/ns_verify.rs` (register in `lib.rs`). Pure, synchronous, no network.

### Task 2.1 Golden vector from the real Elixir encoder
`ns/test/ztlp_ns/record_test.exs`: deterministic signed SVC record (fixed seed keypair, fixed
created_at/ttl/serial, data `address`, `node_id`, `zone`, `registered_by`, `quic_cert_sha256`); assert
`Record.encode/1` equals a committed hex. Write the hex + signer pubkey hex to
`proto/tests/fixtures/ns_signed_svc_record.{hex,pub}`. Also an EXPIRED variant (small ttl, old
created_at) → `ns_signed_svc_record_expired.hex`. Run `cd ns && mix test test/ztlp_ns/record_test.exs`.

### Task 2.2 RED: parse + verify
```rust
#[test]
fn verifies_golden_ns_record() {
    let bytes = hex::decode(include_str!("../tests/fixtures/ns_signed_svc_record.hex").trim()).unwrap();
    let anchor: [u8; 32] = hex::decode(include_str!("../tests/fixtures/ns_signed_svc_record.pub").trim()).unwrap().try_into().unwrap();
    let rec = ns_verify::parse_signed_record(&bytes).unwrap();           // Record.encode bytes (after the 0x02 status byte)
    assert_eq!(rec.type_byte, 2);
    let v = ns_verify::verify(&rec, &[anchor], now_fixed()).unwrap();
    assert_eq!(v.data_str("quic_cert_sha256").as_deref(), Some("<fp from fixture>"));
}
```
More RED tests: flipped CBOR byte → `BadSignature`; signer not in anchors → `UntrustedSigner`;
expired fixture → `Expired`; truncated input → parse error, no panic; wrong `sig_len` → rejected.

### Task 2.3 GREEN
`parse_signed_record`: walk `type:u8, name_len:u16, name, data_len:u32, data, created_at:u64, ttl:u32,
serial:u64`; `canonical = bytes[..end]`; then `sig_len:u16, sig, pub_len:u16, pub`.
`verify(rec, anchors, now)`: signer ∈ anchors, `ed25519_dalek::VerifyingKey::verify_strict(canonical,
sig)`, `created_at + ttl > now`. Returns `VerifiedRecord { name, type_byte, data_cbor, signer,
created_at, ttl, serial }`. Never route through `parse_ns_record`/bare-CBOR helpers (documented
double-unwrap trap).

### Task 2.4 Signed-record cache `proto/src/ns_cache.rs`
API: `put(dir, &VerifiedRecord, raw_bytes)`, `get(dir, name, type, anchors, now) -> Option<VerifiedRecord>`,
`highest_serial_seen(dir, name, type)`. Files `<dir>/<sanitized name>.<type>.rec` (reuse the pin-path
sanitizer). RED tests: round trip; expired entry returns `None` and is deleted; a record with a lower
serial than the stored one is refused by `put` (replay guard); traversal names sanitized; verification
runs again on read (a tampered file returns `None`).

### Task 2.5 `ns_query_verified` in `agent/proxy.rs`
Sibling of `ns_query_raw` keeping the full `0x02` reply. Returns `NsAnswer::{Verified(VerifiedRecord),
Unverified(bare_cbor), NotFound}`. Keeps the 256 B padding. On `Verified`: `ns_cache::put`. On
`Unverified` with `strict`: error `UnverifiedAnswer`. Fake-UDP-NS test pattern as in `proxy.rs` ~1114,
serving the golden bytes; also a test where the NS is unreachable and the cache answers.
Leave every existing `ns_query_raw` caller untouched in this task.

### Task 2.6 Trusted keys in config (`agent/config.rs`)
```toml
[[ns.servers]]
addr  = "44.227.148.151:23096"
key   = "<64 hex>"
zones = ["trs.ztlp", "chooseforce.ztlp"]
home  = true
```
`NsConfig` gains `servers: Vec<NsServerTrust>`; keep the existing address list working for old files.
RED: TOML round trip; an old `agent.toml` without the table still parses (v0.35.18 regression);
`strict_for_zone(zone) -> bool` true iff some trusted entry lists that zone; anchors lookup by zone.

## 7. Phase 3: the NS vouches for its peers (NSSET) and publishes gateway fingerprints

### Task 3.1 SVC passthrough proof (Elixir, test only)
`ns/test/ztlp_ns/query_test.exs`: signed v2 SVC registration with `quic_cert_sha256`, query it back,
assert the key is present. Expected: passes without NS changes; otherwise fix and note here.

### Task 3.2 NSSET seeder (`ns/lib/ztlp_ns/ns_set_seeder.ex`, modeled on `relay_seeder.ex`)
Config `ZTLP_NS_PEERS="label=ip:port=hexpubkey=zone1,zone2;…"` (or the config-file equivalent used by
`relay_seeder`). On start and every TTL/2: author `_ns.<zone>` for each authoritative zone with the
server list (self first), serial = unix time, signed with the registration key. RED tests: record
content, re-seed bumps serial, a peer listed for a zone this NS is not authoritative for is refused
(3.4 item 4).

### Task 3.3 Client consumes NSSET
`agent/ns_checkin.rs`: after each check-in (and at enrollment) query `_ns.<zone>` via
`ns_query_verified`; on `Verified` by the HOME key, merge into `[[ns.servers]]` (add/update/remove
entries with `home=false`); persist config. RED tests: add, remove, zone scope enforced, a NSSET signed
by a non-home key is ignored, lower serial ignored.

### Task 3.4 Gateway publishes its fingerprint
`quic_transport.rs`: server reports `sha256(leaf DER)` of the cert it binds (RED: same dir twice →
same fp; equals the fp seen by a loopback client). `ztlp-cli.rs` SVC pairs (~7255): add
`("quic_cert_sha256", fp)`; extract `svc_record_pairs(...)` as a pure fn and test it; ensure
`cmd_listen` binds QUIC before the first NS registration (check order around `:5588`). Startup log:
`QUIC cert sha256=<fp> persisted=<dir|ephemeral>` + WARN when ephemeral.

## 8. Phase 4: enrollment carries the NS key

### Task 4.1 Inventory token minters (read-only)
`ztlp admin enroll` (`ztlp-cli.rs`), Z2LS, desktop app, any script. Every minter must set `0x10`.
List them in this file before coding.

### Task 4.2 Token flag `0x10 FLAG_HAS_NS_KEY` — Rust and Elixir together
Rust `enrollment.rs`: serialize/parse 32 raw bytes after the relay-secret field, covered by the MAC
(`serialize_without_mac`). Elixir `enrollment.ex::parse_token` (~304): skip the field when the flag is
set (the NS does not need the value). RED tests on BOTH sides, including: a token with `0x10` set parses
on the Elixir side (this is exactly the `0x02` skew bug); a token without it is byte-identical to today.
`ztlp admin enroll` reads the NS key from `--ns-key <hex>` or the NS's own key file.

### Task 4.3 Enrollment reply carries the signed NSSET (optional trailing field)
`enrollment.ex`: append `<<nsset_len::16, Record.encode(nsset)>>` to the success reply when an NSSET
exists. Rust: parser tolerates both old (no trailing field) and new replies (RED test for each), verifies
the NSSET with the token key, stores `[[ns.servers]]` (home + peers). If the token carries a key and
the first verified lookup/NSSET does not verify → enrollment fails with a clear message.

### Task 4.4 Old tokens
No `0x10` → `strict=false`, WARN at every agent start: "enrolled without a name-server key; re-enroll".
Agent `status` surfaces it.

## 9. Phase 5: client uses the published fingerprint; pins retired

### Task 5.1 Pure decision function (table 3.3)
`quic_transport.rs`: `fn decide_cert(record: &RecordState, presented: &str, strict: bool, cached_pin:
Option<&str>) -> CertDecision` with `Accept{cache_record: bool}` / `Reject(NsMismatch | UnverifiedAnswer |
LegacyPinMismatch)`. One RED test per table row + case-insensitive hex. GREEN. Commit.

### Task 5.2 Verifier takes the record state
`TofuCertVerifier` gets `expect: RecordState` and `strict: bool`; `verify_or_pin` → `decide_cert`.
Legacy `tofu_tests` stay green unchanged (`strict=false`, `RecordState::None`). New tests: verified
fp match ignores a stale pin file and does not need one; strict + unverified rejects even with a
matching pin; error text names the gateway and never says "delete the pin".

### Task 5.3 Thread it through
- `agent/proxy.rs`: `NsResolution` gains `record: RecordState` (from `ns_query_verified` on SVC).
- `QuicEndpoint::connect_with_socket_for_service` gains `expect: RecordState, strict: bool`;
  `connect_with_socket` passes `(None, false)`.
- `agent/daemon.rs:3236` and `bin/ztlp-cli.rs:4277` pass the resolution's state (direct and relayed
  dials alike: the cert is the gateway's either way).
- VIP cache (`VipEntry` / `set_peer_candidates`): cache the record state too; test that a cache hit
  dials with it.

### Task 5.4 Retry once on `NsMismatch`
Drop the cached resolution + cache entry for that name, re-resolve from the NS (cache bypass), redial
once; then fail. Test with a fake NS whose answer changes between queries (models the window after a
gateway restart before re-registration).

### Task 5.5 Retire `quic_pins` for covered gateways
When `RecordState::Verified` with fp: do not read or write a pin file. One-time cleanup (like
`remove_legacy_sni_pins`) of pins for names that now have verified fingerprints. Keep legacy behavior
only for `strict=false` devices.

## 10. Phase 6: release, rollout, live proof

1. `cargo fmt --check`, `cargo clippy`, `cargo test` (proto); `mix test` (ns, gateway). Full CI ~19 min
   (performance gate), don't call it stuck early.
2. Version bump (Steven picks 0.35.21 vs 0.36.0; the token flag and NSSET argue for 0.36.0), CHANGELOG,
   PR, fix CodeRabbit before merge, ask before tagging.
3. Rollout order: (a) NS: `ZTLP_NS_PEERS` + new image on `44.227.148.151` (and `44.230.7.100`);
   verify `_ns.trs.ztlp` resolves and verifies with the CLI; (b) gateways with `ZTLP_QUIC_CERT_DIR`:
   CF `.112`, blitz, then the audit list; confirm `quic_cert_sha256` in each SVC record; (c) clients:
   desktop app release + Windows service; (d) re-enroll the 3 devices with `0x10` tokens.
4. Live proof as a real user in a real browser (curl 200 does not count); tracker
   `docs/NS-ANCHORED-TRUST-TRACKER.md`:
   - Test gateway (not CF prod): delete `quic-cert.der`/`quic-key.der`, restart → browser on the AI
     computer and on a Mac keeps working with no user action; agent log shows NsMismatch → re-resolve
     → accept; `quic_pins` untouched.
   - Negative: gateway serving a cert that does not match its record → rejected, page does not load.
   - Negative: forged unsigned NS reply (fake UDP responder on the LAN) → `UnverifiedAnswer`, no connect.
   - Negative: replayed expired record → rejected.
   - Old client vs new gateway still works.
   - NSSET: add a replica → device trusts it within an hour; remove → trust gone within an hour.
5. Update the skill `ztlp-architecture-and-debugging` failure row and the SECURITY GAP note.

## Operator rollout (each step needs Steven's OK)
1. NS `44.227.148.151`: deploy `ztlp-ns:v0.36.0`; read "NS registration public key" from the log; set
   `ZTLP_NS_NSSET_ZONES` (+ `ZTLP_NS_SELF_ADDR`, peers if any); back up `registration_signing.key`
   off-box (it is now the fleet root).
2. Gateways (CF `.112` first): v0.36.0 image + `ZTLP_QUIC_CERT_DIR`; confirm the SVC record carries
   `quic_cert_sha256` (`ztlp ns lookup`).
3. Clients: desktop 1.3.0 / Windows service; re-enroll the 3 devices with
   `ztlp admin enroll --ns-key <key>` tokens.
4. Live proof per section 10.4 (real browser), tracker `docs/NS-ANCHORED-TRUST-TRACKER.md`.

## 11. Follow-ups (file as issues, not in this branch)
- `ztlp connect` (CLI) and the persistent-endpoint path: use the NS record state.
- ztlp.net launch app / Z2LS token minters: set flag 0x10.
- Channel binding: TLS exporter value into the Noise prologue, so Noise cannot be relayed by a MITM
  even if a gateway key leaks. Defense in depth after this plan.
- Keep the gateway's own registration signature in the stored record so clients verify gateway AND NS
  (a compromised NS alone then cannot fake a gateway). Needs an NS record-format change.
- Desktop/Windows check of the gateway's Noise static key against `registered_by` (iOS already does).
- Encrypted NS lookups (Noise/ZTLP channel to the NS) for privacy of queried names; an addition on
  top of signed records, not a replacement (adds a per-lookup handshake and a stateful NS).
- Elixir gateway: publish `quic_cert_sha256` for parity.
- iOS FFI path: same record-state logic.

## 12. Risks and open items
- Provider/rcgen agreement (Phase 1): ship only with the loopback test green, or every handshake breaks.
- The NS registration key is now the fleet root: strict file perms, off-box backup (task 0.6),
  minimal shell access on the Lightsail box. Compromise = re-enroll everything.
- Enrollment window: with `0x10` the key is in the token, so there is no first-contact window. Old
  tokens stay weak until re-enrolled (WARN + status, 4.4).
- Reply size: SVC + 64-hex field is far under the 2 KB budget; NSSET with many peers could approach it
  (assert in 3.2: cap peers or raise client padding).
- Relayed dials: relay forwards QUIC untouched, so the presented cert is still the gateway's; prove it
  in the live tests.
- Decisions for Steven: secret store for 0.6; version number; whether `44.230.7.100` becomes a peer of
  `44.227.148.151` (one home key for techs' laptops) or stays a separate home for customer devices.
