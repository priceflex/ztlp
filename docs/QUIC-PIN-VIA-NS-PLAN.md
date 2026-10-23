# Gateway QUIC Certificate Trust via ZTLP-NS — Implementation Plan

> For the implementing session: work task by task, strict TDD (RED → GREEN → commit).
> Phase 0 is operations on live boxes: every step that touches a live box needs
> Steven's explicit OK first, one step at a time. Phases 1-6 are code on a branch
> off `main`. Do not push tags or rotate secrets without asking.

Status: PLAN ONLY (written 2026-10-22). Nothing here has been implemented yet.
Branch for the code work: `feat/quic-pin-via-ns` (create from `origin/main`, currently v0.35.20 `b7875708`).

---

## 1. Goal

A gateway rebuild, restart, or certificate change must never require an end user to delete a pin
file. At the same time, the client must actually authenticate the gateway it is talking to (today it
does not, see section 2.3).

End state: the gateway publishes its QUIC certificate fingerprint in its signed SVC record in the
name server (NS). The client verifies the NS record's signature against a trusted NS key and accepts
the gateway's certificate only if it matches the published fingerprint and the TLS handshake proves
the gateway holds the matching private key. The local pin file becomes a cache. Users never touch it.

## 2. Background: verified facts (code on origin/main v0.35.20 + live boxes, 2026-10-22)

### 2.1 Why the ChooseForce pin broke

- The CF gateway (`10.42.42.112`, container `ztlp-gateway-rust`, `~/ztlp-gateway-rust/docker-compose.yml`)
  runs image `ztlp-cli:signed-reg` = **ztlp 0.35.13**.
- Before v0.35.17 the gateway generates a fresh self-signed QUIC cert on every start
  (`quic_transport.rs::generate_ephemeral_self_signed`). Our `docker compose down && up` on 2026-10-23
  05:37 UTC produced cert `7e23d6f4…`. Clients had pinned `1ed9b2e9…` from the previous run.
- `identity.json` (the gateway's Noise/Ed25519 key) has NOT changed since 2026-10-05 03:58 UTC:
  the live file and the 2026-10-17 PBS backup have the same sha256 (`ba73a24be860f475…`). The QUIC cert
  is not derived from identity.json, so restoring a backup can never fix a pin mismatch.
- v0.35.17 (`db9aa5f8`, ZT-06) added cert persistence: with `ZTLP_QUIC_CERT_DIR=<dir>` the gateway
  loads or creates `quic-cert.der` + `quic-key.der` there (`load_or_generate_self_signed_in`).
  Without the env var it still generates a new cert per start.

### 2.2 Client pin today (`proto/src/quic_transport.rs`)

- `TofuCertVerifier` (line ~355): trust on first use. The pin file is
  `$HOME/.ztlp/quic_pins/<sanitized pin key>.pin` holding a hex SHA-256 of the leaf cert DER.
  The pin key is `pin_key_for_service(remote, sni, relayed_service)`. On macOS the daemon HOME is
  `/Library/Application Support/ZTLP`, and the Windows service uses the SYSTEM profile.
- `verify_or_pin` (line ~544): if a pin exists and differs, hard-fail with "delete the pin". There is
  no expiry and no automatic recovery.
- Dial call sites: `QuicEndpoint::connect_with_socket_for_service` (line ~902) builds the verifier.
  Callers: `agent/daemon.rs:3236` (the agent: desktop apps and the Windows service) and
  `bin/ztlp-cli.rs:4277` (`ztlp connect`).

### 2.3 SECURITY GAP (must fix first): the pin does not prove anything today

`TofuCertVerifier::verify_tls12_signature` and `verify_tls13_signature` (lines ~595-610) return
`HandshakeSignatureValid::assertion()` without checking anything. In TLS 1.3, the CertificateVerify
signature is the only thing proving the server holds the private key for the certificate it presents.
The gateway's certificate is public (any client that connects sees it). So an attacker on the network
path can present the pinned certificate, sign the handshake with their own key, and pass the pin check.

The NS lookup does not close this gap either:
- After the handshake, data frames travel as plaintext `0x5A|len|bytes` inside QUIC's TLS
  (see the skill's "QUIC wire contract"). Noise is only used to authenticate the client and bind the session.
- The desktop client does not check the gateway's Noise static key against anything.
  `HandshakeContext::verify_gateway_pin` (`handshake.rs:286`) is only called from the iOS FFI.
- The Noise handshake is not bound to the TLS channel. A man-in-the-middle can terminate QUIC on both
  sides, relay the Noise messages untouched (so the real gateway still sees the real client), and read
  or modify all application data.

Phase 1 fixes the TLS signature check, which is what makes a pin (cached or NS-published) meaningful.
Channel binding is a listed follow-up (section 9).

### 2.4 Name server facts (`ns/lib/ztlp_ns/`)

- Gateway registration: `ztlp-cli.rs::build_signed_registration_packet` (line ~7064) sends opcode
  `0x09` with name, type, CBOR data, Ed25519 signature over `type|name_len|name|data`, and the gateway
  pubkey. The SVC data map today holds `address`, `node_id`, `zone`, and optionally `addresses`
  (line ~7255).
- The NS checks the registrant signature and zone authority (`server.ex:~580`), adds
  `"registered_by" => <registrant pubkey hex>` to the data, and **re-signs the stored record with the
  NS registration key** (`Record.sign(record, server_priv)`, `server.ex:~620`).
- That key is persisted: `Config.identity_key_file/0`, default `<ca_data_dir>/registration_signing.key`,
  overridable with `ZTLP_NS_IDENTITY_KEY_FILE`. It is stable across NS restarts.
- Query `0x01` returns `<<0x02, Record.encode(record)>>` where
  `encode = canonical || sig_len::16 || sig || pub_len::16 || pub` and
  `canonical = type::8 | name_len::16 | name | data_len::32 | cbor | created_at::64 | ttl::32 | serial::64`
  (`record.ex:94`, `:196`). CBOR uses sorted keys.
- The Elixir gateway already verifies NS records against `ZTLP_GATEWAY_TRUST_ANCHORS=label:hexpubkey`
  (`gateway/lib/ztlp_gateway/config.ex:168`, `ns_client.ex`). Live: `trs.ztlp:584a83c8…` on
  `ztlp-gateway-trs`. **The Rust client has no NS record signature verification at all.**
  `agent/proxy.rs::ns_query_raw` (line ~284) strips the response to bare CBOR, so the signature is
  thrown away.
- The TRS primary NS (`44.227.148.151`, container `ztlp-ns:v0.35.19`) has `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=true`.

### 2.5 Other live observations to carry forward

- The CF compose passes `--admin-pubkey-email fe0f39312fd8f9a4c986=steve@techrockstars.com`. That key
  is 20 hex characters, not a 64-hex X25519 key. Check in Phase 0 whether it is truncated, because it
  would break the `/ztlp/who` SSO email header even after the pin issue is fixed.
- The ChooseForce ZTLP device tracker is `~/customer-records/chooseforce-ztlp-clients/tracker.md`
  (heidys-macbook-air-2 enrolled, carina-macbook-air pending) plus Steven's Macs.

## 3. Design

### 3.1 Trust chain

```
NS registration key (stable, persisted)          <- client trust anchor (config / enrollment / first use)
  signs -> SVC record for www.chooseforce.ztlp
             data.quic_cert_sha256 = <hex sha256 of the gateway's leaf cert DER>
             data.registered_by    = <gateway Ed25519 pubkey>   (already present)
client dials a candidate -> TLS 1.3 -> presented leaf cert
  1. CertificateVerify signature really verified against the presented cert's key   (Phase 1)
  2. sha256(leaf) == data.quic_cert_sha256 from a signature-verified NS record       (Phase 4)
  3. accept + cache the pin; mismatch -> one fresh NS lookup -> else hard fail
```

### 3.2 Pin decision table (pure function, the heart of Phase 4)

Inputs: `cached` (pin file contents, optional), `presented` (sha256 of the leaf),
`ns` (`None`, `Unverified(fp)`, or `Verified(fp)`).

| ns | cached | presented vs ns / cached | Decision |
|---|---|---|---|
| `Verified(fp)` | any | presented == fp | ACCEPT, write the pin (overwrite if different) |
| `Verified(fp)` | any | presented != fp | REJECT `NsMismatch` (caller does one fresh NS lookup, then fails; no first-use fallback) |
| `Unverified(_)` or `None` | none | n/a | ACCEPT first use, write the pin (legacy behavior) |
| `Unverified(_)` or `None` | some | presented == cached | ACCEPT |
| `Unverified(_)` or `None` | some | presented != cached | REJECT `PinMismatch` (legacy message, minus "delete the pin" advice) |

An unverified NS fingerprint is never allowed to override a cached pin. Otherwise a spoofed NS reply
would just move the weak point.

### 3.3 Where the client gets the trusted NS key (`[ns] trusted_keys`)

In priority order:
1. `agent.toml` `[ns] trusted_keys = ["<64 hex>", ...]`. Explicit and works for the fleet via Chef or
   desktop config.
2. The enrollment response from the NS carries its registration pubkey, and the agent saves it to
   `trusted_keys`. This is for new enrollments; verify the 0x07 ENROLL reply format first (task 2.6).
3. Migration for devices that are already enrolled: trust the NS key on first use, per NS address,
   stored in `~/.ztlp/ns_trust/<sanitized ns addr>.key`. There is one NS key for the whole zone, it is
   persisted on the NS, and it is a far smaller target than per-gateway certs. It is logged loudly on
   first use. A changed NS key is a hard fail for verification (records are treated as `Unverified`,
   so behavior falls back to legacy pins without breaking connectivity) plus an ERROR log.

### 3.4 Compatibility

| Gateway | Client | Result |
|---|---|---|
| old (no fingerprint published) | new | NS data has no fingerprint, so legacy pin behavior (Phase 1 signature fix still applies) |
| new | old | old client ignores the unknown CBOR key, legacy pin behavior |
| new + `ZTLP_QUIC_CERT_DIR` | new | stable cert, no re-pin ever |
| new without `ZTLP_QUIC_CERT_DIR` | new | cert changes per restart, but the fingerprint is republished at start, so the client follows automatically (short window until re-registration, then retry) |

The NS needs no code change if SVC data passes unknown keys through. Task 3.1 proves it with a test.

## 4. Phase 0: stop the bleeding (operations, each step needs Steven's OK)

### Task 0.1: Read-only pre-checks
```bash
ssh trs@10.42.42.112 'docker exec ztlp-gateway-rust ztlp --version; docker exec ztlp-gateway-rust env | grep -c QUIC_CERT; ls -la ~/ztlp-gateway-rust/'
```
Expected: `ztlp 0.35.13`, count `0`, no `quic-cert.der`.
Also resolve the `--admin-pubkey-email fe0f39312fd8f9a4c986` question (2.5): get Steven's Mac tunnel
X25519 key (`ztlp ns pubkey` / Mac identity) and confirm the full 64-hex value.

### Task 0.2: Build the v0.35.20 gateway image
On the Hermes box from a clean `v0.35.20` checkout:
```bash
cd ~/projects/ztlp-quic-pin-ns && git checkout v0.35.20 -- . 2>/dev/null || true
docker build -t ztlp-cli:v0.35.20 -f proto/Dockerfile proto   # confirm build context in proto/Dockerfile header first
docker run --rm ztlp-cli:v0.35.20 --version                     # expect: ztlp 0.35.20
docker save ztlp-cli:v0.35.20 | ssh trs@10.42.42.112 docker load
```

### Task 0.3: Compose change (show the diff to Steven before saving)
In `~/ztlp-gateway-rust/docker-compose.yml`: `image: ztlp-cli:v0.35.20`, add
`ZTLP_QUIC_CERT_DIR: "/data"` under `environment:`, and fix `--admin-pubkey-email` if task 0.1 found it
truncated. Back up first: `cp docker-compose.yml docker-compose.yml.bak-pre-0.35.20`.
Container runs as `1000:1000` and `./` is mounted at `/data` read-write, so it can create the cert files.

### Task 0.4: Recreate the gateway (needs a window; about 10 s outage)
```bash
cd ~/ztlp-gateway-rust && docker compose up -d && sleep 5 && docker logs --tail 30 ztlp-gateway-rust
ls -la quic-cert.der quic-key.der && sha256sum quic-cert.der
docker compose restart && sleep 5 && sha256sum quic-cert.der   # MUST be identical after restart
```
Verify the cert is stable from the client side: after re-pinning, restart once more and confirm the
browser still loads.

### Task 0.5: One-time re-pin of the affected devices
This is the last manual re-pin. It applies to Steven's Mac(s) and heidys-macbook-air-2 (carina is not
enrolled yet). Mac daemon path:
`sudo rm "/Library/Application Support/ZTLP/.ztlp/quic_pins/localhost_10_42_42_112_23097.pin"`
(plus any `*_44_227_148_151_23095*` relayed-pin variant for `www`). Then test
`https://www.chooseforce.ztlp/ztlp/who` in a real browser. Record the result in the tracker.

### Task 0.6: Back up the gateway's key material outside the VM
Back up `identity.json`, `quic-cert.der`, and `quic-key.der` to the secret store Steven chooses (ask;
do not invent a location). PBS already covers them inside VM 296 (weekly, `backupnas`).

### Task 0.7: Fleet audit (read-only) and a written list
For every Rust `ztlp listen --gateway` (known: CF `.112`, blitz `10.69.95.12`) and the Elixir
`ztlp-gateway-trs` (`ZTLP_GATEWAY_QUIC_DATA_DIR=/var/lib/ztlp/gateway`; check it is a persistent volume
and that the cert really survives a restart), record the version, `ZTLP_QUIC_CERT_DIR` status, and
whether the cert survives a restart. Windows endpoint listeners (`ztlp_listener`) are gateways too
(operators pin them). Check the agent/listener version spread from Z2LS. Output:
`docs/QUIC-PIN-FLEET-AUDIT.md`. Fixes per box are separate, individually approved steps.

## 5. Phase 1: make the TLS signature check real (client, security)

Files: `proto/src/quic_transport.rs` (`TofuCertVerifier` impl and `tofu_tests` module, line ~1153).

### Task 1.1 RED: forged CertificateVerify must be rejected
Add to `mod tofu_tests`:
```rust
#[test]
fn tls13_signature_from_a_different_key_is_rejected() {
    use rustls::client::danger::ServerCertVerifier;
    let real = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let attacker = rcgen::KeyPair::generate().unwrap();
    let cert: CertificateDer<'static> = real.cert.der().clone();
    let msg = b"tls13 transcript stand-in";
    let sig = attacker.sign(msg).unwrap();          // signed by a key that does NOT match the cert
    let dss = rustls::DigitallySignedStruct::new(rustls::SignatureScheme::ECDSA_NISTP256_SHA256, sig);
    let tmp = tempfile::tempdir().unwrap();
    let v = TofuCertVerifier::with_pin_dir("sig.example", tmp.path().to_path_buf());
    assert!(v.verify_tls13_signature(msg, &cert, &dss).is_err());
}
```
Check the exact rcgen 0.13 API for `KeyPair::sign` before writing (it may need `rcgen::KeyPair::sign`
through the `signature` trait, or use `ring`/`aws-lc-rs` signing directly from the crypto provider
already in the tree). Adjust the test, not the intent.
Run: `cd proto && cargo test --lib quic_transport::tokio_endpoint::tofu_tests::tls13_signature -- --nocapture`
Expected: FAIL (currently returns `assertion()`).

### Task 1.2 RED: genuine signature is accepted
Same as 1.1 but signed with `real.key_pair` and asserting `is_ok()`. It passes today for the wrong
reason. Keep it as the regression guard.

### Task 1.3 GREEN
Store the provider's algorithms in the verifier and delegate:
```rust
fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct)
    -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs())
}
fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct)
    -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs())
}
fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { self.algs().supported_schemes() }
// algs(): rustls::crypto::CryptoProvider::get_default().expect("ensure_crypto ran").signature_verification_algorithms
```
Update the misleading comment block there ("intentionally a no-op") to describe the new behavior.

### Task 1.4: End-to-end loopback test
Add a tokio test that stands up a `QuicEndpoint` server with a persisted cert (`load_or_generate_self_signed_in(tmp)`),
connects with a fresh pin dir, then reconnects. Expect both to succeed and the pin file to exist.
This proves Phase 1 did not break real handshakes (rcgen ECDSA P-256 and the provider must agree).
Run the whole module: `cargo test --lib quic_transport` (all green), then `cargo test` for the crate.

### Task 1.5: Commit
`fix(quic): verify TLS CertificateVerify signatures in TofuCertVerifier (pin now proves key possession)`

## 6. Phase 2: NS record signature verification in the Rust client

New module: `proto/src/ns_verify.rs` (register in `lib.rs`). Keep it pure and synchronous.

### Task 2.1: Golden vector from the real NS code (cross-language fixture)
In `ns/test/ztlp_ns/record_test.exs` add a test that builds a deterministic signed SVC record (fixed
keypair seed, fixed created_at/ttl/serial, data with `address`, `node_id`, `zone`, `quic_cert_sha256`),
then asserts `Record.encode/1` equals a committed hex string. Write the same hex to
`proto/tests/fixtures/ns_signed_svc_record.hex` together with the signer pubkey hex
(`ns_signed_svc_record.pub`). Run: `cd ns && mix test test/ztlp_ns/record_test.exs`.
Purpose: Rust verifies bytes produced by the real Elixir encoder, not a Rust re-implementation of it.

### Task 2.2 RED: parse and verify the golden record
```rust
#[test]
fn verifies_golden_ns_record() {
    let bytes = hex::decode(include_str!("../tests/fixtures/ns_signed_svc_record.hex").trim()).unwrap();
    let anchor = hex::decode(include_str!("../tests/fixtures/ns_signed_svc_record.pub").trim()).unwrap();
    let rec = ns_verify::parse_signed_record(&bytes).unwrap();   // input = Record.encode bytes (after the 0x02 status byte)
    assert_eq!(rec.type_byte, 2);
    assert!(ns_verify::verify(&rec, &[anchor.try_into().unwrap()]).is_ok());
}
```
Plus tests: flipped byte in the CBOR fails; signer not in anchors gives `UntrustedSigner`; truncated input
gives a parse error without panicking; wrong sig_len is rejected.

### Task 2.3 GREEN
`parse_signed_record` walks `type:u8, name_len:u16, name, data_len:u32, data, created_at:u64, ttl:u32, serial:u64`,
keeps `canonical = bytes[..end_of_serial]`, then reads `sig_len:u16, sig, pub_len:u16, pub`.
`verify` checks that `pub` is one of the anchors, then `ed25519_dalek::VerifyingKey::verify_strict(canonical, sig)`.
Return `VerifiedRecord { name, type_byte, data_cbor, signer }`.
Note: this is the FULL record. Do not route it through `parse_ns_record` or the bare-CBOR path. The
skill documents a recurring double-unwrap bug in exactly this area.

### Task 2.4: `ns_query_verified` in `agent/proxy.rs`
Add a sibling to `ns_query_raw` that keeps the full `0x02` response and returns
`NsAnswer::{Verified(VerifiedRecord), Unverified(bare_cbor)}`. Keep the existing 256-byte query padding.
RED test with a fake UDP NS (pattern exists in proxy.rs tests ~1114) serving the golden bytes; GREEN.
Grep every caller of `ns_query_raw` and leave them unchanged in this task.

### Task 2.5: Trust anchors in config
`agent/config.rs` `NsConfig`: add `trusted_keys: Vec<String>` (default empty) and
`tofu_ns_key: bool` (default true). TOML round-trip test, including that an old agent.toml without the
keys still parses (regression: v0.35.18 broke on an unknown `[renewal]` key).
Implement the first-use NS-key store `~/.ztlp/ns_trust/<sanitized addr>.key`, reusing the pin-path
sanitizer pattern. Tests: first use stores, same key passes, a different key returns `Unverified` and
logs ERROR, path traversal is sanitized.

### Task 2.6: Enrollment hands out the NS key
Read `ns/lib/ztlp_ns/enrollment.ex` (0x07 reply) and `proto/src/enrollment.rs` first. If the reply has
no NS pubkey: Elixir RED test that the success reply includes the registration pubkey (append it as a
new trailing length-prefixed field). Rust RED test that the parser accepts both old and new reply shapes,
then GREEN on both. The agent writes the key into `trusted_keys` on enrollment.
Wire-skew rule from the skill: grep the other language's decoder for every new field before shipping.

## 7. Phase 3: gateway publishes its QUIC fingerprint

### Task 3.1: NS passes the new SVC key through (Elixir, test only)
`ns/test/ztlp_ns/query_test.exs` (or a server registration test): signed v2 SVC registration with
`quic_cert_sha256`, then query and assert the key is present in the returned data.
Expected: passes without NS code changes. If it fails, fix the NS validation and note it in the plan.

### Task 3.2: Expose the served cert fingerprint
`quic_transport.rs`: make the server endpoint report `sha256(leaf DER)` of the cert it actually binds
(the persisted or ephemeral one). RED: unit test that `load_or_generate_self_signed_in(tmp)` called
twice yields the same fingerprint, and that it equals the fingerprint the server presents in the
loopback test from 1.4.

### Task 3.3: Put it in the SVC record
`ztlp-cli.rs` SVC registration (~7255): add `("quic_cert_sha256", fp)` to `svc_pairs` when known.
Extract the pair-building into a pure fn `svc_record_pairs(...)` and test it (with and without fp,
keys sorted via `cbor_map`). Make sure `cmd_listen` binds the QUIC endpoint before the first NS
registration, so the fingerprint is the one being served. Check the order around `ztlp-cli.rs:5588`.

### Task 3.4: Startup log line
Log `QUIC cert sha256=<fp> persisted=<dir|ephemeral>` at gateway start. When ephemeral, add a WARN
recommending `ZTLP_QUIC_CERT_DIR`. Operators should see this in `docker logs` immediately.

## 8. Phase 4: client uses the published fingerprint

### Task 4.1: Pure decision function (table 3.2)
In `quic_transport.rs`: `fn decide_pin(cached: Option<&str>, presented: &str, ns: &NsFingerprint) -> PinDecision`
where `PinDecision = Accept { write_pin: bool } | Reject(PinReject::{NsMismatch, PinMismatch})`.
RED: one test per table row (5 rows), plus case-insensitive hex comparison. GREEN. Commit.

### Task 4.2: Verifier carries the NS expectation
`TofuCertVerifier` gets `ns: NsFingerprint` (default `None`), and `verify_or_pin` delegates to
`decide_pin`. Existing `tofu_tests` must stay green unchanged, because the `None` path is the legacy path.
New tests: a stale cached pin plus a matching `Verified` fp means accept and the pin file is
rewritten; `Unverified` with a mismatch is rejected.
Remove the "delete … to reset the pin" advice from the error. Name the gateway and say an update is
required or a possible attack.

### Task 4.3: Thread it through resolution and dialing
- `agent/proxy.rs`: `NsResolution` gains `quic_cert: NsFingerprint`, filled from `ns_query_verified`
  on the SVC record (`svc_candidates_from_cbor` stays as is).
- `QuicEndpoint::connect_with_socket_for_service` gains `ns_fp: NsFingerprint`, and `connect_with_socket` passes `None`.
- `agent/daemon.rs:3236` passes the resolution's fingerprint. This applies to both direct and relayed
  dials, because the cert is the gateway's own either way.
- `bin/ztlp-cli.rs:4277` (`ztlp connect`) does the same.
- The VIP cache (`VipEntry` / `set_peer_candidates` in daemon.rs) must also cache the fingerprint, or a
  cache hit dials without it. Add a test for that.

### Task 4.4: One retry with a fresh lookup on `NsMismatch`
In the agent dial path: if the dial fails with `NsMismatch`, drop the cached resolution for that name,
resolve again from the NS (bypass the cache), and redial once. If it still mismatches, fail. Test with
a fake NS whose answer changes between the two queries (it models the window right after a gateway
restart, before re-registration lands).

## 9. Phase 5: release, rollout, live proof

1. `cargo fmt --check`, `cargo clippy`, `cargo test` (proto), `mix test` (ns, gateway). Full ZTLP CI
   is about 19 min (the performance gate is the long pole), so don't call it stuck early.
2. Bump the version (0.35.21 or 0.36.0, Steven decides), update CHANGELOG, open a PR. Fix CodeRabbit
   findings before merging. Ask before pushing the tag.
3. Rollout order: (a) NS only if 2.6 changed it; (b) gateways: CF `.112`, then blitz, then the rest
   from the audit, each with `ZTLP_QUIC_CERT_DIR`; (c) desktop app release (Mac/Windows), and the
   Windows service through the normal channel.
4. Live proof as a real user in a real browser (curl 200 does not count). Track it in
   `docs/QUIC-PIN-VIA-NS-TRACKER.md`:
   - Test gateway (NOT the CF prod gateway): delete `quic-cert.der`/`quic-key.der` and restart, which
     forces a new cert. The browser on the AI computer and on a Mac keeps working with no user action.
     The agent log shows `NsMismatch` → re-resolve → accept → pin rewritten.
   - Negative test: a gateway serving a cert that does not match its NS record is rejected and the
     page does not load.
   - An old client against the new gateway still works (legacy path).
5. Update the skill `ztlp-architecture-and-debugging` failure row ("pin mismatch after gateway restart")
   with the new behavior.

## 10. Out of scope here (follow-ups to file)

- **Channel binding**: bind the Noise handshake to the TLS session (TLS exporter value in the Noise
  prologue). Without it, a man-in-the-middle holding the real cert key could still relay Noise. With
  Phase 1 + 4 an attacker no longer has that key, so this becomes defense in depth.
- Desktop check of the gateway's Noise static key against `registered_by` / the KEY record (iOS already
  has `verify_gateway_pin`).
- Elixir gateway: publish `quic_cert_sha256` too (parity), and confirm its QUIC data dir persists.
- iOS FFI path: same NS fingerprint logic.
- NS key rotation procedure (multiple `trusted_keys` makes an overlap window possible; document it).

## 11. Risks and open questions

- rustls signature verification and rcgen's default key type: confirm in task 1.4 that the provider in
  use (`ensure_crypto`) supports rcgen's default ECDSA P-256 leaf. Otherwise every handshake breaks
  after Phase 1. Ship Phase 1 only with the loopback test green.
- First-use trust of the NS key on already-enrolled devices still has a first-contact window. That is
  acceptable (one key per zone), but tell Steven explicitly.
- NS response size: one more 64-hex field. The NS caps replies at 8× the query size with 256-byte
  padding (2 KB), so there is ample room. Assert it in the 2.4 test.
- Relay-carried dials: the relay forwards QUIC untouched, so the presented cert is still the gateway's.
  Verify in the live proof that relayed dials pick up the NS fingerprint (pin key differs per service).
- Open: Steven decides the secret store for task 0.6 and the version number in Phase 5.
