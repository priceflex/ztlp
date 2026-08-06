# DEF CON 34 Kali Demo Buildout — What We Learned

**Date:** August 5-6, 2026
**Target:** Kali laptop (10.3.2.28), full ZTLP stack for live DEF CON demo
**Goal:** `https://demo-dashboard.defcon.ztlp` loads in a real browser with a
valid TLS chain and shows live proof of ZTLP identity/auth, not a static page.

This documents every real bug we hit standing up the full stack end-to-end
(Docker NS/relay/gateway + local agent + browser), what caused each one, and
the fix. All fixes below are now applied to `main` in this repo.

---

## 1. rustls dual crypto-provider panic (agent crash on start)

**Symptom:**
```
thread 'main' panicked at rustls-0.23.43/src/crypto/mod.rs:249:14:
Could not automatically determine the process-level CryptoProvider from
Rustls crate features. Call CryptoProvider::install_default() before this
point...
```

**Root cause:** The dependency tree pulls in both `ring` and `aws-lc-rs` as
rustls crypto backends (quinn brings one in, other code paths brought in the
other). `quic_transport.rs` explicitly installed the `ring` provider;
`vip.rs`'s `build_tls_acceptor` separately tried to install `aws_lc_rs`. Only
one process-level default can ever be installed — whichever code path ran
second panicked.

**Fix:**
- `proto/src/vip.rs` — changed `build_tls_acceptor` to install `ring` instead
  of `aws_lc_rs`, matching what `quic_transport.rs` already does.
- `proto/src/bin/ztlp-cli.rs` — added an explicit
  `rustls::crypto::ring::default_provider().install_default()` at the very
  top of `main()`, before `Cli::parse()` runs, so the provider is locked in
  before *any* code path (agent, connect, gateway-elixir bridge, etc.) can
  race to install a different one.

**Lesson:** any binary embedding rustls transitively through multiple crates
needs exactly one explicit `install_default()` call, done once, as early as
possible in `main()`. Don't rely on individual modules doing it lazily.

---

## 2. Gateway backend service-hash mismatch ("No backend configured")

**Symptom:** Gateway logs showed successful Noise handshakes but every
session hit:
```
[warn] [Session] No backend configured for service hash: <<27, 168, ...>>
```
and the browser just hung with no data ever returned (TLS handshake OK, HTTP
request silently swallowed).

**Root cause:** The ZTLP agent's local VIP→TCP proxy (`daemon.rs`) always
requests service `format!("tcp:{}", port)` — e.g. `"tcp:443"` — for any TCP
connection bridged over a virtual IP. This is **not** derived from the
hostname or any friendly per-service name; it's purely `"tcp:" + port
number`. The gateway's `ZTLP_GATEWAY_BACKENDS` env var was configured with a
friendly name (`web:172.28.0.40:8420`), which hashes to a completely
different value than what the client actually sends (`tcp:443`). Since the
gateway matches on exact hash, nothing ever matched.

**Fix:** Set `ZTLP_GATEWAY_BACKENDS=tcp:443:172.28.0.40:8420` — i.e. the
backend *name* must literally be `tcp:443` to match what the agent sends for
any HTTPS-port VIP connection.

**Known limitation (not fixed, flagged for follow-up):** because the service
identifier is purely port-based (`tcp:443`), multiple different hostnames
routed through the same gateway on the same port will currently collide onto
the same backend bucket. There's no per-hostname routing at the gateway
today for VIP-proxied TCP connections — only one backend per port is
possible. If DEF CON demo needs `demo-dashboard` and, say, `demo-vault` both
reachable over 443 through one gateway simultaneously, `daemon.rs`'s
`handle_tcp_connection`/`handle_tcp_connection_with_tls` would need to be
patched to send the actual ZTLP hostname as the service string instead of
`tcp:<port>`, and the gateway's backend matching would need to switch from
port-hash to hostname-hash.

---

## 3. Env var parser couldn't handle colon-containing service names

**Symptom:** Once we needed a backend name like `tcp:443` (see #2 above),
the existing `ZTLP_GATEWAY_BACKENDS` parser broke, because it split on the
first two colons (`String.split(entry, ":", parts: 3)`), which mis-parses
`tcp:443:172.28.0.40:8420` as name=`tcp`, host=`443`, port=`172.28.0.40:8420`
(a parse failure).

**Fix:** `gateway/lib/ztlp_gateway/config.ex` — rewrote the backend-entry
parser to split on ALL colons, then take the *last* segment as the port and
the *second-to-last* as the host, joining everything before that back
together (with `:`) as the name. This correctly supports service names that
themselves contain colons.

---

## 4. NS auto-init created a NEW CA that didn't match the trusted one

**Symptom:** Browser showed `ERR_CERT_AUTHORITY_INVALID` (or a raw
`ERR_SSL_PROTOCOL_ERROR` before that, see #5) even after installing "the"
ZTLP root CA into the system trust store and Chromium/Firefox NSS
databases.

**Root cause:** Earlier troubleshooting wiped `~/.ztlp/ca/*` on the host
(mounted into the NS container) to work around a permissions issue, then
relied on `ZTLP_CA_AUTO_INIT=true` to have the NS auto-generate a fresh CA on
next boot. That auto-init genuinely created a **brand new** CA keypair —
different fingerprint from the CA cert we had previously exported and
trusted in the browser stores. Every cert the gateway/agent subsequently
minted chained to the *new* CA, but the browsers still trusted the *old* one.

**Fix:** Whenever the NS's CA is (re)initialized — whether by `ztlp admin
ca-init` or via `ZTLP_CA_AUTO_INIT`, always re-export the *current* root with
`ztlp admin ca-export-root` and re-run the trust-store install (system +
each browser's NSS db) afterward. Don't assume a previously-trusted CA file
is still the one in active use — verify by comparing SHA-256 fingerprints:
```bash
openssl x509 -in <exported-root>.pem -noout -fingerprint -sha256
openssl x509 -in /usr/local/share/ca-certificates/ztlp.crt -noout -fingerprint -sha256
```

---

## 5. On-demand cert minting failed silently (PKCS#1 vs PKCS#8 key format)

**Symptom:** Agent logs:
```
WARN local TLS: intermediate CA present at .../intermediate.pem but failed
to load: PEM parse error: intermediate key: Could not parse key pair —
on-demand minting disabled
```
Browser got a raw `ERR_SSL_PROTOCOL_ERROR` (TLS handshake failed at the
protocol level, no cert offered at all) because the local TLS acceptor had
no cert to serve.

**Root cause:** The intermediate CA's private key file
(`~/.ztlp/ca/intermediate.key`) was in PKCS#1 RSA format
(`-----BEGIN RSA PRIVATE KEY-----`), but `rcgen::KeyPair::from_pem` (used by
`cert_mint.rs`'s `CertAuthorityIntermediate::from_pem`) requires PKCS#8
(`-----BEGIN PRIVATE KEY-----`).

**Fix:** Convert the key format in place:
```bash
openssl pkey -in intermediate.key -out intermediate_pkcs8.key
```
then swap it in as `intermediate.key`. This is a data/config issue, not a
code bug — but worth documenting since the NS's own `ca-init` currently
writes PKCS#1, and the agent's cert-minting path needs PKCS#8. Either the NS
should write PKCS#8 keys from the start, or the agent's loader should accept
both formats. **Follow-up recommended:** patch `ztlp_ns/cert_authority.ex`
to write intermediate/root keys in PKCS#8 format so this conversion step
isn't needed on every fresh CA init.

---

## 6. File ownership traps: Docker containers vs host user

The NS container runs as `uid 999` (`ztlp` user inside the container). The
CA directory is bind-mounted from the host (`/home/trs/.ztlp/ca`), which is
normally owned by `trs` (`uid 1000`). Any time the container needs to
**write** into that directory (auto-init, key rotation), it will silently
fail with `EACCES` unless the host directory is world-writable or explicitly
chowned to match the container's uid. We hit this twice:
- `ZTLP_CA_AUTO_INIT` failing with `File.Error{reason: :eacces, ...
  root.key.enc}` until the CA dir was `chmod 777`'d.
- The intermediate key coming out owned by the container's uid after
  auto-init, blocking the *host-side* agent process (running as `trs`) from
  reading it — needed an explicit `chown` back to `trs` before the local
  agent could load it for on-demand minting.

**Lesson:** when bind-mounting a directory both a container and a host
process need read/write access to, either run the container with
`user: "1000:1000"` (matching the host uid) in the compose file, or budget
for a manual `chown`/`chmod` step after any auto-init that runs inside the
container.

---

## 7. VIP proxy listener is lazy — allocated only on real DNS resolution

**Symptom:** A hardcoded `/etc/hosts` entry pointing a hostname straight at
the agent's VIP address (`127.100.0.1`) results in `ERR_CONNECTION_REFUSED`
even though `agent status` shows the agent running.

**Root cause:** The agent's `run_tcp_proxy` background task (in
`daemon.rs`) only spawns TCP listeners on a VIP address once that VIP has
actually been **allocated** by a real DNS query through the agent's own
resolver (`127.0.0.53:5353`). It polls the VIP pool every 500ms and binds
listeners (on a fixed list of common ports including 443) for any newly
allocated VIP — but if you bypass DNS entirely with a static `/etc/hosts`
entry, the VIP pool entry is never created, so no listener ever exists at
that IP.

**Fix:** Always resolve the ZTLP name through the agent's DNS resolver at
least once (e.g. `dig @127.0.0.53 -p 5353 <name>`) before expecting
connections to that VIP to work. Static `/etc/hosts` entries are fine
**after** that first resolution has happened (to allocate the VIP and
trigger listener spawn), but won't work as a substitute for it.

---

## 8. NS SVC record registration required for name resolution

Simply enrolling a device in a zone and having Docker containers up is not
enough for `<name>.defcon.ztlp` to resolve — the name needs an actual SVC
record registered in NS pointing at the gateway:
```bash
ztlp ns register --name demo-dashboard.defcon.ztlp --zone defcon.ztlp \
  --key ~/.ztlp/identity.json --ns-server 127.0.0.1:23096 \
  --address 127.0.0.1:23097
```
Without this, DNS lookups for the name return NXDOMAIN even though the zone
itself is fully enrolled and the gateway is healthy.

---

## Summary of code changes now on `main`

| File | Change |
|---|---|
| `proto/src/vip.rs` | `build_tls_acceptor`: install `ring` provider instead of `aws_lc_rs` (avoid dual-provider panic) |
| `proto/src/bin/ztlp-cli.rs` | `main()`: explicit `rustls::crypto::ring::default_provider().install_default()` as the first line, before any subcommand dispatch |
| `gateway/lib/ztlp_gateway/config.ex` | `ZTLP_GATEWAY_BACKENDS` parser rewritten to support colon-containing service names (e.g. `tcp:443`) by splitting from the right instead of `parts: 3` from the left; added `ZTLP_GATEWAY_TRUST_ANCHORS` env var support (was previously compile-time-only, unreachable in practice) |
| `ns/lib/ztlp_ns/config.ex` | `ca_data_dir/0`: `ZTLP_CA_DIR` now takes priority over `ZTLP_CA_DATA_DIR`, matching `cert_authority.ex`'s existing priority order (the two disagreed before, silently splitting CA state); `identity_key_file/0` now defaults to `<ca_data_dir>/registration_signing.key` instead of `nil`, so NS's record-signing key persists across restarts without requiring an operator to set `ZTLP_NS_IDENTITY_KEY_FILE` |
| `ns/lib/ztlp_ns/server.ex` | `get_registration_key/0`: clarified as a defensive cache-read fallback now that `ensure_registration_key/0` + the `identity_key_file/0` default reliably populate the cache at startup |

## Recommended follow-up work (not yet done)

1. **Port-exposure proof** — a demo script that shows the actual open ports
   on the Kali box are ZTLP VIP proxy listeners (127.100.x.x range), not
   Docker port-forwarding, to visually prove no `-p host:container` mapping
   is doing the work.
2. **Live/dynamic demo, not a static page** — script that actively drives
   traffic through the tunnel (repeated real requests, or an action that
   changes visible state) so the audience sees packets moving, not just a
   page that loaded once.
3. **Gateway per-hostname backend routing** — today it's port-based only
   (`tcp:443`); multiple distinct hostnames sharing a port will collide.

## 9. Named identities: NS registration-signing key was never persisted

**Symptom:** Even after registering a friendly KEY record
(`kali-demo-laptop.defcon.ztlp`) for the device's pubkey in NS, the
dashboard kept showing the raw NodeID hex as the identity, and the
gateway's `Identity.resolve/1` NS lookup returned `{:error,
:untrusted_signer}` (or `:no_trust_anchors_configured` before that).

**Root cause (two-part):**

1. **No trust anchor configured at all.** `ZtlpGateway.NsClient`
   cryptographically verifies every record NS returns against a
   configured "trust anchor" (the public key that's supposed to have
   signed it) before accepting it — a correct fail-closed default to
   prevent a compromised/spoofed NS from injecting fake identities. But
   `ZTLP_GATEWAY_TRUST_ANCHORS` had no environment-variable wiring at
   all — `Config.get(:trust_anchors)` only ever read a compile-time
   `Application.get_env`, which was never set anywhere. **Fixed**: added
   env var support to `gateway/lib/ztlp_gateway/config.ex`
   (`ZTLP_GATEWAY_TRUST_ANCHORS=<label>:<hex-pubkey>[,<label>:<hex-pubkey>...]`).

2. **The key NS actually signs records with was never persisted.**
   NS's registration-signing keypair (used by `Record.sign/2` for every
   record it stores) is loaded/generated by `ensure_registration_key/0`
   in `server.ex`, which delegates to `ZtlpNs.Config.identity_key_file/0`
   for a path to persist to. That function had **no default path** — it
   returned `nil` unless an operator explicitly set
   `ZTLP_NS_IDENTITY_KEY_FILE`, which nobody had ever done. With no path
   configured, NS silently fell back to generating a **brand new random
   ephemeral keypair on every single container restart** — meaning any
   trust anchor a gateway operator configured would go stale (mismatch)
   the moment NS restarted, and nobody would notice why identity
   resolution just stopped working after a routine restart. **Fixed**:
   `Config.identity_key_file/0` now defaults to
   `<ca_data_dir>/registration_signing.key` (same durable volume already
   used for the CA files) instead of `nil`, so a fresh deployment
   persists a stable signing key with zero required operator
   configuration. `ca_data_dir()` itself was also fixed (see below) to
   agree with `cert_authority.ex`'s directory-resolution priority order
   — the two previously disagreed under certain env var combinations,
   which could silently split CA state and the registration key across
   two different directories.

**A wrong turn along the way, documented so it isn't repeated:** the
first attempt at fixing this reimplemented persistence logic directly
inside `get_registration_key/0` in `server.ex` — duplicate work, since
`ensure_registration_key/0` (called once at NS startup, before
`get_registration_key/0` is ever invoked) already had a complete,
correct persist/load implementation via `ZtlpNs.ComponentAuth` — it just
had nowhere to point by default. The actual fix ended up being much
smaller: give `identity_key_file/0` a sane default path. Lesson: when a
`nil`-returning config accessor feeds into an "ensure X exists, else
generate ephemeral" pattern, always check whether the *real* problem is
just a missing default, before writing new persistence code from
scratch.

**How to correctly pick the gateway's trust anchor value**: it is NOT
the client's zone-enrollment key (`~/.ztlp/zone.key`, exported via `ztlp
admin export-zone-key`) — that was the mistake made on the first
attempt, which produced `{:error, :untrusted_signer}`. It is NS's own
registration-signing public key, derivable from the persisted private
key:
```bash
# private key is at <ca_data_dir>/registration_signing.key inside the
# NS container / mounted volume, hex-encoded
sudo docker exec <ns-container> /app/bin/ztlp_ns rpc '
priv = Base.decode16!("<hex from file>", case: :lower)
{pub, _} = :crypto.generate_key(:eddsa, :ed25519, priv)
IO.puts(Base.encode16(pub, case: :lower))
'
```
Feed that public key hex into `ZTLP_GATEWAY_TRUST_ANCHORS` on the
gateway. If NS's key file is later regenerated (e.g. the volume is
wiped), this value must be re-derived and the gateway's env updated —
this coupling should probably be automated in a future iteration (e.g.
NS publishing its own signing pubkey to a well-known lookup path that
the gateway can query at startup, instead of a manually-copied env var).

