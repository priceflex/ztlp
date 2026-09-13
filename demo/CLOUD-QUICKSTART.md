# ZTLP Cloud Demo — Quickstart

Full stack (NS + relay1 + relay2 + QUIC gateway + dashboard) on one cloud
box, reachable from any laptop running the `ztlp` CLI. Zero manual RPC
steps, zero key copying between containers, zero hand-edited config files,
survives restarts.

Transport: the gateway speaks **real QUIC** (ALPN `ztlp/1`) with ZTLP's own
magic-framed `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake tunneled inside
the first QUIC stream. The legacy raw-UDP listener is OFF in this compose.

Reference deployment: AWS Lightsail `44.240.16.59` (us-west-2). Everything
below works for any Linux box with Docker; substitute the IP.

---

## 0. One-time host prep (cloud box)

```bash
sudo apt-get install -y docker.io docker-compose-v2
```

Open UDP **23095** (relay1), **23096** (NS), **23097** (gateway) and TCP 22 in
the cloud firewall. `/var/lib/ztlp` must be a real ext4/xfs path (NOT tmpfs,
NOT FUSE) — the CA and QUIC certs persist there. The ship script creates it.

## 1. Server: one command from your workstation

Never build on the 2 vCPU cloud box (the gateway image compiles msquic).
`demo/ship-cloud-demo.sh` builds locally, ships the images + every mounted
config file, fixes file modes, brings the stack up from a clean slate and
runs the green checks. Non-zero exit = something is wrong; it prints what.

```bash
cd ztlp
demo/ship-cloud-demo.sh                       # ubuntu@44.240.16.59, ~/.ssh/ztlp-defcon-demo.pem
demo/ship-cloud-demo.sh ubuntu@1.2.3.4 ~/.ssh/other.pem   # any other box
demo/ship-cloud-demo.sh --no-wipe             # restart, keep gateway QUIC cert (clients keep TOFU pin)
demo/ship-cloud-demo.sh --no-build            # reuse the images already built locally
```

Expected tail:

```
▶ Green checks
  ✓ 5 containers up, 4 healthy
  ✓ ns: Config loaded (component_auth)
  ✓ gateway: QUIC listening :23097
  ✓ gateway: SVC registered
  ✓ gateway: All certs provisioned
  ✓ relay1: gateway registered (0x0D)
  ✓ dashboard: /api/health ok
  ✓ ALL GREEN — stack ready on ubuntu@44.240.16.59
  ℹ clean slate regenerated the gateway QUIC cert: existing clients must  rm ~/.ztlp/quic_pins/localhost.pin
```

Default (no `--no-wipe`) is a full clean slate: `down -v`, wipe
`/var/lib/ztlp/{ca,gateway}`, `up -d`. That regenerates the gateway QUIC cert,
so every client that connected before must drop its pin (last line above).

## 2. Client: install `ztlp` (once per machine / per rebuild)

```bash
cd ztlp/proto && cargo build --release --bin ztlp
sudo install -m 755 target/release/ztlp /usr/local/bin/ztlp
sudo setcap cap_net_bind_service=+ep /usr/local/bin/ztlp     # agent binds VIP :80/:443
```

Re-run all three lines after every `cargo build` (setcap does not survive a
rebuild, and `install` copies the binary).

## 3. Client: enroll — three commands, no config editing

```bash
echo -n 06984504bf07f1cd8462fd9909dcd39cd3e04beb96100a3bbe45eb6113025103 > /tmp/defcon-zone-secret.hex
ztlp admin enroll --zone defcon.ztlp --secret /tmp/defcon-zone-secret.hex \
   --ns-server 44.240.16.59:23096 --relay 44.240.16.59:23095 \
   --gateway 44.240.16.59:23097 --expires 24h
ztlp setup --token 'ztlp://enroll/...' --name my-laptop-01 --yes \
   --relay-secret 03949c364265e5e2cf0eb0f90a27cf51b97e85c2564a9ece899d6daab2a70d7c
```

- Zone secret = `ZTLP_ENROLLMENT_SECRET`, relay secret =
  `ZTLP_RELAY_REGISTRATION_SECRET`, both in `defcon-cloud-compose.yml`
  (demo-only, published on purpose). `--secret` wants a FILE path.
- **Pick a device name nobody has used before** (`--name`). Tokens are
  single-use and NS rejects a taken name (`0x08 0x05`).
- `ztlp setup` writes `~/.ztlp/identity.json`, `config.toml` AND
  `agent.toml` (ns, relay, relay_secret, DNS on `127.0.0.55:15353` for
  `defcon.ztlp`, TLS off). Nothing to edit.
- **Already enrolled?** `setup` refuses (even with `--yes`) if
  `~/.ztlp/identity.json` exists. Add `--force` to re-enroll; the old
  identity.json / config.toml / agent.toml (and zone.key, on the
  create-network path) are moved to `*.<ts>.bak` first.
- The relay runs `ZTLP_RELAY_HMAC_MODE=prod`: without `--relay-secret` the
  relay drops every route and the tunnel times out at the QUIC handshake.
  Forgot it? Add `relay_secret = "..."` under `[tunnel]` in `~/.ztlp/agent.toml`.

## 4. Client: run the agent and hit the dashboard

```bash
ztlp agent start --foreground -v &
dig @127.0.0.55 -p 15353 demo-dashboard.defcon.ztlp +short          # 127.100.0.1
curl -s http://127.100.0.1/api/health                                # {"status":"ok"}
curl -s http://127.100.0.1/ | grep -E 'hmac_verified|node name'      # true, my-laptop-01.defcon.ztlp
```

**Resolve first (once).** The VIP `127.100.0.1` exists only after the agent
has answered a DNS query for the name (log: `allocate(demo-dashboard...) →
127.100.0.1`). Allocations are saved to `~/.ztlp/vip_state.json` and
re-bound on the next agent start (log: `VIP pool: restored N allocation(s)`),
so browsers with a cached A record and `curl --resolve` keep working across
agent restarts. On a brand-new `~/.ztlp` with no prior `dig`, `connection
refused` on every port is expected — not a TLS or tunnel fault.

Gateway side shows one line per tunnel:
`[Quic] handshake ok session=<24 hex> peer=<64 hex> service=demo-dashboard`.
Relay side (prod HMAC mode) shows `CLIENT_ROUTE ... (legacy)` for each signed
route; an unsigned/mis-keyed client shows `rejected: invalid HMAC` or
`REJECTED: no secret configured` and never gets a tunnel.

### 4b. `https://` without `-k` (local TLS termination)

The dashboard is plain HTTP behind the gateway; the AGENT terminates TLS on
the VIP and mints a per-hostname leaf on demand from a local CA:

```bash
ztlp admin ca-init --zone defcon.ztlp        # ~/.ztlp/ca/{root,intermediate}.{pem,key}
                                             # also flips [tls] enabled = true in ~/.ztlp/agent.toml
# restart the agent, then:
dig @127.0.0.55 -p 15353 demo-dashboard.defcon.ztlp +short          # allocate the VIP (if not restored)
curl -s --cacert ~/.ztlp/ca/root.pem \
     --resolve demo-dashboard.defcon.ztlp:443:127.100.0.1 \
     https://demo-dashboard.defcon.ztlp/api/health          # {"status":"ok"}, no -k
```

Leaf `CN=demo-dashboard.defcon.ztlp` issued by `ZTLP Intermediate CA -
defcon.ztlp`, `openssl s_client ... -CAfile ~/.ztlp/ca/root.pem` -> `Verify
return code: 0 (ok)`; cached at `~/.ztlp/certs/demo-dashboard_defcon_ztlp.{pem,key}`.
System-wide browser trust: `ztlp admin ca-export-root | sudo tee
/usr/local/share/ca-certificates/ztlp.crt && sudo update-ca-certificates`
(Linux) or `ztlp agent install-ca-cert --machine-scope` (Windows). The agent
only mints when `~/.ztlp/ca/intermediate.{pem,key}` exist.

Optional: route the OS resolver for `defcon.ztlp` to `127.0.0.55:15353` so
`curl http://demo-dashboard.defcon.ztlp/` works without `dig` — see
`ztlp agent dns-setup`. Laptop-OS-specific, not part of the server story.

Reference numbers (Hermes VM in Monrovia -> us-west-2): ~170 ms per request,
HTTP 200, `hmac_verified: true`, 0 `bad_magic`, 0 `handshakes_fail`.

### Manual tunnel instead of the agent

`ztlp connect <name> -L ...` takes the same secret as `--relay-secret <hex>`
or `--relay-secret-file <path>` and falls back to `agent.toml`. It picks up
`~/.ztlp/identity.json` when `--key` is omitted.

---

## Pitfalls (each of these cost real time; don't relearn them)

- **TOFU pin.** The client pins the gateway's QUIC cert SHA-256 in
  `~/.ztlp/quic_pins/localhost.pin` (all gateways share the pin because SNI
  is always `localhost`). Restarts keep the cert; a clean-slate ship
  regenerates it and every existing client fails with "certificate
  fingerprint ... does not match the pinned value" until
  `rm ~/.ztlp/quic_pins/localhost.pin`. Use `--no-wipe` to avoid it.
- **Stale `HOME`.** Every `ztlp` command reads `$HOME/.ztlp`; if a shell has
  `HOME` exported elsewhere you silently enroll into the wrong directory.
- **Do not pass `--transport udp` or `--no-multi-candidate`.** Real QUIC is
  the only path this gateway accepts (`ZTLP_GATEWAY_UDP_ENABLED=false`).
- **Three env vars must agree on the service name** (`demo-dashboard`):
  `ZTLP_GATEWAY_BACKENDS`, `ZTLP_GATEWAY_POLICIES`,
  `ZTLP_GATEWAY_SERVICE_NAMES`. The relay does exact-match, no wildcard.
- **Relay HMAC mode is `prod`** (fail-closed). relay1, relay2 and the gateway
  share `ZTLP_RELAY_REGISTRATION_SECRET`; every client needs the SAME value
  (`ztlp setup --relay-secret`, or `[tunnel] relay_secret` in agent.toml, or
  `ztlp connect --relay-secret`). The relay decodes a 64-hex secret to 32 raw
  bytes before HMAC'ing; gateway (`RelayRegistrar.legacy_secret/0`) and
  client (`tunnel::decode_relay_secret`) do the same, so use hex everywhere.
  For V1 frames the relay derives "zone" from the SERVICE name, so a per-zone
  `ZTLP_HMAC_SECRET_DEFCON_ZTLP` never matches. Pinned by
  `ns/test/ztlp_ns/demo_compose_consistency_test.exs`,
  `relay/test/ztlp_relay/client_route_prod_hmac_test.exs`,
  `gateway/test/ztlp_gateway/relay_registrar_addr_test.exs`.
- **File modes on the box** (handled by the ship script; relevant if you scp
  by hand): scp preserves local 0600, ns and gateway run as uid 999 and get
  `:eacces` on the `:ro` mounts -> NS `component_auth` silently
  `not_configured` -> gateway `CertProvisioner ... :unauthorized`. `chmod 644`
  every mounted file **including `ns-registration.key`**, then restart BOTH
  ns and gateway.
- **`local-loopback.override.yml` uses `volumes: !override`**, which REPLACES
  the base list. Any mount added to `defcon-cloud-compose.yml` must be
  mirrored there. Pinned by `demo_compose_consistency_test.exs`.
- **`X-ZTLP-Zone`** is derived from the resolved device name
  (`<device>.<zone>` -> `<zone>`); `unknown:<hex>` identities have no zone.
- **`ztlp connect ... -L` from a machine that ALSO runs the local loopback
  demo stack** direct-dials the SVC address `172.42.90.30:23097`, which is
  the local Docker bridge, so it hits the local gateway and trips the TOFU
  pin. Test-rig artifact only; the agent path uses the configured relay.
- **Trust anchor must match NS's registration-signing key.** NS signs every
  device KEY/SVC record with `demo/ns-registration.key`
  (`ZTLP_NS_IDENTITY_KEY_FILE`); `ZTLP_GATEWAY_TRUST_ANCHORS` is that key's
  Ed25519 pubkey. If they drift, every lookup is `:untrusted_signer` and the
  dashboard shows `node name: unknown:<hex>` while HMAC still verifies.
  Pinned by `ns/test/ztlp_ns/demo_trust_anchor_consistency_test.exs`.
- **`ztlp setup` refuses to clobber an existing `~/.ztlp`** (both the join and
  create-network paths). `--force` moves `identity.json`, `config.toml`,
  `agent.toml` and `zone.key` to `*.<ts>.bak` first.

## Doing it by hand (what the ship script does)

```bash
docker compose -f demo/defcon-cloud-compose.yml build
docker save demo-ns demo-relay1 demo-relay2 demo-gateway demo-dashboard -o /tmp/ztlp-demo-images.tar
scp -i $KEY /tmp/ztlp-demo-images.tar $BOX:/tmp/
scp -i $KEY demo/defcon-cloud-compose.yml demo/gateway-config.yaml demo/gateway-identity.key \
    demo/ns-config.yaml demo/ns-registration.key $BOX:~/ztlp/demo/
ssh -i $KEY $BOX '
  cd ~/ztlp/demo && chmod 644 *.yml *.yaml gateway-identity.key ns-registration.key
  sudo mkdir -p /var/lib/ztlp/ca /var/lib/ztlp/gateway && sudo chmod 777 /var/lib/ztlp/ca /var/lib/ztlp/gateway
  sudo docker load -i /tmp/ztlp-demo-images.tar && rm /tmp/ztlp-demo-images.tar
  sudo docker compose -f defcon-cloud-compose.yml down -v --remove-orphans
  sudo rm -rf /var/lib/ztlp/ca/* /var/lib/ztlp/gateway/*          # clean slate (omit to keep the QUIC cert)
  sudo docker compose -f defcon-cloud-compose.yml up -d'          # no --build
```

Green checks are the `check` lines at the bottom of `demo/ship-cloud-demo.sh`.

## What is inside (for the curious)

| Piece | Where | Notes |
|---|---|---|
| NS component-auth allowlist | `demo/ns-config.yaml` (`ZTLP_NS_CONFIG`) | fixed gateway pubkey, no RPC |
| NS record-signing key | `demo/ns-registration.key` (`ZTLP_NS_IDENTITY_KEY_FILE`) | pubkey = gateway `ZTLP_GATEWAY_TRUST_ANCHORS`; gives real device names in X-ZTLP-Node-Name |
| Gateway identity | `demo/gateway-identity.key` (`:ro`) + `gateway-config.yaml` | fixed seed, demo-only |
| QUIC listener | `ZTLP_GATEWAY_QUIC_ENABLED=true`, port 23097 | ALPN `ztlp/1`, ECDSA P-256 self-signed, persisted |
| Relay registration | `ZTLP_GATEWAY_RELAY_ADVERTISE_ADDR=":23097"` | `GATEWAY_REGISTER_ADDR` (0x5A 0x37 0x0D) frame; msquic owns the UDP socket so the register is sent from a side socket declaring the QUIC port |
| SVC record | gateway `ServiceRegistrar` | self-registers `demo-dashboard.defcon.ztlp -> 172.42.90.30:23097` after cert issuance |
| Header HMAC | gateway `HeaderSigner` -> dashboard `verify_hmac` | `X-ZTLP-Signature` over sorted lowercase `x-ztlp-*` headers |
| Client agent.toml | written by `ztlp setup` (`write_agent_config_file`) | refuses to clobber a hand-tuned one |

Wire-level details of the QUIC transport: `gateway/README.md`, section
"QUIC transport".
