# ZTLP Cloud Demo — Quickstart

Full stack (NS + relay1 + relay2 + QUIC gateway + dashboard) on one cloud
box, reachable from any laptop running the `ztlp` CLI. Zero manual RPC
steps, zero key copying between containers, survives restarts.

Transport: the gateway speaks **real QUIC** (ALPN `ztlp/1`) with ZTLP's own
magic-framed `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake tunneled inside
the first QUIC stream. The legacy raw-UDP listener is OFF in this compose.

Reference deployment: AWS Lightsail `44.240.16.59` (us-west-2). Everything
below works for any Linux box with Docker; substitute the IP.

---

## 0. One-time host prep (cloud box)

```bash
sudo apt-get install -y docker.io docker-compose-v2
sudo mkdir -p /var/lib/ztlp/ca /var/lib/ztlp/gateway
sudo chmod 777 /var/lib/ztlp/ca /var/lib/ztlp/gateway   # containers run non-root
```

Open UDP **23095** (relay1), **23096** (NS), **23097** (gateway) and TCP 22 in
the cloud firewall. `/var/lib/ztlp` must be a real ext4/xfs path (NOT tmpfs,
NOT FUSE) — the CA and QUIC certs persist there.

## 1. Build images on a FAST machine, ship them (never build on the cloud box)

The gateway image compiles msquic (quicer NIF) — minutes on a 2 vCPU cloud
box, ~30 s incremental on a real workstation.

```bash
cd ztlp
docker compose -f demo/defcon-cloud-compose.yml build
docker save demo-ns demo-relay1 demo-relay2 demo-gateway demo-dashboard \
    -o /tmp/ztlp-demo-images.tar                                   # ~250 MB

BOX=ubuntu@44.240.16.59; KEY=~/.ssh/ztlp-defcon-demo.pem
scp -i $KEY /tmp/ztlp-demo-images.tar $BOX:/tmp/
ssh -i $KEY $BOX 'mkdir -p ~/ztlp/demo'
scp -i $KEY demo/defcon-cloud-compose.yml demo/gateway-config.yaml \
    demo/gateway-identity.key demo/ns-config.yaml demo/ns-registration.key $BOX:~/ztlp/demo/
```

## 2. Bring the stack up (cloud box)

```bash
ssh -i $KEY $BOX
chmod 644 ~/ztlp/demo/*.yml ~/ztlp/demo/*.yaml ~/ztlp/demo/gateway-identity.key   # MANDATORY, see pitfalls
sudo docker load -i /tmp/ztlp-demo-images.tar && rm /tmp/ztlp-demo-images.tar
cd ~/ztlp/demo
sudo docker compose -f defcon-cloud-compose.yml up -d        # no --build
```

Verify (about 30 s after `up`):

```bash
sudo docker ps --format '{{.Names}} {{.Status}}'          # all 5 up, ns/relays/gateway healthy
sudo docker logs ztlp-ns-defcon 2>&1 | grep -c 'Config loaded'                 # 1
sudo docker logs ztlp-gateway-defcon 2>&1 | grep -E 'Config loaded|QUIC listening|Registered demo-dashboard|All certs provisioned'
sudo docker logs ztlp-gateway-defcon 2>&1 | grep -ciE 'unauthorized|eacces'    # 0
sudo docker logs ztlp-relay1-defcon 2>&1 | grep GATEWAY_REGISTER_ADDR | tail -1 # declares {172,42,90,30},23097
curl -s localhost:8420/api/health                                              # {"status":"ok"}
```

Clean slate (repeatable, verified twice against the reference box):

```bash
sudo docker compose -f defcon-cloud-compose.yml down -v --remove-orphans
sudo rm -rf /var/lib/ztlp/ca/* /var/lib/ztlp/gateway/*
sudo docker compose -f defcon-cloud-compose.yml up -d
```

## 3. Client: enroll a device (laptop / any machine with `ztlp`)

```bash
Z=ztlp   # or proto/target/release/ztlp
echo -n 06984504bf07f1cd8462fd9909dcd39cd3e04beb96100a3bbe45eb6113025103 > /tmp/defcon-zone-secret.hex
$Z admin enroll --zone defcon.ztlp --secret /tmp/defcon-zone-secret.hex \
   --ns-server 44.240.16.59:23096 --relay 44.240.16.59:23095 \
   --gateway 44.240.16.59:23097 --expires 24h
$Z setup --token 'ztlp://enroll/...' --name my-laptop-01 --yes
```

The zone secret is `ZTLP_ENROLLMENT_SECRET` in `defcon-cloud-compose.yml`
(demo-only, published on purpose). `--secret` wants a FILE path. Tokens are
single-use; device names must be new each time.

`ztlp setup` does NOT write `agent.toml`. Create `~/.ztlp/agent.toml`:

```toml
[identity]
path = "/home/<you>/.ztlp/identity.json"
[ns]
servers = ["44.240.16.59:23096"]
[tunnel]
relays = ["44.240.16.59:23095"]
[dns]
enabled = true
listen = "127.0.0.55:15353"
zones = ["defcon.ztlp"]
[tls]
enabled = false          # dashboard is plain HTTP behind the gateway
```

## 4. Client: run the agent and hit the dashboard

```bash
sudo setcap cap_net_bind_service=+ep $(readlink -f $(which ztlp))   # once per binary build
ztlp agent start --foreground -vv &
dig @127.0.0.55 -p 15353 demo-dashboard.defcon.ztlp +short          # 127.100.0.1
curl -s http://127.100.0.1/api/health                                # {"status":"ok"}
curl -s http://127.100.0.1/ | grep hmac_verified                     # "hmac_verified": true
```

Gateway side shows one line per tunnel:
`[Quic] handshake ok session=<24 hex> peer=<64 hex> service=demo-dashboard`.

Optional: route the OS resolver for `defcon.ztlp` to `127.0.0.55:15353` so
`curl http://demo-dashboard.defcon.ztlp/` works without `dig`. That is
laptop-OS-specific (systemd-resolved on Linux) — see `ztlp agent dns-setup`
and the `ztlp-defcon-demo-recovery` notes. Not part of the server story.

Reference numbers (Hermes VM in Monrovia -> us-west-2): ~165 ms per request,
5/5 HTTP 200, `hmac_verified: true`, 0 `bad_magic`, 0 `handshakes_fail`.

---

## Pitfalls (each of these cost real time; don't relearn them)

- **`chmod 644` the config files after every scp.** scp preserves local
  0600 modes; ns and gateway run as uid 999 and get `:eacces` on the `:ro`
  mounts. Symptom chain: NS `component_auth` silently `not_configured` ->
  gateway `CertProvisioner ... :unauthorized`. After fixing modes restart
  BOTH ns and gateway (or `down`/`up`).
- **TOFU pin.** The client pins the gateway's QUIC cert SHA-256 in
  `~/.ztlp/quic_pins/localhost.pin` (all gateways share the pin because SNI
  is always `localhost`). The cert is persisted in `/var/lib/ztlp/gateway/`
  and is stable across restarts; a clean-slate wipe regenerates it and
  every existing client fails with "certificate fingerprint ... does not
  match the pinned value" until `rm ~/.ztlp/quic_pins/localhost.pin`.
- **`setcap` after every cargo rebuild** of `ztlp`, or the agent logs
  `cannot bind VIP 127.100.0.1:80/443: Permission denied`.
- **Stale `HOME`.** Every `ztlp` command reads `$HOME/.ztlp`; if a shell has
  `HOME` exported elsewhere you silently enroll into the wrong directory.
- **Do not pass `--transport udp` or `--no-multi-candidate`.** Real QUIC is
  the only path this gateway accepts (`ZTLP_GATEWAY_UDP_ENABLED=false`).
- **Three env vars must agree on the service name** (`demo-dashboard`):
  `ZTLP_GATEWAY_BACKENDS`, `ZTLP_GATEWAY_POLICIES`,
  `ZTLP_GATEWAY_SERVICE_NAMES`. The relay does exact-match, no wildcard.
- **Relay HMAC mode** is `staging` in this compose (accepts unverified
  routes, logs `unverified_staging`). Production needs per-zone secrets.
- **`ztlp connect ... -L` from a machine that ALSO runs the local loopback
  demo stack** (`demo/local-loopback.override.yml`) direct-dials the SVC
  address `172.42.90.30:23097`, which is the local Docker bridge, so it hits
  the local gateway and trips the TOFU pin. Test-rig artifact only; the
  agent path uses the configured relay and is unaffected.
- **Trust anchor must match NS's registration-signing key.** NS signs every
  device KEY/SVC record with the key in `demo/ns-registration.key`
  (`ZTLP_NS_IDENTITY_KEY_FILE`); `ZTLP_GATEWAY_TRUST_ANCHORS` is that key's
  Ed25519 pubkey. If they drift (or the key file is unreadable and NS
  generates a random one) every lookup is `:untrusted_signer` and the
  dashboard shows `node name: unknown:<hex>` while HMAC still verifies.
  Pinned by `ns/test/ztlp_ns/demo_trust_anchor_consistency_test.exs`.

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

Wire-level details of the QUIC transport: `gateway/README.md`, section
"QUIC transport".
