# Z2LS Windows Deploy Spec (v0.32.2+)

**Audience:** Chef cookbook authors, operations engineers, and anyone responsible for
provisioning a new "Z2LS" Windows machine into Tech Rockstars' ZTLP overlay.

**Status:** Authoritative as of 2026-05-27 (post-v0.32.2 release). Captures the live
configuration verified on `DESKTOP-LRC8DKH` (10.170.3.111). Each section enumerates
"what" + "why" + "Chef-recipe shape" so the cookbook implementation can follow
directly.

**Companion docs (read together):**
- [`Z2LS-E2E-RUNBOOK.md`](Z2LS-E2E-RUNBOOK.md) — operator runbook for live debugging.
  **Out of date as of v0.30 — supersede with this doc when conflicts arise.**
- [`WINDOWS-RELAY-SSH.md`](WINDOWS-RELAY-SSH.md) — Windows-side SSH bring-up steps.
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — generic ZTLP deployment guide.

---

## 1. Architecture — what Z2LS is

```
                          Internet
                              │
                              ▼
              ┌───────────────────────────────┐
              │  AWS us-west-2                │
              │                               │
              │  Relay  34.218.240.106:23095  │  v0.32.2  ← stable EIP
              │   priceflex/ztlp-relay:v0.32.2│
              │                               │
              │  NS     16.147.41.195:23096   │  v0.32.2  ← IP rotates on stop/start
              │   priceflex/ztlp-ns:v0.32.2   │
              │                               │
              └───────────────┬───────────────┘
                              │
                              ▼
       ┌─────────────────────────────────────────────────┐
       │  Customer LAN (Tech Rockstars HQ — 10.170.0/16) │
       │                                                 │
       │  Z2LS Windows VM   DESKTOP-LRC8DKH              │
       │  10.170.3.111                                   │
       │  ──────────────                                 │
       │  ztlp.exe v0.32.2 (NSSM service: ztlp_listener) │
       │   ├─ --gateway     (registers w/ NS + relay)    │
       │   ├─ --bind 0.0.0.0:23095/udp  (multi-candidate)│
       │   ├─ --forward ssh:127.0.0.1:22                 │
       │   └─ --service-name z2ls-desktop-lrc8dkh-dcc1e2 │
       │                                                 │
       │  OpenSSH server (Windows feature)               │
       │  Listening 127.0.0.1:22, password auth          │
       │                                                 │
       │  Windows Defender Firewall                      │
       │    inbound allow UDP 23095 (ZTLP Gateway)       │
       └─────────────────────────────────────────────────┘
                              ▲
                              │
                              │  Any TR-LAN box runs:
                              │    ztlp connect --multi-candidate
                              │      --ns-server 16.147.41.195:23096
                              │      --service ssh -L 2299:127.0.0.1:22
                              │      z2ls-desktop-lrc8dkh-dcc1e2.z2ls-final-e2e.techrockstars.ztlp
                              │  ↓
                              │    NS resolves the zone-FQDN to a list of candidates
                              │    (LAN IPs + WAN IPs + relay)
                              │    Client races candidates in parallel (v0.32 ICE-style)
                              │    Wins on the LAN candidate (direct, no relay hop)
                              │    QUIC handshake → forwards to 127.0.0.1:22 over the tunnel
                              │    Operator runs:  ssh -p 2299 trs@127.0.0.1
                              │
                          Operator box
```

**Why Z2LS in one sentence:** any Tech Rockstars technician with a ZTLP identity can
SSH into the shop's Windows machine from anywhere by name — `z2ls-<id>.z2ls-final-e2e.techrockstars.ztlp` —
without VPN, port forwards, or shop-side networking changes. The Z2LS box just runs
`ztlp listen --gateway` and the rest is handled by ZTLP.

---

## 2. What changed between v0.30 and v0.32.2 — read this first

If you're updating a working v0.30-era cookbook, only these things really moved:

| Concern | v0.30 / earlier | v0.32.2 (now) |
|---|---|---|
| `ztlp.exe` binary version | 0.30.x or 0.31.0 | **0.32.2** (and the binary actually reports it via `ztlp --version`) |
| Connectivity model | Relay-mandatory; LAN-direct was bench-only and required hand-coded IPs | **Multi-candidate discovery (ICE-style)** in QUIC dial path. NS-name + `--multi-candidate` resolves to a LAN candidate first, falls back through other private addresses, host public, srflx, and finally relay. No code changes needed on the Z2LS side — server just advertises addresses. |
| NS image | `priceflex/ztlp-ns:v0.30.10` or `v0.31.0` | `priceflex/ztlp-ns:v0.32.2` (deployed 2026-05-27). **Schema change: new index tables `device_index` + `group_index` — Mnesia wipe required on upgrade; preserve `ca/`.** |
| Relay image | `priceflex/ztlp-relay:v0.30.11` (pinned old) | `priceflex/ztlp-relay:v0.32.2`. Old wire-format-incompatibility note in `Z2LS-E2E-RUNBOOK.md` is **resolved** — relay + gateway can both be v0.32.2 together. |
| Gateway port advertisement | Advertised the keepalive ephemeral port (broken — multi-candidate dials timed out) | Advertises the actual listener port (e.g. `23095`). Fixed in v0.32.1 (PR #70). |
| `QuicDialer` IPv6 | Bound `0.0.0.0:0` for all dials → `EAFNOSUPPORT` on IPv6 candidates | Family-matched socket bind (`0.0.0.0:0` for v4, `[::]:0` for v6). Fixed in v0.32.1 (PR #70). |
| Connection bootstrapping | Many flags overloaded, M6 lived in legacy-UDP path which is broken vs current relay | Multi-candidate dial now lives in the **QUIC path** (PR #71). The QUIC path always worked for direct-IP; now it works for NS-name too. |

**Net cookbook impact:** identical to v0.30 from the cookbook's perspective — same files,
same service definition, same firewall rule. The only thing the cookbook needs to do
differently is **pin to v0.32.2** in attributes.

---

## 3. Filesystem layout — the source of truth

Everything Chef writes lives in two directories. Nothing else.

### `C:\TRS_Tools\ztlp\` — code and logs (operator-managed)

```
C:\TRS_Tools\ztlp\
├── ztlp.exe                     ← live binary, 10.5 MB, must be v0.32.2
├── ztlp.exe.new                 ← staging slot for next deploy (Chef writes here first)
├── ztlp.exe.backup-pre-vX.Y.Z   ← previous binaries, never auto-pruned
├── nssm.exe                     ← v2.24 service manager
└── logs\
    ├── ztlp-listener.out.log    ← service stdout
    └── ztlp-listener.err.log    ← service stderr
```

**Why two directories:** `C:\TRS_Tools` is the standard TR utilities path — operators
already know to look there. `C:\ProgramData\ZTLP` is the standard Windows app-data
path for system services, and is where the NSSM-installed LocalSystem service expects
secrets to live. Mixing them would put the identity key next to the binary, which is
wrong.

### `C:\ProgramData\ZTLP\` — runtime state (system-managed)

```
C:\ProgramData\ZTLP\
├── identity.json                ← 234 bytes; ZTLP node identity (3 JSON keys)
├── config.toml                  ← Chef-rendered; static settings
├── policy.toml                  ← Chef-rendered; auth/forwarding policy
└── logs\                        ← reserved for service crash dumps
```

`identity.json` schema (verified on the live box):
```json
{
  "node_id":            "<32-hex>",
  "static_private_key": "<base64 X25519 private>",
  "static_public_key":  "<base64 X25519 public>"
}
```

**Generated, NOT shipped.** The cookbook MUST generate this on first install via
`ztlp.exe gen-identity --out C:\ProgramData\ZTLP\identity.json` and then never touch
it again on subsequent runs. The `node_id` is what the NS uses to look up this
machine; rotating the file = orphaning the registration.

**Permissions:** owned by `BUILTIN\Administrators`, readable by `NT AUTHORITY\SYSTEM`
(the service account). Operators should NOT be able to read it.

```powershell
# Chef should run something equivalent to:
icacls 'C:\ProgramData\ZTLP\identity.json' /inheritance:r
icacls 'C:\ProgramData\ZTLP\identity.json' /grant:r 'BUILTIN\Administrators:(F)'
icacls 'C:\ProgramData\ZTLP\identity.json' /grant:r 'NT AUTHORITY\SYSTEM:(R)'
```

---

## 4. The configuration files — what Chef renders

### `C:\ProgramData\ZTLP\config.toml` — static settings

Verified live contents:

```toml
# Managed by Chef cookbook ztlp.
identity = "C:/ProgramData/ZTLP/identity.json"
ns_server = "16.147.41.195:23096"
relay = "34.218.240.106:23095"
zone = "z2ls-final-e2e.techrockstars.ztlp"
```

Cookbook attributes that should produce this:

| TOML key | Chef attribute | Notes |
|---|---|---|
| `identity` | `node['ztlp']['identity_path']` | Default `C:/ProgramData/ZTLP/identity.json`. Use forward slashes — TOML doesn't escape backslashes the way you'd want. |
| `ns_server` | `node['ztlp']['ns_server']` | **Pin to a hostname, not an IP**, the moment ZTLP NS supports it. Today the SaaS box rotates its public IP on stop/start (see Section 7 — `ns_server` is the highest-churn attribute). |
| `relay` | `node['ztlp']['relay']` | Stable EIP `34.218.240.106:23095`. Low-churn. |
| `zone` | `node['ztlp']['zone']` | The DNS-suffix the gateway registers under. Per-fleet, not per-machine. Current Tech Rockstars value: `z2ls-final-e2e.techrockstars.ztlp`. |

### `C:\ProgramData\ZTLP\policy.toml` — what services this gateway exposes

Verified live contents:

```toml
# Managed by Chef cookbook ztlp. Local edits may be overwritten.
default = "deny"

[[services]]
name = "ssh"
allow = ["*"]
```

**Cookbook contract:** `default = "deny"` is the only sane value here.
`allow = ["*"]` is currently OK because Z2LS gateways only expose `ssh` (which has
its own auth at the OpenSSH layer). When we add more services, each one needs an
`allow` list of admitted ZTLP node_ids OR groups — see "Future work" §10.

Cookbook attributes:

| TOML key | Chef attribute | Notes |
|---|---|---|
| `default` | hardcode `"deny"` | Do NOT make this an attribute. Deny-by-default is policy. |
| `[[services]]` | `node['ztlp']['services']` (array of hashes) | Each hash: `name`, `allow`. |

---

## 5. The NSSM service definition

Verified live `nssm get` for `ztlp_listener`:

| NSSM key | Value |
|---|---|
| `Application` | `C:\TRS_Tools\ztlp\ztlp.exe` |
| `AppDirectory` | `C:\TRS_Tools\ztlp` |
| `AppStdout` | `C:\TRS_Tools\ztlp\logs\ztlp-listener.out.log` |
| `AppStderr` | `C:\TRS_Tools\ztlp\logs\ztlp-listener.err.log` |
| `Start` | `SERVICE_AUTO_START` |
| `ObjectName` | `LocalSystem` |
| `AppParameters` | (next subsection) |

### Parameters — the load-bearing arg list

```
listen
  --key C:\ProgramData\ZTLP\identity.json
  --bind 0.0.0.0:23095
  --policy C:\ProgramData\ZTLP\policy.toml
  --forward ssh:127.0.0.1:22
  --ns-server 16.147.41.195:23096
  --gateway
  --relay 34.218.240.106:23095
  --service-name z2ls-desktop-lrc8dkh-dcc1e2
  --max-sessions 100
```

What each flag does and where it should come from:

| Flag | Value | Chef attribute / derivation | Notes |
|---|---|---|---|
| `listen` | (subcommand) | hardcode | This is the long-running daemon mode. |
| `--key` | `C:\ProgramData\ZTLP\identity.json` | `node['ztlp']['identity_path']` | Same as `config.toml#identity`. |
| `--bind` | `0.0.0.0:23095` | `node['ztlp']['listen_addr']` | Bind ALL interfaces so multi-candidate works on LAN + WAN. |
| `--policy` | `C:\ProgramData\ZTLP\policy.toml` | `node['ztlp']['policy_path']` | |
| `--forward` | `ssh:127.0.0.1:22` | Each entry of `node['ztlp']['forwards']` | The cookbook should iterate and emit one `--forward` per entry. |
| `--ns-server` | `16.147.41.195:23096` | `node['ztlp']['ns_server']` | Same source as `config.toml`. **Yes, this is duplicated. CLI flags override the config file.** Cookbook should only set it in one place to avoid drift — pick the CLI flag (more visible in `nssm get` audit). |
| `--gateway` | (flag-only) | hardcode | This is what makes the listener register as a routable gateway with the NS. |
| `--relay` | `34.218.240.106:23095` | `node['ztlp']['relay']` | Same source as `config.toml`. |
| `--service-name` | `z2ls-desktop-lrc8dkh-dcc1e2` | **derived: see below** | The per-machine slug under the zone. Required to disambiguate Z2LS gateways on the shared relay — default `"ztlp-gateway"` would collide across every Z2LS box. |
| `--max-sessions` | `100` | `node['ztlp']['max_sessions']` | Default 100 is fine for Z2LS shop boxes. |

### `--service-name` vs `--service` — don't confuse them

These are two flags on opposite ends of a ZTLP connection:

| Flag | On which command | What it does | Cookbook concern |
|---|---|---|---|
| `--service-name` | `ztlp listen --gateway` (Z2LS side) | Routing slug the relay indexes this gateway under. Default `"ztlp-gateway"` — must be overridden on Z2LS so multiple shops' gateways don't collide on the shared relay. | **Yes — cookbook MUST set this per-machine.** Derivation in subsection below. |
| `--service` | `ztlp connect` (operator side) | Names which `--forward NAME:HOST:PORT` on the gateway the client wants to route to. Gets emitted in a CLIENT_ROUTE frame inside the handshake. | **Not a cookbook concern.** The cookbook never runs `ztlp connect`. Operators do, from their own laptop. The spec only mentions it in §9 (healthcheck) and §1 (architecture). |

If you see a `--forward NAME:H:P` flag on the listener and a `--service NAME` flag on the client, they pair: `--service ssh` from the client tells the gateway to forward to `127.0.0.1:22` from its `--forward ssh:127.0.0.1:22` config.

### Computing `--service-name`

Per the live deploy: `z2ls-desktop-lrc8dkh-dcc1e2`. The shape is:

```
z2ls-<hostname-lowercased-and-sanitized>-<6-hex of node_id>
```

In Chef terms:

```ruby
hostname_slug = node['hostname'].downcase.gsub(/[^a-z0-9-]/, '-')
node_id_hex   = JSON.parse(File.read(identity_path))['node_id'][0,6]
service_name  = "z2ls-#{hostname_slug}-#{node_id_hex}"
```

**Why this shape:** matches the `<service-name>.<zone>` FQDN that NS records as a
gateway entry. `ztlp connect z2ls-desktop-lrc8dkh-dcc1e2.z2ls-final-e2e.techrockstars.ztlp`
is what operators type. The 6-hex suffix prevents collisions when two shops happen
to have the same Windows computer name. Don't deviate from this shape — the existing
NS records use it, and the dashboard / Z2LS portal indexes by it.

### Putting it together: NSSM install commands

This is what the cookbook's `nssm_service 'ztlp_listener'` resource should produce:

```powershell
# One-shot install (run only when service doesn't exist):
nssm install ztlp_listener "C:\TRS_Tools\ztlp\ztlp.exe"
nssm set ztlp_listener AppDirectory  "C:\TRS_Tools\ztlp"
nssm set ztlp_listener AppParameters "listen --key C:\ProgramData\ZTLP\identity.json --bind 0.0.0.0:23095 --policy C:\ProgramData\ZTLP\policy.toml --forward ssh:127.0.0.1:22 --ns-server 16.147.41.195:23096 --gateway --relay 34.218.240.106:23095 --service-name z2ls-desktop-lrc8dkh-dcc1e2 --max-sessions 100"
nssm set ztlp_listener AppStdout     "C:\TRS_Tools\ztlp\logs\ztlp-listener.out.log"
nssm set ztlp_listener AppStderr     "C:\TRS_Tools\ztlp\logs\ztlp-listener.err.log"
nssm set ztlp_listener Start         SERVICE_AUTO_START
nssm set ztlp_listener ObjectName    LocalSystem
nssm set ztlp_listener AppRotateFiles 1
nssm set ztlp_listener AppRotateBytes 10485760
nssm start ztlp_listener
```

**Pitfall — NSSM Unicode round-trip:** `nssm get` returns UTF-16 strings on
Windows. If your Chef recipe reads them back to compare with current state, decode
explicitly. Some Chef Windows resources do this for you; others don't. (See user
memory: "NSSM Trap: `nssm get` returns UTF-16; `nssm set` requires clean strings.
Avoid round-tripping.")

**Pitfall — restart vs reload:** `nssm restart` works but is destructive (drops
in-flight sessions). When Chef changes attributes, prefer:
1. `nssm set` the new values (no restart yet)
2. Trigger restart via Chef's `notifies :restart, 'service[ztlp_listener]', :delayed`

This batches multiple attribute changes into one restart at the end of the run.

---

## 6. The Windows Firewall rule

Verified live:

```
Rule Name: ZTLP Gateway (UDP 23095)
  Direction: In
  Action:    Allow
  Protocol:  UDP
  LocalPort: 23095
```

Chef:

```ruby
windows_firewall_rule 'ZTLP Gateway (UDP 23095)' do
  description 'Allow inbound UDP for ZTLP listener'
  direction :in
  action    :allow
  protocol  :udp
  local_port '23095'
end
```

**Why open to all profiles (not just `private`):** multi-candidate discovery requires
that ANY peer (LAN or via SD-WAN tunnel) be able to send UDP to the listener so the
"host other private" candidate (e.g. `10.170.3.111`) can win. Restricting to `private`
profile is fine on a managed corp LAN but breaks the moment the Windows profile flips
to `public` (e.g. unknown network classification on first connect). Z2LS gateways
should accept the rule on all profiles — confidentiality comes from ZTLP's Noise
handshake, not from firewall scope.

---

## 7. Dependencies the cookbook must satisfy first

Order matters. Chef resources should be ordered so the dependent ones notify the
ZTLP service for restart.

| # | Dependency | Why | Chef shape |
|---|---|---|---|
| 1 | **OpenSSH Server feature enabled** | `--forward ssh:127.0.0.1:22` requires sshd to be running and listening on `127.0.0.1:22`. | `windows_feature 'OpenSSH-Server~~~~0.0.1.0' { action :install }` + `service 'sshd' { action [:enable, :start] }` |
| 2 | **`sshd_config` set up** | Password auth enabled (Z2LS users SSH in with their domain creds), `127.0.0.1:22` is the listener. **Do NOT bind sshd to 0.0.0.0** — only ZTLP should reach it from outside. | Template `C:\ProgramData\ssh\sshd_config` then notify `service[sshd]` restart. |
| 3 | **NSSM v2.24 installed at `C:\TRS_Tools\ztlp\nssm.exe`** | Used to install + supervise `ztlp_listener`. | `remote_file` from your internal artifact mirror. SHA256 in attributes. |
| 4 | **`C:\TRS_Tools\ztlp` directory created** | Code lives here. | `directory` with owner = Administrators, mode :read_execute for operators. |
| 5 | **`C:\ProgramData\ZTLP` directory created** | State lives here. | `directory` with owner = SYSTEM, deny operators read. |
| 6 | **`ztlp.exe` v0.32.2 downloaded + verified** | The actual gateway binary. | `remote_file` to `C:\TRS_Tools\ztlp\ztlp.exe.new`, verify SHA256, then `windows_atomic_rename` to `ztlp.exe`. See §8 for upgrade flow. |
| 7 | **`identity.json` exists** | Required for every `ztlp` invocation. | `execute 'ztlp gen-identity'` with `not_if { File.exist?('C:\ProgramData\ZTLP\identity.json') }`. THIS IS LOAD-BEARING IDEMPOTENCE — running it twice = node re-registration churn. |
| 8 | **`config.toml`, `policy.toml` rendered** | Both via `template` resources, notifying restart. | See §4 above. |
| 9 | **Firewall rule** | See §6. | |
| 10 | **NSSM service installed + started** | Final step. | See §5. |

---

## 8. The upgrade flow — going from version X to v0.32.2

The cookbook should support both fresh install (Section 7) and in-place upgrade
without dropping the running service longer than ~10 seconds. Recommended flow:

```
1. Download new binary to ztlp.exe.new (staging slot)
2. Verify SHA256 against expected (attribute)
3. Copy current ztlp.exe → ztlp.exe.backup-pre-v<OLD_VERSION>
4. nssm stop ztlp_listener        ← unavailability window starts
5. Atomic-rename ztlp.exe.new → ztlp.exe
6. nssm set ztlp_listener AppParameters ...   (only if changed)
7. nssm start ztlp_listener        ← unavailability window ends
8. Wait 5-10s, verify via:
     ztlp.exe --version            → must equal expected version
     sc.exe query ztlp_listener    → STATE = 4 RUNNING
9. Tail logs for "Listening on UDP port 23095" or similar in
   ztlp-listener.out.log to confirm gateway came up
```

**Pitfall — verify the binary actually reports the version you think it reports.**
This is the v0.30.3/v0.32.x lesson learned the hard way (see `proto/tests/version_pin_test.rs`
and the `release-version-pinning` hermes skill). The cookbook should:

```powershell
$expected = '0.32.2'
$actual = (& 'C:\TRS_Tools\ztlp\ztlp.exe' --version) -replace 'ztlp\s+', ''
if ($actual -ne $expected) {
    throw "ztlp.exe reports $actual but cookbook expected $expected. Rollback."
}
```

If the version mismatch fires, the cookbook should auto-rollback by copying
`ztlp.exe.backup-pre-v<OLD>` back over `ztlp.exe` and restarting the service.

**Pitfall — never delete backups.** The `ztlp.exe.backup-pre-v*` files are how
operators recover from a botched deploy. The cookbook should keep at least the
last 3 by lexicographic sort, prune older silently. Operator should also be able
to do a manual rollback via:

```powershell
Stop-Service ztlp_listener
Copy-Item C:\TRS_Tools\ztlp\ztlp.exe.backup-pre-v0.32.1 C:\TRS_Tools\ztlp\ztlp.exe -Force
Start-Service ztlp_listener
```

---

## 9. Verifying the box is healthy

A Chef `kitchen` test or post-converge verifier should confirm all of the following:

1. **Binary version matches expected.**
   ```powershell
   & 'C:\TRS_Tools\ztlp\ztlp.exe' --version    # → ztlp 0.32.2
   ```
2. **Service is RUNNING.**
   ```powershell
   (sc.exe query ztlp_listener | Select-String 'STATE').Line   # → STATE : 4 RUNNING
   ```
3. **No restarts in last 5 min.**
   ```powershell
   $events = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='ztlp_listener'} -MaxEvents 20
   # Inspect for restart loops
   ```
4. **Identity file exists with correct ACL.**
   ```powershell
   $acl = Get-Acl C:\ProgramData\ZTLP\identity.json
   # Owner = BUILTIN\Administrators, no IdentityReference matching ordinary users
   ```
5. **UDP 23095 is bound.**
   ```powershell
   Get-NetUDPEndpoint -LocalPort 23095   # → LocalAddress=0.0.0.0
   ```
6. **NS sees us.** From an operator box (NOT from Z2LS itself):
   ```bash
   ztlp resolve z2ls-desktop-lrc8dkh-dcc1e2.z2ls-final-e2e.techrockstars.ztlp \
       --ns-server 16.147.41.195:23096
   ```
   Should return one or more candidate addresses including `10.170.3.111:23095`.
7. **End-to-end SSH works.** From an operator box on the same LAN:
   ```bash
   ztlp connect --multi-candidate --ns-server 16.147.41.195:23096 \
       --service ssh -L 2299:127.0.0.1:22 \
       z2ls-desktop-lrc8dkh-dcc1e2.z2ls-final-e2e.techrockstars.ztlp &
   sleep 2
   ssh -p 2299 trs@127.0.0.1 'hostname'
   # → DESKTOP-LRC8DKH
   ```

The Chef recipe shouldn't *require* step 6 or 7 to converge — they depend on NS
reachability which may be offline during a fresh-box install. But the post-converge
verifier should run them and warn if they fail.

---

## 10. Future work (cookbook v2+)

These are explicitly OUT of scope for the v1 cookbook but should be planned:

1. **Per-machine RBAC in `policy.toml`.** Today every Z2LS box's `policy.toml`
   says `allow = ["*"]` for ssh. As we onboard more shops, the cookbook should
   accept a list of allowed node_ids OR group names (the v0.32.2 NS now has a
   `group_index` table for this; the in-tree RBAC isn't fully wired yet but the
   index is ready). Pattern:
   ```toml
   [[services]]
   name = "ssh"
   allow = ["group:tr-techs", "group:tr-emergency", "node:<32hex>"]
   ```
2. **NS-name instead of IP.** The SaaS box's public IP rotates on stop/start (a
   well-known foot-gun — see user memory and `ztlp-prod-deployment` skill). The
   cookbook should accept a hostname and resolve it via DNS at first run, refresh
   on schedule. Filed but not yet specced.
3. **Multi-relay failover.** v0.32.2 supports advertising multiple relays in a
   single registration; the cookbook should accept `node['ztlp']['relays']` as
   an array. Today there's one relay (`34.218.240.106`) so this is moot.
4. **Auto-enrollment.** Today the identity is generated locally (`gen-identity`)
   and there's no zone-level enrollment because Z2LS uses the
   `REQUIRE_REGISTRATION_AUTH=false` NS posture. When we tighten NS to
   `=true`, the cookbook will need to call the Bootstrap API to mint a token,
   then run `ztlp setup --token ...` instead of `gen-identity`. See the
   `ztlp-bootstrap-enrollment` skill — the same logic, but driven from a
   non-interactive Chef context.
5. **TPM-backed identity.** `static_private_key` is a plaintext base64 blob on
   disk today. v0.33+ should support sealing the private key to the TPM so an
   attacker who exfiltrates `identity.json` can't impersonate the gateway.
   Cookbook will eventually need to detect TPM availability and pass a
   `--use-tpm` flag.
6. **Log rotation by size + retention.** NSSM `AppRotateBytes 10485760` is set
   but there's no log-archive policy. Pair with `windows_task` doing weekly
   cleanup of old `.log.N` rotations.

---

## 11. Attribute summary (paste into `attributes/default.rb`)

```ruby
# ─── ztlp binary ───────────────────────────────────────────────────────
default['ztlp']['version']        = '0.32.2'
default['ztlp']['binary_url']     = 'https://github.com/priceflex/ztlp/releases/download/v0.32.2/ztlp-v0.32.2-x86_64-pc-windows-msvc.zip'
default['ztlp']['binary_sha256']  = '<fill_in_from_SHA256SUMS.txt_in_release>'
default['ztlp']['install_dir']    = 'C:\TRS_Tools\ztlp'
default['ztlp']['data_dir']       = 'C:\ProgramData\ZTLP'

# ─── overlay topology (per-fleet) ──────────────────────────────────────
default['ztlp']['ns_server']      = '16.147.41.195:23096'   # SaaS IP rotates — confirm before deploy
default['ztlp']['relay']          = '34.218.240.106:23095'  # stable EIP
default['ztlp']['zone']           = 'z2ls-final-e2e.techrockstars.ztlp'

# ─── per-machine ───────────────────────────────────────────────────────
default['ztlp']['identity_path']  = "#{node['ztlp']['data_dir']}/identity.json"
default['ztlp']['policy_path']    = "#{node['ztlp']['data_dir']}/policy.toml"
default['ztlp']['config_path']    = "#{node['ztlp']['data_dir']}/config.toml"
default['ztlp']['listen_addr']    = '0.0.0.0:23095'
default['ztlp']['max_sessions']   = 100
default['ztlp']['forwards']       = ['ssh:127.0.0.1:22']

# ─── policy ────────────────────────────────────────────────────────────
default['ztlp']['services'] = [
  { 'name' => 'ssh', 'allow' => ['*'] }   # tighten in cookbook v2 — see §10
]

# ─── NSSM ──────────────────────────────────────────────────────────────
default['ztlp']['nssm']['version']   = '2.24'
default['ztlp']['nssm']['url']       = 'https://nssm.cc/release/nssm-2.24.zip'
default['ztlp']['nssm']['sha256']    = 'be7b3577c6e3a280e5106a9e9db5b3775931cefc7c3a4181b81fe267e8c8be25'
default['ztlp']['service_name']      = 'ztlp_listener'
```

---

## 12. Reference: the exact live state (snapshot 2026-05-27)

For Chef-test golden-file purposes. Captured from `DESKTOP-LRC8DKH` after the
v0.32.2 deploy:

- `C:\TRS_Tools\ztlp\ztlp.exe` — size 10,505,216 bytes, `ztlp --version` reports
  `ztlp 0.31.0` (older binary still on box — Steve's pending v0.32.2 deploy here).
  **When the cookbook ships, that should become 10,xxx,xxx bytes reporting `ztlp 0.32.2`.**
- `C:\TRS_Tools\ztlp\nssm.exe` — size 331,264 bytes (NSSM v2.24).
- `C:\ProgramData\ZTLP\identity.json` — 234 bytes, contains the three JSON keys
  documented in §3.
- `C:\ProgramData\ZTLP\config.toml` — 193 bytes, exactly as shown in §4.
- `C:\ProgramData\ZTLP\policy.toml` — 131 bytes, exactly as shown in §4.
- Service `ztlp_listener` — `STATE: 4 RUNNING`, `Start: SERVICE_AUTO_START`,
  `ObjectName: LocalSystem`.
- Firewall rule `ZTLP Gateway (UDP 23095)` — inbound allow UDP/23095.
- AWS infra: relay `34.218.240.106:23095` (v0.32.2), NS `16.147.41.195:23096`
  (v0.32.2) — both deployed 2026-05-27, both healthy via runtime RPC.

---

## Document history

| Date | Change |
|---|---|
| 2026-05-27 | Initial draft. Captures v0.32.2 architecture + verified-live config from DESKTOP-LRC8DKH. Supersedes v0.30 sections of `Z2LS-E2E-RUNBOOK.md`. |
