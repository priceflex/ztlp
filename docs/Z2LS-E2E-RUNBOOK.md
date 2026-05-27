# Z2LS End-to-End Test Runbook

**Status:** Living document — captured 2026-05-26 after a multi-hour e2e debug session
**Topology:** Mac client (LAN/WAN) → AWS relay → Windows VM gateway → OpenSSH

This is the canonical runbook for the Z2LS bench setup at Tech Rockstars. It captures the
working topology, the working commands, and every bug we found along the way so future
sessions don't repeat the same debugging.

---

## Topology

```
┌───────────────────┐      ┌────────────────────────────────┐      ┌─────────────────────┐
│ Steve's Mac       │      │ AWS us-west-2                  │      │ Windows VM          │
│ Stevens-Mac-Studio│      │                                │      │ DESKTOP-LRC8DKH     │
│ 10.170.3.134      │─────▶│ Relay  34.218.240.106:23095    │◀────▶│ 10.170.3.111        │
│                   │      │   priceflex/ztlp-relay:v0.30.11│      │   ztlp listen       │
│ ztlp connect      │      │                                │      │   nssm + OpenSSH 22 │
│ (or LAN-direct)   │      │ NS     16.147.41.195:23096     │      │                     │
│                   │      │   priceflex/ztlp-ns:v0.30.10   │      │                     │
└───────────────────┘      │   (IP rotates on stop/start!)  │      └─────────────────────┘
                           └────────────────────────────────┘
SD-WAN edge: 204.16.122.24 (both Mac + Windows egress through this)
```

### Components and pinned versions

| Component         | Where                              | Version / Image                  |
|-------------------|------------------------------------|----------------------------------|
| Relay             | AWS `34.218.240.106:23095/udp`     | `priceflex/ztlp-relay:v0.30.11`  |
| NS                | AWS SaaS box `16.147.41.195:23096` | `priceflex/ztlp-ns:v0.30.10`     |
| Windows gateway   | `10.170.3.111` (LAN) / `204.16.122.24` (WAN) | `ztlp v0.30.13` via NSSM   |
| Mac client        | `10.170.3.134`                      | `ztlp v0.30.13` aarch64-darwin   |

> **DO NOT** swap the relay to `v0.30.13`. The v0.30.13 relay binary rejects v0.30.11
> SaaS gateway registrations with `unknown header length / could not extract SessionID`.
> See "Known wire-format incompatibility" below. Until that's properly fixed, **the relay
> stays on v0.30.11**.

---

## Working commands

### From the Mac (LAN-direct, fastest path — bypasses relay)

```bash
cd /Users/stevenprice/Desktop/ztlp-v0.30.13-aarch64-apple-darwin
./ztlp connect 10.170.3.111:23095 \
  --service ssh \
  -L 2222:127.0.0.1:22

# In another terminal:
ssh -p 2222 trs@127.0.0.1
```

Expected output from `ztlp connect`:
```
→ CLIENT_ROUTE sent to 10.170.3.111:23095 (63 bytes, service=ssh)
ZTLP QUIC client listening on TCP 127.0.0.1:2222
Noise Handshake Complete (Quic). Session Init.
```

### From the Mac (WAN-routed, through AWS relay)

```bash
./ztlp connect desktop-lrc8dkh-e2e.z2ls-final-e2e.techrockstars.ztlp \
  --service z2ls-desktop-lrc8dkh-dcc1e2 \
  --ns-server 16.147.41.195:23096 \
  -L 2222:127.0.0.1:22
```

**Note:** today this only works when the Mac is NOT on the same SD-WAN as the Windows VM.
On-LAN it gets blocked by the SD-WAN's lack of NAT hairpin for the unsolicited inbound
packet from the relay. See `NAT-TRAVERSAL.md` for the hole-punch path that fixes this.

### From the Mac (relay-routed + NAT hole punch — robust, works anywhere)

```bash
./ztlp connect desktop-lrc8dkh-e2e.z2ls-final-e2e.techrockstars.ztlp \
  --service z2ls-desktop-lrc8dkh-dcc1e2 \
  --ns-server 16.147.41.195:23096 \
  --stun-server stun.l.google.com:19302 \
  --nat-assist \
  --punch \
  --punch-timeout 15s \
  -L 2222:127.0.0.1:22
```

---

## Windows VM listener config

The gateway runs as a Windows service via NSSM:

```
SERVICE_NAME: ztlp_listener
DISPLAY_NAME: ZTLP Listener
START_TYPE:   AUTO_START
BINARY_PATH:  C:\TRS_Tools\ztlp\nssm.exe
LOGON:        LocalSystem
```

NSSM wraps:
```
C:\TRS_Tools\ztlp\ztlp.exe listen \
  --key C:\ProgramData\ZTLP\identity.json \
  --bind 0.0.0.0:23095 \
  --policy C:\ProgramData\ZTLP\policy.toml \
  --forward ssh:127.0.0.1:22 \
  --ns-server 16.147.41.195:23096 \
  --gateway \
  --relay 34.218.240.106:23095 \
  --service-name z2ls-desktop-lrc8dkh-dcc1e2 \
  --max-sessions 100
```

NSSM logs to:
- stdout: `C:\TRS_Tools\ztlp\logs\ztlp-listener.out.log`
- stderr: `C:\TRS_Tools\ztlp\logs\ztlp-listener.err.log`

### Required Windows Firewall rule

```powershell
New-NetFirewallRule `
  -DisplayName "ZTLP Gateway (UDP 23095)" `
  -Direction Inbound `
  -Protocol UDP `
  -LocalPort 23095 `
  -Action Allow `
  -Profile Any `
  -Enabled True
```

**This rule was missing on the bench and is the single biggest source of "tunnel
hangs at QUIC PTO retries" symptoms.** Without it, packets arrive at the host but are
silently dropped by Windows Firewall — the gateway never sees them. This MUST be in the
Chef cookbook (see `CHEF-COOKBOOK-CHANGES.md`).

### Local files on the Windows VM

| Path                                    | Purpose                                                  |
|-----------------------------------------|----------------------------------------------------------|
| `C:\ProgramData\ZTLP\identity.json`     | Gateway identity (NodeID `bc97d655929c30be37885ff8de4881c8`) |
| `C:\ProgramData\ZTLP\config.toml`       | NS server + relay + zone (Chef-managed)                  |
| `C:\ProgramData\ZTLP\policy.toml`       | Service access policy (default deny, allow ssh)          |
| `C:\TRS_Tools\ztlp\ztlp.exe`            | Gateway binary v0.30.13                                  |
| `C:\TRS_Tools\ztlp\nssm.exe`            | Service wrapper                                          |
| `C:\TRS_Tools\ztlp\logs\*.log`          | NSSM-captured stdout/stderr                              |

---

## AWS relay deployment

The relay runs as a Docker container:

```bash
sudo docker run -d \
  --name ztlp-relay \
  --restart unless-stopped \
  --network bridge \
  -p 23095:23095/udp \
  -p 9101:9101/tcp \
  -v ztlp-relay-data:/data \
  --health-cmd "/app/healthcheck.sh" \
  --health-interval=30s \
  --health-timeout=5s \
  --health-retries=3 \
  priceflex/ztlp-relay:v0.30.11
```

### How to verify the relay is healthy

```bash
ssh -i /home/trs/ztlp/.ssh/ztlp_aws_key ubuntu@34.218.240.106 \
  'sudo docker ps --filter name=ztlp-relay --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"; \
   sudo docker logs ztlp-relay --since 2m 2>&1 | grep "Registered dynamic gateway" | tail -10'
```

Expected: `Up X minutes (healthy)` and a list of every tenant + the z2ls
gateway registering on a ~10s loop:

```
[GatewayForwarder] Registered dynamic gateway BC97D655... service=z2ls-desktop-lrc addr={{204, 16, 122, 24}, 23095} ttl=60s
```

### `dropped_l1` / `sessions=0` is OK at idle

The relay emits `[stats] sessions=0 ... dropped_l1=N` lines every minute. Dropped counters
are normal — they include malformed handshake retries, expired sessions, etc. A healthy
relay can show `dropped_l1=43, sessions=0` and still be working perfectly when no client
is currently connected. **What matters is that `Registered dynamic gateway` lines are
flowing.**

---

## NS records (Mnesia)

The NS is the source of truth for service discovery. We injected this record manually
(via z2ls bootstrap originally) and it must remain in sync with the gateway's
`--service-name`:

```
desktop-lrc8dkh-e2e.z2ls-final-e2e.techrockstars.ztlp  (SVC)
  address: 34.218.240.106:23095   (the relay)
  node_id: bc97d655929c30be37885ff8de4881c8   (the gateway)
```

**Gotcha:** there's name drift between the NS record (`desktop-lrc8dkh-e2e`) and the
gateway's currently registered `--service-name` (`z2ls-desktop-lrc8dkh-dcc1e2`). The
client resolves by the NS-record name but the relay routes by the gateway's
service-name. Both eventually land at the same NodeID so it works, but it's confusing
and brittle. See `Known issues → NS record drift`.

### How to inspect NS records

```bash
ssh -i /home/trs/ztlp/.ssh/ztlp_aws_key ubuntu@16.147.41.195 \
  'sudo docker exec ztlp-ns /app/bin/ztlp_ns rpc \
     "ZtlpNs.Store.list_by_zone(\"z2ls-final-e2e.techrockstars.ztlp\") |> IO.inspect(limit: :infinity, pretty: true)"'
```

### How to query a name end-to-end

```bash
ssh -i /home/trs/ztlp/.ssh/ztlp_aws_key ubuntu@16.147.41.195 \
  'sudo docker exec ztlp-ns /app/bin/ztlp_ns rpc \
     "ZtlpNs.Query.resolve_all(\"desktop-lrc8dkh-e2e.z2ls-final-e2e.techrockstars.ztlp\")"'
```

---

## Known issues / bugs

These all surfaced in the 2026-05-26 debug session and should be filed as GitHub issues:

### 1. CLI `connect <name>:<port>` uses port as QUIC transport port

When you run `ztlp connect host.zone.ztlp:22`, the client takes the `:22` you supplied
and uses it as the UDP transport port instead of the relay port from the SVC record. The
resolver logs `✓ SVC record → 34.218.240.106:23095` but then `Resolved: 34.218.240.106:22`.
Workaround: omit the port (`ztlp connect host.zone.ztlp`).

**File:** issue in priceflex/ztlp — CLI bug

### 2. NS record drift on service-name change

When a gateway's `--service-name` changes (e.g., Chef pushes a new config), the gateway
keeps registering with the relay under the new name, but the NS SVC record still
contains the old name. The client uses NS by name, so any client using the new name fails
with `no SVC record`. The gateway should re-publish its SVC record to NS on startup with
its current `--service-name`.

**File:** issue in priceflex/ztlp — gateway should auto-publish SVC

### 3. `--service` semantics are contextual

- When the client talks to the **relay**, `--service` is the gateway's *registered name*
  (matches `--service-name` on the gateway side, e.g., `z2ls-desktop-lrc8dkh-dcc1e2`).
- When the client talks **directly to the gateway** (LAN bypass), `--service` is the
  *forward name* (matches `--forward NAME:HOST:PORT`, e.g., `ssh`).

This is confusing and easy to get wrong. The client should detect which context it's in
(relay vs direct) and either accept both forms or document the difference loudly.

**File:** issue in priceflex/ztlp — CLI UX bug

### 4. NSSM bind-loop on restart

When the service restarts, NSSM launches the new ztlp.exe before the old process has
fully released UDP/23095. The new process emits
`failed to bind UDP socket: error 10048` 10+ times before succeeding. NSSM should be
configured with `AppRestartDelay` ≥ 5000ms.

**Fix:** update NSSM config (one-liner in Chef cookbook).

### 5. Windows Firewall rule missing in Chef cookbook

See `CHEF-COOKBOOK-CHANGES.md`. Every customer install hits this until the cookbook adds
the inbound UDP/23095 allow rule.

### 6. v0.30.13 relay binary wire incompatibility

`priceflex/ztlp-relay:v0.30.13` (when built and run) rejects gateway registrations from
the v0.30.11 SaaS Launch container with:
```
WARN unknown header length: 3612
WARN relay: could not extract SessionID from packet
```

Until this is properly diagnosed, **pin the relay to `v0.30.11`**. The rogue v0.30.13
binary that was running on the bench was quarantined to
`/tmp/rogue-ztlp-v0.30.13-quarantined.*` on the AWS relay box for post-mortem.

**File:** issue in priceflex/ztlp — wire format diff between v0.30.11 and v0.30.13 on
relay registration path

### 7. SaaS Box IP rotation

The SaaS host (NS + Launch + ngrok) does NOT have an Elastic IP. On stop/start its
public IP rotates. Today (2026-05-26) it's `16.147.41.195`. Was `35.91.88.177`
previously. When the IP rotates, the Chef-pushed `config.toml` on every customer
endpoint goes stale and every customer needs a Chef converge.

**Fix:** allocate an Elastic IP for the SaaS box (Steve to do via AWS console — costs ~$3.65/mo).

---

## Restart procedures

### Restart the relay

```bash
ssh -i /home/trs/ztlp/.ssh/ztlp_aws_key ubuntu@34.218.240.106 \
  'sudo docker restart ztlp-relay'
```

Warning: this drops every active session including iOS clients. **Ask Steve before
restarting** unless explicit freedom-to-restart was given.

### Restart the NS

```bash
ssh -i /home/trs/ztlp/.ssh/ztlp_aws_key ubuntu@16.147.41.195 \
  'sudo docker restart ztlp-ns'
```

Same caveat. NS restart causes a brief discovery outage; existing sessions persist.

### Restart the Windows gateway

```powershell
# From any admin shell on the Windows VM (including SSH-as-admin)
Restart-Service ztlp_listener
```

### Re-deploy the AWS relay from scratch (cold)

See `references/aws-relay-cold-redeploy.md` for the full procedure. TL;DR:

```bash
# Kill any rogue binary first
sudo pkill -f '/tmp/.*ztlp relay'
sudo ss -ulnp | grep 23095  # confirm freed

# Then docker run as in "AWS relay deployment" above
```

---

## Bench-specific paths and credentials

| Resource              | Path / How to access                                               |
|-----------------------|--------------------------------------------------------------------|
| AWS SSH key           | `/home/trs/ztlp/.ssh/ztlp_aws_key`                                 |
| Windows VM SSH        | `ssh trs@10.170.3.111` (key-based, no password)                    |
| Mac SSH               | `ssh stevenprice@10.170.3.134` (Hermes key authorized)             |
| Relay AWS instance    | `i-0aac3277c39593300` (us-west-2)                                  |
| SaaS box ngrok auth   | Container `ngrok` on SaaS host; token lives in container env       |

---

## What "working" looks like

```
$ ssh -p 2222 trs@127.0.0.1 'hostname; whoami'
DESKTOP-LRC8DKH
desktop-lrc8dkh\trs
```

That's the green light. If you get that output, the full ZTLP data plane is working.

---

## Related docs

- `NAT-TRAVERSAL.md` — hole punching, when to use, how it works
- `CHEF-COOKBOOK-CHANGES.md` — what the Z2LS Chef recipe needs
