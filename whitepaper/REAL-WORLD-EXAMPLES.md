# ZTLP Real-World Examples

## Peer-to-Peer Deployment — No Gateway Required

These examples show ZTLP protecting real services using direct peer-to-peer encrypted tunnels. No gateway, no intermediary infrastructure. Just two endpoints that prove identity before connectivity.

---

## Example 1: Protect SSH on a Linux Server

### The Problem

You have a Linux server (cloud VM, on-prem, colo) with SSH on port 22. Right now it's exposed to the Internet. Every day it gets hammered by brute-force bots, credential stuffing, and vulnerability scanners. You've got fail2ban, key-only auth, maybe a non-standard port — but the port is still *there*, still answering, still an attack surface.

### The ZTLP Solution

SSH still runs, but only listens on localhost. ZTLP handles the transport. Your server becomes invisible to the Internet.

### Setup: Server Side (Linux)

```bash
# 1. Generate the server's ZTLP identity (one time)
ztlp keygen --output /etc/ztlp/server.json
chmod 600 /etc/ztlp/server.json

# 2. Lock SSH to localhost only
#    Edit /etc/ssh/sshd_config:
#      ListenAddress 127.0.0.1
#    Then restart:
sudo systemctl restart sshd

# 3. Start ZTLP listener that tunnels to local SSH
ztlp listen --key /etc/ztlp/server.json --bind 0.0.0.0:23095 \
    --forward 127.0.0.1:22
```

That's it. Port 22 is no longer reachable from the Internet. The server's public IP has exactly one open UDP port (23095) that only responds to authenticated ZTLP sessions — everything else is silently dropped at Layer 1.

### Setup: Client Side (Your Laptop — Linux/macOS/Windows)

```bash
# 1. Generate your identity (one time)
ztlp keygen --output ~/.ztlp/identity.json

# 2. Connect to the server through ZTLP, forwarding local port to remote SSH
ztlp connect server-ip:23095 --key ~/.ztlp/identity.json \
    --local-forward 2222:127.0.0.1:22

# 3. SSH through the tunnel
ssh -p 2222 user@127.0.0.1
```

Or if both sides are behind NAT:

```bash
# Use a relay for NAT traversal
ztlp connect server-ip:23095 --key ~/.ztlp/identity.json \
    --relay relay.ztlp.org:23095 \
    --local-forward 2222:127.0.0.1:22
```

### What Changed

| Before | After |
|--------|-------|
| SSH on port 22, visible to Shodan | SSH on localhost only, invisible |
| Bots hit it 10,000+ times/day | Zero unauthorized connection attempts |
| fail2ban, rate limiting, geo-blocking | None needed — no one can reach it |
| VPN or bastion host required for remote access | Direct ZTLP tunnel from anywhere |
| IP-based access control (fragile) | Cryptographic identity (unforgeable) |

### systemd Service (Production)

```ini
# /etc/systemd/system/ztlp-ssh.service
[Unit]
Description=ZTLP tunnel for SSH
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ztlp listen \
    --key /etc/ztlp/server.json \
    --bind 0.0.0.0:23095 \
    --forward 127.0.0.1:22
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now ztlp-ssh
```

---

## Example 2: Protect RDP on a Windows Machine

### The Problem

Remote Desktop Protocol (RDP, port 3389) is the #1 initial access vector for ransomware. It's how most ransomware gangs get in — brute-force an exposed RDP port, buy stolen RDP credentials on the dark web, or exploit an unpatched RDP vulnerability (BlueKeep, etc.). Every Windows machine with RDP exposed to the Internet is a target.

The typical "fix" is a VPN — which adds complexity, license costs, and its own attack surface (VPN concentrators are themselves targeted). ZTLP eliminates the problem at the transport layer.

### The ZTLP Solution

RDP still runs, but only on localhost. ZTLP provides the encrypted, identity-authenticated tunnel. The Windows machine has zero ports exposed to the Internet.

### Setup: Windows Machine (The RDP Host)

```powershell
# 1. Generate the machine's ZTLP identity (one time, run as admin)
ztlp keygen --output C:\ProgramData\ztlp\machine.json

# 2. Restrict RDP to localhost only
#    Open Windows Firewall → Inbound Rules → Remote Desktop
#    Change scope to "Local IP: 127.0.0.1" only
#    Or via PowerShell:
Set-NetFirewallRule -DisplayName "Remote Desktop*" `
    -RemoteAddress 127.0.0.1 -Direction Inbound

# 3. Start ZTLP listener that tunnels to local RDP
ztlp listen --key C:\ProgramData\ztlp\machine.json --bind 0.0.0.0:23095 `
    --forward 127.0.0.1:3389
```

### Setup: Technician's Laptop (Connecting to the Windows Machine)

```bash
# 1. Generate your identity (one time)
ztlp keygen --output ~/.ztlp/identity.json

# 2. Connect through ZTLP, forward local port 3389 to remote RDP
ztlp connect client-ip:23095 --key ~/.ztlp/identity.json \
    --local-forward 3389:127.0.0.1:3389

# 3. Open Remote Desktop Connection to localhost
#    Host: 127.0.0.1:3389
#    (or use mstsc /v:127.0.0.1)
```

Behind NAT (most common for client machines):

```bash
# Both sides behind NAT — use a relay
ztlp connect client-ip:23095 --key ~/.ztlp/identity.json \
    --relay relay.ztlp.org:23095 \
    --local-forward 3389:127.0.0.1:3389
```

### What Changed

| Before | After |
|--------|-------|
| RDP on 3389, exposed to the Internet | RDP on localhost, invisible |
| #1 ransomware entry point | Zero attack surface |
| VPN required ($$$, complexity) | ZTLP tunnel (free, single binary) |
| IP allowlisting (breaks with dynamic IPs) | Cryptographic identity (works everywhere) |
| NLA + strong passwords (still brute-forceable) | Can't even reach the login prompt without ZTLP |
| Thousands of daily brute-force attempts | Zero — port doesn't exist publicly |

### Windows Service (Production)

Use NSSM (Non-Sucking Service Manager) to run ZTLP as a Windows service:

```powershell
# Install NSSM
choco install nssm -y

# Create the service
nssm install ZTLPTunnel "C:\Program Files\ztlp\ztlp.exe" `
    "listen --key C:\ProgramData\ztlp\machine.json --bind 0.0.0.0:23095 --forward 127.0.0.1:3389"

nssm set ZTLPTunnel Start SERVICE_AUTO_START
nssm set ZTLPTunnel AppStdout C:\ProgramData\ztlp\logs\stdout.log
nssm set ZTLPTunnel AppStderr C:\ProgramData\ztlp\logs\stderr.log

# Start it
nssm start ZTLPTunnel
```

Or as a native Windows service (Task Scheduler):

```powershell
$action = New-ScheduledTaskAction -Execute "C:\Program Files\ztlp\ztlp.exe" `
    -Argument "listen --key C:\ProgramData\ztlp\machine.json --bind 0.0.0.0:23095 --forward 127.0.0.1:3389"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "ZTLP RDP Tunnel" -Action $action -Trigger $trigger `
    -Settings $settings -User "SYSTEM" -RunLevel Highest
```

---

## Example 3: MSP Managing Multiple Client Sites

### The Scenario

You're an MSP (like Tech Rockstars) managing 50+ client sites. Each site has servers, workstations, and network gear you need to access for support. Today you're juggling VPN tunnels, port forwards, TeamViewer/ConnectWise licenses, and a spreadsheet of credentials.

### The ZTLP Approach

Every managed device gets a ZTLP identity. Your technicians get ZTLP identities. Access is controlled by cryptographic identity — not IP addresses, not VPN tunnels, not third-party remote access tools.

```
MSP Namespace: techrockstars.ztlp
  ├── techs.techrockstars.ztlp
  │   ├── steve (NodeID: a4e1f0...)
  │   ├── mike  (NodeID: b7f2a3...)
  │   └── sarah (NodeID: c9d4e5...)
  │
  └── clients.techrockstars.ztlp
      ├── acme-corp.clients.techrockstars.ztlp
      │   ├── server-01  (SSH, port forward to 22)
      │   ├── dc-01      (RDP, port forward to 3389)
      │   └── firewall   (HTTPS, port forward to 443)
      │
      ├── wayne-ent.clients.techrockstars.ztlp
      │   ├── server-01
      │   └── nas-01
      │
      └── ... (50+ client sites)
```

### Technician Workflow

```bash
# Steve needs to RDP into Acme Corp's domain controller
ztlp connect dc-01.acme-corp.clients.techrockstars.ztlp \
    --key ~/.ztlp/steve.json \
    --relay relay.techrockstars.ztlp:23095 \
    --local-forward 3389:127.0.0.1:3389

# Open RDP to localhost:3389 — connected to Acme's DC
mstsc /v:127.0.0.1

# Sarah needs SSH into Wayne Enterprises' server
ztlp connect server-01.wayne-ent.clients.techrockstars.ztlp \
    --key ~/.ztlp/sarah.json \
    --relay relay.techrockstars.ztlp:23095 \
    --local-forward 2222:127.0.0.1:22

ssh -p 2222 admin@127.0.0.1
```

### What This Replaces

| Traditional MSP Stack | ZTLP Equivalent |
|----------------------|-----------------|
| Site-to-site VPN ($500+/site) | ZTLP relay (one server, all sites) |
| ConnectWise/TeamViewer ($$$) | ZTLP P2P tunnel (free) |
| Per-site firewall rules | Cryptographic identity |
| VPN credential management | Key files (hardware-backed optional) |
| IP allowlisting across sites | NodeID-based access — works from any IP |
| Separate tools for SSH/RDP/HTTPS | One tool: `ztlp connect` |

### Audit Trail

Every ZTLP session is identity-authenticated. You know *exactly* who accessed what, when:

```
2026-03-10 22:15:03 UTC | steve (a4e1f0) → dc-01.acme-corp (session f8d2a1) | 47min
2026-03-10 22:20:11 UTC | sarah (c9d4e5) → server-01.wayne-ent (session b3c7e4) | 12min
```

No shared credentials. No "who was using the VPN at 3am?" No ambiguity.

---

## The Security Math

For a managed Windows endpoint with ZTLP protecting RDP:

| Attack | Without ZTLP | With ZTLP |
|--------|-------------|-----------|
| Port scan discovers RDP | ✅ Yes — 3389 is open | ❌ No — nothing to find |
| Brute-force RDP login | ✅ Possible (even with NLA) | ❌ Can't reach login prompt |
| Stolen RDP credentials | ✅ Usable from anywhere | ❌ Need ZTLP identity + RDP creds |
| BlueKeep-style RDP exploit | ✅ Exploitable if unpatched | ❌ Can't deliver exploit payload |
| Ransomware initial access via RDP | ✅ Primary attack vector | ❌ Eliminated at transport layer |
| Lateral movement after breach | ✅ RDP hop between machines | ❌ Each machine requires separate ZTLP auth |

The key insight: **ZTLP doesn't make RDP more secure. It makes RDP unreachable.** The vulnerability might still exist, but the attacker can't get a packet to it.

---

## Quick Reference

```bash
# Generate identity
ztlp keygen --output ~/.ztlp/identity.json

# Protect a local service (server side)
ztlp listen --key server.json --bind 0.0.0.0:23095 --forward 127.0.0.1:PORT

# Connect to a protected service (client side)
ztlp connect host:23095 --key identity.json --local-forward LOCAL_PORT:127.0.0.1:REMOTE_PORT

# Through a relay (when behind NAT)
ztlp connect host:23095 --key identity.json --relay relay:23095 --local-forward LOCAL_PORT:127.0.0.1:REMOTE_PORT
```

| Service | Remote Port | Example |
|---------|------------|---------|
| SSH | 22 | `--local-forward 2222:127.0.0.1:22` then `ssh -p 2222 localhost` |
| RDP | 3389 | `--local-forward 3389:127.0.0.1:3389` then `mstsc /v:localhost` |
| HTTPS admin | 443 | `--local-forward 8443:127.0.0.1:443` then browse `https://localhost:8443` |
| MySQL | 3306 | `--local-forward 3306:127.0.0.1:3306` then `mysql -h 127.0.0.1` |
| PostgreSQL | 5432 | `--local-forward 5432:127.0.0.1:5432` then `psql -h 127.0.0.1` |
| VNC | 5900 | `--local-forward 5900:127.0.0.1:5900` then VNC viewer to localhost |
| Printer (IPP) | 631 | `--local-forward 631:127.0.0.1:631` |
| Webcam/NVR | 554/8080 | `--local-forward 8080:127.0.0.1:8080` |
