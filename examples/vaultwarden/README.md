# Zero-Trust Password Manager: Vaultwarden + ZTLP

**Run a self-hosted password manager with zero exposed ports.**

This example deploys [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (a self-hosted Bitwarden-compatible server) behind ZTLP — making your password vault invisible to the public internet. No HTTP ports, no HTTPS ports, no TCP ports at all. The only way in is through an authenticated ZTLP tunnel with cryptographic device identity.

---

## What You're Building

```mermaid
graph TB
    subgraph Internet["☁️ Public Internet"]
        A["🔍 Port Scanner"] -.->|"❌ Nothing to find"| FW
        B["🤖 Bot / Attacker"] -.->|"❌ No HTTP/HTTPS"| FW
    end

    subgraph Devices["Your Devices"]
        subgraph Mac["💻 MacBook"]
            BW_M["Bitwarden App"] -->|"🔒 HTTPS (TLS)"| AG_M["ZTLP Agent"]
        end
        subgraph Phone["📱 iPhone"]
            BW_P["Bitwarden App"] -->|"🔒 HTTPS (TLS)"| AG_P["ZTLP Agent"]
        end
        subgraph Lin["🐧 Linux"]
            BW_L["Browser"] -->|"🔒 HTTPS (TLS)"| AG_L["ZTLP Agent"]
        end
    end

    subgraph Server["Your Server"]
        FW["Firewall<br/>23097/udp + 23095/udp only"]
        subgraph ZTLP["ZTLP Stack"]
            GW["ZTLP Gateway<br/>23097/udp"]
            NS["ZTLP-NS<br/>(internal)"]
            RL["ZTLP Relay<br/>23095/udp"]
        end
        subgraph Internal["Internal Network (no ports exposed)"]
            VW["🔐 Vaultwarden<br/>port 80 (internal only)"]
        end
    end

    AG_M ==>|"🔒 Encrypted ZTLP tunnel<br/>(Noise_XX)"| GW
    AG_P ==>|"🔒 Encrypted ZTLP tunnel<br/>(Noise_XX)"| GW
    AG_L -.->|"🔒 Encrypted ZTLP tunnel<br/>(via Relay — NAT traversal)"| RL
    RL ==>|"Forward"| GW
    GW -->|"Identity verified ✓"| VW
    GW <-->|"Identity lookup"| NS
```

> **Two encryption layers protect every request.** The Bitwarden app connects via HTTPS to the ZTLP agent running locally on your device (Layer 1: TLS). The agent wraps the traffic in an authenticated Noise_XX tunnel to the gateway (Layer 2: ZTLP). Devices that can reach the gateway directly connect over 23097/udp; devices behind NAT or restrictive firewalls connect via the ZTLP Relay on 23095/udp — same encryption, same security, just a different path.

All devices connect through the ZTLP agent. The gateway is the single entry point — it terminates the encrypted tunnel, verifies cryptographic identity, enforces group policy, injects identity headers, and forwards to Vaultwarden on the isolated internal network.

### 🔐 Double Encryption

Every request from your Bitwarden app to Vaultwarden is encrypted **twice**:

| Layer | What | How | Protects Against |
|-------|------|-----|------------------|
| **Layer 1: Local TLS** | Browser/App ↔ ZTLP Agent (same device) | TLS 1.3 with ZTLP CA-issued certificate | Local network sniffing, rogue processes inspecting loopback traffic |
| **Layer 2: ZTLP Tunnel** | ZTLP Agent ↔ ZTLP Gateway (over Internet) | Noise_XX authenticated encryption | Internet-level interception, MITM, replay attacks |

- **TLS layer:** During device enrollment (`ztlp setup`), the agent automatically downloads and trusts the ZTLP root CA. Service certificates are automatically provisioned for known hostnames like `vault.home.ztlp`. Your browser sees a valid, trusted HTTPS site — no certificate warnings, no manual cert installation.
- **ZTLP layer:** The Noise_XX handshake authenticates both the agent and the gateway using Ed25519 keys. Each session has unique ephemeral keys — even if one session were somehow compromised, past and future sessions remain secure (forward secrecy).
- **Defense in depth:** Even if an attacker could somehow intercept the ZTLP tunnel (they can't without the session key), the payload inside is *also* TLS-encrypted. They'd need to break both layers.

### What's Different from a VPN?

| Feature | VPN (WireGuard / Tailscale) | ZTLP |
|---------|----------------------------|------|
| **Attack surface** | VPN port is exposed and scannable | Only ZTLP UDP port — service is invisible |
| **Access control** | IP/subnet based | Cryptographic identity + group policy |
| **Device compromise** | Revoke VPN config (maybe regenerate keys) | Revoke device identity instantly — cascade blocks all sessions |
| **DDoS resistance** | VPN server is a target — must process every packet | Three-layer pipeline drops invalid packets in nanoseconds |
| **Always-on** | Must toggle VPN on/off | Agent runs as a system service, transparent |
| **Audit trail** | IP-based logs | Cryptographic identity in every header — signed with HMAC |
| **Encryption** | Single layer (WireGuard/IPsec) | Double: TLS (app↔agent) + Noise_XX (agent↔gateway) |
| **Service isolation** | VPN gives network access (lateral movement risk) | Per-service authorization — each service has its own policy |

With a VPN, once you're connected you have network-level access. With ZTLP, each service (Vaultwarden, SSH, whatever) has its own access policy — compromising one device doesn't give access to services it's not authorized for.

---

## Prerequisites

- **Docker** and **Docker Compose** (v2) — [install Docker](https://docs.docker.com/get-docker/)
- The **`ztlp` CLI binary** — build from `proto/` or download from [releases](https://github.com/priceflex/ztlp/releases)
- **~5 minutes** of your time
- A server or machine to run the stack (a Raspberry Pi, VPS, NAS — anything with Docker)

```bash
# Build the ztlp CLI from source (if you don't have it)
cd proto && cargo build --release --bin ztlp
sudo cp target/release/ztlp /usr/local/bin/
```

---

## Quick Start

### Step 1: Clone the Repo

```bash
git clone https://github.com/priceflex/ztlp.git
cd ztlp/examples/vaultwarden
```

### Step 2: Configure Secrets

```bash
cp .env.example .env
```

Generate and fill in the secrets:

```bash
# Generate enrollment secret (64 hex chars)
echo "ZTLP_ENROLLMENT_SECRET=$(openssl rand -hex 32)" >> .env

# Generate header HMAC secret
echo "ZTLP_HEADER_HMAC_SECRET=$(openssl rand -hex 32)" >> .env

# Generate Vaultwarden admin token
echo "VAULTWARDEN_ADMIN_TOKEN=$(openssl rand -base64 48)" >> .env
```

Or edit `.env` manually — it's well-commented.

### Step 3: Start the Stack

```bash
docker compose up -d
```

Wait for all services to be healthy:

```bash
docker compose ps
```

```
NAME             STATUS                  PORTS
vaultwarden      Up (healthy)            (no ports)
ztlp-ns          Up (healthy)            (no ports)
ztlp-gateway     Up (healthy)            0.0.0.0:23097->23097/udp
ztlp-relay       Up (healthy)            0.0.0.0:23095->23095/udp
```

Notice: Vaultwarden has **no ports** exposed. The only externally accessible ports are 23097/udp (the ZTLP gateway) and 23095/udp (the ZTLP relay for NAT traversal).

### Step 4: Initialize the Zone

On the server (or any machine with the `ztlp` CLI and access to the NS):

```bash
# Initialize the home.ztlp zone
ztlp admin init-zone \
  --zone home.ztlp \
  --ns-server 127.0.0.1:23096

# Create a group for family/team members
ztlp admin create-group family@home.ztlp \
  --ns-server 127.0.0.1:23096

# Create a user
ztlp admin create-user steve@home.ztlp \
  --role admin \
  --ns-server 127.0.0.1:23096

# Add user to the family group
ztlp admin group add family@home.ztlp steve@home.ztlp \
  --ns-server 127.0.0.1:23096
```

### Step 5: Generate Enrollment Tokens

Create a single-use enrollment token for each device:

```bash
ztlp admin enroll \
  --zone home.ztlp \
  --ns-server 127.0.0.1:23096 \
  --relay YOUR_SERVER_IP:23095 \
  --expires 24h \
  --max-uses 1
```

This outputs a token like:

```
ztlp://enroll/AQtvZmZpY2UudGVjaHJvY2tzdGFycy56dGxw...
```

For mobile devices, generate a QR code:

```bash
ztlp admin enroll \
  --zone home.ztlp \
  --ns-server 127.0.0.1:23096 \
  --relay YOUR_SERVER_IP:23095 \
  --expires 24h \
  --max-uses 1 \
  --qr
```

### Step 6: Enroll a Device

On each client device, enroll with the token:

```bash
ztlp setup \
  --token "ztlp://enroll/AQtvZmZpY2UudGVjaHJvY2tzdGFycy56dGxw..." \
  --name macbook.home.ztlp \
  --type device \
  --owner steve@home.ztlp
```

This generates a device identity, registers it with the NS, and saves the network configuration. The device is now enrolled and can connect through the ZTLP gateway.

---

## Configure Your Devices

Once enrolled, set up the ZTLP agent on each device so traffic to `vault.home.ztlp` is routed through the tunnel.

### macOS

```bash
# Start the ZTLP agent
ztlp agent start

# The agent binds a local VIP (127.0.55.1) and runs a DNS resolver.
# Configure your Mac to use ZTLP DNS for the .ztlp domain:

# Option A: Use the ztlp dns helper (recommended)
sudo ztlp dns install

# Option B: Manual — create a resolver file
sudo mkdir -p /etc/resolver
echo "nameserver 127.0.0.1
port 5354" | sudo tee /etc/resolver/ztlp
```

> **Automatic certificate trust:** During `ztlp setup`, the agent downloads the ZTLP root CA and adds it to the macOS Keychain. Service certificates for hostnames like `vault.home.ztlp` are automatically provisioned. Your browser and the Bitwarden app see `https://vault.home.ztlp` as a valid, trusted HTTPS site — no certificate warnings, no manual installation.

Then configure Bitwarden:

1. Open the Bitwarden app (or any Bitwarden-compatible client)
2. Go to **Settings** → **Self-hosted environment**
3. Set Server URL to: `https://vault.home.ztlp`
4. Save and log in

The Bitwarden app resolves `vault.home.ztlp` via the ZTLP DNS resolver, which returns the local VIP address. Traffic flows through the ZTLP agent — the app connects via HTTPS (TLS) to the local agent, which wraps it in an encrypted ZTLP tunnel to the gateway, and finally to Vaultwarden. Both encryption layers are completely transparent.

### Linux

```bash
# Start the agent as a systemd service
sudo ztlp agent install    # Creates and enables the systemd unit
sudo systemctl start ztlp-agent

# Verify it's running
ztlp status
```

> **Automatic certificate trust:** During `ztlp setup`, the agent downloads the ZTLP root CA and installs it into the system trust store (`/usr/local/share/ca-certificates/` on Debian/Ubuntu, `update-ca-trust` on Fedora/RHEL). Service certificates for `vault.home.ztlp` are auto-provisioned. Browsers and apps see valid HTTPS — no manual cert installation needed.

For DNS, configure systemd-resolved:

```bash
# Create a drop-in for .ztlp resolution
sudo mkdir -p /etc/systemd/resolved.conf.d
cat << 'EOF' | sudo tee /etc/systemd/resolved.conf.d/ztlp.conf
[Resolve]
DNS=127.0.0.1:5354
Domains=~ztlp
EOF

sudo systemctl restart systemd-resolved
```

Then configure Bitwarden (desktop app or browser extension):
- Server URL: `https://vault.home.ztlp`

### Windows (Planned)

Windows support is on the roadmap. The agent will run as a Windows service with a system tray icon. For now, Windows users can run the CLI manually:

```powershell
# Start the agent in the foreground
ztlp agent start
```

DNS configuration on Windows will use the NRPT (Name Resolution Policy Table) to route `.ztlp` queries to the local resolver.

### iOS / iPadOS

1. The ZTLP iOS app handles enrollment and agent connectivity
2. Scan the QR enrollment token from Step 5
3. The app configures a local VPN profile that routes `.ztlp` traffic through the ZTLP tunnel
4. Open the Bitwarden iOS app → **Settings** → **Self-hosted**
5. Server URL: `https://vault.home.ztlp`

> **Automatic certificate trust:** During enrollment, the ZTLP iOS app installs the ZTLP root CA as a trusted profile on your device. Service certs are provisioned automatically. The Bitwarden app connects via HTTPS to the local agent — valid cert, no warnings, no manual configuration.

Your passwords sync through the double-encrypted ZTLP tunnel. No ports exposed on your server, no VPN to toggle — just works.

---

## How It Works

Here's the full request flow when the Bitwarden app on your MacBook syncs passwords:

#### Direct Connection (device can reach gateway)

```mermaid
sequenceDiagram
    participant BW as Bitwarden App
    participant Agent as ZTLP Agent<br/>(127.0.55.1)
    participant GW as ZTLP Gateway<br/>(23097/udp)
    participant NS as ZTLP-NS
    participant VW as Vaultwarden<br/>(internal:80)

    BW->>Agent: HTTPS GET /api/sync<br/>Host: vault.home.ztlp
    Note over BW,Agent: Layer 1: TLS (ZTLP CA cert)<br/>App sees valid HTTPS ✓
    Note over Agent: Decrypt TLS → extract HTTP request<br/>Resolves vault.home.ztlp → local VIP
    Agent->>GW: Encrypted ZTLP packet<br/>(Noise_XX session)
    Note over Agent,GW: Layer 2: ZTLP Noise_XX encryption
    GW->>NS: Verify device identity<br/>+ group membership
    NS-->>GW: ✓ macbook.home.ztlp<br/>Groups: [family@home.ztlp]
    Note over GW: Policy check: family@home.ztlp<br/>→ allowed for vault service ✓
    Note over GW: Inject X-ZTLP-* headers<br/>Strip any forged headers
    GW->>VW: GET /api/sync<br/>X-ZTLP-Identity: steve@home.ztlp<br/>X-ZTLP-Device: macbook.home.ztlp<br/>X-ZTLP-Groups: family<br/>X-ZTLP-Signature: sha256=a1b2c3...
    VW-->>GW: 200 OK (encrypted vault data)
    GW-->>Agent: Encrypted ZTLP response
    Agent-->>BW: HTTPS 200 OK (TLS-encrypted)
```

#### Via Relay (device behind NAT / restrictive firewall)

```mermaid
sequenceDiagram
    participant BW as Bitwarden App
    participant Agent as ZTLP Agent<br/>(127.0.55.1)
    participant RL as ZTLP Relay<br/>(23095/udp)
    participant GW as ZTLP Gateway<br/>(23097/udp)
    participant VW as Vaultwarden<br/>(internal:80)

    BW->>Agent: HTTPS GET /api/sync<br/>Host: vault.home.ztlp
    Note over BW,Agent: Layer 1: TLS (ZTLP CA cert)
    Agent->>RL: Encrypted ZTLP packet<br/>(Noise_XX session)
    Note over Agent,RL: Layer 2: ZTLP Noise_XX encryption
    Note over RL: Relay forwards opaque packet<br/>(cannot read contents)
    RL->>GW: Forward encrypted packet
    Note over GW: Decrypt, verify identity,<br/>inject headers (same as direct)
    GW->>VW: GET /api/sync + X-ZTLP-* headers
    VW-->>GW: 200 OK
    GW-->>RL: Encrypted ZTLP response
    RL-->>Agent: Forward encrypted response
    Agent-->>BW: HTTPS 200 OK (TLS-encrypted)
```

> **The relay is a dumb pipe.** It forwards encrypted packets between agents and the gateway without being able to read or modify them. Both encryption layers (TLS + Noise_XX) remain intact end-to-end. The relay just solves the NAT traversal problem — it never sees plaintext.

### The Identity Headers

Every request that reaches Vaultwarden carries cryptographically-signed identity headers injected by the gateway:

| Header | Description | Example |
|--------|-------------|---------|
| `X-ZTLP-Identity` | User identity (FQDN) | `steve@home.ztlp` |
| `X-ZTLP-Node-ID` | 128-bit device NodeID | `a1b2c3d4e5f60718...` |
| `X-ZTLP-Device` | Device name | `macbook.home.ztlp` |
| `X-ZTLP-Zone` | Zone membership | `home.ztlp` |
| `X-ZTLP-Groups` | Comma-separated groups | `family` |
| `X-ZTLP-Verified` | Identity verification status | `true` |
| `X-ZTLP-Assurance` | Key assurance level | `hardware` / `device-bound` / `software` |
| `X-ZTLP-Key-Source` | Where the private key lives | `secure-enclave` / `file` |
| `X-ZTLP-Timestamp` | Unix timestamp of injection | `1711062600` |
| `X-ZTLP-Signature` | HMAC-SHA256 of all headers | `sha256=a1b2c3d4...` |

The gateway **strips** any existing `X-ZTLP-*` headers from the client request before injecting its own. The `X-ZTLP-Signature` is computed using the `ZTLP_HEADER_HMAC_SECRET` shared between the gateway and backend — so Vaultwarden (or a reverse proxy in front of it) can verify headers weren't tampered with.

### Policy Enforcement

The gateway evaluates access using the `policy.toml` file:

```toml
default = "deny"

[[services]]
name = "vault"
allow = [
  "family@home.ztlp",
  "team@home.ztlp",
]
auth_mode = "identity"       # inject X-ZTLP-* headers into backend requests
min_assurance = "software"   # any enrolled device accepted
```

When a connection arrives:
1. Gateway extracts the device's identity — NodeID from the ZTLP session
2. Queries NS for the device record, owner user, and group memberships
3. Checks if any of the device's groups match the `allow` list for the `vault` service
4. Checks `min_assurance` — is the device's key assurance level sufficient?
5. If no match → connection rejected (the device never reaches Vaultwarden)
6. If match → connection allowed, headers injected, traffic forwarded

This is **default-deny**. If you remove someone from the `family@home.ztlp` group, they immediately lose access to the vault. No VPN reconfiguration, no firewall changes — just remove them from the group.

---

## Security Model

### Why This is Better Than Port-Forwarding Vaultwarden

Most self-hosted Vaultwarden guides tell you to expose ports 80/443 to the internet with a reverse proxy (Nginx, Caddy, Traefik). That works, but it creates attack surface:

```mermaid
graph LR
    subgraph Traditional["Traditional Setup"]
        A["Anyone on the Internet"] -->|"HTTPS :443"| RP["Reverse Proxy<br/>(Nginx/Caddy)"]
        RP --> VW1["Vaultwarden"]
        Note1["Attack surface:<br/>• TLS bugs<br/>• HTTP exploits<br/>• Brute force<br/>• DDoS"]
    end

    subgraph ZTLP_Setup["ZTLP Setup"]
        B["Authorized Device<br/>with crypto identity"] -->|"ZTLP :23097/udp"| GW2["ZTLP Gateway"]
        GW2 -->|"Identity verified"| VW2["Vaultwarden"]
        C["Anyone else"] -.->|"❌ Dropped in 19ns"| GW2
        Note2["Attack surface:<br/>• None visible<br/>• No TCP to exploit<br/>• No HTTP to abuse"]
    end
```

| Threat | Traditional (port-forwarded) | ZTLP |
|--------|------------------------------|------|
| **Port scanning** | Ports 80/443 visible | Service invisible — no TCP ports |
| **TLS vulnerabilities** | Must keep TLS patched, exposed to the internet | TLS is local-only (device loopback) — not internet-facing |
| **Credential stuffing** | Login page is public | Can't reach login without device identity |
| **Zero-day HTTP exploits** | Any HTTP request reaches server | Dropped at Layer 1 in 19ns |
| **DDoS** | Must handle flood traffic | Three-layer UDP pipeline |
| **Compromised device** | Revoke password, hope they don't know it | Revoke device identity → instant lockout |

### Zero Attack Surface

Vaultwarden has literally zero attack surface from the internet:

- **No TCP ports open** — nothing for nmap to find
- **No HTTP/HTTPS facing the internet** — TLS only runs locally between the app and the agent on your device
- **No DNS records** — `vault.home.ztlp` doesn't exist in public DNS
- The ZTLP gateway and relay accept only authenticated ZTLP packets over UDP — everything else is dropped before any state is allocated

### Cryptographic Device Identity

Each device has an Ed25519 key pair. The private key can live in:

- **Apple Secure Enclave** (macOS, iOS) — hardware-backed, non-extractable
- **YubiKey** — hardware token, PIN-protected
- **TPM 2.0** (Linux, Windows) — hardware-backed
- **Android StrongBox** — hardware-backed
- **File** (software) — still unique per device, but extractable

Unlike passwords or VPN configs, hardware-backed keys **cannot be cloned**. Even if an attacker gets root on your device, they can't extract the private key from the Secure Enclave.

### Per-Device Revocation

If a device is lost or compromised:

```bash
# Instantly revoke a device
ztlp admin revoke macbook.home.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096

# Revoke a user (cascades to ALL their devices)
ztlp admin revoke steve@home.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

Revocation is immediate. The NS propagates it, and the gateway rejects the next packet from that device. No VPN keys to rotate, no configs to regenerate.

### Signed Identity Headers

The `X-ZTLP-Signature` header contains an HMAC-SHA256 over all identity headers, signed with the `ZTLP_HEADER_HMAC_SECRET`. This means:

1. The gateway is the only entity that can produce valid headers
2. A malicious backend or sidecar can't forge identity headers
3. Audit logs with signed headers are tamper-evident

---

## Defense in Depth: Internal TLS (Optional)

By default, the gateway forwards requests to Vaultwarden over **plaintext HTTP on the isolated Docker internal network**. This is perfectly fine for most deployments — the Docker network is not exposed to the host or the internet, so there's nothing to sniff.

But if you want **zero plaintext anywhere** in the entire request path — even inside Docker — you can enable internal TLS between the gateway and Vaultwarden using the ZTLP CA. This is optional paranoia for maximum security, not a different access mode. ZTLP is still the only way in.

### Encryption Layers

With agent-side TLS termination, there are already **two encryption layers** before traffic even leaves your device. Internal TLS adds a third on the server side.

```mermaid
graph LR
    subgraph Client["Your Device"]
        App["Bitwarden App"]
        Agent["ZTLP Agent"]
    end

    subgraph Tunnel["Internet (or via Relay)"]
        T["Encrypted ZTLP Tunnel<br/>(Noise_XX)"]
    end

    subgraph Server["Your Server (Docker)"]
        GW["ZTLP Gateway"]
        VW["Vaultwarden"]
    end

    App ==>|"🔒 HTTPS (TLS)"| Agent
    Agent ==>|"🔒 ZTLP encryption"| T
    T ==>|"🔒 ZTLP encryption"| GW
    GW -->|"🔓 Plaintext HTTP<br/>(Docker internal network)"| VW
```

**Without internal TLS** (default): Two encryption layers protect the traffic — TLS between the app and the local agent, and Noise_XX between the agent and the gateway. The gateway decrypts, injects identity headers, and forwards to Vaultwarden as plaintext HTTP over the isolated Docker bridge. The last hop is unencrypted but it's on a network that only the gateway and Vaultwarden can see.

```mermaid
graph LR
    subgraph Client["Your Device"]
        App2["Bitwarden App"]
        Agent2["ZTLP Agent"]
    end

    subgraph Tunnel["Internet (or via Relay)"]
        T2["Encrypted ZTLP Tunnel<br/>(Noise_XX)"]
    end

    subgraph Server["Your Server (Docker)"]
        GW2["ZTLP Gateway"]
        VW2["Vaultwarden"]
    end

    App2 ==>|"🔒 HTTPS (TLS)"| Agent2
    Agent2 ==>|"🔒 ZTLP encryption"| T2
    T2 ==>|"🔒 ZTLP encryption"| GW2
    GW2 ==>|"🔒 Internal TLS<br/>(ZTLP CA-issued cert)"| VW2
```

**With internal TLS**: Three encryption layers — TLS on the device, Noise_XX in the tunnel, and TLS again inside Docker. The gateway re-encrypts with TLS when connecting to Vaultwarden. The ZTLP CA issues a certificate for Vaultwarden, and the gateway verifies it — so the gateway can confirm it's talking to the real Vaultwarden (not a compromised container). Zero plaintext anywhere.

### Without vs With Internal TLS

| | Without Internal TLS (default) | With Internal TLS |
|---|---|---|
| **Entry point** | App → TLS → ZTLP agent → gateway | App → TLS → ZTLP agent → gateway |
| **Device-side encryption** | TLS (app ↔ agent) + Noise_XX (agent ↔ gateway) | TLS (app ↔ agent) + Noise_XX (agent ↔ gateway) |
| **Last hop (gateway → Vaultwarden)** | Plaintext HTTP on Docker network | TLS-encrypted on Docker network |
| **Total encryption layers** | 2 (TLS + Noise_XX) | 3 (TLS + Noise_XX + internal TLS) |
| **Exposed ports** | 23097/udp + 23095/udp | 23097/udp + 23095/udp (same) |
| **Backend identity verification** | None (Docker DNS) | Gateway verifies Vaultwarden's TLS cert |
| **Protection against** | External threats | External threats + compromised containers on Docker network |
| **Setup complexity** | None (works out of the box) | Initialize CA, issue certs, configure gateway |
| **When to use** | Most deployments | High-security environments, compliance requirements |

Both configurations use ZTLP as the access layer. The only difference is whether the last hop inside Docker is encrypted.

### Setting Up Internal TLS

#### Step 1: Initialize the Certificate Authority

```bash
# Initialize the ZTLP CA (creates root + intermediate certificates)
ztlp admin ca init --org "Home Lab"

# Verify it was created
ztlp admin ca show
```

#### Step 2: Issue Certificates

Issue a TLS certificate for the Vaultwarden backend and the gateway:

```bash
# Issue a cert for Vaultwarden (the backend service)
ztlp admin cert issue --service vaultwarden.internal

# Issue a cert for the gateway (client cert for connecting to backend)
ztlp admin cert issue --service gateway.home.ztlp

# Copy certs to the example directory for Docker volume mounts
mkdir -p certs ca
cp ~/.ztlp/certs/gateway.home.ztlp.pem certs/
cp ~/.ztlp/certs/gateway.home.ztlp-key.pem certs/
cp ~/.ztlp/ca/chain.pem ca/
```

#### Step 3: Configure Vaultwarden for TLS

Configure Vaultwarden to listen on HTTPS using the CA-issued certificate. Add these environment variables to the `vaultwarden` service in `docker-compose.yml`:

```yaml
environment:
  # ... existing vars ...
  ROCKET_TLS: '{certs="/etc/ztlp/certs/vaultwarden.internal.pem",key="/etc/ztlp/certs/vaultwarden.internal-key.pem"}'
  ROCKET_PORT: "443"
```

And mount the certificate volumes:

```yaml
volumes:
  - vaultwarden-data:/data
  - ./certs:/etc/ztlp/certs:ro
  - ./ca:/etc/ztlp/ca:ro
```

#### Step 4: Enable Internal TLS on the Gateway

Uncomment the internal TLS settings in `docker-compose.yml` or `.env`:

```yaml
# In the gateway service environment:
ZTLP_GATEWAY_BACKEND_TLS_ENABLED: "true"
ZTLP_GATEWAY_BACKEND_TLS_CERT_FILE: "/etc/ztlp/certs/gateway.home.ztlp.pem"
ZTLP_GATEWAY_BACKEND_TLS_KEY_FILE: "/etc/ztlp/certs/gateway.home.ztlp-key.pem"
ZTLP_GATEWAY_BACKEND_TLS_CA_FILE: "/etc/ztlp/ca/chain.pem"
ZTLP_GATEWAY_BACKEND_TLS_VERIFY: "true"
```

Update the backend port to match Vaultwarden's TLS listener:

```yaml
ZTLP_GATEWAY_BACKEND_PORT: "443"
```

Uncomment the certificate volume mounts:

```yaml
volumes:
  - ./policy.toml:/etc/ztlp/policy.toml:ro
  - ./certs:/etc/ztlp/certs:ro
  - ./ca:/etc/ztlp/ca:ro
```

#### Step 5: Restart

```bash
docker compose up -d
```

Verify internal TLS is working:

```bash
docker compose logs gateway | grep -i "backend.*tls"
```

You should see the gateway connecting to Vaultwarden via TLS. The exposed ports remain exactly the same — only 23097/udp. Nothing changes for your clients.

---

## Day 2 Operations

### Adding New Devices

```bash
# Generate an enrollment token
ztlp admin enroll \
  --zone home.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  --relay YOUR_SERVER_IP:23095 \
  --expires 24h \
  --max-uses 1

# On the new device:
ztlp setup \
  --token "ztlp://enroll/..." \
  --name iphone.home.ztlp \
  --type device \
  --owner steve@home.ztlp

# Add to the family group (if not already a member via the owner)
ztlp admin group add family@home.ztlp steve@home.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Removing Devices

```bash
# Revoke a specific device
ztlp admin revoke old-phone.home.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096

# Remove a user from a group (keeps identity, removes access)
ztlp admin group remove family@home.ztlp former-roommate@home.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Rotating Secrets

```bash
# Rotate the enrollment secret
openssl rand -hex 32
# Update ZTLP_ENROLLMENT_SECRET in .env
docker compose up -d ns    # Restart NS with new secret

# Rotate the HMAC secret
openssl rand -hex 32
# Update ZTLP_HEADER_HMAC_SECRET in .env
docker compose up -d gateway   # Restart gateway with new secret

# Rotate the Vaultwarden admin token
openssl rand -base64 48
# Update VAULTWARDEN_ADMIN_TOKEN in .env
docker compose up -d vaultwarden
```

### Backups

Vaultwarden stores its data (encrypted vault, attachments, keys) in the `vaultwarden-data` Docker volume.

```bash
# Back up Vaultwarden data
docker compose stop vaultwarden
docker run --rm \
  -v vaultwarden_vaultwarden-data:/data:ro \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/vaultwarden-$(date +%Y%m%d).tar.gz -C /data .
docker compose start vaultwarden

# Back up NS data (identity records)
docker compose stop ns
docker run --rm \
  -v vaultwarden_ns-data:/data:ro \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/ztlp-ns-$(date +%Y%m%d).tar.gz -C /data .
docker compose start ns
```

Set up a cron job for automated backups:

```bash
# Add to crontab — daily at 3 AM
0 3 * * * cd /path/to/ztlp/examples/vaultwarden && ./backup.sh
```

### Monitoring

The gateway and NS export Prometheus metrics:

| Component | Metrics Port | Endpoint |
|-----------|-------------|----------|
| Gateway | 9102 | `http://gateway:9102/metrics` |
| NS | 9103 | `http://ns:9103/metrics` |
| Relay | 9101 | `http://relay:9101/metrics` |

These are on the internal network by default. To expose them for a Prometheus scraper, add port mappings to the gateway and NS services in `docker-compose.yml`, or run Prometheus on the same Docker network.

Key metrics to watch:

- `ztlp_gateway_sessions_active` — current connected devices
- `ztlp_gateway_auth_failures_total` — rejected authentication attempts
- `ztlp_gateway_policy_denials_total` — rejected policy checks
- `ztlp_ns_records_total` — registered identities
- `ztlp_relay_sessions_active` — relay sessions (NAT traversal)

---

## Troubleshooting

### "Connection refused" when Bitwarden syncs

**Symptom:** Bitwarden app shows "Unable to connect" or "Connection refused" to `vault.home.ztlp`.

**Checks:**
1. Is the ZTLP agent running?
   ```bash
   ztlp status
   ```
2. Can the agent reach the gateway?
   ```bash
   ztlp ping gateway.home.ztlp
   ```
3. Is the gateway healthy?
   ```bash
   docker compose ps gateway
   docker compose logs gateway --tail 50
   ```
4. Is DNS resolving correctly?
   ```bash
   dig vault.home.ztlp @127.0.0.1 -p 5354
   ```

### "Policy denied" in gateway logs

**Symptom:** Gateway logs show `policy_denied` for your device.

**Fix:** Ensure your user is in the `family@home.ztlp` (or `team@home.ztlp`) group:

```bash
# Check group membership
ztlp admin list-group family@home.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096

# Add the user if missing
ztlp admin group add family@home.ztlp youruser@home.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Enrollment token expired or rejected

**Symptom:** `ztlp setup --token ...` fails with "token expired" or "enrollment rejected".

**Fix:** Generate a fresh token:

```bash
ztlp admin enroll \
  --zone home.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  --relay YOUR_SERVER_IP:23095 \
  --expires 24h \
  --max-uses 1
```

Tokens are single-use by default. If you already used it, you need a new one.

### Vaultwarden not starting

**Symptom:** `docker compose ps` shows Vaultwarden as unhealthy or restarting.

**Fix:** Check the logs:

```bash
docker compose logs vaultwarden --tail 100
```

Common issues:
- Missing `ADMIN_TOKEN` — set it in `.env` or remove it to disable the admin panel
- Volume permissions — the Vaultwarden container runs as UID 1000 by default
- Invalid `DOMAIN` — must be a valid URL (e.g., `https://vault.home.ztlp`)

### Can't reach the admin panel

The Vaultwarden admin panel is at `https://vault.home.ztlp/admin`. It's only accessible through the ZTLP tunnel (like everything else). Make sure:

1. Your ZTLP agent is running and enrolled
2. `VAULTWARDEN_ADMIN_TOKEN` is set in `.env`
3. You're accessing it via `vault.home.ztlp` (not `localhost`)

### Internal TLS not connecting

**Symptom:** Gateway logs show TLS handshake errors when connecting to Vaultwarden.

**Checks:**
1. Are the certificates mounted correctly?
   ```bash
   docker compose exec gateway ls -la /etc/ztlp/certs/
   docker compose exec gateway ls -la /etc/ztlp/ca/
   ```
2. Does the cert match the backend hostname?
   ```bash
   openssl x509 -in certs/gateway.home.ztlp.pem -text -noout | grep -A1 "Subject Alternative Name"
   ```
3. Is Vaultwarden configured for TLS?
   ```bash
   docker compose logs vaultwarden | grep -i tls
   ```
4. Check that `ZTLP_GATEWAY_BACKEND_PORT` matches Vaultwarden's TLS port (443 if using `ROCKET_TLS`)

### NAT traversal issues

If your devices are behind carrier-grade NAT or restrictive firewalls:

1. Make sure the relay is running:
   ```bash
   docker compose ps relay
   ```
2. Verify the relay address was included in the enrollment token (the `--relay` flag)
3. Check relay logs:
   ```bash
   docker compose logs relay --tail 50
   ```

---

## File Structure

```
examples/vaultwarden/
├── docker-compose.yml   # The complete stack
├── .env.example         # Environment variable template
├── policy.toml          # Gateway access policy (groups, auth_mode, min_assurance)
├── certs/               # TLS certificates (created during internal TLS setup)
│   ├── gateway.home.ztlp.pem
│   └── gateway.home.ztlp-key.pem
├── ca/                  # CA chain (created during internal TLS setup)
│   └── chain.pem
└── README.md            # This file
```

---

## What's Next?

- **[Getting Started with ZTLP](../../GETTING-STARTED.md)** — The 5-minute ZTLP demo
- **[Deployment Guide](../../DEPLOYMENT.md)** — Full production deployment for MSPs
- **[CLI Reference](../../CLI.md)** — Every `ztlp` subcommand documented
- **[Architecture](../../ARCHITECTURE.md)** — How the three-layer pipeline and relay mesh work
- **[GitHub Repository](https://github.com/priceflex/ztlp)** — Source code, issues, and discussions
