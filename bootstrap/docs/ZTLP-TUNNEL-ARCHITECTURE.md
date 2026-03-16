# ZTLP Tunnel Architecture — Bootstrap Metrics

How the Bootstrap server collects metrics from deployed ZTLP components
through encrypted ZTLP tunnels (dogfooding the protocol).

## Overview

Each deployed machine gets a **gateway sidecar** — a lightweight ZTLP gateway
container that proxies Prometheus metrics through an encrypted tunnel. Bootstrap
opens a ZTLP tunnel to the sidecar, fetches `/metrics`, and closes the tunnel.
No open TCP ports required for metrics collection.

```
┌─────────────┐     ZTLP tunnel      ┌──────────────────────────┐
│  Bootstrap   │ ──────────────────── │  Machine (NS or Relay)   │
│  Server      │                      │                          │
│              │   Noise_XX handshake  │  ┌───────────────────┐  │
│  ZtlpTunnel  │ ←──────────────────→ │  │ Gateway Sidecar    │  │
│  (ztlp CLI)  │                      │  │ (host network)     │  │
│              │   Encrypted metrics   │  │                    │  │
│              │ ←───────────────────  │  │ proxies to ──────┐ │  │
└─────────────┘                       │  └──────────────────┘ │  │
                                      │                       ▼  │
                                      │  ┌────────────────────┐  │
                                      │  │ Component           │  │
                                      │  │ (NS/Relay/Gateway)  │  │
                                      │  │ :9101/:9103 metrics │  │
                                      │  └────────────────────┘  │
                                      └──────────────────────────┘
```

## Port Assignment

Each role gets a dedicated gateway sidecar port so they're uniquely addressable:

| Role    | Sidecar Port | Metrics Backend | Connection Method       |
|---------|-------------|-----------------|-------------------------|
| NS      | **23098**   | localhost:9103  | Direct (no relay)       |
| Relay   | **23099**   | localhost:9101  | Self-relay via :23095   |
| Gateway | **23098**   | localhost:9102  | Direct (no relay)       |

**Why different ports?** The relay forwards HELLO packets to gateways, but
uses round-robin selection and can't determine which gateway a client intended
(the HELLO packet has no destination hint). If both NS and relay sidecars used
the same port, the relay would randomly connect clients to the wrong gateway.
Giving the relay its own port (23099) and restricting it to local-only forwarding
eliminates this ambiguity.

### Constants (in `SshProvisioner`)

```ruby
GATEWAY_SIDECAR_PORT       = 23098  # NS and dedicated gateway machines
GATEWAY_SIDECAR_RELAY_PORT = 23099  # Relay machines

SshProvisioner.gateway_port_for(machine)  # Returns correct port for role
```

## Connection Routing

### NS / Gateway Machines → Direct Connection

Bootstrap connects directly to the machine's gateway sidecar. No relay routing.

```
Bootstrap → ztlp connect <ns_ip>:23098 → NS gateway sidecar → metrics
```

### Relay Machines → Self-Relay

The relay's sidecar port (23099) may not be open in the firewall (e.g., AWS
security groups only allow 23095/23096). Bootstrap routes through the relay's
own UDP port, which forwards to the local sidecar:

```
Bootstrap → ztlp connect <relay_ip>:23099 --relay <relay_ip>:23095
                                                     │
                                    relay forwards HELLO to 127.0.0.1:23099
                                                     │
                                              gateway sidecar → metrics
```

### Why the Relay Only Forwards Locally

The relay's `ZTLP_RELAY_GATEWAYS` is set to **only** its local sidecar:

```
ZTLP_RELAY_GATEWAYS=127.0.0.1:23099
```

**Not** remote gateways. This is intentional:

1. The relay uses `pick_gateway()` with round-robin — it can't know which
   gateway a client's HELLO is destined for
2. Listing remote gateways causes 50% of HELLOs to be mis-routed
3. Remote gateways (NS, dedicated) are reachable directly — they don't need
   relay forwarding for Bootstrap's metrics collection

## Docker Networking

Both the relay container and its gateway sidecar run on **host networking**:

- **Relay** (`--network host`): so `127.0.0.1:23099` reaches the sidecar
- **Gateway sidecar** (`--network host`): so it can reach `localhost:9101` (metrics)

⚠️ **Don't use bridge networking for relay containers.** Docker bridge gives
each container its own loopback — `127.0.0.1` inside the relay won't reach
the sidecar on the host's loopback.

## Key Files

| File | Role |
|------|------|
| `app/services/ssh_provisioner.rb` | Deploys components + gateway sidecars, generates configs |
| `app/services/ztlp_tunnel.rb` | Opens tunnel, fetches metrics, parses Prometheus text |
| `app/services/ztlp_connectivity.rb` | Handshake-only connectivity check (green/red dots) |
| `app/services/health_checker.rb` | Full health check: container, ports, metrics, resources |

## Adding a New Network

When provisioning a new network, this all works automatically:

1. **Add machines** in Bootstrap UI, assign roles (NS, relay, gateway)
2. **Deploy** each machine — the provisioner:
   - Deploys the component container
   - Deploys a gateway sidecar with the correct port (`gateway_port_for`)
   - Generates relay config with `ZTLP_RELAY_GATEWAYS=127.0.0.1:23099` (local only)
   - Relay gets `--network host`; other components get bridge + port mappings
3. **Health checks** automatically use the correct connection method:
   - `find_relay_addr` returns `nil` for non-relay → direct connection
   - `find_relay_addr` returns self-relay for relay machines
   - `gateway_port_for` returns 23098 or 23099 based on role

No manual configuration needed. The architecture is encoded in the provisioner.

## Troubleshooting

### Dashboard shows red dots but CLI `ztlp connect` works
- Check if the health checker's `wait_for_tunnel` matches the CLI output markers
- The ztlp CLI outputs to stderr; `ZtlpConnectivity` reads both stdout and stderr

### Relay gets NS metrics (or vice versa)
- Check `ZTLP_RELAY_GATEWAYS` on the relay — should be `127.0.0.1:23099` only
- If it lists remote gateways, re-provision the relay

### Tunnel handshake times out
- For relay: ensure both relay container and sidecar use host networking
- For NS: ensure UDP port 23098 is open in the firewall/security group
- Check sidecar logs: `docker logs ztlp-gateway-sidecar`

### Gateway sidecar shows 0 handshakes
- If relay is on bridge network, `127.0.0.1:23099` is unreachable from the relay
- Fix: re-provision relay (uses `--network host` now)

## History

- **v0.9.10**: Initial ZTLP tunnel metrics — worked for NS, relay fell back to SSH
- **v0.9.11**: Fixed relay routing (3 issues: same ports, bridge networking, round-robin)
