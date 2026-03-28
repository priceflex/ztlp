# ZTLP iOS Virtual IP Architecture

## Problem

iOS only allows binding to `127.0.0.1` — no other loopback addresses (`127.0.0.2+` fail with `EADDRNOTAVAIL`).
This means the current "userspace VIP proxy" approach (bind a TCP listener on a loopback address per service)
is limited to a single IP with different ports:

| Service | Current (port-based) |
|---------|---------------------|
| vault   | 127.0.0.1:8080      |
| http    | 127.0.0.1:9080      |
| ssh     | 127.0.0.1:2222      |

This doesn't scale and doesn't match the desktop agent's behavior (`127.100.0.x` VIP pool).

## Solution: Tunnel-Level VIP Routing

iOS **does** support virtual IP addresses — through the `utun` interface created by `NEPacketTunnelProvider`.
This is exactly how Tailscale (`100.x.y.z`), WireGuard, and every other iOS VPN works.

### How It Works

```
┌──────────────┐     ┌──────────────────┐     ┌───────────────────────┐
│  App Process  │     │   iOS Routing    │     │  Network Extension    │
│               │     │   (kernel)       │     │  (PacketTunnelProvider)│
│ URLSession    │────▶│ dest 10.0.0.11   │────▶│ readPackets()         │
│ .GET(10.0.0.  │     │ matches 10.0.0.  │     │ → parse IP header     │
│  11:8080/ping)│     │ 0/24 route       │     │ → lookup dest IP      │
│               │     │ → send to utun   │     │ → map to service name │
│               │◀────│                  │◀────│ → ZTLP encapsulate    │
│ HTTP response │     │ inject via utun  │     │ → send to gateway     │
└──────────────┘     └──────────────────┘     │ → gateway forwards    │
                                               │ → response back       │
                                               │ → writePackets()      │
                                               └───────────────────────┘
```

### Key APIs

```swift
// In PacketTunnelProvider.startTunnel():
let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "34.219.64.205")

// Assign tunnel interface address
settings.ipv4Settings = NEIPv4Settings(
    addresses: ["10.0.0.2"],          // phone's address on the virtual network
    subnetMasks: ["255.255.255.0"]     // /24 = 254 usable service addresses
)

// Route the entire 10.0.0.0/24 subnet through the tunnel
settings.ipv4Settings?.includedRoutes = [
    NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.255.255.0")
]
```

### Service → VIP Mapping

The PacketTunnelProvider maintains a lookup table:

```swift
let serviceMap: [String: String] = [
    "10.0.0.10": "vault",      // Vaultwarden
    "10.0.0.11": "http",       // HTTP echo / web services
    "10.0.0.12": "ssh",        // SSH access
    "10.0.0.13": "postgres",   // Database
    // ... up to 10.0.0.254
]
```

When the extension reads a packet from the utun with destination `10.0.0.11:8080`:
1. Extract destination IP from the IP header
2. Look up service name: `10.0.0.11` → `"http"`
3. Encapsulate the full IP packet in ZTLP with service routing header
4. Send through the Noise_XX session to the gateway
5. Gateway matches service name to `--forward http:127.0.0.1:8180`
6. Gateway forwards the decapsulated TCP payload to the backend
7. Response flows back the same path

### Advantages Over Current Approach

| Feature | Port-based (current) | Tunnel VIP (proposed) |
|---------|---------------------|----------------------|
| Address per service | No (same IP, different ports) | Yes (`10.0.0.x`) |
| Works from any app | No (only apps that use the VIP) | Yes (any app, even Safari) |
| Standard ports | No (must avoid conflicts) | Yes (each VIP can use port 443, 22, etc.) |
| Scalability | ~65K services (port space) | 254 per /24, millions per /16 |
| DNS integration | No | Yes (resolve `vault.ztlp` → `10.0.0.10`) |
| Architecture | Userspace proxy in main app | Kernel-routed through utun |

### Implementation Plan

#### Phase 1: Service Registry in Extension
- Add `ServiceRegistry` class to `ZTLPTunnel` target
- Store VIP→service mappings in shared UserDefaults (`group.com.ztlp.shared`)
- Main app writes mappings, extension reads them
- Format: `ztlp_vip_map` → `{"10.0.0.10":"vault","10.0.0.11":"http"}`

#### Phase 2: Packet Router in PacketTunnelProvider
- After `setTunnelNetworkSettings`, start packet read loop
- Parse IPv4 header (20 bytes minimum): extract dest IP, protocol, dest port
- For TCP: establish per-flow ZTLP streams with service routing
- For UDP: forward individual datagrams
- Inject response packets back via `packetFlow.writePackets()`

#### Phase 3: Multi-Service Gateway Support
- Gateway already supports `--forward service:host:port` for multiple services
- Ensure ZTLP wire format includes service name in the session/stream metadata
- Gateway demuxes incoming data to the correct backend based on service header

#### Phase 4: DNS Integration
- Extension runs DNS resolver (already exists: `ztlp_dns_start`)
- Resolve `vault.techrockstars.ztlp` → `10.0.0.10`
- Configure `NEDNSSettings` to route `.ztlp` queries to the resolver
- Apps can use hostnames instead of IPs

### References
- Apple DTS (Quinn): iOS only supports `127.0.0.1` for loopback bind — confirmed
  https://developer.apple.com/forums/thread/724864
- Apple routing docs: `includedRoutes` controls what goes through utun
  https://developer.apple.com/forums/thread/94430
- Tailscale uses `100.64.0.0/10` (CGNAT range) on iOS — same mechanism
- NEIPv4Settings `addresses` parameter accepts an array (multiple IPs possible)

### Notes
- The tunnel IP (`10.0.0.2`) is the phone's identity on the virtual network
- Gateway IPs (`10.0.0.10+`) are virtual — they exist only in the routing table
- No actual remote host has IP `10.0.0.11` — the extension intercepts before routing
- This doesn't conflict with ZTLP's identity model — it's a local convenience layer
- The `vipAddService()` C API is still useful for desktop (macOS/Linux) where
  loopback aliases work; iOS just needs the tunnel-based approach instead
