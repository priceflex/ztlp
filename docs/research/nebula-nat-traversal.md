# Nebula NAT Traversal & Hole Punching Analysis

## How Nebula Does It

### Architecture
Nebula uses a **Lighthouse** pattern (equivalent to a STUN/TURN server):
- **Lighthouse nodes** are publicly reachable and act as registrars
- Clients periodically report their public IP:port to the lighthouse
- When client A wants to reach client B, it queries the lighthouse for B's addresses
- The lighthouse tells both sides to punch toward each other simultaneously

### Hole Punching Flow
1. **Client A** wants to connect to **Client B**
2. A sends `HostQuery` to lighthouse asking for B's addresses
3. Lighthouse responds with `HostQueryReply` containing B's known addresses (learned + reported)
4. **Simultaneously**, lighthouse sends `HostPunchNotification` to B with A's addresses
5. Both A and B send empty UDP packets (1 byte: `{0}`) to each other's addresses
6. The crossed UDP packets create NAT mapping entries on both sides
7. Once NAT is open, the actual Noise handshake packets can flow through

### Key Timing Parameters
- `punchy.delay`: Default **1 second** — delay before sending punch packets (gives NAT time to set up)
- `punchy.respond_delay`: Default **5 seconds** — delay before responding to punch notifications
- `handshakes.try_interval`: Default **100ms** — retry interval for handshake attempts
- `handshakes.retries`: Default **10** — max retries (so ~1s total handshake timeout)
- `lighthouse.interval`: Default **10 seconds** — how often clients report their address to lighthouse
- `timers.connection_alive_interval`: Default **5 seconds** — how often to check tunnel health
- `punchy.target_all_remotes`: Default **false** — if true, punch ALL known addresses (not just primary)

### NAT Keepalive
- `connectionManager.sendPunch()` sends 1-byte UDP packets to keep NAT state alive
- Triggered when there's incoming traffic but no outgoing (passive keepalive)
- Also triggered when `punchy.target_all_remotes` is true and there's outgoing but no incoming
- Does NOT punch to lighthouses (their update interval maintains state)

### Relay Fallback
When hole punching fails (double NAT, symmetric NAT), Nebula falls back to **relay nodes**:
- Relay nodes are configured via `relay.relays` (list of VPN IPs)
- `relay.am_relay: true` makes a node act as a relay
- Relay uses `CreateRelayRequest`/`CreateRelayResponse` control messages
- Three-phase: Requested → PeerRequested → Established
- Relay types: Terminal (I'm the endpoint) vs Forwarding (I'm the middle)
- Relays are signed/encrypted — relay node can't read traffic, just forwards

### What Makes It Work
1. **Simultaneous punch from both sides** — the lighthouse coordinates timing
2. **Multi-address awareness** — sends to ALL known addresses (IPv4 + IPv6, learned + reported)
3. **Timer wheel for retries** — efficient linear backoff, not exponential
4. **Roaming support** — if a host changes address, Nebula detects it and updates
5. **Calculated remotes** — can derive expected public addresses from VPN addresses (for predictable NAT)

### Key Lessons for ZTLP
1. **Lighthouse = ZTLP-NS** — Our NS server already has the right shape, just needs address tracking
2. **Punch coordination requires server-side notification** — NS must notify both peers
3. **1s default punch delay is generous** — most NATs set up in <100ms, but some carrier-grade NATs are slow
4. **Relay is essential** — symmetric NAT can't be hole-punched, must have relay fallback
5. **Address freshness matters** — stale addresses waste punch attempts
6. **1 byte punch packets** — empty payloads are fine for NAT piercing, no crypto needed
7. **Target all known addresses** — don't guess which one is right, try them all in parallel
