# ZTLP Peer Discovery and Direct Connectivity

**Status:** Draft Specification — Target: v0.6.0  
**Author:** Steven Price / ZTLP.org  
**Date:** 2026-03-12  
**License:** Apache 2.0

---

## Abstract

This specification extends ZTLP-NS (Section 9) and the Node
Initialization and Bootstrap Procedure (Section 10) to enable
peer-to-peer discovery and direct connectivity between ZTLP nodes
without requiring a gateway or relay in the data path. It introduces
two new NS record types (`ZTLP_PEER` and `ZTLP_ZONE_HINT`), a DNS
bootstrap mechanism for cross-organization discovery, and a
connection negotiation protocol that selects the optimal path
(direct, hole-punched, or relay-assisted) based on detected network
conditions.

## 1. Motivation

ZTLP v0.5.x supports direct peer-to-peer connections when one node
knows the other's IP address and port. However, there is no
standardized mechanism for:

1. A node to **advertise its current reachable endpoint** to other
   nodes in the same zone or across federated zones.
2. A node to **discover another node's endpoint by NodeID** without
   prior out-of-band configuration.
3. **Cross-organization discovery** — finding a peer's NS server
   when all you know is their zone name.
4. **Automated path selection** — choosing between direct connection,
   UDP hole-punching, or relay fallback based on NAT topology.

This specification addresses all four gaps while preserving ZTLP's
security model: all discovery data is signed, all connections are
mutually authenticated via Noise_XX, and no sensitive information
is exposed to unauthenticated observers.

## 2. Design Principles

1. **NS is the source of truth** — all peer endpoint, key, and
   reachability data lives in ZTLP-NS, authenticated by Ed25519
   signatures and replicated via federation.

2. **DNS is the front door only** — DNS SRV/TXT records provide
   the bootstrap path to find an organization's NS server. DNS
   MUST NOT carry keys, endpoints, or any security-relevant data.

3. **Privacy by default** — `ZTLP_PEER` records are zone-scoped.
   A node in `office.acme.ztlp` cannot query peer endpoints in
   `cardiac.mercy-hospital.ztlp` unless an explicit cross-zone
   trust delegation exists.

4. **Graceful degradation** — if direct connectivity fails, the
   system falls back to relay-assisted transport transparently.
   The application layer sees no difference.

5. **No new wire protocol messages** — peer discovery uses existing
   QUERY (0x01), REGISTER (0x09), and RESPONSE (0x02/0x03)
   messages with new record types. The wire protocol is unchanged.

## 3. New ZTLP-NS Record Types

### 3.1 ZTLP_PEER (Record Type Byte: 8)

A `ZTLP_PEER` record advertises a node's current reachable network
endpoint. Unlike `ZTLP_KEY` records (which are long-lived identity
bindings), `ZTLP_PEER` records are ephemeral — they reflect the
node's current network location and MUST be refreshed periodically.

**Record data (CBOR, sorted keys):**

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `endpoint` | text | REQUIRED | IP:port in the form `"203.0.113.5:23095"` or `"[2001:db8::1]:23095"` |
| `endpoint_v6` | text | OPTIONAL | Secondary IPv6 endpoint if dual-stack |
| `nat_type` | uint | REQUIRED | NAT classification (see §3.1.1) |
| `node_id` | bytes (16) | REQUIRED | The advertising node's NodeID |
| `observed_at` | uint | REQUIRED | Unix epoch seconds when endpoint was last verified |
| `capabilities` | array of text | OPTIONAL | Protocol capabilities: `"tunnel"`, `"relay"`, `"mesh"` |

**Constraints:**

- TTL MUST be between 30 and 300 seconds (RECOMMENDED: 60 seconds).
- The record MUST be signed by the advertising node's Ed25519 private
  key (the same key bound to the NodeID via `ZTLP_KEY`).
- NS servers MUST reject `ZTLP_PEER` records where the signer's
  public key does not match the `ZTLP_KEY` record for the claimed
  `node_id`.
- NS servers MUST reject `ZTLP_PEER` records with TTL > 300 seconds.
- Expired `ZTLP_PEER` records MUST be purged from storage and MUST
  NOT be returned in query responses.
- `ZTLP_PEER` records MUST NOT be cached beyond their TTL by any
  querying client.

#### 3.1.1 NAT Type Classification

| Value | Name | Description |
|-------|------|-------------|
| 0 | `PUBLIC` | Node has a publicly routable IP; no NAT detected |
| 1 | `CONE_NAT` | Full cone, restricted cone, or port-restricted cone NAT — hole-punchable |
| 2 | `SYMMETRIC_NAT` | Symmetric NAT — each destination gets a different mapped port; hole-punching unreliable |
| 3 | `UNKNOWN` | NAT type could not be determined (e.g., STUN failed) |
| 4 | `RELAY_ONLY` | Node is explicitly configured to use relay transport only (e.g., policy constraint) |

NAT type detection MUST use the STUN protocol (RFC 8489) against at
least two independent STUN servers to distinguish cone NAT from
symmetric NAT. Implementations SHOULD use the STUN servers listed in
the node's configuration; if none are configured, implementations
SHOULD fall back to well-known public STUN servers.

#### 3.1.2 ZTLP_PEER Registration Flow

```
  Node A                          NS Server
    │                                │
    │  1. STUN binding request       │
    │  ──────────────────────→       │ (to external STUN server)
    │  ← STUN mapped address         │
    │                                │
    │  2. REGISTER (0x09)            │
    │     name: "nodeA.office.acme.ztlp"
    │     type: 8 (ZTLP_PEER)       │
    │     data: {endpoint, nat_type, │
    │            node_id, observed_at}
    │     sig: Ed25519(node_key)     │
    │  ──────────────────────→       │
    │                                │
    │  3. NS verifies:               │
    │     - sig matches ZTLP_KEY     │
    │       for this node_id         │
    │     - TTL ≤ 300s               │
    │     - node_id matches name     │
    │       ownership                │
    │                                │
    │  4. REGISTER_ACK (0x06)        │
    │  ←──────────────────────       │
    │                                │
    │  5. Repeat every TTL/2         │
    │     (heartbeat refresh)        │
    │                                │
```

Nodes MUST re-register their `ZTLP_PEER` record at an interval of
no more than `TTL / 2` to prevent expiration. If the node's endpoint
changes (e.g., DHCP renewal, network roam), it MUST re-register
immediately.

#### 3.1.3 Federation Behavior

`ZTLP_PEER` records participate in NS federation (Section 38)
identically to other record types:

- Eager replication pushes new/updated `ZTLP_PEER` records to
  federated NS peers immediately on registration.
- Merkle-tree anti-entropy synchronization reconciles stale records.
- TTL-based expiration applies at each NS server independently —
  a federated NS server MUST NOT serve an expired `ZTLP_PEER`
  record even if the originating NS has not yet sent a deletion.
- Conflict resolution follows standard rules: revocation > higher
  serial > valid signature > longer TTL.

**Cross-zone queries:** A node in zone A querying for a `ZTLP_PEER`
record in zone B requires an explicit trust delegation between the
zones (via `ZTLP_POLICY` or zone delegation records). NS servers
MUST reject cross-zone `ZTLP_PEER` queries that lack a valid
delegation chain.

### 3.2 ZTLP_ZONE_HINT (Record Type Byte: 9)

A `ZTLP_ZONE_HINT` record provides the information needed to
bootstrap connectivity to a remote zone's NS infrastructure. This
enables cross-organization peer discovery when combined with DNS
bootstrap (Section 5).

**Record data (CBOR, sorted keys):**

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `ns_endpoints` | array of text | REQUIRED | IP:port pairs for the zone's NS servers |
| `ns_pubkeys` | array of bytes | REQUIRED | Ed25519 public keys of the NS servers (for Noise_XX auth) |
| `zone` | text | REQUIRED | The target zone FQDN (e.g., `"partner.example.ztlp"`) |
| `trust_anchor` | bytes | OPTIONAL | Root public key for the zone's trust chain |
| `capabilities` | array of text | OPTIONAL | `"peer"`, `"relay"`, `"gateway"` |

**Constraints:**

- TTL SHOULD be between 3600 and 86400 seconds (hours to days).
- The record MUST be signed by the local zone's authority key.
- `ns_pubkeys` MUST contain at least one entry and MUST correspond
  positionally to `ns_endpoints`.

**Use case:** When `office.acme.ztlp` needs to discover peers in
`partner.example.ztlp`, it queries its own NS for a `ZTLP_ZONE_HINT`
record for `partner.example.ztlp`. The response contains the
partner's NS endpoint and public key, enabling a direct,
authenticated NS connection.

## 4. DNS Bootstrap for Zone Discovery

### 4.1 SRV Records

Organizations deploying ZTLP SHOULD publish DNS SRV records to
enable automated zone discovery:

```
_ztlp._udp.example.com.  IN  SRV  10 0 23097 ns1.example.com.
_ztlp._udp.example.com.  IN  SRV  20 0 23097 ns2.example.com.
```

**Fields:**
- **Service:** `_ztlp`
- **Protocol:** `_udp`
- **Port:** The NS server's listening port (default: 23097)
- **Priority/Weight:** Standard SRV semantics for failover and
  load distribution
- **Target:** Hostname of the NS server

### 4.2 TXT Records

Organizations SHOULD also publish a TXT record containing zone
metadata:

```
_ztlp._udp.example.com.  IN  TXT  "v=ztlp1 zone=example.ztlp cap=peer,relay,gateway"
```

**Fields (space-delimited key=value pairs):**

| Key | Required | Description |
|-----|----------|-------------|
| `v` | REQUIRED | Protocol version. MUST be `ztlp1` for this specification. |
| `zone` | REQUIRED | The ZTLP-NS zone name (may differ from DNS domain). |
| `cap` | OPTIONAL | Comma-separated capability list: `peer`, `relay`, `gateway`, `mesh` |
| `fp` | OPTIONAL | BLAKE2s fingerprint of the NS server's Ed25519 public key (hex, first 16 chars). Used for TOFU verification. |

### 4.3 Security Constraints

DNS is fundamentally unauthenticated without DNSSEC. The following
rules apply:

1. **DNSSEC SHOULD be used** where available. If DNSSEC validation
   succeeds, the SRV/TXT response MAY be used directly for NS
   server connection.

2. **Without DNSSEC**, DNS responses are treated as **hints only**.
   The connecting node MUST verify the NS server's identity during
   the Noise_XX handshake. If the NS server's public key does not
   match a previously trusted key (TOFU or out-of-band provisioned),
   the connection MUST be rejected.

3. **DNS MUST NOT carry:**
   - Public keys (use `fp` fingerprint for TOFU only)
   - Peer endpoint addresses
   - Internal zone structure beyond the top-level zone name
   - Any data that would be security-relevant if spoofed

4. **TTL:** DNS SRV/TXT records for ZTLP SHOULD have a TTL of
   300–3600 seconds. Shorter TTLs increase DNS query volume without
   security benefit (the NS connection is authenticated regardless).

### 4.4 Discovery Flow (Cross-Organization)

```
  Node A (acme.ztlp)           DNS              NS-B (partner.ztlp)
    │                            │                    │
    │  1. SRV query:             │                    │
    │  _ztlp._udp.partner.com   │                    │
    │  ─────────────────────→    │                    │
    │  ← SRV: ns1.partner.com:23097                   │
    │  ← TXT: v=ztlp1 zone=partner.ztlp              │
    │                            │                    │
    │  2. Connect to NS-B        │                    │
    │  ────────────────────────────────────────→       │
    │      Noise_XX handshake (verify NS-B pubkey)    │
    │  ←────────────────────────────────────────       │
    │                                                  │
    │  3. QUERY: ZTLP_PEER for "nodeX.partner.ztlp"  │
    │  ────────────────────────────────────────→       │
    │  ← RESPONSE_FOUND: endpoint, nat_type           │
    │                                                  │
    │  4. Direct connect to Node X                     │
    │  ════════════════════════════════════════════     │
    │    (Noise_XX, verify NodeX pubkey from KEY)      │
```

**Important:** Step 2 requires trust establishment. Node A must either:
- Have a pre-configured `ZTLP_ZONE_HINT` for `partner.ztlp`, OR
- Use TOFU (Trust On First Use) with the `fp` fingerprint from the
  DNS TXT record, OR
- Have received an out-of-band trust delegation (e.g., enrollment
  token with partner zone info)

The DNS lookup in Step 1 only provides the network address of the NS
server. Authentication always happens at the ZTLP layer.

## 5. Peer Connection Negotiation

### 5.1 Connection Strategy Selection

When a node resolves a `ZTLP_PEER` record for a target, it MUST
select a connection strategy based on both nodes' NAT types:

| Initiator NAT | Target NAT | Strategy |
|---------------|------------|----------|
| PUBLIC | PUBLIC | Direct connect to target endpoint |
| PUBLIC | CONE_NAT | Direct connect (target's mapped endpoint) |
| PUBLIC | SYMMETRIC_NAT | Direct connect (may work; fall back to relay) |
| CONE_NAT | PUBLIC | Direct connect to target endpoint |
| CONE_NAT | CONE_NAT | Simultaneous UDP hole-punch (§5.2) |
| CONE_NAT | SYMMETRIC_NAT | Relay-assisted (§5.3) |
| SYMMETRIC_NAT | PUBLIC | Direct connect to target endpoint |
| SYMMETRIC_NAT | CONE_NAT | Relay-assisted (§5.3) |
| SYMMETRIC_NAT | SYMMETRIC_NAT | Relay-assisted (§5.3) |
| ANY | RELAY_ONLY | Relay-assisted (§5.3) |
| RELAY_ONLY | ANY | Relay-assisted (§5.3) |
| ANY | UNKNOWN | Try direct, fall back to relay |

### 5.2 UDP Hole-Punching Procedure

When both peers are behind cone NAT, they coordinate a simultaneous
hole-punch using a signaling channel. The signaling channel is an
authenticated ZTLP-NS connection (not a separate protocol).

```
  Node A                     NS Server                    Node B
    │                           │                            │
    │ 1. REGISTER ZTLP_PEER    │                            │
    │    (mapped endpoint A)    │                            │
    │ ─────────────────────→    │                            │
    │                           │                            │
    │                           │  2. REGISTER ZTLP_PEER    │
    │                           │     (mapped endpoint B)    │
    │                           │  ←─────────────────────    │
    │                           │                            │
    │ 3. QUERY ZTLP_PEER       │                            │
    │    for Node B             │                            │
    │ ─────────────────────→    │                            │
    │ ← endpoint B              │                            │
    │                           │                            │
    │ 4. Send ZTLP HELLO to B  │   4. (B sends HELLO to A)  │
    │ ═══════════════════════════════════════════════════════ │
    │              (simultaneous — punches both NATs)         │
    │                           │                            │
    │ 5. Noise_XX handshake     │                            │
    │ ═══════════════════════════════════════════════════════ │
    │         (direct UDP, NAT bindings now open)            │
```

**Timing:** Both nodes MUST begin sending HELLO packets within 500ms
of resolving each other's `ZTLP_PEER` records. Each node MUST send
at least 5 HELLO packets at 100ms intervals. If no response is
received within 5 seconds, the node MUST fall back to relay-assisted
connectivity.

**HELLO packet for hole-punching:** The standard ZTLP HELLO message
(Section 11) is used. The magic bytes, SessionID field, and
HeaderAuthTag serve to identify the packet as ZTLP traffic even
before the handshake completes.

### 5.3 Relay Fallback

When direct connectivity is not possible (symmetric NAT on both
sides, RELAY_ONLY policy, or hole-punch timeout), the initiating
node MUST fall back to relay-assisted transport:

1. Query NS for `ZTLP_RELAY` records in the zone.
2. Connect to the nearest relay (by PathScore).
3. Request forwarding to the target NodeID.
4. The relay forwards packets between both peers.

This is the existing relay behavior defined in Section 12. No
changes are required to the relay protocol.

### 5.4 Connection Attempt Timeout and Retry

| Phase | Timeout | Action on timeout |
|-------|---------|-------------------|
| DNS SRV/TXT lookup | 5 seconds | Skip DNS, use configured NS directly |
| NS QUERY for ZTLP_PEER | 3 seconds | Retry once, then fail |
| Direct connect (PUBLIC targets) | 3 seconds | Fall back to relay |
| Hole-punch (CONE_NAT) | 5 seconds | Fall back to relay |
| Relay connect | 10 seconds | Try next relay, then fail |

Total worst-case time to connection: ~21 seconds (DNS timeout +
NS retry + hole-punch timeout + relay connect). Typical case with
public endpoints: < 1 second.

## 6. CLI Interface

### 6.1 Peer Registration

```bash
# Register this node's endpoint in NS (automatic STUN detection)
ztlp peer register --zone office.acme.ztlp --ns 10.0.1.1:23097

# Register with explicit endpoint (skip STUN)
ztlp peer register --zone office.acme.ztlp --ns 10.0.1.1:23097 \
    --endpoint 203.0.113.5:23095 --nat public

# Start background daemon that re-registers every 30s
ztlp peer register --zone office.acme.ztlp --ns 10.0.1.1:23097 --daemon
```

### 6.2 Peer Discovery

```bash
# Find a peer by name
ztlp peer find nodeX.partner.ztlp --ns 10.0.1.1:23097

# Find a peer by NodeID
ztlp peer find --node-id ab01cd02... --ns 10.0.1.1:23097

# Discover NS server via DNS (cross-organization)
ztlp peer find nodeX.partner.ztlp --dns-bootstrap partner.com
```

### 6.3 Connect by NodeID

```bash
# Connect to a peer by name (auto-discovers endpoint via NS)
ztlp connect nodeX.partner.ztlp --ns 10.0.1.1:23097

# Tunnel SSH through a peer-to-peer ZTLP connection
ztlp tunnel --service ssh --peer nodeX.office.acme.ztlp \
    --ns 10.0.1.1:23097 --local-port 2222
```

## 7. NS Wire Protocol Additions

### 7.1 New Record Type Bytes

| Byte | Record Type | Description |
|------|-------------|-------------|
| 8 | ZTLP\_PEER | Node endpoint and reachability (ephemeral) |
| 9 | ZTLP\_ZONE\_HINT | Cross-zone NS bootstrap information |

These are added to the existing table in Section 9.5.2.

### 7.2 ZTLP_PEER Record Data Schema

**CBOR encoding (sorted keys, RFC 8949 §4.2):**

```cbor-diag
{
  "capabilities": ["tunnel", "relay"],   ; optional
  "endpoint": "203.0.113.5:23095",       ; required
  "endpoint_v6": "[2001:db8::1]:23095",  ; optional
  "nat_type": 1,                         ; required (uint)
  "node_id": h'AB01CD02...',             ; required (16 bytes)
  "observed_at": 1741817200              ; required (uint, epoch)
}
```

### 7.3 ZTLP_ZONE_HINT Record Data Schema

**CBOR encoding (sorted keys):**

```cbor-diag
{
  "capabilities": ["peer", "relay"],                ; optional
  "ns_endpoints": ["198.51.100.10:23097"],          ; required
  "ns_pubkeys": [h'ED25519_PUBKEY_32_BYTES...'],    ; required
  "trust_anchor": h'ROOT_PUBKEY_32_BYTES...',       ; optional
  "zone": "partner.example.ztlp"                    ; required
}
```

## 8. Security Considerations

### 8.1 ZTLP_PEER Record Authenticity

`ZTLP_PEER` records are signed by the advertising node's Ed25519
key. NS servers MUST cross-reference the signer against the
existing `ZTLP_KEY` record for the claimed NodeID. An attacker
cannot publish a false endpoint for a node without possessing that
node's private key.

Even if an attacker publishes a valid-looking `ZTLP_PEER` record
(e.g., via a compromised NS server), the connecting node verifies
the target's identity during the Noise_XX handshake. A misdirected
connection attempt will fail at handshake — the attacker cannot
complete the handshake without the target's private key.

### 8.2 DNS Spoofing

DNS is used only for bootstrap (finding NS servers). A DNS spoofing
attack can direct a node to a malicious NS server, but:

1. The Noise_XX handshake with the NS server will fail if the
   server's key doesn't match expectations (TOFU or pre-configured).
2. Even if a node connects to a malicious NS server via TOFU (first
   contact), the malicious NS can only provide false `ZTLP_PEER`
   records. The subsequent peer connection still requires Noise_XX
   authentication — the attacker cannot impersonate the target peer.

**Attack surface:** A DNS spoofing attack can cause a denial of
service (pointing to unreachable NS servers) but cannot cause a
node to connect to an impersonated peer.

### 8.3 Endpoint Privacy

`ZTLP_PEER` records contain IP addresses, which are sensitive. The
following mitigations apply:

1. **Zone-scoped access** — `ZTLP_PEER` queries are only answered
   for nodes within the same zone or with explicit cross-zone
   delegation.
2. **Short TTL** — records expire quickly, limiting the window for
   passive collection.
3. **NS transport encryption** — queries to ZTLP-NS are
   authenticated and encrypted (Noise_XX channel to NS server).
   An eavesdropper on the network cannot observe `ZTLP_PEER`
   queries or responses.

### 8.4 Hole-Punch Amplification

The hole-punching procedure sends multiple HELLO packets to a
peer's mapped address. To prevent amplification:

1. A node MUST NOT send more than 10 HELLO packets during a
   single hole-punch attempt.
2. HELLO packets MUST be minimal size (standard ZTLP HELLO, no
   payload beyond handshake initiation).
3. The 5-second timeout prevents sustained packet generation.

### 8.5 ZTLP_PEER Record Flooding

A malicious node could attempt to flood NS with rapid `ZTLP_PEER`
re-registrations. NS servers MUST apply rate limiting to REGISTER
operations:

- Maximum 1 `ZTLP_PEER` registration per NodeID per 15 seconds.
- Implementations SHOULD use token-bucket rate limiting per NodeID.

## 9. Relationship to Existing Specification Sections

| Existing Section | Interaction |
|------------------|-------------|
| §9 (ZTLP-NS) | New record types 8 and 9 added to §9.3 and §9.5.2 |
| §10 (Bootstrap) | DNS SRV/TXT mechanism formalized; existing §10.1 Step 2 expanded |
| §14.3 (NAT Traversal) | Hole-punching procedure specified normatively |
| §32.3 (NAT Traversal overview) | Updated to reference this specification |
| §38 (Federated Identity) | Cross-zone trust model extended for peer discovery |
| §12 (Relay Mesh) | Relay fallback unchanged; referenced as fallback path |

## 10. Open Questions

| Question | Context |
|----------|---------|
| Should `ZTLP_PEER` records support multiple endpoints per node (e.g., WiFi + LTE)? | Mobile devices may have multiple network paths. Could use an array of `{endpoint, nat_type, priority}` objects. |
| Should hole-punch coordination use a dedicated NS message type instead of polling? | Current design: both peers poll NS for each other's endpoint. A NOTIFY push from NS to connected clients would reduce latency but adds complexity. |
| What is the minimum viable STUN implementation for embedded/IoT devices? | Full STUN (RFC 8489) may be heavy for constrained devices. A simplified binding-only subset may suffice. |
| Should `ZTLP_ZONE_HINT` records be auto-populated from DNS, or always manually configured? | Auto-population is convenient but creates a dependency on DNS availability for the NS control plane. |
| Relay-assisted hole-punching for symmetric NAT? | TURN-like behavior where the relay allocates a public port pair and coordinates the punch. More complex but eliminates the "both symmetric = relay only" limitation. |
| mDNS/LAN peer discovery? | For same-network peers, mDNS (`_ztlp._udp.local`) could discover peers without any NS infrastructure. Useful for home lab, ad-hoc, and air-gapped deployments. |

## 11. Implementation Phases

### Phase A — ZTLP_PEER Records and Registration (1-2 days)

- Add record type byte 8 to NS server (Elixir)
- ZTLP_PEER registration handler with signer verification
- TTL enforcement and automatic expiration
- STUN NAT detection in Rust client
- CLI: `ztlp peer register` and `ztlp peer find`
- Tests: registration, expiration, cross-reference with KEY records

### Phase B — DNS Bootstrap (1 day)

- DNS SRV/TXT resolver in Rust client (`trust-dns-resolver` or `hickory-dns`)
- CLI: `ztlp ns discover <domain>`
- Integration with `ztlp setup` wizard
- ZTLP_ZONE_HINT record type in NS (type byte 9)
- Tests: DNS resolution, TXT parsing, fallback behavior

### Phase C — Connect by NodeID (1-2 days)

- `ztlp connect <name>` with NS-based endpoint resolution
- `ztlp tunnel --peer <name>` for tunneled services
- Connection strategy selection (direct / hole-punch / relay)
- Timeout and fallback logic
- Tests: all NAT combinations, fallback paths

### Phase D — UDP Hole-Punching (1-2 days)

- Simultaneous hole-punch implementation
- STUN-based symmetric NAT detection (requires 2 STUN servers)
- Coordination via NS (both peers query each other's ZTLP_PEER)
- Retry and timeout logic
- Tests: hole-punch success, fallback to relay

### Phase E — Federation and Cross-Zone (1 day)

- ZTLP_PEER federation replication (should work via existing
  federation with TTL-aware expiration)
- Cross-zone ZTLP_PEER queries with delegation verification
- ZTLP_ZONE_HINT integration for cross-org discovery
- End-to-end test: node A (zone X) discovers and connects to
  node B (zone Y) via federated NS

**Total estimate: 5-8 days**

## 12. Spec Changes Summary (for README.md integration)

When this feature is implemented and merged into the main specification,
the following sections require updates:

1. **§9.3 Record Types table** — add `ZTLP_PEER` and `ZTLP_ZONE_HINT`
2. **§9.5.2 Record Type Bytes table** — add bytes 8 and 9
3. **§9.5.9 Record data schemas** — add CBOR schemas for both types
4. **§10.1 Step 2 (DNS-SRV Discovery)** — expand with `_ztlp._udp`
   SRV/TXT format, TXT field definitions, security constraints
5. **§14.3 NAT Traversal** — expand with normative hole-punch procedure,
   timing, retry, fallback
6. **§21 Open Issues** — mark "Peer discovery mechanism" as Addressed;
   add mDNS and relay-assisted hole-punch as future work
7. **§38.2 Supported Identity Classes** — note that `ZTLP_PEER` records
   provide runtime endpoint binding for device identities
8. **New subsection under §10** — "Peer-to-Peer Discovery and Direct
   Connectivity" with the full negotiation protocol

## 13. Wire Format Examples

### 13.1 ZTLP_PEER Registration

```
  REGISTER (0x09) message:
  ┌──────┬────────────────────────────────────┬──┬─────────┬──────┬─────┐
  │ 0x09 │ name: "nodeA.office.acme.ztlp" (29)│08│data_len │ CBOR │ sig │
  │      │ (2-byte len + UTF-8)               │  │ (2-byte)│ data │(64B)│
  └──────┴────────────────────────────────────┴──┴─────────┴──────┴─────┘

  CBOR data (approx 80-120 bytes):
  {
    "endpoint": "203.0.113.5:23095",
    "nat_type": 0,
    "node_id": <16 bytes>,
    "observed_at": 1741817200
  }
```

### 13.2 DNS TXT Record

```
  _ztlp._udp.techrockstars.com.  300  IN  TXT  "v=ztlp1 zone=trs.ztlp cap=peer,relay,gateway fp=a1b2c3d4e5f6a7b8"
```

### 13.3 Cross-Organization Discovery Sequence

```
  1. DNS:  dig SRV _ztlp._udp.partner.com
     →  10 0 23097 ns.partner.com

  2. DNS:  dig TXT _ztlp._udp.partner.com
     →  "v=ztlp1 zone=partner.ztlp fp=9f8e7d6c5b4a3210"

  3. ZTLP-NS: connect ns.partner.com:23097 (Noise_XX, verify fp)
  4. ZTLP-NS: QUERY "target-node.partner.ztlp" type=8 (ZTLP_PEER)
     →  endpoint=198.51.100.50:23095, nat_type=0

  5. ZTLP: connect 198.51.100.50:23095 (Noise_XX, verify KEY record)
     →  Encrypted session established, no relay, no gateway
```

---

**Copyright © 2026 Steven Price / ZTLP.org — Apache License 2.0**
