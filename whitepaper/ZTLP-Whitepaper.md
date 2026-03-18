# ZTLP: Zero Trust Layer Protocol

## Identity-First Networking for the Post-Perimeter Internet

**Version 2.0 — March 2026**

**Steven Price**
Tech Rockstar Academy / ZTLP.org

---

## Abstract

The modern Internet was built on a foundational assumption: any device can send packets to any other device. This open connectivity model, while instrumental in the Internet's growth, has become its greatest security liability. Distributed denial-of-service attacks, credential stuffing, port scanning, and unauthorized service discovery are all consequences of a network architecture where reachability precedes identity.

The Zero Trust Layer Protocol (ZTLP) inverts this model. ZTLP is a transport-layer overlay protocol in which cryptographic identity verification is a precondition for network connectivity — not a consequence of it. Services protected by ZTLP have no public ports, no discoverable attack surface, and no exposure to unauthenticated traffic. To an observer without valid credentials, a ZTLP-protected service simply does not exist on the network.

This whitepaper presents the architecture, design rationale, security properties, and measured performance of the ZTLP protocol and its reference implementation. The protocol provides mutual authentication via the Noise_XX handshake framework, a three-layer DDoS-resistant admission pipeline, a distributed identity namespace (ZTLP-NS) with federated replication, relay mesh routing with consistent-hash load distribution, a gateway model for incremental deployment in front of existing infrastructure, a structured identity model with users, devices, and groups, an agent daemon for transparent tunnel management, and a device enrollment system with QR-code provisioning.

A working reference implementation comprising over 70,000 lines of Rust, Elixir/OTP, and C — with over 1,900 tests and zero failures — demonstrates that ZTLP is not merely theoretical. The implementation includes a complete CLI toolchain, Docker deployment manifests, a web-based fleet management application, stress testing and fuzz testing infrastructure, and a production deployment protecting a live web application behind a ZTLP gateway. Benchmarks show Layer 1 packet rejection in 19 nanoseconds (Rust eBPF), full Noise_XX handshake completion in under 300 microseconds, tunnel throughput exceeding 300 MB/s, and SCP file transfers at 31 MB/s through encrypted ZTLP tunnels — confirming the protocol's viability for production deployment.

---

## Table of Contents

1. [The Problem: Anonymous Connectivity as a Security Primitive](#1-the-problem)
2. [Design Principles](#2-design-principles)
3. [Protocol Architecture](#3-protocol-architecture)
4. [The Three-Layer Admission Pipeline](#4-the-three-layer-admission-pipeline)
5. [Session Establishment: Noise_XX Handshake](#5-session-establishment)
6. [Transport Reliability](#6-transport-reliability)
7. [ZTLP-NS: Distributed Identity Namespace](#7-ztlp-ns)
8. [Identity Model: Users, Devices, and Groups](#8-identity-model)
9. [Device Enrollment](#9-device-enrollment)
10. [Relay Mesh Architecture](#10-relay-mesh-architecture)
11. [Gateway Deployment Model](#11-gateway-deployment-model)
12. [Agent Daemon](#12-agent-daemon)
13. [Threat Model and Security Properties](#13-threat-model)
14. [Performance](#14-performance)
15. [Comparison with Existing Systems](#15-comparison)
16. [Post-Quantum Migration Path](#16-post-quantum)
17. [Reference Implementation](#17-reference-implementation)
18. [Deployment Roadmap](#18-deployment-roadmap)
19. [Conclusion](#19-conclusion)

---

## 1. The Problem: Anonymous Connectivity as a Security Primitive

Every service on the public Internet today — from a bank's login portal to a hospital's patient records system — must accept packets from any source address on Earth before it can determine whether the sender is authorized. Security is applied *after* connectivity is established: firewalls filter by IP, WAFs inspect HTTP, rate limiters count requests, and DDoS mitigation services absorb volumetric attacks. All of these defenses share a structural weakness: they operate on traffic that has already reached the service.

The consequences are measurable:

- **DDoS attacks** exceeded 5.6 Tbps in early 2025 (Cloudflare), with the average enterprise spending $6,000–$12,000 per minute of downtime during an attack.
- **Credential stuffing** accounts for over 60% of login traffic on major web properties (Akamai State of the Internet report).
- **Port scanning and reconnaissance** tools like Shodan index over 3 billion exposed services, providing attackers with a free target map of the Internet.
- **Ransomware** exploits exposed management ports (RDP, SSH, SMB) — the initial access vector in the majority of ransomware incidents.

These are not implementation failures. They are architectural consequences of a network model where *reachability is the default* and *identity is optional*.

ZTLP proposes a different foundation: **identity before connectivity**. A service protected by ZTLP does not listen on a public port. It does not respond to unauthenticated probes. It generates no observable surface for scanning or exploitation. To reach it, a client must first prove — cryptographically — who it is. Only then does a session exist. Only then can packets flow.

This is not a VPN. VPNs still expose their own endpoints to the Internet. This is not a firewall rule. Firewall rules still require the packet to arrive before it can be evaluated. ZTLP operates at the transport layer, below application logic but above IP routing, making identity verification a structural property of the network path rather than a policy applied after the fact.

---

## 2. Design Principles

ZTLP was designed under five governing principles:

### 2.1 Identity Is the Network Primitive

In ZTLP, a 128-bit NodeID — cryptographically bound to a public key pair (X25519 for key exchange, Ed25519 for signatures) — is the fundamental unit of network participation. NodeIDs are not derived from IP addresses, MAC addresses, or any location-dependent identifier. A node's identity persists across network changes, device migrations, and IP reassignment.

IP addresses serve only as transport hints — the means by which packets reach relays and gateways. They carry no trust, no authorization, and no identity semantics.

### 2.2 No Open Ports

A ZTLP-protected service has zero publicly reachable sockets. Traffic arrives exclusively through authenticated ZTLP sessions terminated at a gateway. The service is invisible to network scanners, unreachable by bots, and unexposed to volumetric floods. This eliminates entire categories of attack — not by mitigating them, but by removing the surface they require.

### 2.3 Cheap Rejection, Expensive Admission

ZTLP's admission pipeline is designed so that rejecting unauthorized traffic is orders of magnitude cheaper than admitting legitimate traffic. Invalid packets are discarded in nanoseconds. Valid sessions require a full Noise_XX handshake — three message round-trips, six Diffie-Hellman operations, and policy evaluation. This asymmetry ensures that attackers bear the computational cost, not defenders.

### 2.4 Overlay Deployment

ZTLP operates over standard UDP on existing IPv4/IPv6 infrastructure. No router changes, no ISP support, no kernel modifications are required for initial deployment. This follows the proven deployment path of QUIC, WireGuard, and Tailscale — protocols that achieved adoption precisely because they could deploy immediately on today's Internet.

### 2.5 Gateway-First Adoption

Organizations should not need to rewrite applications to adopt ZTLP. The protocol is designed to sit in front of existing services via an edge gateway, leaving internal infrastructure (HTTP, gRPC, databases, microservices) unchanged. A ZTLP gateway is analogous to a reverse proxy or load balancer — but one that enforces cryptographic identity before any traffic reaches the application.

---

## 3. Protocol Architecture

ZTLP defines six components that together form a complete identity-first network:

```
┌──────────────┐                              ┌──────────────┐
│   Client     │                              │   Service    │
│   Agent      │                              │   Gateway    │
│  (Rust)      │        ┌──────────────┐      │  (Elixir)    │
│              │        │    Relay     │      │              │
│  Identity    │        │    Mesh     │      │  Identity    │
│  Noise_XX    │◄──────►│  (Elixir)   │◄────►│  Policy      │
│  Tunnels     │   UDP  │             │  UDP │  Bridge      │
│  DNS Proxy   │        │  Routing    │      │  Audit       │
└──────────────┘        └──────────────┘      └──────┬───────┘
       ▲                       ▲                     │
       │                       │               ┌─────┴────────┐
  ┌────┴─────┐           ┌────┴─────┐         │  Internal    │
  │ ZTLP-NS  │           │  eBPF    │         │  Services    │
  │ Namespace│           │  XDP     │         │  (unchanged) │
  │ (Elixir) │           │  Filter  │         └──────────────┘
  └──────────┘           └──────────┘
```

### 3.1 Client Agent

A Rust binary that runs as a background daemon on endpoint devices. The agent manages cryptographic identities, establishes ZTLP tunnels transparently, provides a local DNS resolver that maps service names to virtual IP addresses, handles credential renewal, and supports stream multiplexing with up to 256 concurrent streams per tunnel. The unified CLI (`ztlp`) provides keygen, connect, listen, relay interaction, namespace queries, packet inspection, device enrollment, fleet administration, and agent lifecycle management.

### 3.2 Relay Mesh

Elixir/OTP processes that form a distributed mesh for session routing. Relays perform admission control (handshake validation, identity verification, policy enforcement) for new sessions and high-speed SessionID-based forwarding for established sessions. The BEAM VM provides per-session fault isolation via supervised GenServer processes, with ETS tables delivering O(1) session lookups at millions of operations per second. The relay mesh uses consistent-hash routing with PathScore-based selection and supports multi-hop forwarding through up to 4 relay hops.

### 3.3 ZTLP-NS Namespace

A distributed, hierarchical identity namespace with Ed25519-signed records, Mnesia-backed persistent storage, and federated replication using Merkle-tree anti-entropy synchronization. ZTLP-NS provides identity-to-key bindings, service discovery, relay advertisements, zone delegation, credential revocation, and the structured identity model (users, devices, groups) — replacing the need for external certificate authorities with a protocol-native trust infrastructure.

### 3.4 Gateway

Edge terminators that bridge ZTLP sessions to internal service protocols. A gateway performs the full Noise_XX handshake as responder, resolves the client's identity via ZTLP-NS, evaluates group-based access policy, and forwards authenticated traffic to internal services over conventional protocols. Gateways support named backend services, zone-wildcard policy rules, circuit breakers for backend fault isolation, and structured audit logging of all admission decisions.

### 3.5 eBPF/XDP Filter

A kernel-level packet filter written in C that provides Layer 1 rejection at line rate. The XDP program validates the ZTLP magic byte before packets reach userspace, rejecting non-ZTLP traffic in approximately 19 nanoseconds. The filter supports dual-port operation (client + mesh traffic), peer allowlists, FORWARD TTL checking, and RAT-aware HELLO processing.

### 3.6 Bootstrap Management UI

A Rails web application that provides fleet management for ZTLP deployments. Bootstrap enables user and device CRUD operations, group management, enrollment token generation with QR codes, audit logging, machine provisioning via SSH, and real-time ZTLP connectivity monitoring — all backed by the `ztlp admin` CLI over SSH connections to managed infrastructure.

### 3.7 Packet Format

ZTLP uses two wire formats optimized for their respective roles:

**Handshake Header (96 bytes, fixed):** Carries the full identity and crypto fields needed for session establishment — Magic, Version, Flags, MessageType, CryptoSuite, KeyID, SessionID, PacketSequence, Timestamp, SrcNodeID, DstSvcID, PolicyTag, and HeaderAuthTag.

**Compact Data Header (42 bytes):** Used for all post-handshake traffic. Carries only Magic, Version, Flags, SessionID, PacketSequence, and HeaderAuthTag. NodeIDs are deliberately absent from the data path — they were verified during the handshake and are not needed for forwarding. This keeps the per-packet overhead minimal and prevents passive observers from correlating traffic to specific identities.

Packet type discrimination uses the HdrLen field: 24 words = handshake, 11 words = data. This allows the admission pipeline to classify packets with a single field comparison.

---

## 4. The Three-Layer Admission Pipeline

The core DDoS resilience property of ZTLP is a three-layer admission pipeline where each layer is progressively more expensive — and progressively fewer packets survive to reach the next layer:

| Layer | Check | Cost (Rust) | Cost (Elixir) | What It Rejects |
|-------|-------|-------------|---------------|-----------------|
| **L1: Magic** | 2-byte comparison | **19 ns** | **89 ns** | All non-ZTLP traffic (random floods, port scans, protocol confusion) |
| **L2: SessionID** | Hash table lookup | **31 ns** | **1.05 µs** | Traffic with unknown session identifiers (forged or expired) |
| **L3: HeaderAuthTag** | AEAD verification | **840 ns** | **5.8 µs** | Packets targeting valid sessions but with forged authentication |

**The key insight:** In a volumetric DDoS attack, the vast majority of flood traffic is random garbage. It fails L1 in 19 nanoseconds — a single branch instruction in an eBPF kernel filter — consuming effectively zero resources. Traffic crafted with the correct magic byte but a random SessionID fails L2 in 31 nanoseconds via a hash table miss. Only traffic that guesses both the correct magic byte AND a valid 96-bit SessionID (probability: 2⁻⁹⁶ against a sparse session table) reaches the cryptographic layer.

**Measured impact:** The Rust client rejects invalid traffic 42× cheaper than it admits valid traffic. In practical terms, a single CPU core can reject 54 million garbage packets per second at L1 while simultaneously processing 1.1 million legitimate packets through the full pipeline.

This is the structural DDoS advantage: defenders pay nanoseconds to reject what attackers spend bandwidth to send.

---

## 5. Session Establishment: Noise_XX Handshake

ZTLP establishes sessions using the Noise_XX handshake pattern from the Noise Protocol Framework (Trevor Perrin, 2018). Noise_XX was selected for three properties critical to ZTLP's design:

1. **Mutual authentication** — Both initiator and responder prove possession of their static keys. There are no anonymous or unauthenticated sessions in ZTLP.
2. **Forward secrecy** — Ephemeral X25519 keys are generated per-session and discarded after key derivation. Compromise of long-term keys does not reveal past session data.
3. **No PKI dependency** — Unlike TLS, Noise_XX does not require certificate authorities. Identity binding is handled by ZTLP-NS, not by external trust infrastructure.

### 5.1 Handshake Flow

```
Client                          Relay / Gateway
  │                                    │
  │── HELLO (e, NodeID) ──────────────►│  
  │                                    │  L1: Magic check
  │                                    │  L2: Rate limit check
  │◄── CHALLENGE (e, ee, s, es) ──────│  
  │                                    │
  │── AUTH (s, se, proof) ────────────►│  
  │                                    │  Verify identity
  │                                    │  Evaluate policy
  │                                    │  Allocate session
  │◄── SESSION_OK (SessionID) ────────│  
  │                                    │
  │══ Encrypted Data (SessionID) ═════│  Data path: no NodeID
```

The three-message exchange performs six X25519 Diffie-Hellman operations and derives symmetric session keys via BLAKE2s-based HKDF. The entire handshake completes in **293 µs (Rust)** or **471 µs (Elixir)** — enabling a single gateway core to establish over 2,100 new sessions per second.

Handshake reliability is ensured through exponential-backoff retransmission (500ms–5s), a half-open connection cache (64 entries, 15-second TTL) for handling duplicate HELLO packets, and an amplification limit (3 retransmits per session) to prevent handshake reflection attacks.

### 5.2 Post-Handshake Data Path

After `SESSION_OK`, all traffic carries only the 96-bit SessionID — no NodeIDs, no identity fields, no policy metadata. This design serves three purposes:

- **Privacy:** Passive observers see only random-looking session identifiers that change per session. Traffic cannot be correlated to specific identities by network observers.
- **Performance:** Relays perform SessionID-based label switching — a constant-time ETS/HashMap lookup — without touching any cryptographic state on the forwarding path.
- **Scalability:** The separation of identity verification (admission plane) from packet forwarding (forwarding plane) allows relay infrastructure to scale horizontally.

### 5.3 Session Lifecycle

Sessions have a maximum lifetime of 24 hours with mandatory rekeying every hour. Rekeying is transparent to applications — a new SessionID is issued, relay forwarding tables are updated atomically, and the old SessionID remains valid for a 5-second overlap window to drain in-flight packets. Sessions may also terminate via explicit CLOSE, lifetime expiry, or inactivity timeout (default: 5 minutes for interactive sessions).

---

## 6. Transport Reliability

ZTLP provides a reliable, ordered byte stream over UDP with congestion-aware transport and NAT traversal — capabilities essential for tunneling TCP-based protocols such as SSH and HTTP.

### 6.1 Congestion Control

The transport implements a production-grade congestion controller inspired by modern TCP stacks:

- **SACK-based selective retransmission** — Receivers report gaps in received sequence space, allowing the sender to retransmit only lost packets rather than the entire window.
- **Proportional Rate Reduction (PRR)** — Smoothly reduces the congestion window during loss recovery, avoiding the throughput cliff of multiplicative decrease.
- **Token bucket pacing** — Spreads packet transmission evenly across the congestion window interval to prevent burst-induced loss.
- **Eifel spurious retransmit detection** — Identifies and undoes unnecessary retransmissions triggered by delayed ACKs or reordering, preventing spurious congestion window reductions.
- **Jacobson/Karels RTT estimation** — Maintains smoothed RTT and RTT variance for adaptive retransmission timeout calculation with a bounded RTO cap of 4 seconds.
- **Fast retransmit** — Triggers immediate retransmission after 3 duplicate ACKs without waiting for the retransmission timer.

### 6.2 NAT Traversal

ZTLP supports deployment across NAT boundaries without requiring port forwarding or UPnP:

- **UDP hole punching** — Coordinated via relay signaling for peer-to-peer tunnel establishment through symmetric and cone NATs.
- **NAT timeout auto-detection** — Probes the NAT binding lifetime and adjusts keepalive intervals to maintain the mapping.
- **Roaming support** — Tunnels survive IP address changes (e.g., Wi-Fi to cellular transitions) by rebinding to the new source address and renegotiating relay paths.
- **Tunnel health monitoring** — Continuous liveness probing with automatic reconnection using exponential backoff (1s–60s).

### 6.3 Stream Multiplexing

A single ZTLP tunnel supports up to 256 concurrent streams using three wire frame types:

- **STREAM_OPEN (0x05)** — Opens a new stream within an existing tunnel, carrying service name and destination metadata.
- **STREAM_DATA (0x06)** — Carries payload data for a specific stream, with per-stream flow control.
- **STREAM_CLOSE (0x07)** — Gracefully terminates a stream without tearing down the tunnel.

This allows a single authenticated tunnel to carry multiple TCP connections — SSH sessions, HTTP requests, and database connections — without repeated handshakes.

### 6.4 Measured Throughput

End-to-end tunnel benchmarks (TCP → encrypt → UDP → decrypt → TCP, localhost) demonstrate practical throughput:

| Transfer Size | Throughput | Notes |
|--------------|-----------|-------|
| 1 MB | 334–415 MB/s | Peak performance (congestion window covers entire transfer) |
| 10 MB | 235–275 MB/s | Large transfer steady-state |
| SCP 10 MB | 31 MB/s | Real-world SSH file transfer through ZTLP tunnel |

The crypto overhead is negligible: ChaCha20-Poly1305 encrypt + decrypt takes approximately 10 µs per 16KB packet, accounting for less than 6% of total transfer time. The primary bottleneck on Linux systems is the default UDP receive buffer size (208KB), which limits burst absorption.

---

## 7. ZTLP-NS: Distributed Identity Namespace

ZTLP-NS is a protocol-native namespace that provides the trust infrastructure ZTLP requires without depending on external certificate authorities or DNS.

### 7.1 Record Types

ZTLP-NS supports nine record types that cover identity binding, service discovery, access control, and organizational modeling:

| Record Type | Wire Code | Purpose |
|-------------|-----------|---------|
| `ZTLP_KEY` | 0x01 | Binds a NodeID to its Ed25519 public key. Signed by an Enrollment Authority. |
| `ZTLP_SVC` | 0x02 | Publishes a service identity, gateway endpoint, and policy requirements. |
| `ZTLP_RELAY` | 0x03 | Advertises a relay node's availability, capacity, and geographic region. |
| `ZTLP_POLICY` | 0x04 | Defines which NodeIDs or identity classes may access a service. |
| `ZTLP_REVOKE` | 0x06 | Invalidates a previously issued identity binding or credential. |
| `ZTLP_ZONE` | 0x07 | Delegates authority over a sub-namespace to a subordinate zone. |
| `ZTLP_DEVICE` | 0x10 | Hardware-bound device identity: NodeID, X25519 key, optional owner link, hardware attestation. |
| `ZTLP_USER` | 0x11 | Person-bound identity: role (admin/tech/user), contact email, associated device list. |
| `ZTLP_GROUP` | 0x12 | Named group with flat membership list, used for policy evaluation. |

All records are Ed25519-signed. Unsigned records are rejected unconditionally. Record validity is enforced via explicit TTLs and expiration timestamps.

### 7.2 Hierarchical Delegation

ZTLP-NS uses hierarchical zone delegation analogous to DNS, but with cryptographic integrity at every level:

```
Root Trust Anchor
  └── org.ztlp (delegated to Org enrollment authority)
       ├── engineering.org.ztlp
       │    ├── ZTLP_DEVICE: laptop-01 (NodeID → pubkey)
       │    ├── ZTLP_USER: alice (role=admin, devices=[laptop-01])
       │    └── ZTLP_SVC: api.engineering.org.ztlp
       └── partners.org.ztlp
            ├── ZTLP_GROUP: vendors (members=[alice, bob])
            └── ZTLP_POLICY: partner-access rules
```

Each delegation is signed by the parent zone authority. Trust chain verification traverses from the queried record up through delegation records to a configured trust anchor. The reference implementation verifies a 2-level trust chain in ~250 µs.

### 7.3 Multi-Root Trust

ZTLP does not require a single global root authority. Deployments may configure multiple independent trust roots — enterprise roots, partner roots, public roots — and define per-interaction trust policies. This federated model avoids the single-point-of-failure inherent in centralized PKI while maintaining auditable trust chains.

### 7.4 Federation and Replication

ZTLP-NS supports multi-node federation for availability and partition tolerance:

- **Eager replication** — Record writes are immediately forwarded to all known peers, providing fast convergence under normal conditions.
- **Merkle-tree anti-entropy** — Periodic Merkle-tree synchronization detects and repairs divergence caused by network partitions or missed replication events.
- **Conflict resolution** — Deterministic resolution ordering: revocations always win, followed by highest serial number, then most recent signature timestamp, then shortest TTL. This ensures convergence without coordination.
- **Cluster management** — Nodes discover peers via configuration or DNS, with health monitoring and automatic reconnection.

### 7.5 Security Hardening

The NS server enforces multiple layers of protection against abuse:

- **Registration authentication** — Ed25519 signature verification and zone authorization for all record writes (configurable: can be disabled for development).
- **Rate limiting** — Per-source-IP query and registration rate limits, enforced at the server entry point.
- **Size limits** — Maximum 8KB per packet, 4KB per record, with DNS-compatible name validation.
- **Amplification prevention** — Response size capped at 8× request size, with truncation flag when exceeded.
- **Pubkey reverse index** — O(1) lookups from public key to registered name via a dedicated Mnesia table, enabling identity resolution in the gateway policy engine.
- **Worker pool** — Bounded concurrency via Task.Supervisor (max 100 workers) to prevent resource exhaustion.
- **Audit logging** — Structured JSON logging of all registration, query, and administrative operations.

### 7.6 Revocation

Credential revocation is a first-class operation. `ZTLP_REVOKE` records propagate through the namespace via federation, and relay nodes periodically synchronize revocation state. Revoked NodeIDs are rejected at the admission stage — before any session resources are allocated. Revocation supports cascade semantics: revoking a USER record automatically revokes all linked DEVICE records. Revocation is fast (sub-second propagation to connected relays) and does not require cooperation from the revoked party.

---

## 8. Identity Model: Users, Devices, and Groups

ZTLP v0.9 introduces a structured identity model that maps real-world organizational relationships onto the cryptographic identity layer.

### 8.1 Design Rationale

The original ZTLP identity model used only NodeIDs and KEY records — sufficient for machine-to-machine authentication but insufficient for answering questions like "which person owns this device?" or "should employees in the engineering team have access to the staging server?" The structured identity model adds the organizational layer needed for practical deployment without compromising the cryptographic foundation.

### 8.2 Record Types

**DEVICE (0x10)** — Represents a physical or virtual machine. Every endpoint that connects to a ZTLP gateway is a device. Each device has a unique NodeID, an X25519 key pair for Noise_XX handshakes, an Ed25519 key for signing NS registrations, an optional owner link to a USER record, and an optional hardware identifier (hostname, serial number, TPM attestation).

**USER (0x11)** — Represents a person. Users own devices and belong to groups. Each user has a unique name within a zone, a role (admin, tech, or user), an Ed25519 signing key for administrative operations, and an optional contact email.

**GROUP (0x12)** — Represents a named collection of users for policy evaluation. Groups have flat membership (no nesting) and are referenced in gateway access policies. A user may belong to multiple groups.

### 8.3 Relationship Model

```
GROUP "admins"          GROUP "techs"
  ├── steve               ├── alice
  └── alice               └── bob

USER "steve"            USER "alice"           USER "bob"
  └── DEVICE laptop-01    ├── DEVICE mbp-02      └── DEVICE ipad-03
                          └── DEVICE desktop-04
```

**Key principle:** Users are people. Devices are machines. Groups collect users for policy enforcement. A device can exist without a user (e.g., a kiosk or shared terminal), but when a device has an owner, policy evaluation considers the owner's group membership.

### 8.4 Group-Based Policy Evaluation

The gateway policy engine evaluates access in the following order:

1. Complete Noise_XX handshake with the connecting device.
2. Query ZTLP-NS to resolve the device's X25519 public key to a DEVICE record.
3. If the device has an owner, resolve the USER record.
4. Query the user's group memberships.
5. Evaluate the service's access policy against the user's groups, role, or NodeID.

Group membership is cached at the gateway with a configurable TTL (default: 60 seconds), avoiding per-connection NS queries for repeated access patterns.

### 8.5 Administrative Operations

The `ztlp admin` CLI provides fleet management:

```
ztlp admin create-user alice --role tech --zone clients.corp.ztlp
ztlp admin create-group techs --zone clients.corp.ztlp
ztlp admin group add techs alice
ztlp admin group remove techs bob
ztlp admin revoke alice            # Cascades to all alice's devices
ztlp admin audit --since 24h --json
ztlp admin ls --zone clients.corp.ztlp
```

All administrative operations are Ed25519-signed and produce audit log entries. The `--json` output mode enables integration with external tooling and the Bootstrap web management UI.

---

## 9. Device Enrollment

Device enrollment is the process by which a new machine joins a ZTLP network. ZTLP provides a secure, user-friendly enrollment flow suitable for both self-service and IT-managed deployment.

### 9.1 Enrollment Tokens

An Enrollment Token is a compact, authenticated credential that authorizes a device to register with a specific zone. Tokens are generated by an administrator and distributed to end users or embedded in QR codes.

**Token structure:**
- Zone name (variable length)
- Expiration timestamp (48 bits)
- Maximum usage count (16 bits)
- HMAC-BLAKE2s MAC (32 bytes) over all fields, keyed with the zone's enrollment secret

Tokens are encoded as base64url strings and can be embedded in `ztlp://enroll/` URIs for one-click enrollment from mobile devices or QR code scanners.

### 9.2 Wire Protocol

Enrollment uses two dedicated message types:

| Type | Code | Direction | Purpose |
|------|------|-----------|---------|
| ENROLL Request | 0x07 | Client → NS | Presents enrollment token + device identity |
| ENROLL Response | 0x08 | NS → Client | Returns registration result with status code |

Response codes: `0x00` success, `0x01` expired, `0x02` usage exhausted, `0x03` invalid MAC, `0x04` zone mismatch, `0x05` name already taken, `0x06` invalid format.

### 9.3 Enrollment Flow

```
Administrator                     New Device                       NS Server
     │                                │                                │
     │── ztlp admin enroll ──────────►│                                │
     │   (generates token + QR)       │                                │
     │                                │                                │
     │   Scan QR or paste token       │                                │
     │                                │── ztlp setup --token TOKEN ──►│
     │                                │   1. Generate X25519 + Ed25519 │
     │                                │   2. Send ENROLL request       │
     │                                │                                │
     │                                │◄── ENROLL response (0x00) ────│
     │                                │   3. Save identity to disk     │
     │                                │   4. Start agent               │
     │                                │                                │
```

The `ztlp setup` wizard is interactive by default, guiding the user through token entry, identity generation, and agent configuration. The `--token` flag enables non-interactive provisioning for automation.

### 9.4 Key Overwrite Protection

ZTLP-NS rejects registration attempts that would overwrite an existing name with a different public key, preventing identity theft. Administrators can force re-enrollment with an explicit flag for legitimate device replacement scenarios.

---

## 10. Relay Mesh Architecture

ZTLP relays form a distributed mesh that provides session routing, admission control, NAT traversal, and path optimization.

### 10.1 Consistent-Hash Routing

Relays are organized into a hash ring using BLAKE2s with 128 virtual nodes per physical relay. Session admission is deterministically assigned to a bounded set of ingress relays based on consistent hashing of the client's NodeID or target ServiceID. This distribution prevents any single relay from being overwhelmed by targeted admission floods and enables predictable load distribution across the mesh.

### 10.2 PathScore-Based Selection

Relay selection uses a composite scoring function:

```
PathScore = RTT × (1 + loss × 10) × (1 + load × 2) × (1 + jitter / 100)
```

Clients maintain real-time PathScore measurements via sequence-numbered PING/PONG probes with a 20-probe sliding window for loss detection and jitter tracking (standard deviation of RTT). Relay health states (healthy / degraded / unreachable) use hysteresis to prevent flapping. Clients maintain at least two active relay paths for failover.

### 10.3 Multi-Hop Forwarding

When no single relay provides adequate connectivity, ZTLP supports multi-hop forwarding through up to 4 relay hops. Each forwarded packet carries a TTL byte and traversed-path list for loop detection. Route planning selects ingress → transit → service paths using measured PathScores. The forwarding table uses ETS-backed route caching with configurable TTL.

### 10.4 Relay Admission Tokens

Transit relays authenticate forwarded sessions using Relay Admission Tokens (RATs) — 93-byte HMAC-BLAKE2s authenticated tokens that bind a session to a specific relay path. RAT issuance runs at 275,000 tokens/sec; verification at 393,000/sec. Key rotation is supported for zero-downtime relay credential updates. The Rust client includes full RAT parsing, serialization, verification, and issuance, enabling cross-language interoperability.

### 10.5 NS-Based Relay Discovery

Relays self-register with ZTLP-NS on startup and periodically refresh their advertisements. Clients discover available relays by querying NS for RELAY records in their zone, with fallback to statically configured bootstrap addresses when NS is unavailable. Relay records include capacity class, geographic region, and supported protocol features.

### 10.6 Admission Plane / Forwarding Plane Separation

ZTLP explicitly separates expensive admission operations (identity verification, policy evaluation, handshake processing) from cheap forwarding operations (SessionID lookup, packet relay). Admission is confined to ingress relays; transit relays perform only label-switching. Under DDoS conditions, handshake floods are contained to the admission plane while established sessions continue uninterrupted on the forwarding plane.

---

## 11. Gateway Deployment Model

The ZTLP gateway is the critical adoption enabler. It allows organizations to protect existing services without modifying them.

### 11.1 Architecture

```
Internet                    ZTLP Network                    Internal Network
─────────                   ────────────                    ────────────────
                  ┌─────────────────────────┐
  ZTLP Client ──►│     ZTLP Gateway        │──► HTTP service
                  │                         │──► gRPC API
  Unauthorized ──►│  • Noise_XX termination │──► Database
  traffic    ✗    │  • Identity resolution  │──► Admin console
  (rejected)      │  • Group-based policy   │
                  │  • Circuit breaker      │    (all unchanged,
                  │  • Audit logging        │     internal protocols)
                  └─────────────────────────┘
```

The gateway performs the full Noise_XX handshake as responder, resolves the client's identity via ZTLP-NS (including pubkey reverse lookup for human-readable identity resolution), evaluates group-based access policy, and bridges authenticated ZTLP sessions to internal TCP services. Internal services see standard protocol traffic — they have no awareness of ZTLP.

### 11.2 Policy Engine

The gateway policy engine supports:

- **Group-based access** — Allow access based on group membership (e.g., `allow = ["techs@corp.ztlp"]`).
- **Exact NodeID matching** — Permit specific devices by their 128-bit NodeID.
- **Zone-based wildcards** — Allow all identities within a zone (e.g., `*.engineering.org.ztlp`).
- **Role-based rules** — Restrict access by user role (admin, tech, user).
- **Named backend services** — Route different services to different internal backends (e.g., `beta → 127.0.0.1:80`, `db → 127.0.0.1:5432`).
- **Audit logging** — Structured JSON logging of all admission decisions with identity, service, timestamp, and outcome.

Policy evaluation adds sub-microsecond overhead — even with 10 pattern rules, the engine completes in 371 ns.

### 11.3 Production Hardening

Gateways include several features for production deployment:

- **Circuit breaker** — Protects backends from cascading failure by detecting error rate thresholds and temporarily rejecting new connections.
- **Backpressure** — Propagates load signals from overloaded backends back through the ZTLP session, allowing clients to apply flow control.
- **Rate limiting** — Per-identity and per-service rate limits to prevent individual actors from consuming disproportionate resources.
- **Inter-component authentication** — Ed25519 challenge-response authentication between gateway, NS, and relay components.
- **Prometheus metrics** — Exposes handshake rates, session counts, policy evaluation latency, backend health, and error rates for monitoring.

### 11.4 Phased Adoption

Organizations adopt ZTLP incrementally:

1. **Phase 1:** Protect administrative interfaces and privileged access (SSH, management consoles)
2. **Phase 2:** Protect authentication endpoints (login portals, MFA flows)
3. **Phase 3:** Protect APIs and partner integrations (B2B, financial endpoints)
4. **Phase 4:** Extend to internal east-west service traffic

Each phase is independently valuable. Phase 1 alone eliminates exposed management ports — the initial access vector in the majority of ransomware incidents.

---

## 12. Agent Daemon

The ZTLP Agent is a background daemon that makes ZTLP connections seamless and transparent. Instead of manually running `ztlp connect` with IP addresses and port forwards, users simply use ZTLP names or custom domain names as if they were regular hostnames.

### 12.1 Design Goals

- **Zero-config after enrollment** — `ztlp setup` + `ztlp agent start` and the device is connected.
- **Works with any TCP application** — SSH, HTTP, databases, arbitrary protocols.
- **Custom domains** — Organizations use their own domain names; ZTLP handles identity underneath.
- **Auto-reconnect** — Tunnels recover from network changes (Wi-Fi → cellular, IP reassignment).
- **Credential lifecycle** — Automatic certificate renewal, NS record refresh, and key rotation.
- **Minimal privileges** — Runs as an unprivileged user; no TUN device or kernel module required.
- **Pure Rust** — Single binary, no runtime dependencies.

### 12.2 Architecture

The agent consists of five cooperating subsystems:

**DNS Resolver** — Listens on a local address (default: `127.0.0.1:5353`) and intercepts queries for configured domains. A domain map translates custom domain names (e.g., `app.internal.corp.com`) to ZTLP zone names (e.g., `app.services.corp.ztlp`). The resolver queries ZTLP-NS, assigns a virtual IP from the VIP pool (`127.100.0.0/16`), creates a tunnel if needed, and returns the VIP as a DNS A record. Unrecognized queries are forwarded to upstream DNS.

**Tunnel Pool** — Maintains persistent ZTLP tunnels to gateways, with automatic reconnection using exponential backoff (1s–60s). Tunnels are created on-demand when DNS resolution triggers a new service lookup. Keepalive probes (30-second interval) maintain NAT bindings and detect dead tunnels. Idle tunnels are torn down after a configurable timeout (default: 5 minutes).

**TCP Proxy** — Binds a listener on each assigned VIP and proxies TCP connections through the corresponding ZTLP tunnel. Supports stream multiplexing — multiple TCP connections share a single authenticated tunnel.

**Credential Renewal** — Monitors certificate lifetimes and NS record TTLs, triggering renewal at 67% of lifetime (certificates) and 75% of TTL (NS records). Applies ±10% jitter to prevent thundering herd renewal storms. Failed renewals use exponential backoff.

**Control Socket** — Provides a Unix domain socket for CLI interaction (`ztlp agent status`, `ztlp agent tunnels`, `ztlp agent flush-dns`).

### 12.3 SSH Integration

The agent provides `ztlp proxy` as an SSH ProxyCommand:

```
# ~/.ssh/config
Host *.corp.ztlp
    ProxyCommand ztlp proxy %h %p
```

This enables transparent SSH tunneling through ZTLP:

```bash
ssh admin@fileserver.corp.ztlp
scp report.pdf admin@nas.corp.ztlp:~/
```

### 12.4 System Integration

The agent integrates with platform-specific DNS and service management:

- **macOS** — `/etc/resolver/` split DNS configuration; `ztlp agent install` generates a LaunchAgent plist.
- **Linux (systemd)** — systemd-resolved split DNS configuration; `ztlp agent install` generates a systemd unit file.
- **DNS TXT discovery** — Queries `_ztlp` TXT records for automatic NS server discovery, enabling zero-configuration deployment in environments with TXT-capable DNS.

---

## 13. Threat Model and Security Properties

### 13.1 Attacker Classes

ZTLP's security analysis considers five attacker positions at increasing levels of access:

| Attacker Position | Payload Visibility | Can Impersonate | Can Disrupt Service | Can Discover Services |
|---|---|---|---|---|
| External (no identity) | None | No | Bandwidth only | No |
| Network Observer | None | No | No | No |
| Compromised Relay | None | No | Selective drop | Limited |
| Authorized Insider | Own sessions only | Others: no | App-layer only | Authorized only |
| Endpoint Compromise | That node's traffic | That node only | That node | That node's access |

### 13.2 Cryptographic Properties

| Property | Mechanism |
|----------|-----------|
| **Forward secrecy** | Ephemeral X25519 DH per session; keys destroyed after derivation |
| **Mutual authentication** | Noise_XX: both parties prove static key possession |
| **Replay protection** | 64-bit sequence numbers with sliding anti-replay window |
| **Endpoint confidentiality** | ChaCha20-Poly1305 AEAD; relays forward opaque ciphertext |
| **Key freshness** | Mandatory rekeying every hour; 24-hour max session lifetime |
| **Revocation** | ZTLP_REVOKE records propagated via NS federation; checked at admission |

### 13.3 Trust Assumptions

When deploying ZTLP, the operator trusts:

1. **The cryptographic primitives** — Ed25519, X25519, ChaCha20-Poly1305, BLAKE2s. Well-studied, widely deployed. Post-quantum migration path defined (Section 16).
2. **The Enrollment Authority** — Issues NodeIDs. Compromise allows minting valid identities. Mitigation: hardware-backed EA keys, certificate transparency-style logging.
3. **The trust root** — Anchors the namespace hierarchy. Mitigation: offline storage, multi-party signing, regular rotation.
4. **Endpoint integrity** — ZTLP secures the network layer, not the endpoint. A compromised endpoint with root access bypasses ZTLP's protections on that node.
5. **Relay operators (partially)** — Trusted for availability but not confidentiality or integrity. A malicious relay can deny service but cannot decrypt or forge traffic.

### 13.4 Explicit Non-Goals

- **Traffic analysis** — ZTLP is not an anonymity network. Multi-hop relaying provides topology hiding, but a global passive adversary can correlate flows.
- **Endpoint compromise with key extraction** — If an attacker holds the private key, they ARE the node. Hardware key storage (TPM, Secure Enclave) mitigates this.
- **Application-layer vulnerabilities** — ZTLP protects the transport path, not the application logic. SQL injection, XSS, and business logic flaws require application-layer defenses.
- **Quantum computing** — Current asymmetric primitives are vulnerable to Shor's algorithm. Migration path defined in Section 16.
- **Layer 0 denial of service** — ZTLP cannot prevent bandwidth saturation at the physical link, BGP hijacking, or infrastructure-level attacks.

---

## 14. Performance

All benchmarks measured on a 4-vCPU AMD EPYC 4564P system with 7.8 GiB RAM running Linux 5.15.

### 14.1 Admission Pipeline

| Operation | Rust | Elixir |
|-----------|------|--------|
| L1 reject (bad magic) | **19 ns** — 54M ops/sec | **89 ns** — 11.3M ops/sec |
| L2 reject (unknown session) | **31 ns** — 32M ops/sec | **1.05 µs** — 950K ops/sec |
| L3 AEAD verify | **840 ns** | **5.8 µs** |
| Full pipeline (valid packet) | **904 ns** — 1.1M ops/sec | **7.5 µs** |

### 14.2 Handshake

| Implementation | Latency | Throughput |
|---------------|---------|------------|
| Rust (client) | **293 µs** | 3,412 handshakes/sec |
| Elixir (gateway) | **471 µs** | 2,125 handshakes/sec |

With 4 BEAM schedulers: **~8,500 new sessions/sec** per gateway node.

### 14.3 Cryptographic Operations

| Operation | Rust Latency |
|-----------|-------------|
| ChaCha20-Poly1305 (64B) | 1.15 µs |
| ChaCha20-Poly1305 (1KB) | 1.60 µs |
| ChaCha20-Poly1305 (8KB) | 5.12 µs |

### 14.4 Tunnel Throughput

| Transfer Size | Throughput |
|--------------|-----------|
| 1 MB | **334–415 MB/s** |
| 10 MB | **235–275 MB/s** |
| SCP 1 MB | 3.9 MB/s |
| SCP 10 MB | **31 MB/s** |

SCP overhead vs. direct SSH: ~1.6× (includes Noise_XX crypto + UDP encapsulation + flow control + reassembly).

### 14.5 Steady-State Data Path

| Operation | Throughput |
|-----------|------------|
| Gateway data path (decrypt + identity + policy) | **669K ops/sec** per core |
| Relay forwarding (no auth) | **600K pkt/sec** per core |
| Relay forwarding (with auth) | **377K pkt/sec** per core |
| Mesh overhead | **3.2%** (vs. non-mesh forwarding) |

### 14.6 Namespace

| Operation | Latency |
|-----------|---------|
| ETS lookup (cache hit) | **432 ns** — 2.3M lookups/sec |
| Verified query (lookup + Ed25519 verify) | **79.7 µs** — 12.5K queries/sec |
| Trust chain verification (2-level) | **250 µs** |

### 14.7 Relay Mesh

| Operation | Throughput |
|-----------|------------|
| Hash ring lookup | 36K ops/sec |
| Packet forwarding | 233K pkt/sec |
| RAT issuance | 275K tokens/sec |
| RAT verification | 393K tokens/sec |

---

## 15. Comparison with Existing Systems

| Capability | ZTLP | WireGuard | Tailscale | Cloudflare Access | Teleport |
|-----------|------|-----------|-----------|-------------------|----------|
| Identity-first admission | ✓ Transport layer | ✗ | Partial (control plane) | Partial (HTTP only) | Partial (app proxy) |
| No open ports | ✓ | ✗ (UDP port exposed) | ✗ (device IPs visible) | ✗ (proxy exposed) | ✗ (proxy exposed) |
| DDoS-resistant pipeline | ✓ Three-layer, 19ns reject | ✗ | ✗ | ✓ (L3/L4/L7 mitigation) | ✗ |
| Distributed relay mesh | ✓ Consistent-hash | ✗ (point-to-point) | ✓ (DERP relays) | ✓ (Anycast CDN) | ✗ |
| Protocol-native namespace | ✓ ZTLP-NS | ✗ | ✗ | ✗ | ✗ |
| Multi-root federated trust | ✓ | ✗ | ✗ (single control plane) | ✗ (single provider) | ✗ (single cluster) |
| Hardware identity support | ✓ (TPM/YubiKey/SE) | ✗ | ✗ | ✗ | ✓ (hardware keys) |
| Identity model (users/groups) | ✓ DEVICE/USER/GROUP | ✗ | ✗ | ✓ (IdP-dependent) | ✓ (RBAC) |
| Device enrollment (QR/token) | ✓ | ✗ | ✓ | ✗ | ✓ |
| Agent daemon (transparent DNS) | ✓ | ✗ | ✓ | ✗ | ✗ |
| Gateway for existing services | ✓ | ✗ | ✗ | ✓ | ✓ |
| Forward secrecy | ✓ (per-session) | ✓ | ✓ | ✓ (TLS) | ✓ (TLS) |
| Open protocol/spec | ✓ (full spec + impl) | ✓ | ✗ (proprietary) | ✗ (proprietary) | ✓ |

**Key differentiator:** ZTLP is a *transport protocol* — not a product, not a service, not an application proxy. It provides the identity and session layer that existing systems implement partially or proprietarily. WireGuard provides excellent encryption but no identity namespace, no relay mesh, and no gateway model. Tailscale adds coordination but depends on a single proprietary control plane. Cloudflare Access protects HTTP but not arbitrary protocols. Teleport provides identity-first access for specific infrastructure (SSH, databases, Kubernetes) but operates as an application-layer proxy rather than a general-purpose transport.

ZTLP aims to be the layer beneath all of these — the transport primitive that makes identity-first connectivity a protocol property rather than a product feature.

---

## 16. Post-Quantum Migration Path

ZTLP's current cryptographic suite (X25519, Ed25519, ChaCha20-Poly1305, BLAKE2s) provides ~128-bit classical security. The symmetric primitives (ChaCha20, BLAKE2s) retain adequate security under quantum models. The asymmetric primitives (X25519, Ed25519) are vulnerable to Shor's algorithm on a fault-tolerant quantum computer.

### 16.1 Threat Assessment

The "harvest-now, decrypt-later" risk is real: adversaries can record encrypted ZTLP sessions today and attempt decryption once a cryptographically relevant quantum computer (CRQC) becomes available. While ZTLP's per-session forward secrecy protects ephemeral key material (which is destroyed after derivation), the static long-term identity keys used in ZTLP-NS records are not protected by forward secrecy and could be recovered retroactively.

### 16.2 Migration Strategy

**Phase 1 — Hybrid Key Exchange:**
Replace the Noise_XX ephemeral key exchange with a hybrid construction combining X25519 with ML-KEM-768 (NIST FIPS 203). This provides quantum resistance for session key derivation while preserving classical security as a fallback. The handshake payload increases by ~2,272 bytes (ML-KEM-768 public key 1,184B + ciphertext 1,088B) — acceptable for the three-message handshake. Expected operation latency: keygen ~27 µs, encapsulation ~42 µs, decapsulation ~44 µs.

**Phase 2 — Hybrid Signatures:**
Replace Ed25519 identity signatures with a hybrid scheme combining Ed25519 with ML-DSA-65 (NIST FIPS 204). This increases ZTLP-NS record sizes and handshake authentication payloads (ML-DSA-65 signatures are 3,309 bytes vs. Ed25519's 64 bytes) but preserves the existing trust model. Sign ~58 µs, verify ~41 µs.

**Phase 3 — Pure Post-Quantum:**
Once confidence in lattice-based constructions is established through widespread deployment and continued cryptanalysis (estimated no earlier than 2030), the classical fallbacks may be removed.

### 16.3 Design Decisions

- **Symmetric primitives unchanged:** ChaCha20-Poly1305 and BLAKE2s are not quantum-vulnerable at their current security levels.
- **Per-packet overhead unchanged:** Post-quantum primitives affect only the handshake and namespace operations. The compact 42-byte data header is unaffected.
- **Algorithm agility via CryptoSuite field:** Post-quantum migration will be introduced via the versioned CryptoSuite field in the handshake header, with explicit negotiation rules and no downgrade path to classical-only.
- **SLH-DSA fallback:** A hash-based signature scheme (NIST FIPS 205) is specified as a root-of-trust fallback, providing conservative post-quantum security for the highest-value signing keys at the cost of larger signatures (7,856 bytes).

---

## 17. Reference Implementation

The ZTLP reference implementation is open source under the Apache 2.0 license. It comprises six primary components implemented in three languages, reflecting the protocol's design philosophy of using each language where it excels.

### 17.1 Component Summary

| Component | Language | Lines of Code | Tests | Purpose |
|-----------|----------|---------------|-------|---------|
| Client + Agent | Rust | ~48,000 | 394+ | Endpoint identity, tunnels, CLI, agent daemon |
| Relay | Elixir/OTP | ~8,700 | 541 | Session routing, mesh, admission control |
| Namespace (NS) | Elixir/OTP | ~7,300 | 286+ | Identity records, federation, queries |
| Gateway | Elixir/OTP | ~5,900 | 202+ | Session termination, policy, TCP bridge |
| eBPF/XDP Filter | C | ~1,000 | N/A | Kernel-level L1 packet rejection |
| Bootstrap Web UI | Ruby (Rails) | ~5,000 | 54 | Fleet management, enrollment, audit |

**Total: ~76,000 lines of source code, 1,900+ tests, 0 failures.**

### 17.2 Language Architecture

- **Rust** — Client endpoints and the agent daemon. Chosen for single-binary deployment, memory safety without garbage collection, and nanosecond-precision packet processing.
- **Elixir/OTP** — All server-side components (relay, NS, gateway). Chosen for per-session fault isolation (each ZTLP session is a supervised GenServer), massive concurrency on the BEAM VM (millions of lightweight processes), hot code upgrades via OTP releases, and Mnesia for built-in distributed storage. **All Elixir components have zero external dependencies** — they use only OTP standard library modules.
- **C** — eBPF/XDP filter only. Chosen for kernel-level execution at line rate.

### 17.3 CLI Tool

The unified `ztlp` binary provides comprehensive protocol interaction:

| Command | Purpose |
|---------|---------|
| `ztlp keygen` | Generate cryptographic identity (X25519 + Ed25519 key pair) |
| `ztlp connect` | Establish a ZTLP tunnel with port forwarding |
| `ztlp listen` | Accept ZTLP connections as a responder |
| `ztlp ns lookup/register` | Query and register identities in ZTLP-NS |
| `ztlp admin` | Fleet administration (create-user, create-group, revoke, audit) |
| `ztlp setup` | Interactive device enrollment wizard |
| `ztlp agent` | Agent daemon lifecycle (start, stop, status, tunnels, dns-setup) |
| `ztlp proxy` | SSH ProxyCommand for transparent ZTLP tunneling |
| `ztlp inspect` | Packet decoder with three output modes |
| `ztlp ping` | ZTLP-level connectivity test |

### 17.4 Testing Infrastructure

The implementation includes comprehensive testing beyond unit tests:

- **Interop test suite** — 31 tests verifying Rust ↔ Elixir interoperability for Noise_XX handshakes, pipeline validation, gateway end-to-end flows, and NS resolution.
- **Stress testing** — Userspace impairment proxy simulating packet loss, delay, reordering, and corruption across 11 extreme network scenarios.
- **Fuzz testing** — 8 mutation strategies applied to ZTLP packets for 50,000+ iterations with zero panics discovered.
- **Docker chaos lab** — 7 failure scenarios testing mesh resilience under node failure, network partition, and concurrent session storms.
- **Network integration tests** — 10 Docker-based end-to-end scenarios with 3 isolated networks, 7 containers, and configurable impairment parameters.

### 17.5 Deployment Artifacts

- **Docker images** — Dockerfiles for all four server components with multi-stage builds.
- **Docker Compose** — Full-stack deployment manifest with environment-variable configuration.
- **OTP releases** — Production Elixir releases with runtime configuration and hot upgrade support via appup templates.
- **Prebuilt binaries** — Cross-compiled Rust client for Linux (x86_64, aarch64) and macOS (Apple Silicon).
- **MSP Deployment Guide** — Step-by-step documentation for protecting web applications behind ZTLP gateways.
- **Ops Runbook** — 1,687-line operational guide covering monitoring, alerting, incident response, and capacity planning.
- **Key Management Guide** — 1,367-line guide covering Vault/KMS integration, key rotation procedures, and incident response protocols.

---

## 18. Deployment Roadmap

### Stage 1 — Private Network Tool (Deployed)

ZTLP is deployed in production protecting a live web application (a Ruby on Rails CRM system) behind a ZTLP gateway on AWS infrastructure. A macOS client enrolled via the `ztlp setup` enrollment flow establishes an authenticated, encrypted tunnel to the gateway, which proxies traffic to the application's reverse proxy. This deployment validates the complete stack: identity generation, NS registration, Noise_XX handshake, tunnel establishment, TCP bridging, and gateway policy enforcement — all functioning end-to-end over the public Internet.

The Bootstrap web management UI provides fleet visibility: machine status, ZTLP component health, enrollment token management, and audit logging. The relay, NS, and gateway components run as Docker containers with host networking on production infrastructure.

### Stage 2 — MSP Adoption

Managed Service Providers deploy ZTLP to protect client infrastructure. The structured identity model (users, devices, groups) maps directly to MSP organizational models: technicians belong to the `techs` group, customer devices are enrolled with scoped access, and group-based policy ensures each client can only access their own services. The MSP Deployment Guide provides step-by-step instructions for this use case.

### Stage 3 — Enterprise Adoption

Organizations deploy ZTLP at scale for compliance, access control, and remote workforce requirements. Enterprises operate their own trust roots, enrollment authorities, and relay infrastructure. NS federation enables multi-site deployments with automatic record synchronization. External IdP integration (OIDC/SAML/LDAP) is planned for this stage to enable authentication against existing enterprise directories during enrollment.

### Stage 4 — Service Provider Integration

Cloud providers, CDN operators, and security vendors integrate ZTLP gateway and relay functionality into their platforms. Organizations adopt ZTLP-secured access without operating relay infrastructure themselves.

### Stage 5 — Public Ecosystem

ZTLP becomes a generally available Internet security layer. Public services offer ZTLP-authenticated access alongside legacy Internet access. Independent relay operators establish commercial relay networks. Developer SDKs (Go SDK scaffolded, additional languages planned) enable integration across application frameworks.

---

## 19. Conclusion

The Internet's anonymous connectivity model was designed for an era when the primary challenge was making communication possible. That era has passed. The primary challenge now is making communication *trustworthy* — and the current model, where security is applied after connectivity is already established, is structurally inadequate.

ZTLP proposes a different foundation. By making cryptographic identity a precondition for connectivity rather than an afterthought, the protocol eliminates entire categories of attack at the transport layer. Services become invisible to unauthorized parties. DDoS floods are rejected in nanoseconds at the kernel level. Relay infrastructure scales horizontally through consistent-hash distribution and label-switching forwarding. Existing applications gain identity-first protection without modification, deployed incrementally through edge gateways. A structured identity model with users, devices, and groups provides the organizational mapping that practical deployment requires. An agent daemon makes ZTLP connections transparent to end users and existing applications.

The reference implementation — over 70,000 lines of Rust, Elixir, and C with 1,900+ tests and zero failures — demonstrates that this architecture is not merely theoretical. A production deployment protects a live web application behind a ZTLP gateway today. The benchmarks show that identity-first networking is practical at Internet scale: 19-nanosecond packet rejection, sub-300-microsecond handshake completion, 300+ MB/s tunnel throughput, and multi-gigabit steady-state packet forwarding on commodity hardware.

ZTLP is not a product. It is a protocol specification and open reference implementation, released under Apache 2.0, designed to be the transport-layer foundation for identity-first networking. The specification, implementation, benchmarks, and documentation are available at **ztlp.org**.

The Internet does not need a new application. It needs a new transport primitive — one where identity comes first.

---

## References

1. Noise Protocol Framework. Trevor Perrin, 2018.
2. RFC 7748 — Elliptic Curves for Security (X25519).
3. RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519).
4. RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols.
5. RFC 7693 — The BLAKE2 Cryptographic Hash and Message Authentication Code.
6. RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport.
7. RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3.
8. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM).
9. NIST FIPS 204 — Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
10. NIST FIPS 205 — Stateless Hash-Based Digital Signature Algorithm (SLH-DSA).
11. WireGuard: Next Generation Kernel Network Tunnel. Donenfeld, J., NDSS 2017.
12. BeyondCorp: A New Approach to Enterprise Security. Ward & Beyer, Google.
13. SCION: A Secure Internet Architecture. Barrera et al., ETH Zurich.
14. NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes.

---

**ZTLP.org — 2026**
**Tech Rockstar Academy**
**Apache License 2.0**
