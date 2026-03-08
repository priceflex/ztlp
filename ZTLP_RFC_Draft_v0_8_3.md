# ZTLP — Zero Trust Layer Protocol

**Draft RFC – Version 0.8.3 | Experimental / Informational**

| | |
|---|---|
| **Author** | Steven Price |
| **Organization** | ZTLP.org |
| **Location** | Monrovia, CA |
| **Status** | Internet-Draft – This document is intended for public discussion. Distribution is unlimited. |
| **Note** | This document is not an IETF RFC. It is a working concept specification. |
| **Year** | 2026 |

---

## Abstract

Distributed Denial of Service (DDoS) attacks and unauthenticated network access represent the two most persistent and costly structural failures of the modern Internet. Both exist for the same reason: the Internet was designed to carry any packet from any source, with security left as an afterthought for endpoints and applications to solve individually. ZTLP (Zero Trust Layer Protocol) is a direct response to this design flaw.

ZTLP defines a secure, identity-first network overlay that enforces cryptographic authentication before any network state is allocated. Invalid packets are rejected in a three-layer pipeline — Magic byte check, SessionID allowlist lookup, and HeaderAuthTag AEAD verification — with each layer progressively more expensive but handling a progressively smaller fraction of attack traffic. The vast majority of flood traffic is discarded at the first two layers with no cryptographic work performed and no session state created. This makes volumetric DDoS attacks structurally ineffective and eliminates the concept of an open attack surface entirely. ZTLP rides over existing IPv4 and IPv6 infrastructure and is invisible and unusable to any node that does not possess a valid, hardware-backed cryptographic identity.

The primary design goals of ZTLP are DDoS mitigation and Zero Trust network access at the protocol layer — not at the application, firewall, or middleware layer where such controls are currently implemented. Bandwidth reservation across the public Internet backbone is a future target capability of ZTLP, motivated by its application as a structural DDoS defense mechanism. This document is submitted as an Informational/Experimental specification. It does not propose changes to IP addressing or BGP routing. It defines a protocol layer that can be deployed today over the existing Internet.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Introduction and Motivation](#2-introduction-and-motivation)
3. [Terminology](#3-terminology)
4. [Goals, Non-Goals, and Design Philosophy](#4-goals-non-goals-and-design-philosophy)
5. [Threat Model](#5-threat-model)
6. [Protocol Overview](#6-protocol-overview)
7. [ZTLP Addressing — Node Identity](#7-ztlp-addressing--node-identity)
8. [ZTLP Packet Format](#8-ztlp-packet-format)
9. [ZTLP-NS — Distributed Trust Namespace](#9-ztlp-ns--distributed-trust-namespace)
10. [Node Initialization and Bootstrap Procedure](#10-node-initialization-and-bootstrap-procedure)
11. [Handshake and Session Establishment](#11-handshake-and-session-establishment)
12. [Relay Node Architecture](#12-relay-node-architecture)
    - 11.4 Ingress Admission Domains and Relay Admission Tokens
    - 11.5 Authenticated Relay Federation and Capacity Classes
13. [Hardware Enforcement Profiles](#13-hardware-enforcement-profiles)
14. [Transport Fallback and NAT Traversal](#14-transport-fallback-and-nat-traversal)
15. [Routing and Path Selection](#15-routing-and-path-selection)
16. [Key Management and Hardware Identity](#16-key-management-and-hardware-identity)
    - 15.3 Node Identity Assurance Model and Attestation
17. [Deployment Model and Migration Strategy](#17-deployment-model-and-migration-strategy)
18. [Security Considerations](#18-security-considerations)
19. [Privacy Considerations](#19-privacy-considerations)
20. [Operational Tooling](#20-operational-tooling)
21. [Open Issues and Future Work](#21-open-issues-and-future-work)
22. [References](#22-references)

---

## 1. Problem Statement

The Internet was not designed to be secure. It was designed to be resilient and reachable — to move packets from one place to another regardless of who sent them or why. That was the right decision in 1974. It is the source of most of our problems in 2026.

### 1.1 The Cost of the Status Quo

The structural insecurity of the Internet is not an abstract concern. It has measurable, recurring costs that affect every organization connected to it:

- **DDoS attacks** cost the global economy an estimated $2.5 billion annually in direct mitigation costs, downtime, and lost revenue. Volumetric attacks regularly exceed 1 Tbps. They work because the Internet accepts any packet from anyone.
- **Ransomware attacks** on critical infrastructure — hospitals, water treatment facilities, school districts, manufacturers — succeed primarily because internal networks are flat and unauthenticated. Once an attacker is inside, lateral movement is trivial. The network has no concept of identity; if you can reach an IP, you can attempt to exploit it.
- **BGP route hijacking** allows nation-state actors and misconfigured routers to silently redirect Internet traffic, intercept communications, or cause widespread outages. RPKI deployment has improved but remains incomplete, and BGP itself has no cryptographic path validation.
- **IoT insecurity** is systemic and worsening. Billions of devices connect to the Internet with no meaningful authentication, becoming permanent botnet members and attack platforms. The network layer offers them no protection and demands nothing of them.
- **Compliance frameworks** are compensating controls, not solutions. HIPAA, PCI-DSS, CMMC, and SOC 2 require organizations to build security on top of an insecure network layer using firewalls, VPNs, intrusion detection, and monitoring. These are necessary but they are expensive, operationally complex, and fundamentally reactive. They detect and respond to threats that a secure-by-design network layer would never allow to exist.

### 1.2 Why IPv6 Did Not Solve This

IPv6 solved the address exhaustion problem. It did not change the fundamental model: any host can still send packets to any reachable address. IPv6 nodes are still exposed by default. Services still require firewalls. Authentication and encryption are still optional. DDoS attacks work identically over IPv6. The attack surface is the same; the addresses are just longer.

The root cause is philosophical, not technical. IPv4 and IPv6 both treat the network as a neutral carrier of packets. Security is the responsibility of endpoints. ZTLP inverts this: the network refuses to carry packets that cannot prove their identity. Security becomes structural rather than bolted on.

### 1.3 Why Now

The prerequisites for a protocol like ZTLP did not exist a decade ago. They exist today:

- **Hardware identity is mainstream.** YubiKeys, TPM 2.0 chips, and Secure Enclaves are now standard in consumer and enterprise hardware. Hardware-bound private keys that cannot be extracted or cloned are no longer exotic or expensive.
- **QUIC provides a proven encrypted UDP transport substrate.** ZTLP does not need to solve NAT traversal, encrypted transport, or firewall compatibility from scratch. QUIC has already done that work, and it is now deployed at Internet scale.
- **Zero Trust Architecture is now industry consensus.** NIST SP 800-207, the US Executive Order on Improving the Nation's Cybersecurity (2021), and widespread enterprise adoption have established Zero Trust as the direction of travel. ZTLP embeds this model at the network layer rather than requiring it to be retrofitted at every application.
- **The Noise Protocol Framework provides a proven handshake foundation.** WireGuard demonstrated that a simple, auditable, high-performance cryptographic protocol can achieve widespread real-world deployment. ZTLP builds on this foundation.
- **The regulatory and threat environment demands action.** CMMC 2.0, HIPAA enforcement, critical infrastructure protection mandates, and escalating cyber insurance requirements are creating strong economic incentives for organizations to move beyond perimeter-based security models. ZTLP aligns with and accelerates that direction.

### 1.4 Who Benefits First

ZTLP does not require global deployment to deliver value. The following sectors have acute pain points that ZTLP directly addresses, making them natural early adopters:

- **Healthcare.** Hospitals and clinics are the most targeted sector for ransomware. HIPAA mandates data protection but provides no network-layer enforcement mechanism. ZTLP makes lateral movement structurally impossible within a ZTLP-enrolled network: no open ports, no unauthenticated access, no attack surface for an attacker who gains a foothold on one device.
- **Defense contractors and CMMC-regulated organizations.** CMMC Level 2 and 3 requirements map directly to ZTLP capabilities: access control, identification and authentication, system and communications protection. ZTLP provides these at the network layer, reducing the compliance burden on individual applications.
- **Managed Service Providers (MSPs).** MSPs manage networks across dozens or hundreds of client environments, often connected via VPNs and jump hosts that are themselves attack targets. ZTLP replaces the VPN mesh with identity-based direct sessions, eliminates jump hosts as an attack surface, and makes client network isolation structural rather than policy-dependent.
- **Manufacturing and industrial control systems.** OT and ICS environments increasingly connect to IT networks and the Internet, creating attack paths into physical systems. ZTLP's zero-open-port model provides a network layer that industrial devices can participate in without exposing control interfaces to the public Internet.
- **Internet of Things deployments.** IoT devices with hardware identity (TPM or Secure Enclave) can participate in ZTLP networks without any application-layer security configuration. The device either has a valid identity and is enrolled, or it cannot communicate with enrolled services. This eliminates entire categories of IoT attack.

### 1.5 The Vision

A network where ZTLP is widely deployed looks fundamentally different from the Internet of today:

- Port scanners return nothing. There are no open ports to find. Services do not exist to unenrolled nodes.
- DDoS floods exhaust bandwidth at the physical link but cannot exhaust CPU or memory — the three-layer enforcement pipeline ensures that flood traffic is rejected before expensive session state is allocated, and before cryptographic verification is performed on packets that fail the cheaper checks first.
- A stolen laptop or cloned VM cannot authenticate. The hardware token is the credential; without it the identity does not exist.
- Ransomware that gains a foothold on one device cannot move laterally. Every other service on the network requires a separate authenticated identity to reach.
- Network connectivity follows identity, not location. A device works identically whether it is in the office, at home, or on a cellular connection — because the network authenticates who you are, not where you are.

This is not a utopian vision. Every component described above already exists in some form. What does not yet exist is a unified, open protocol that assembles them into a coherent network layer. That is what ZTLP proposes to be.

---

## 2. Introduction and Motivation

The Internet's current network layer (IPv4/IPv6) was designed with **reachability** as the primary objective. Security was not a first-class design principle. As a result, the global Internet suffers from persistent structural problems that cannot be fully resolved within the IPv4/IPv6 paradigm:

- Any host can send packets to any reachable address, regardless of authorization.
- Services are exposed by default; security is enforced reactively by firewalls and ACLs.
- DDoS attacks exploit the fact that routers cannot distinguish authorized from unauthorized traffic.
- BGP routing prioritizes policy over performance; path selection is opaque to endpoints.
- Encryption and authentication are optional add-ons, not protocol requirements.
- Identity is tied to IP addresses, which are location-based and easily spoofed.

ZTLP proposes a different model. Rather than replacing IPv6, ZTLP defines a secure overlay that rides on existing Internet infrastructure and enforces a single rule before any network state is allocated:

> **"If you cannot prove who you are, you do not exist on this network."**

This produces a network layer where port scanning returns nothing, SYN floods are rejected before session state is allocated, spoofed packets fail authentication, and services have no externally visible attack surface unless explicitly permitted. DDoS mitigation becomes **structural rather than reactive**.

ZTLP is not a replacement for the Internet. It is a *protected lane on top of it*.

---

## 3. Terminology

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`, `MAY`, and `OPTIONAL` in this document are to be interpreted as described in RFC 2119.

| Term | Definition |
|------|------------|
| `ZTLP Node` | Any device running the ZTLP stack with a valid Node Identity. |
| `Node ID` | A stable 128-bit identifier assigned to a node at enrollment. Permanent — does not change when keys rotate or hardware is replaced. The associated public key is bound via a signed ZTLP_KEY record in ZTLP-NS. |
| `Service ID` | A 128-bit identifier for a named service, derived from hash(service-name + tenant). |
| `ZTLP Relay` | A ZTLP Node that forwards traffic between other nodes across the public Internet. |
| `ZTLP Gateway` | A ZTLP Node that bridges between ZTLP and legacy IPv4/IPv6 networks. |
| `ZTLP-NS` | The ZTLP Namespace — a distributed DNS-like trust namespace for identity and service discovery. |
| `Trust Anchor` | A hardcoded public key embedded in ZTLP implementations that bootstraps initial trust. |
| `Session` | An established, mutually authenticated, encrypted ZTLP communication channel. |
| `HeaderAuthTag` | A 128-bit authentication tag over the ZTLP header allowing fast pre-decryption packet rejection. |
| `Hardware Identity` | A private key bound to a physical hardware token (e.g., YubiKey, TPM, Secure Enclave). |
| `Policy Tag` | A 32-bit compact field encoding tenant, role, or zone for fast edge policy decisions. |
| `CryptoSuite` | A 16-bit identifier specifying the AEAD, hash, and handshake algorithms in use. |

---

## 4. Goals, Non-Goals, and Design Philosophy

### 4.1 Goals

- Enforce cryptographic authentication before allocating any network state.
- Eliminate the concept of 'open ports' — services are invisible without authorization.
- Support hardware-backed identity (YubiKey, TPM, Secure Enclave) as a first-class primitive.
- Provide performance-aware, multipath relay routing across the public Internet.
- Deploy incrementally over existing IPv4/IPv6 infrastructure without router changes.
- Define a distributed, DNS-like trust namespace (ZTLP-NS) for identity and service discovery.
- Support gradual migration from legacy networks (Phase 1 through Phase 4 model).
- Provide structural DDoS resistance through cryptographic air-gapping of the packet surface.

### 4.2 Non-Goals

- ZTLP does not propose a new IP version number or changes to IPv4/IPv6 headers.
- ZTLP does not require Internet routers or BGP to be modified.
- ZTLP v0.8 does not implement hard bandwidth reservations across the public Internet backbone. Bandwidth-aware path selection and soft admission control via the `BANDWIDTH_HINT` extension TLV are defined in Section 15. Hard per-session bandwidth reservation between participating relay operators is a target capability for a future revision — motivated primarily by its application to volumetric DDoS mitigation, where pre-allocated authenticated capacity lanes prevent attackers from consuming resources reserved for legitimate traffic.
- ZTLP is not a VPN product, though it shares architectural concepts with secure overlays.
- ZTLP does not provide anonymity — identity is a core requirement of the protocol.

### 4.3 Design Philosophy

Every design decision in ZTLP is evaluated against two governing principles. These are not aspirational — they are the criteria by which proposed changes to this specification `MUST` be judged.

#### Principle 1 — DDoS Resistance Must Be Structural, Not Reactive

The current Internet responds to DDoS after the fact: detect the attack, classify the traffic, apply rate limits, absorb or block. This approach is expensive, slow, and fundamentally asymmetric — the attacker spends pennies per gigabit while the defender spends dollars. ZTLP inverts this entirely.

In ZTLP, invalid packets are rejected through a three-layer pipeline ordered by cost. The Magic byte check costs a single comparison — nanoseconds, no crypto, no kernel involvement, handled at the NIC driver. The SessionID allowlist lookup costs an O(1) BPF hash map read — still no cryptographic work. Only packets that survive both cheaper checks reach the HeaderAuthTag AEAD verification, which does involve real cryptographic computation. By the time a packet reaches AEAD verification, it has already proved it knows a valid SessionID — meaning the attacker is not sending random flood traffic, they are sending traffic that at minimum knows the structure of active sessions. That is a dramatically harder attack to mount, and the volume of such traffic is orders of magnitude lower than a raw flood. No session state is allocated until all three checks pass. The cost asymmetry strongly favors the defender across the entire pipeline.

> **Hard constraint:** Any feature added to ZTLP that increases the cost of processing unauthenticated packets — or that creates exploitable state before authentication — `MUST` be rejected. DDoS resistance is a hard architectural constraint, not a feature that can be traded off for convenience.

#### Principle 2 — Identity Must Precede Communication

The current Internet allows any host to send packets to any reachable address. Security is the endpoint's problem. Firewalls, intrusion detection systems, WAFs, VPNs, and Zero Trust access proxies all exist to compensate for this single design choice. They are expensive, complex, and they fail regularly.

ZTLP moves this check to the network layer and makes it mandatory. A node without a cryptographically verified identity cannot initiate communication. A service without an enrolled identity cannot receive communication. There are no open ports. There is no visible attack surface. There is no unauthenticated state. The Zero Trust model is not enforced by policy on top of an insecure network — it is enforced by the protocol itself, at the packet level, before anything else happens.

These two principles — structural DDoS resistance and mandatory identity — are not independent. They are the same idea expressed at different layers. An unauthenticated packet is both a potential DDoS vector and a Zero Trust violation. ZTLP treats them as one problem with one solution: if you cannot prove who you are, you do not exist on this network.

---

## 5. Threat Model

ZTLP is designed to mitigate the following classes of threat:

| Threat | Description | ZTLP Mitigation |
|--------|-------------|-----------------|
| **Volumetric DDoS** | Flood of packets to exhaust CPU, memory, or bandwidth. | Three-layer pipeline: Magic check (no crypto), SessionID allowlist (no crypto), HeaderAuthTag AEAD verification. Session state is not allocated until all three pass. The majority of flood traffic is rejected at layers 1 and 2 before any cryptographic work is performed. |
| **Packet Spoofing** | Attacker forges source address. | Every packet carries a HeaderAuthTag tied to session keys; forgeries fail immediately. |
| **Port Scanning** | Attacker enumerates open services. | No services are visible; ZTLP nodes do not respond to unauthenticated probes. |
| **Replay Attacks** | Attacker replays captured valid packets. | PacketSeq (64-bit) and Timestamp fields enforce anti-replay windows. |
| **Route Hijacking** | BGP prefix hijack redirects traffic. | ZTLP traffic is encrypted and authenticated end-to-end; hijacked routes carry opaque ciphertext. |
| **Man-in-the-Middle** | Attacker intercepts and modifies traffic. | Mutual authentication during handshake; session keys are ephemeral and hardware-bound. |
| **Credential Theft** | Private key or certificate stolen. | Hardware-bound keys (YubiKey/TPM) cannot be extracted; short-lived session tokens limit exposure. |
| **Lateral Movement** | Compromised node attacks others internally. | Each service requires separate policy authorization; Node ID alone does not grant access. |
| **Identity Cloning** | VM clone or config copy impersonates a node. | Hardware-bound keys mean a cloned config without the physical hardware token cannot authenticate. |

> **Out of Scope:** ZTLP does NOT protect against bandwidth saturation at the physical link layer before packets reach ZTLP edges, compromise of the hardware identity device itself, or application-layer attacks from legitimately authenticated nodes.

---

## 6. Protocol Overview

ZTLP operates as a secure overlay. The public Internet (IPv4/IPv6) acts as a dumb transport substrate. ZTLP does not require routers or ISPs to understand the protocol. A ZTLP packet is an encrypted, authenticated payload carried inside a standard UDP or QUIC datagram — to the public Internet, ZTLP traffic appears as ordinary encrypted UDP, indistinguishable from QUIC, DNS-over-QUIC, or other encrypted UDP traffic.

### 6.1 Layering

```
[ Physical / Ethernet ]
[ IPv4 or IPv6 ]           ← public Internet routing
[ UDP or QUIC ]            ← transport substrate
[ ZTLP Header ]            ← identity, auth, routing
[ Encrypted Payload ]      ← application data
```

### 6.2 Connection Model

ZTLP uses a connection-oriented model with explicit session establishment. The phases are:

1. Node discovers relay via bootstrap procedure (Section 10).
2. Node performs HELLO handshake with relay or peer (Section 11).
3. Mutual identity verification and policy check.
4. Session keys derived; short-lived session established.
5. Data packets flow; keys rotate automatically per session policy.
6. Session closes via explicit CLOSE message or timeout.

### 6.3 Identity vs. Location

In IPv4/IPv6, an address is a *location*. In ZTLP, identity is primary. A Node ID is a stable identifier for the node — it is the same regardless of what IPv6 address the node currently uses, which keys it currently holds, or what hardware it runs on. This enables seamless mobility, key rotation, hardware replacement, multihoming, and relay-based routing without breaking sessions or invalidating policies.

### 6.4 Locator/Identifier Separation

ZTLP explicitly separates network identity from transport location. This is a fundamental architectural principle, not an implementation detail. The Internet has historically conflated these two concepts — an IPv4 or IPv6 address simultaneously identifies a host and describes where it lives in the routing topology. This conflation causes mobility failures, multihoming complexity, inefficient routing, and reactive DDoS mitigation. Research protocols including HIP, LISP, SCION, and ILNP have attempted to solve this problem for decades. They struggled with deployment because all required changes to Internet routing infrastructure. ZTLP solves it differently — as an overlay.

ZTLP defines three distinct layers:

- **Identifier layer** — NodeID and ServiceID. Stable, permanent, hardware-backed. These never change and are what policies, ACLs, and logs reference.
- **Locator layer** — IPv4/IPv6 transport addresses. Transient. Change freely as nodes move networks, change ISPs, or fail over. Sessions are bound to identifiers, not locators, so locator changes do not break established sessions.
- **Routing layer** — The relay mesh. Relay nodes dynamically select the best locator path for a given identifier, optimizing for latency, packet loss, congestion, and trust score. Path optimization is performed at the relay level without any changes to Internet routing or BGP.

This separation is what makes ZTLP's DDoS resistance structurally stronger than IP-layer defenses. DDoS attacks target locators — IP addresses. ZTLP's enforcement is identity-based. An attacker flooding a locator accomplishes nothing if the packets cannot prove a valid identifier. The attack surface is the identifier space, not the locator space, and identifier space is cryptographically controlled.

---

## 7. ZTLP Addressing — Node Identity

### 7.1 Node ID

A ZTLP Node ID is a **stable 128-bit random identifier assigned at node enrollment. It is NOT derived from the node's public key.**

```
NodeID = RAND_128()   // generated once at enrollment, never changes
```

The NodeID represents the node as an entity — the device, service, or principal — independent of its current cryptographic key material. The public key is a separate attribute, bound to the NodeID via a signed `ZTLP_KEY` record in ZTLP-NS. This separation enables key rotation, hardware replacement, and multi-key configurations without changing the node's identity.

#### 7.1.1 Why NodeID Is Not Derived From the Public Key

Early protocol designs (including HIP — Host Identity Protocol) derived node identifiers directly from public keys. This is cryptographically elegant but operationally painful. When NodeID = HASH(public_key), any key change — routine rotation, compromise response, hardware replacement, lost YubiKey — changes the node's identity. Every policy, ACL, relay allowlist, security log, and service binding that referenced the old NodeID must be updated. In practice this means key rotation is avoided, which is the opposite of good security hygiene.

ZTLP separates identity from key material. The NodeID identifies the node permanently. The public key proves current possession of the private key bound to that NodeID. These are two different concepts and the protocol treats them as such. This is consistent with modern identity systems: TLS certificates, SSH known hosts, OAuth identities, and Kubernetes service accounts all separate stable identity from rotating key material.

#### 7.1.2 Key Binding and Rotation

A node's current public key is published as a `ZTLP_KEY` record in ZTLP-NS, signed by the ZTLP-NS zone authority. During session handshake, the initiator proves possession of the private key bound to its NodeID by completing the Noise_XX exchange. Verifiers check the `ZTLP_KEY` record to confirm the public key is currently bound to the presented NodeID.

Key rotation is performed by publishing a new `ZTLP_KEY` record with an updated public key and invalidating the previous record. The NodeID does not change. Existing sessions negotiate rekeying. Policies, ACLs, and logs continue to reference the same NodeID without modification. A node MAY have multiple active public keys simultaneously — useful for hardware HSMs with backup keys, emergency recovery keys, or phased key rotation with overlap periods.

Node IDs are NOT routable addresses. They are stable identity handles used for authentication, policy decisions, and logging. They do not change when a node moves networks, changes IP addresses, or replaces hardware.

### 7.2 Service ID

Services are identified independently from the hosts that run them:

```
ServiceID = TRUNCATE_128(SHA3-256(service-name || tenant-id))
```

Example Service ID resolutions from ZTLP-NS:

```
rdp.clinic.acmedental.ztlp  →  ServiceID: 8f23:9c11:ae45:...
backup.server.example.ztlp  →  ServiceID: c341:0f8a:21bc:...
```

### 7.3 Human-Readable Names

The ZTLP-NS namespace (Section 9) maps human-readable names to Node IDs, Service IDs, relay addresses, and policy records — functioning similarly to DNS but with mandatory signing and delegated trust.

---

## 8. ZTLP Packet Format

### 8.1 Base Header (64 bytes, fixed)

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Magic (16)   |Ver(4)|HdrLen |    Flags (16)  |  MsgType (8) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   CryptoSuite (16)            |   KeyID / TokenID (16)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     SessionID (96 bits)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     PacketSeq (64 bits)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Timestamp (64 bits)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     SrcNodeID (128 bits)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     DstSvcID  (128 bits)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  PolicyTag (32)               | ExtLen (16)  | PayloadLen(16)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   HeaderAuthTag (128 bits)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 8.2 Field Definitions

| Field | Size | Description |
|-------|------|-------------|
| `Magic` | 16 bits | Fixed 16-bit value `0x5A37` ('Z7'). Allows fast rejection of random UDP noise before any parsing. 16-bit width is required to hold the full 0x5A37 value. |
| `Ver` | 4 bits | Protocol version. Current: 1. |
| `HdrLen` | 12 bits | Header length in 4-byte words, including extensions. |
| `Flags` | 16 bits | Bitfield: HAS_EXT, ACK_REQ, REKEY, MIGRATE, MULTIPATH, RELAY_HOP. |
| `MsgType` | 8 bits | DATA, HELLO, HELLO_ACK, REKEY, CLOSE, ERROR, PING, PONG. |
| `CryptoSuite` | 16 bits | Identifies AEAD + hash + handshake family (e.g., ChaCha20-Poly1305 + Noise_XX). |
| `KeyID/TokenID` | 16 bits | Selects active credential slot; allows edge to pick correct verification key instantly. |
| `SessionID` | 96 bits | Stable per-flow identifier. Assigned during HELLO with cryptographically strong entropy. 96-bit width provides sufficient keyspace to make random guessing attacks computationally infeasible even under large-scale enumeration attempts. Rotates on REKEY. |
| `PacketSeq` | 64 bits | Monotonically increasing per-session counter. Anti-replay window enforced. In multipath sessions, the anti-replay window MUST be sized to accommodate path-induced reordering — implementations SHOULD use a minimum window of 1024 packets. |
| `Timestamp` | 64 bits | Unix epoch milliseconds. Used as a replay heuristic — packets with timestamps significantly outside the receiver's clock window SHOULD be treated as suspicious. Implementations MUST NOT hard-reject packets solely on timestamp deviation, as clock drift or embedded device limitations can produce legitimate out-of-window timestamps. The HeaderAuthTag provides the authoritative replay defense. |
| `SrcNodeID` | 128 bits | Sender's Node ID (stable 128-bit enrollment identifier). Zero during initial HELLO. |
| `DstSvcID` | 128 bits | Destination Service ID. No port numbers; services are resolved by identity. |
| `PolicyTag` | 32 bits | Compact policy hint (tenant/role/zone). Edge uses for fast admission decisions. |
| `ExtLen` | 16 bits | Length in bytes of extension TLV area following the base header. |
| `PayloadLen` | 16 bits | Length in bytes of the encrypted payload following extensions. |
| `HeaderAuthTag` | 128 bits | AEAD tag over the base header. Verified BEFORE decrypting payload. Invalid = silent drop. |

### 8.3 Extension TLVs (Optional)

If the HAS_EXT flag is set, a Type-Length-Value extension area follows the base header:

| Type | Name | Description |
|------|------|-------------|
| `0x01` | PATH_HINT | Preferred relay node IDs for this flow. |
| `0x02` | DEVICE_POSTURE | Signed attestation blob from TPM/Secure Enclave. |
| `0x03` | ROUTE_SCOPE | Site or realm identifier for routing policy. |
| `0x04` | TRACE_CTX | Correlation ID for distributed tracing and diagnostics. |
| `0x05` | BANDWIDTH_HINT | Requested bandwidth profile (informational; not a hard reservation). |
| `0x06` | RELAY_PATH | Ordered list of relay Node IDs traversed (for diagnostics). |

### 8.4 Payload

The payload is AEAD-encrypted application data. The authentication tag produced by the AEAD cipher is appended to the ciphertext. Decryption `MUST` fail and the packet `MUST` be silently dropped if authentication fails.

---

## 9. ZTLP-NS — Distributed Trust Namespace

ZTLP-NS is the control-plane identity and discovery layer. It is inspired by DNS delegation and DNSSEC chain-of-trust principles, adapted for ZTLP's identity-first model.

### 9.1 Design Principles

- **Hierarchical delegation** — trust flows from root anchors through operator zones to individual nodes.
- **All records are signed** — unsigned records MUST be rejected.
- **Federated roots** — multiple trust roots are supported; no single global authority.
- ZTLP-NS is a **control-plane lookup layer** — it is NOT used for per-packet routing decisions.

### 9.2 Namespace Structure

```
Root Trust Anchors (embedded in ZTLP software)
  └── Operator Zones  (e.g., example.ztlp)
        └── Tenant Zones  (e.g., acmedental.example.ztlp)
              └── Node / Service Records
```

### 9.3 Record Types

| Record Type | Description | Example |
|-------------|-------------|---------|
| `ZTLP_KEY` | Node's public key and Node ID. | node1.office.acmedental.ztlp → NodeID + pubkey |
| `ZTLP_SVC` | Service definition: ServiceID, allowed Node IDs, policy. | rdp.acmedental.ztlp → ServiceID + policy |
| `ZTLP_RELAY` | Relay node: Node ID, IPv6 endpoints, capacity metrics. | relay1.apac.ztlp → NodeID + endpoints |
| `ZTLP_POLICY` | Access policy: which Node IDs can reach which Service IDs. | policy.acmedental.ztlp → ACL |
| `ZTLP_REVOKE` | Revocation notice for a Node ID or Token ID. | revoke.acmedental.ztlp → revoked IDs + timestamp |
| `ZTLP_BOOTSTRAP` | Signed list of relay nodes for initial discovery. | bootstrap.ztlp → signed relay list |

### 9.4 Federated Trust Roots

ZTLP-NS supports multiple trust roots for different deployment contexts. Implementations SHOULD include at least:

- **Public ZTLP Root** — maintained by the ZTLP protocol governance body.
- **Enterprise Root** — self-hosted by organizations for private deployments.
- **Industry Roots** — sector-specific (e.g., healthcare, government, finance).

A node MAY trust multiple roots simultaneously. Policy records specify which trust roots are accepted for a given service. No single trust anchor SHALL be required for ZTLP network participation. Implementations MUST support multiple simultaneous trust roots and MUST NOT hardcode a single global root as a prerequisite for joining any ZTLP network. Bootstrap discovery URLs MUST span at least three independent operators to prevent any single party from controlling network access. This requirement exists because ZTLP's zero trust philosophy applies equally to its own governance: the protocol does not trust any single authority, including the one that published this specification.

---

## 10. Node Initialization and Bootstrap Procedure

A ZTLP node that has no prior session state MUST follow the Node Initialization Procedure (NIP) to discover its first relay connection. The following steps MUST be attempted in order. A node MUST proceed to the next step only if the current step fails or returns no usable result.

### Step 1 — HTTPS Discovery `[REQUIRED]`

The node MUST attempt an HTTPS GET request to each URL in the hardcoded discovery URL list. The response MUST be a signed JSON object containing:

- A list of relay node addresses (IPv6 and IPv4).
- Each relay's Node ID and public key.
- A validity timestamp and TTL.
- A signature verifiable against the software trust anchor.

The node MUST validate the signature before using any relay address from the response. The node MUST cache a valid response locally with its stated TTL, minimum 24 hours. HTTPS is chosen as the primary mechanism because it survives NAT, CGNAT, and enterprise firewalls in nearly all deployment environments.

### Step 2 — DNS-SRV Discovery `[RECOMMENDED]`

The node SHOULD query for SRV records at the well-known bootstrap domain:

```
_ztlprelay._udp.bootstrap.ztlp
```

If DNSSEC validation is available, the node MUST validate the response chain before use. If validation fails, the node MUST treat the response as untrusted and proceed to Step 3.

### Step 3 — Hardcoded Trust Anchors `[FALLBACK]`

If Steps 1 and 2 both fail, the node MUST attempt connection to the hardcoded relay node list embedded in the software distribution. This list:

- MUST contain a minimum of 15 relay nodes.
- MUST span a minimum of 5 distinct Autonomous Systems (ASNs).
- MUST span a minimum of 3 geographic regions.
- MUST include the pre-pinned public key for each relay.

The hardcoded list is a bootstrap-of-last-resort. Nodes that successfully complete Step 1 SHOULD NOT rely on hardcoded anchors for subsequent connections.

### 10.2 Post-Bootstrap Peer Exchange

Once a node establishes a session with any relay, it MUST request the relay's routing table via a `PEER_EXCHANGE` message. The relay responds with a signed list of known relay nodes. The node caches this list and uses it for all future connections, independent of the bootstrap anchors.

### 10.3 Discovery URL Resilience

Implementations MUST include discovery URLs hosted by at least 3 independent operators. This prevents a single-point-of-failure in HTTPS discovery. Discovery URL operators MUST be geographically and organizationally independent.

---

## 11. Handshake and Session Establishment

ZTLP uses a **Noise Protocol Framework** pattern (`Noise_XX`) for session establishment.

### 11.1 Handshake Overview

`Noise_XX` provides:

- **Mutual authentication** — both parties prove identity.
- **Perfect forward secrecy** — compromise of long-term keys does not expose past sessions.
- **Identity hiding** — identities are encrypted after the first message.

### 11.2 Message Flow

```
Initiator                          Responder
   |                                   |
   |--- HELLO (ephemeral pubkey) -----> |
   |                                   |
   |<-- HELLO_ACK (ephemeral pubkey,   |
   |    encrypted identity + cert) ---- |
   |                                   |
   |--- (encrypted identity + cert,    |
   |    policy request) -------------> |
   |                                   |
   |<-- SESSION_OPEN (SessionID,       |
   |    PolicyTag, session keys) ------ |
   |                                   |
   |=== DATA flows (encrypted) ======= |
```

### 11.3 Policy Enforcement

The Responder MUST perform the following checks before issuing SESSION_OPEN:

1. Verify the Initiator's certificate chain against a trusted ZTLP-NS root.
2. Verify the certificate has not been revoked (ZTLP_REVOKE record check).
3. Evaluate policy: is SrcNodeID authorized to reach DstSvcID?
4. Check device posture if DEVICE_POSTURE extension is present and required by policy.
5. Reject with ERROR if any check fails. No state is allocated on failure.

### 11.4 Key Rotation

Session keys MUST be rotated at intervals defined by the CryptoSuite policy, or upon explicit REKEY message. A new SessionID is issued on each rotation. Applications MUST NOT experience connection interruption during key rotation.

---

## 12. Relay Node Architecture

### 12.1 Role of Relay Nodes

ZTLP Relay nodes form the backbone of the overlay network. They perform three functions:

1. Forward authenticated ZTLP traffic between nodes that cannot communicate directly.
2. Participate in peer exchange, distributing routing table information.
3. Publish capacity metrics (latency, packet loss, bandwidth) to the ZTLP-NS.

### 12.2 Relay Selection Criteria

```
PathScore = w1*Latency + w2*PacketLoss + w3*Congestion + w4*TrustScore
```

Lower PathScore is preferred. Weights (w1–w4) are configurable per deployment. Nodes MUST maintain at least 2 active relay paths simultaneously for failover.

PathScore-based selection alone is insufficient at large scale. ZTLP relay selection SHOULD use a two-step model combining consistent hashing with PathScore optimization:

- **Step 1 — Candidate set via consistent hash:** Map the destination ServiceID to the nearest N relay nodes on a consistent hash ring of relay NodeIDs: `CandidateSet = Hash(ServiceID) → nearest 3 relays`. This provides stable, load-distributed assignment.
- **Step 2 — Optimize within the candidate set:** Select the relay with the lowest PathScore from the candidate set. This provides latency and performance optimization within the bounded set without creating global convergence on a single best relay.

Consistent hashing ensures that traffic to popular services is automatically distributed across multiple relays, relay churn causes minimal session migration, and the relay mesh scales to thousands of nodes without central coordination. The consistent hash ring is derived from ZTLP-NS relay records and updated as relays join and leave the mesh.

### 12.3 Relay Operator Requirements

Relay nodes MUST:

- Maintain a valid ZTLP_RELAY record in at least one ZTLP-NS zone.
- Publish latency and capacity metrics no less than once per 60 seconds.
- Support all four transport modes defined in Section 14.
- Honor CLOSE messages and release session state within 30 seconds.
- **Not log plaintext payload content** (relays see only encrypted data).

### 12.4 Ingress Admission Domains and Relay Admission Tokens

Large-scale relay networks face a structural risk: if all relay nodes accept first-contact session establishment attempts from any initiator, the entire relay mesh becomes a global handshake surface. ZTLP mitigates this by separating relay roles and limiting where first-contact admission occurs. Relay deployments SHOULD organize relays into **Ingress Admission Domains**.

#### 12.4.1 Relay Role Separation

- **Ingress Relay** — Handles first-contact traffic. Processes HELLO messages, performs Stateless Admission Challenge when required, verifies identity and policy, and issues Relay Admission Tokens upon successful authentication.
- **Transit Relay** — Forwards authenticated ZTLP sessions. SHOULD only accept traffic associated with already-authenticated sessions or carrying valid Relay Admission Tokens.
- **Service Relay** — Located near destination services or gateway clusters. Handles final-hop forwarding and service-specific policy enforcement.

#### 12.4.2 Deterministic Ingress Assignment

```
IngressSet = Hash(NodeID || bootstrap_salt) → nearest N relays on ring
N = ingress redundancy factor (RECOMMENDED: 3)
```

The `bootstrap_salt` is a periodically rotated value published by ZTLP-NS, preventing long-term fingerprinting of ingress assignments.

#### 12.4.3 Relay Admission Tokens

After successful session establishment, the ingress relay SHOULD issue a **Relay Admission Token (RAT)**. A RAT MUST contain at minimum: NodeID of the authenticated node, issuing relay NodeID, issuance timestamp, expiration timestamp, and a cryptographic signature or MAC. Tokens SHOULD have short lifetimes (RECOMMENDED: 5–30 minutes).

#### 12.4.4 Token Verification

Relay Admission Tokens MUST be verifiable without requiring global per-client state. Verification MAY use relay-issued MAC cookies, signed tokens using relay public keys published in ZTLP-NS, or short-lived relay federation keys. Token verification MUST be cheaper than full Noise_XX handshake processing.

#### 12.4.5 Attack Containment

Ingress Admission Domains limit the blast radius of admission floods. Under attack conditions: ingress relays apply rate limits and Stateless Admission Challenge; transit relays continue forwarding authenticated traffic unimpeded; service relays remain insulated from handshake floods.

### 12.5 Authenticated Relay Federation and Capacity Classes

Relay operators MAY optionally form **authenticated relay federations** to enable enhanced transport guarantees and differentiated traffic handling between participating networks.

#### 12.5.1 Relay Operator Identity

Each participating relay operator MUST possess an Operator Identity, represented by a cryptographic key pair and associated `ZTLP_OPERATOR` record published in ZTLP-NS, containing: OperatorID, PublicKey, OrganizationName, Contact, FederationClass (optional), and a Signature.

#### 12.5.2 Capacity Classes

| Class | Name | Description |
|-------|------|-------------|
| C0 | Best Effort | ZTLP traffic carried over public Internet with no special treatment. |
| C1 | Authenticated Relay Class | Relay-to-relay traffic authenticated by federation membership. |
| C2 | Soft Reserved Capacity | Operators reserve a portion of link capacity for relay traffic during congestion. |
| C3 | Hard Reserved Capacity | Dedicated bandwidth allocation between relay domains. |

Relay federation is optional and MUST NOT affect baseline ZTLP functionality. ZTLP nodes and relays MUST continue to operate correctly over standard Internet routing infrastructure even when federation mechanisms are unavailable.

---

## 13. Hardware Enforcement Profiles

The ZTLP base specification assumes packet enforcement occurs at ZTLP-aware endpoint software. This section defines four Hardware Enforcement Profiles that push ZTLP enforcement progressively closer to the wire. Each profile is independently implementable and additive.

### 13.1 Profile 1 — Software Enforcement (eBPF/XDP)

The baseline enforcement model, implementable today on any Linux host using eBPF and XDP (eXpress Data Path). XDP programs attach directly to the NIC driver and execute before the Linux kernel network stack.

An XDP program on a ZTLP node MUST implement the following decision pipeline for every inbound UDP packet on the ZTLP port:

```
1. Read first 16 bits. If Magic != 0x5A37 → XDP_DROP (immediate, zero state)
2. Read SessionID field. Check against eBPF SessionID allowlist map.
   If SessionID not in map AND MsgType != HELLO → XDP_DROP
3. Rate-limit HELLO packets per source IP (token bucket in eBPF map).
   If rate exceeded → XDP_DROP
4. Pass to kernel → full HeaderAuthTag verification in ZTLP userspace daemon.
```

**Deployment requirements:** Linux kernel 5.4 or later; NIC with XDP native driver support (Intel i40e, Mellanox mlx5, or equivalent); ZTLP daemon maintaining the SessionID BPF map in real time.

### 13.2 Profile 2 — SmartNIC Offload (DPU)

Data Processing Units (DPUs) — representative hardware includes the Nvidia BlueField-3 DPU and the AMD Pensando DSP — move full ZTLP HeaderAuthTag verification off the host CPU and onto the DPU. The DPU performs the full ZTLP verification pipeline entirely on-device. Only packets that pass all checks are forwarded to the host PCIe bus. Attack traffic never reaches host memory.

> **RECOMMENDED** for relay nodes and gateway nodes handling high-volume traffic. A compromised host OS cannot bypass DPU enforcement — the DPU is a separate trust boundary.

### 13.3 Profile 3 — Programmable Switch Enforcement (P4)

P4-capable switch hardware (Intel Tofino, Nvidia Spectrum-3 with P4, Barefoot Networks) can enforce packet admission at the switch ASIC. Enforcement is split into two tiers:

- **Tier 1 — Switch ASIC (P4, line rate):** Magic byte check, SessionID allowlist lookup, source IP rate limiting, HELLO packet metering.
- **Tier 2 — Server (eBPF or DPU):** Full HeaderAuthTag AEAD verification, anti-replay window enforcement, policy check.

Session lifecycle events update the switch's P4 tables via P4Runtime over gRPC:

```
SESSION_OPEN  → write SessionID to P4 allowlist table
SESSION_CLOSE → remove SessionID from P4 allowlist table
REKEY         → update SessionID entry with new session identifier
REVOKE        → immediately flush all entries for revoked NodeID
```

### 13.4 Profile 4 — Native Switch ASIC (Future)

The long-term target state: switch ASICs that natively understand ZTLP packet structure and enforce admission decisions in hardware without P4 programming, analogous to how modern switches natively implement MACsec (IEEE 802.1AE).

### 13.5 Profile Comparison

| Profile | Enforcement Point | Full AuthTag? | Available Today? | Host CPU Used? | HW Cost |
|---------|-------------------|---------------|-----------------|----------------|---------|
| 1 — eBPF/XDP | NIC driver (software) | Daemon only | Yes | Minimal (XDP) | Low ($0 extra) |
| 2 — SmartNIC/DPU | DPU (hardware) | Yes (on DPU) | Yes | None (DPU handles) | Medium (DPU card) |
| 3 — P4 Switch | Switch ASIC (Tier 1) + server (Tier 2) | Tier 1 only (SessionID) | Yes (P4 hardware) | Tier 2 only | High (P4 switch) |
| 4 — Native ASIC | Switch silicon | Full (optional AEAD) | Future (vendor req.) | None | Standard switch |

---

## 14. Transport Fallback and NAT Traversal

ZTLP MUST function in environments where ISPs, enterprise firewalls, or carrier-grade NAT devices block or reshape UDP traffic on non-standard ports. Implementations MUST support the following transport fallback ladder in order:

| Priority | Transport | Condition | Notes |
|----------|-----------|-----------|-------|
| 1 | UDP / ZTLP Port | Preferred | Native ZTLP transport. Best performance. |
| 2 | UDP / 443 | If port blocked | Harder for ISPs to block without disrupting QUIC. |
| 3 | TCP / 443 (TLS framed) | If UDP blocked | ZTLP framed inside TLS record layer. |
| 4 | WebSocket over HTTPS | Last resort | Maximum firewall compatibility. Higher overhead. |

Relay nodes MUST support all four transport modes. Initiating nodes MUST attempt them in order and use the first that succeeds.

### 14.1 NAT Traversal

For direct peer-to-peer connections (without relay), ZTLP nodes SHOULD attempt UDP hole-punching coordinated via a relay node. If hole-punching fails within 5 seconds, the relay MUST continue to forward the session.

---

## 15. Routing and Path Selection

ZTLP does not modify BGP or Internet routing. Path selection occurs within the ZTLP overlay, using relay-published metrics.

### 15.1 Congestion Control

ZTLP sessions MUST implement a congestion control algorithm. A ZTLP implementation without congestion control risks starving competing TCP flows, creating network unfairness, and contributing to congestion collapse on shared links. **This is a normative requirement with no exception.**

Implementations SHOULD use BBR (Bottleneck Bandwidth and Round-trip propagation time) or CUBIC as the default congestion control algorithm.

### 15.2 Path MTU Discovery and Fragmentation

The ZTLP base header is 64 bytes. Combined with a UDP header (8 bytes) and an IPv6 header (40 bytes), the minimum overhead before payload is 112 bytes. The default maximum payload size SHOULD be calculated as:

```
PathMTU - 112 - ExtensionHeaderBytes
```

ZTLP implementations MUST perform path MTU discovery (PMTUD) using the standard ICMP/ICMPv6 "Packet Too Big" mechanism. Implementations MUST NOT rely on IP fragmentation as a substitute for ZTLP-layer fragmentation, as IP fragments bypass the ZTLP header authentication check at the receiver.

### 15.3 Multipath

ZTLP nodes MAY split flows across multiple relay paths, providing resilience against relay outages, aggregate bandwidth, and geographic traffic distribution. The `MULTIPATH` flag signals multipath mode; receivers MUST reassemble using `PacketSeq`. The anti-replay window for MULTIPATH sessions MUST be at least 1024 packets.

### 15.4 Mobility

Because Node IDs are identity-based and not location-based, a node that changes its underlying IPv6 address (e.g., Wi-Fi to cellular) MUST issue a `MIGRATE` message containing its new transport endpoint. The existing session continues without interruption. Applications MUST NOT observe a connection break during migration.

---

## 16. Key Management and Hardware Identity

### 16.1 Hardware-Backed Keys

ZTLP STRONGLY RECOMMENDS that long-term private keys be stored in hardware security devices:

- FIDO2 / YubiKey (USB, NFC)
- Trusted Platform Module (TPM 2.0)
- Secure Enclave (Apple Silicon, ARM TrustZone)
- Hardware Security Module (HSM) for relay and gateway nodes

When hardware identity is in use, the private key MUST NOT be exportable. Signing operations MUST occur on-device. A cloned VM or stolen configuration file WITHOUT the physical hardware token MUST NOT be able to authenticate as the original node.

### 16.2 Certificate Lifecycle

| Stage | Description |
|-------|-------------|
| **Enrollment** | Node generates key pair on hardware; submits public key to ZTLP-NS operator. |
| **Issuance** | Operator validates identity; issues signed certificate with TTL. |
| **Renewal** | Certificate renewed before expiry; hardware must sign the renewal request. |
| **Revocation** | Operator publishes ZTLP_REVOKE record; nodes MUST check revocation. |

Certificate TTL SHOULD NOT exceed 90 days. Short-lived session tokens (issued per-session) SHOULD NOT exceed 24 hours.

### 16.3 Node Identity Assurance Model and Attestation

ZTLP defines an optional **Node Identity Assurance Model**, which allows policy decisions to incorporate verifiable security attributes associated with a NodeID. This model does not change packet-level behavior.

#### 16.3.1 Identity vs. Proof vs. Assurance

- **Identity** — the NodeID. Answers: "Who is this node?"
- **Proof** — cryptographic evidence that the node currently controls the private key bound to the NodeID. Answers: "Can this node demonstrate control of its key?"
- **Assurance** — verified properties of the device or environment hosting the identity. Answers: "How trustworthy is the environment in which this identity is operating?"

#### 16.3.2 Assurance Levels

| Level | Name | Description |
|-------|------|-------------|
| A0 | Software Identity | Private key stored in software; suitable for development or low-risk services. |
| A1 | Hardware-Backed Identity | Private key stored in a hardware security device (TPM, Secure Enclave, or FIDO2 token); key extraction is not possible. |
| A2 | Attested Managed Device | Hardware-backed key plus device posture verification (TPM attestation, Secure Enclave attestation, or enterprise device management enrollment). |
| A3 | Infrastructure Identity | High-assurance identity for relay nodes, gateways, and infrastructure services; keys stored in an HSM or equivalent hardware. |

Policies MAY require a minimum assurance level. Example: a service requiring A2 ensures that only verified managed devices with hardware-backed identities may connect.

#### 16.3.3 Attestation Records

Assurance attributes are published in ZTLP-NS using an optional `ZTLP_ATTEST` record, containing: NodeID, AssuranceLevel (A0–A3), AttestationType, IssuingAuthority, ValidFrom/ValidUntil timestamps, and a Signature. Nodes without attestation records are treated as Assurance Level A0.

#### 16.3.4 Device Posture Evidence

When the DEVICE_POSTURE extension TLV is present, it MAY contain TPM attestation quotes, Secure Enclave attestation blobs, enterprise device posture tokens, or managed device certificates. If a service policy requires device posture verification, the responder MUST validate the attestation evidence during session establishment before issuing SESSION_OPEN.

#### 16.3.5 Policy Integration

ZTLP policy records MAY evaluate any combination of: NodeID, ServiceID, tenant or zone, assurance level, attestation authority, and device posture requirements. Example:

> *Allow nodes in tenant acmedental with AssuranceLevel ≥ A2 and DeviceClass managed-workstation to reach rdp.clinic.acmedental.ztlp.*

#### 16.3.6 Privacy Considerations for Attestation

Implementations SHOULD minimize exposure of detailed posture information and SHOULD only transmit attestation data when required by policy. Services that do not require posture verification SHOULD omit the DEVICE_POSTURE extension entirely.

---

## 17. Deployment Model and Migration Strategy

ZTLP is designed for incremental deployment. Organizations can adopt ZTLP in phases without disrupting existing infrastructure.

### 17.1 Gateway Operation

A ZTLP Gateway translates between ZTLP-authenticated sessions and legacy TCP/UDP connections. The gateway:

- Terminates the ZTLP session on behalf of the legacy service.
- Enforces ZTLP policy at the boundary.
- Hides the legacy service's real IP address from the public Internet.
- Logs session metadata (Node IDs, Service IDs, timestamps) for audit.

### 17.2 Migration Phases

| Phase | Description | Legacy Compatibility |
|-------|-------------|---------------------|
| **Phase 1 — Overlay** | ZTLP nodes communicate with each other over the overlay. Legacy IPv4/IPv6 traffic is unchanged. | Full — ZTLP is additive. |
| **Phase 2 — Gateway** | ZTLP Gateways bridge between ZTLP overlay and legacy systems. Legacy clients can reach ZTLP services via gateway. | High — legacy clients need no changes. |
| **Phase 3 — Preferred** | ZTLP paths are preferred for sensitive services. Critical systems require ZTLP authentication. | Medium — legacy clients use gateway. |
| **Phase 4 — Native** | ZTLP is the default for all inter-node communication. Legacy fallback is restricted or deprecated. | Low — legacy clients require gateway or upgrade. |

---

## 18. Security Considerations

### 18.1 DDoS Resistance

ZTLP's primary DDoS defense is structural: packets are rejected through a three-layer pipeline before session state is allocated.

- **Layer 1 — Magic byte check (nanoseconds, no crypto):** A single 16-bit comparison at the NIC driver via XDP. Any packet not beginning with `0x5A37` is dropped before the kernel sees it. Eliminates all random UDP flood traffic immediately.
- **Layer 2 — SessionID allowlist lookup (microseconds, no crypto):** An O(1) BPF hash map lookup against the set of currently active SessionIDs. Packets with unknown SessionIDs are rate-limited and dropped before any cryptographic work is performed.
- **Layer 3 — HeaderAuthTag AEAD verification (real cryptographic cost):** ChaCha20-Poly1305 or AES-GCM tag verification is performed only on packets that passed both Layer 1 and Layer 2. A packet that reaches Layer 3 has already demonstrated it knows a valid active SessionID. Session state is not allocated until Layer 3 passes.

This pipeline does not prevent link-layer saturation — an attacker with sufficient bandwidth can still fill the physical uplink before packets reach ZTLP enforcement. That problem is addressed by the distributed relay architecture (Section 12) and, in future revisions, by bandwidth reservation between relay operators.

### 18.2 Amplification Prevention

ZTLP nodes MUST NOT generate responses whose byte size exceeds the initiating packet before authentication is complete. This is a normative requirement. HELLO responses and CHALLENGE messages MUST be padded or truncated such that `response_bytes ≤ request_bytes`. This prevents the classic UDP amplification pattern used in DNS, NTP, and SSDP reflection attacks.

### 18.3 Stateless Admission Challenge

To defend against handshake exhaustion, ZTLP relays and services MAY require unknown initiators to complete a **Stateless Admission Challenge (SAC)**:

```
Initiator                    Responder

HELLO              -------->
                   <--------  CHALLENGE (nonce, difficulty, expiry, cookie)
HELLO_PROOF        -------->  (solution + original HELLO)
                   <--------  HELLO_ACK (proceed with Noise_XX)
```

The CHALLENGE MUST be stateless on the responder side. The cookie field is a MAC computed over `(source_ip, timestamp, responder_secret)`, verifiable when HELLO_PROOF arrives without any per-client state being stored — directly analogous to TCP SYN cookies and QUIC retry tokens.

The puzzle SHOULD require the initiator to find a nonce such that `HASH(challenge || nonce)` has N leading zero bits. Difficulty N SHOULD be adaptive — zero or disabled under normal load, increasing automatically as HELLO rate exceeds configurable thresholds.

SAC MUST NOT be applied to: established sessions, rekeying operations, trusted relay-to-relay handshakes, or nodes presenting valid short-lived trust tokens from a prior successful session.

### 18.4 Clock Synchronization

The Timestamp field is used as a replay heuristic, not as a hard rejection criterion. Implementations MUST NOT reject packets solely based on timestamp deviation from local clock. Implementations SHOULD flag packets with timestamps more than ±5 minutes from local time for additional scrutiny, but MUST NOT drop them on that basis alone. The HeaderAuthTag provides the authoritative replay defense.

### 18.5 Cryptographic Agility

The `CryptoSuite` field allows future algorithm upgrades without protocol version changes. Implementations MUST NOT negotiate CryptoSuites with known weaknesses. A registry of approved CryptoSuite identifiers will be maintained separately.

### 18.6 Revocation Latency

`ZTLP_REVOKE` records propagate through ZTLP-NS with TTL-governed latency. Implementations MUST check revocation status during session establishment. For high-security deployments, short certificate TTLs (hours rather than days) are preferred over reliance on revocation propagation.

---

## 19. Privacy Considerations

ZTLP's identity-first model introduces privacy tradeoffs relative to the anonymous packet model of IPv4/IPv6. This section describes the privacy risks introduced by ZTLP's design and the normative mitigations that implementations MUST apply.

### 19.1 Packet-Level Identity Privacy

NodeID values represent long-lived identities and MUST NOT appear in normal data packets. A passive observer observing ZTLP traffic headers could correlate long-lived NodeIDs across sessions to track device behavior, infer organizational relationships, and fingerprint device mobility.

To prevent this, ZTLP requires ephemeral pseudonymous session identifiers in data packet headers. During the Noise_XX handshake, both parties MUST derive ephemeral session-scoped identifiers:

```
SrcSessionID = HASH(SrcNodeID || SessionKey)
DstSessionID = HASH(DstNodeID || SessionKey)
```

Data packets MUST carry `SrcSessionID` and `DstSessionID` in place of `SrcNodeID` and `DstSvcID` in normal operation. Because SessionKey is unique per session, these identifiers change with each new session. NodeID values are only transmitted during the authenticated handshake phase.

Implementations that include raw NodeID values in data packet headers are non-conforming.

### 19.2 Remaining Privacy Risks

Even with packet-level identity privacy enforced, the following residual risks remain:

- ZTLP-NS lookups for a node's services may reveal organizational relationships to operators of ZTLP-NS infrastructure. Implementations SHOULD use oblivious or privacy-preserving lookup mechanisms where available.
- Traffic volume and timing patterns can enable inference attacks even when identifiers are pseudonymous. ZTLP does not address traffic analysis attacks.
- The handshake phase necessarily reveals that ZTLP is in use, though not the specific identities involved after the first message.
- Relay operators can observe which SessionIDs are active, even if they cannot identify the underlying NodeIDs.

### 19.3 Operational Guidance

- ZTLP-NS operators SHOULD NOT log individual lookup queries beyond what is required for operational purposes.
- Relay operators MUST NOT log plaintext payload content.
- Ephemeral SessionIDs are rotated on REKEY, limiting per-session correlation windows.

**This document acknowledges that ZTLP is not an anonymity protocol.** Applications requiring strong anonymity SHOULD use additional layers such as onion routing above ZTLP.

---

## 20. Operational Tooling

Network operators MUST have access to diagnostic tools. The following tools are defined as part of the ZTLP operational suite:

| Tool | Function | Equivalent |
|------|----------|------------|
| `ztlp-ping` | Test reachability to a Node ID or Service ID. | ping |
| `ztlp-trace` | Display relay path taken to a destination. | traceroute |
| `ztlp-status` | Show local node state, active sessions, current relay. | netstat |
| `ztlp-relay-info` | Query a relay node's metrics and peer table. | BGP show route |
| `ztlp-ns-lookup` | Resolve ZTLP-NS records for a name. | dig / nslookup |
| `ztlp-revoke-check` | Verify revocation status of a Node ID. | OCSP check |

---

## 21. Open Issues and Future Work

The following issues are known and will be addressed in subsequent draft revisions:

- **Bandwidth reservation model** — formal definition of the BANDWIDTH_HINT TLV semantics and interaction with relay QoS policies.
- **Congestion control** — specification of a ZTLP-native congestion control algorithm for long-haul relay paths.
- **ZTLP-NS governance** — formal governance structure for the public ZTLP-NS root.
- **Relay operator incentives** — economic models for relay node operation at scale.
- **Lawful intercept considerations** — engagement with regulatory frameworks.
- **Hardware identity enrollment UX** — simplifying the YubiKey/TPM enrollment flow for non-technical users.
- **ZTLP for IoT** — lightweight profile for constrained devices.
- **Formal security proof** — cryptographic analysis of the Noise_XX handshake under ZTLP's threat model.

---

## 22. References

### 22.1 Normative References

- **RFC 2119** — Key words for use in RFCs to indicate requirement levels.
- **RFC 8446** — TLS 1.3.
- **RFC 7748** — Elliptic Curves for Diffie-Hellman Key Agreement (X25519, X448).
- **Noise Protocol Framework** — Trevor Perrin, 2018.
- **RFC 9000** — QUIC: A UDP-Based Multiplexed and Secure Transport.

### 22.2 Informative References

- **RFC 7401** — Host Identity Protocol Version 2 (HIPv2).
- **RFC 6698** — The DANE Transport Layer Security (TLS) Protocol.
- **SCION: A Secure Internet Architecture** — Barrera et al., ETH Zurich.
- **BeyondCorp: A New Approach to Enterprise Security** — Ward & Beyer, Google.
- **RFC 4960** — Stream Control Transmission Protocol (SCTP).
- **RFC 8555** — Automatic Certificate Management Environment (ACME).
- **Nebula** — A scalable overlay networking tool. Slack Technologies / Defined Networking, 2019. ZTLP's relay architecture extends the Nebula lighthouse/relay model to public Internet deployment with identity-first security and structural DDoS resistance as primary design constraints.
- **WireGuard: Next Generation Kernel Network Tunnel** — Donenfeld, J., NDSS 2017. Demonstrates that a minimal, auditable, high-performance cryptographic protocol can achieve widespread deployment. ZTLP builds on this precedent.
- **RFC 6830** — The Locator/ID Separation Protocol (LISP). Prior work on identifier/locator separation; ZTLP achieves the same architectural separation as an overlay without requiring router changes.
- **RFC 9000 Section 8** — QUIC Address Validation and Retry Tokens. The stateless cookie model used by ZTLP's Stateless Admission Challenge (Section 18.3) is directly analogous to QUIC retry token design.

---

*─────────────────────────────────────────*

*End of ZTLP Draft RFC v0.8.3*

*ZTLP.org — 2026*
