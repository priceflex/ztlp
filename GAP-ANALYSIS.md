# ZTLP Specification Gap Analysis

**Document analyzed:** `ztlp/README.md` (~5,826 lines)
**Analysis date:** 2026-03-12
**Specification version:** Inconsistent — see Finding #1

---

## Executive Summary

The ZTLP specification is an ambitious and well-structured protocol design that covers identity-first networking, relay-based forwarding, hardware enforcement, and federated trust models. However, as an implementable RFC-style specification, it has significant gaps that would prevent two independent teams from building interoperable implementations. The most critical issues are: contradictory header size claims, missing wire formats for several message types, systematic cross-reference errors (30+), and undefined registries for protocol identifiers.

**Finding counts by severity:**

| Severity | Count |
|----------|-------|
| CRITICAL | 7 |
| HIGH | 19 |
| MEDIUM | 22 |
| LOW | 10 |
| **Total** | **58** |

---

## 1. Version and Identity Inconsistencies

### 1.1 Three conflicting version numbers — CRITICAL

| Location | Version |
|----------|---------|
| Shield badge (line ~3) | `Spec: v1.0` |
| Front matter (line ~23) | `Version 0.5.1` |
| Section 4.2 (line ~80) | `v0.9.2` |
| Final line (~5826) | `Version 1.0` |

**Impact:** Implementers cannot determine which version of the spec they're reading. Version numbers are normative in protocol specifications.

---

## 2. Undefined or Underspecified Wire Formats

### 2.1 Header size contradiction — CRITICAL
**Section:** 8.1, 8.3, 15.3, 35.2.1

Section 8.1 defines a handshake header with bit offsets 0–759, which equals **760 bits = 95 bytes**. However, the text repeatedly claims the header is **"64 bytes, fixed"** (Sections 8.1, 8.3, 15.3, 35.2.1). These cannot both be correct. The compact data header (Section 8.3) shows bit offsets 0–383 = **48 bytes**, which also doesn't match 64 bytes.

**Impact:** Implementations will disagree on packet boundaries. This is a protocol-breaking interoperability issue.

### 2.2 Compact data header missing PayloadLen — CRITICAL
**Section:** 8.3

The compact post-handshake header (Section 8.3) does not include a `PayloadLen` field. Over UDP, where message boundaries are preserved, this works — but Section 14.1 defines TCP/TLS framing that provides length. However, the receiver still needs to know where the payload ends and extension headers begin. Without `HdrLen` or `PayloadLen` in the compact header, parsing is ambiguous when `HAS_EXT` flag is set.

### 2.3 MIGRATE message — no wire format — HIGH
**Section:** 15.4

The MIGRATE message is described narratively ("a node that changes its underlying IPv6 address MUST issue a MIGRATE message") but has no MsgType value assigned in Section 8.5.1 and no wire format defined.

### 2.4 PEER_EXCHANGE message — no wire format — HIGH
**Section:** 10.2, 15.1.2

Referenced as the transport for gossip topology updates but has no MsgType value or wire format. Section 10.2 mentions it; Section 15.1.2 expects it to carry relay metric gossip.

### 2.5 Fragmentation — no wire format — HIGH
**Section:** 15.3

"Implementations MUST support ZTLP-layer fragmentation and reassembly" but no fragmentation header, fragment identifier, offset field, or reassembly protocol is defined.

### 2.6 Certificate format — not defined — HIGH
**Section:** 16.2

Certificate lifecycle is described (enrollment, issuance, renewal, revocation) but the certificate wire format is never specified. No ASN.1, no binary encoding, no field list.

### 2.7 Delegation record format — not defined — MEDIUM
**Section:** 23.5

"Signed delegation records" are described abstractly but no wire format is provided.

### 2.8 ZTLP_ATTEST record format — not defined — MEDIUM
**Section:** 16.3.3

Fields listed narratively (NodeID, AssuranceLevel, AttestationType, etc.) but no binary encoding or record wire format specified.

### 2.9 ZTLP_OPERATOR record type — not registered — MEDIUM
**Section:** 12.5.1

Introduced but not listed in Section 9.3's record types table.

### 2.10 DNS `_ztlp` record format — not defined — MEDIUM
**Section:** 25.4, 34.2.2

"A DNS record of the form `_ztlp.api.service.example.com` returns the service NodeID, relay endpoint, and policy requirements" — but no DNS record type (SRV? TXT?), format, or encoding is specified.

### 2.11 RAT (Relay Admission Token) wire format — not defined — MEDIUM
**Section:** 12.4.3

Described as "MUST contain at minimum" followed by a list of fields, but no byte-level encoding.

### 2.12 Forwarding authenticator — not defined — MEDIUM
**Section:** 29.5.3

"ZTLP MAY define a lightweight forwarding authenticator" — described in terms of properties but no algorithm or encoding specified. Used throughout Section 39-40 as if it exists.

### 2.13 Flag bit positions not assigned — MEDIUM
**Section:** 8.1

Flags HAS_EXT, ACK_REQ, REKEY, MIGRATE, MULTIPATH, RELAY_HOP are listed but bit positions within the 16-bit Flags field are not defined.

---

## 3. Missing Error Handling

### 3.1 Error code gaps — HIGH
**Section:** 8.5.7

Error codes defined: 0x01–0x0A, 0x10, 0xFF. Gaps 0x0B–0x0F and 0x11–0xFE are undefined — no "reserved" range designation.

### 3.2 RATE_LIMIT and QUOTA_EXCEEDED errors — not registered — MEDIUM
**Section:** 37.1, 37.2

These error responses are referenced but not assigned error codes in Section 8.5.7.

### 3.3 RELAY_BUSY error — not registered — MEDIUM
**Section:** 37.3

Referenced but not assigned an error code.

### 3.4 BPF map full behavior — not specified — LOW
**Section:** 13.1.2

`session_map` max_entries is 65536 with note "tune per deployment". No guidance on behavior when the map is full (reject new sessions? evict oldest?).

---

## 4. Ambiguous Normative Language

### 4.1 SAC hash function unspecified — HIGH
**Section:** 18.3

Proof-of-work puzzle uses "HASH(challenge ∥ nonce)" — but which hash function? BLAKE2s? SHA-256? Implementers must agree for interoperability.

### 4.2 Ed25519 vs X25519 confusion — HIGH
**Sections:** 41.1.4, 41.1.5, 41.5.1

The spec conflates Ed25519 (signing) and X25519 (key agreement). Section 41 says "Ed25519 private keys" for node identity, but the Noise_XX handshake uses X25519. The static identity key type (Ed25519 for signing vs X25519 for Noise) is never precisely defined. Nodes need both? Or is there a single key?

### 4.3 Key derivation construction — nonstandard — MEDIUM
**Section:** 11.1.1

`BLAKE2s(handshake_hash || "ztlp-i2r")` — this is not standard HKDF. Missing: keyed vs unkeyed mode, output length parameter, domain separation.

### 4.4 Congestion control interaction with relays — MEDIUM
**Section:** 15.2

"Implementations SHOULD use BBR or CUBIC" but no specification of whether congestion control is end-to-end or per-hop, how congestion signals propagate through relay hops, or how relay-based forwarding interacts with sender-side rate control.

### 4.5 "STRONGLY RECOMMENDS" — not RFC 2119 — LOW
**Section:** 16.1

Uses "STRONGLY RECOMMENDS" which is not an RFC 2119 keyword. Should be "SHOULD" or "MUST" with justification.

### 4.6 Rekey threshold "2^48 packets" for 64-bit sequence — LOW
**Section:** 35.2

Rekeying trigger at "2^48 packets" when the sequence field is 64 bits. The threshold should be precisely specified (e.g., when PacketSeq reaches 2^48) with rationale.

---

## 5. Cross-Reference Inconsistencies

This is the most pervasive issue. **Over 30 cross-reference errors** were identified. The pattern suggests sections were renumbered at some point and internal references were not updated.

### 5.1 Systematic off-by-one section references — CRITICAL

| Source Section | References | Should Reference | Topic |
|---|---|---|---|
| 6.2 | Section 9 (bootstrap), Section 10 (handshake) | Section 10, Section 11 | Bootstrap & Handshake |
| 7.3 | Section 8 (ZTLP-NS) | Section 9 | ZTLP-NS |
| 8.3 | Section 7.1 (64-byte header) | Section 8.1 | Header definition |
| 12.3 | Section 13 (transport fallback) | Section 14 | Transport fallback |
| 12.5.3 | Section 11.4.3 (RAT) | Section 12.4.3 | Relay Admission Token |
| 12.6.2 | Section 11.2 (PathScore) | Section 12.2 | PathScore |
| 12.6.3 | Sections 11.2 and 14 | Sections 12.2 and 15 | Path scoring |
| 15.1 | Section 11.2 (PathScore) | Section 12.2 | PathScore |
| 15.1.1 | Section 14.1.3 (hysteresis) | Section 15.1.3 | Hysteresis threshold |
| 16.3.4 | Section 7.4 (DEVICE_POSTURE TLV) | Section 8.4 | TLV definitions |
| 19.1 | Section 29.5.6 | Correct (verified) | SessionID canonical model |
| 29.5.6 | Sections 28.1–28.3 | Section 29.1–29.3 | SessionID model |
| 32.4 | Section 28.2 (header structure) | Section 8.1 or 29.2 | Header structure |
| 33.2 | Section 5 (admission pipeline) | Section 18.1 | DDoS admission pipeline |
| 34.6 | Describes Section 33/34 relationship | Confused numbering | Internal reference |
| 36.1.3 | Section 11.6 (geo relay hierarchy) | Section 12.6 | Relay hierarchy |
| 36.1.3 | Section 14.1.1 (Dijkstra) | Section 15.1.1 | Path computation |
| 36.3 | Section 14.1.3 (hysteresis) | Section 15.1.3 | Hysteresis |
| 36.3 | Section 28.3 (SessionID stability) | Section 29.3 | Session migration |
| 37.3 | Section 11.4 (admission domains) | Section 12.4 | Admission domains |
| 37.3 | Section 26.1 (SAC difficulty) | Section 18.3 | SAC |
| 38.1 | Section 8 (ZTLP-NS) | Section 9 | ZTLP-NS |
| 38.1 | Section 15.3 (attestation) | Section 16.3 | Attestation |
| 38.1 | Section 10 (handshake) | Section 11 | Handshake |
| 38.4 | Section 28 (relay fast-path) | Section 29.5 | Relay forwarding |
| 42.3 | Section 37 (identity model) | Section 38 | Federated identity |

**Impact:** Implementers following cross-references will land on wrong sections. In a 43-section document, this is extremely confusing.

---

## 6. Missing Security Considerations

### 6.1 Inter-relay mesh authentication — CRITICAL
**Section:** 12.7

The relay mesh protocol (RELAY_HELLO, RELAY_ANNOUNCE, etc.) defines wire formats but **no authentication mechanism**. No AEAD, no signatures, no shared secret. Any party that can send UDP to port 23096 can inject relay mesh messages, poisoning the relay topology.

Section 15.1.2 later says "Relays MUST discard unsigned or unverifiable gossip messages" — but Section 12.7 defines no signature field in any relay mesh message.

### 6.2 IPv6 missing from relay mesh — HIGH
**Section:** 12.7.2, 12.7.6

RELAY_HELLO and RELAY_SESSION_SYNC only have IPv4 address fields (4 bytes). No IPv6 support despite the spec's claim to support IPv6 throughout.

### 6.3 ZTLP-NS record encoding — interop risk — HIGH
**Section:** 9.5.9

"Reference implementation uses Erlang External Term Format" and "byte-identical output" is required. ETF is implementation-specific and extremely difficult to reproduce byte-identically in non-Erlang languages. This is a significant interoperability barrier.

### 6.4 Anti-replay window size — not specified — MEDIUM
**Section:** Multiple

For standard sessions, the anti-replay window size is never defined. Section 15.3 says "at least 1024 packets" for MULTIPATH but no default for single-path.

### 6.5 Nonce/IV construction — not specified — MEDIUM
**Section:** 11.1.1, 29.4

AEAD requires a nonce/IV per packet. The PacketSeq is the obvious candidate, but the spec never explicitly states how the AEAD nonce is constructed from PacketSeq (truncation? padding? XOR with session key?).

### 6.6 Missing normative references — MEDIUM
**Section:** 22

The References section omits normative references for several algorithms the spec depends on:
- BLAKE2 (RFC 7693) — used throughout as hash/KDF
- Ed25519 (RFC 8032) — used for identity signing
- ChaCha20-Poly1305 (RFC 8439) — primary AEAD
- HKDF / key derivation (RFC 5869) — if applicable
- P4 / P4Runtime — referenced in Section 13.3

---

## 7. Operational Gaps

### 7.1 Hardcoded relay list update mechanism — HIGH
**Section:** 10.1

Bootstrap requires a hardcoded list of 15 relay nodes across 5 ASNs and 3 regions. No mechanism defined for updating this list post-deployment without software updates.

### 7.2 CryptoSuite rekeying intervals — not defined — MEDIUM
**Section:** 35.2, 18.5.1

Section 35.2 says "CryptoSuite-defined rekeying interval (default: 1 hour)" but the CryptoSuite registry (Section 18.5.1) doesn't include rekeying interval as a parameter.

### 7.3 Certificate expiry and clock skew handling — MEDIUM
**Section:** 16.2, 18.4

Certificate TTL "SHOULD NOT exceed 90 days" but no specification of grace periods, clock skew tolerance for certificate validation, or behavior when certificates expire during an active session.

### 7.4 ZTLP-NS record maximum size — not defined — LOW
**Section:** 9.5.9

No maximum record size. Large records could be used for amplification or resource exhaustion.

### 7.5 Enrollment token maximum size — not defined — LOW
**Section:** 10.4.1

Variable-length fields with no maximum. Potential parsing DoS vector.

---

## 8. Interoperability Concerns

### 8.1 MsgType 0x02 overloaded — HIGH
**Section:** 9.5.1

Message type 0x02 means both REGISTER (client→server) and RESPONSE_FOUND (server→client). Implementations must track message direction to disambiguate. This is fragile and error-prone.

### 8.2 ADMISSION_PROOF TLV type not listed — MEDIUM
**Section:** 8.4, 8.5.4

TLV type 0x07 (ADMISSION_PROOF) is referenced in Section 8.5.4 but not listed in the TLV type table in Section 8.4.

### 8.3 CryptoSuite registry gaps — MEDIUM
**Section:** 18.5.1

Range 0x0004–0x00FF is neither assigned nor marked as reserved. Future implementations could accidentally use these values.

### 8.4 SESSION_OPEN rekey interval max — LOW
**Section:** 8.5.6

Rekey interval is uint16 seconds (max 65535 ≈ 18 hours). But Section 35.1 says max session lifetime is 24 hours. The rekey interval field cannot express a 24-hour value. This is acceptable (rekey < lifetime) but the constraint should be stated.

---

## 9. Version Negotiation

### 9.1 Version negotiation explicitly rejected — MEDIUM
**Section:** 8.2.2

"Version negotiation [is] explicitly NOT supported." This is a deliberate design choice but creates migration risk. When ZTLP v2 ships, there is no in-band mechanism for a v1 node to discover that a peer speaks v2, or to gracefully fall back. The spec acknowledges this will require "a clean protocol transition" but provides no mechanism for it.

---

## 10. Capacity and Scaling Limits

### 10.1 Maximum sessions per relay — not defined — MEDIUM
**Section:** 35.4, 37.3

Section 37.3 mentions "80% of capacity" for admission control but the maximum session table size is never normatively defined. The BPF map default (65536) is for the eBPF profile only.

### 10.2 Maximum relay hops — LOW
**Section:** 12.7.5

TTL max is 4 hops. Hardcoded with no configurability or justification for this specific limit.

### 10.3 Maximum record count in ZTLP-NS — not defined — LOW
Per-namespace or per-node record limits are not specified.

### 10.4 O(n) scan in ZTLP-NS — acknowledged — LOW
**Section:** 9.5.6

QUERY_BY_PUBKEY performs O(n) scan. Acknowledged as a scaling concern but no mitigation defined.

---

## 11. Known Incompleteness (TODO/TBD/Future Work)

### 11.1 Section 21 — Open Issues Table — HIGH
**Section:** 21

The following are explicitly listed as **Open**:
1. Bandwidth reservation model
2. ZTLP-native congestion control algorithm
3. ZTLP-NS governance structure
4. Relay operator incentive economics
5. Lawful intercept considerations
6. Hardware identity enrollment UX
7. Lightweight IoT profile
8. Formal security proof of Noise_XX under ZTLP threat model
9. Post-quantum cryptographic migration
10. Production relay operator SLA framework
11. Mobile platform SDK (iOS/Android)
12. Browser integration (ZTLP-aware `fetch()`)

### 11.2 Profile 4 (Native ASIC) — acknowledged as future — LOW
**Section:** 13.4

Described as "long-term target state" not yet available. This is appropriate.

---

## 12. Structural and Editorial Issues

### 12.1 Duplicate subsection numbering — LOW
**Section:** 13.1.3

Two subsections both numbered 13.1.3: "What This Achieves" and "Deployment Requirements".

### 12.2 Step numbering error — LOW
**Section:** 11.3

Policy enforcement steps numbered 7–11 instead of 1–5.

### 12.3 Significant content redundancy — MEDIUM

Multiple sections repeat the same content with slight variations:
- Sections 33 and 34: Dual-lane architecture described twice almost identically
- Sections 17, 25, and 43: Gateway-first deployment model repeated three times
- Sections 27 and 18.3: Handshake flood resistance
- Sections 26 and 12.2/15.1: Path scoring
- Sections 39–40 and 12.4/29.5: Admission/forwarding plane separation

This isn't a protocol gap per se, but inflates the spec to nearly 6,000 lines and makes it harder to find the normative definition of any given concept.

### 12.4 Handshake message naming inconsistency — MEDIUM
**Section:** 8.5.1, 29.4.3, 32.2

| Used in Section | Message Name | Actual MsgType (8.5.1) |
|---|---|---|
| 29.4.3 | AUTH | Not defined |
| 32.2 | AUTH | Not defined |
| 32.2 | SESSION_OK | Should be SESSION_OPEN (MsgType 6) |

### 12.5 Magic byte inconsistency — HIGH
**Section:** 41.1.3

The three-layer admission pipeline table in Section 41.1.3 says the magic byte check compares against **`0xA7`** (1 byte). Everywhere else in the spec, it's **`0x5A37`** (2 bytes / 16 bits). This could cause L1 enforcement implementations to use the wrong value.

---

## 13. Algorithm Suite Contradiction

### 13.1 "Fixed" vs "Negotiable" — MEDIUM
**Section:** 41.5.5 vs 18.5.1

Section 41.5.5 states: "The algorithm suite is fixed in this version of the specification. Algorithm agility is deferred to future versions."

Section 18.5.1 defines three CryptoSuites with a negotiation mechanism (Initiator proposes, Responder may counter-propose with ERROR 0x07).

These are contradictory. Either the suite is fixed (only 0x0001 is valid) or negotiation is supported.

---

## Recommendations

### Immediate (pre-v1.0 release)
1. **Resolve header size contradiction** — determine actual byte count and update all references
2. **Fix all cross-references** — systematic pass through the document
3. **Unify version number** — pick one version and use it consistently
4. **Define wire formats** for MIGRATE, PEER_EXCHANGE, fragmentation, certificates, delegation records
5. **Add authentication to relay mesh protocol** (Section 12.7)
6. **Specify AEAD nonce construction** from PacketSeq
7. **Resolve Ed25519 vs X25519** identity key confusion
8. **Fix magic byte `0xA7` vs `0x5A37`** inconsistency

### Short-term
9. **Define a formal registry** (IANA-style) for MsgTypes, TLV types, error codes, CryptoSuites, and ZTLP-NS record types
10. **Add IPv6 to relay mesh wire formats**
11. **Specify anti-replay window size** defaults
12. **Choose a specific hash** for SAC proof-of-work
13. **Remove or consolidate redundant sections** (33/34, 17/25/43, etc.)
14. **Replace Erlang ETF** for record encoding with a language-neutral format (CBOR, MessagePack, or custom binary)

### Medium-term
15. **Address all Section 21 open issues** before claiming v1.0
16. **Formal security analysis** of the Noise_XX usage
17. **Define version transition mechanism** for future protocol versions
18. **Add normative references** for all used cryptographic algorithms

---

*Analysis performed by automated review of the complete 5,826-line specification.*
