# ZTLP Specification Gap Analysis

**Document analyzed:** `ztlp/README.md` (~6,093 lines)
**Initial analysis date:** 2026-03-12
**Resolution date:** 2026-03-12
**Status:** ✅ ALL 58 GAPS RESOLVED

---

## Executive Summary

A thorough gap analysis of the ZTLP v0.5.1 specification identified 58 issues across 13 categories. All issues were resolved in a single session across 4 commits (`48f2c5f`, `306fb20`, `3163b10`, plus the analysis itself).

**Finding counts by severity:**

| Severity | Found | Fixed | Status |
|----------|-------|-------|--------|
| CRITICAL | 7 | 7 | ✅ Complete |
| HIGH | 19 | 19 | ✅ Complete |
| MEDIUM | 22 | 22 | ✅ Complete |
| LOW | 10 | 10 | ✅ Complete |
| **Total** | **58** | **58** | **✅ All resolved** |

---

## Resolution Summary

### Commit 1: `48f2c5f` — Mechanical Fixes (37 items)
- Unified version numbers to v0.5.1 (was v1.0, v0.9.2 in places)
- Fixed 30+ broken cross-references (systematic off-by-one from renumbering)
- Fixed magic byte `0xA7` → `0x5A37` in Section 41.1.3
- Added ADMISSION_PROOF (0x07) to TLV type table
- Fixed duplicate Section 13.1.3 numbering → 13.1.4
- Fixed step numbering in Section 11.3 (7-11 → 1-5)

### Commit 2: `306fb20` — CRITICAL and HIGH Fixes (15 items)
- Header size corrected: 64→96 bytes with reserved padding byte
- Inter-relay mesh authentication: Ed25519 signatures on all mesh messages
- All mesh subsection offsets updated (12.7.2-12.7.8)
- Flag bit positions defined (Section 8.2.3)
- AEAD nonce construction specified (Section 11.1.1)
- MIGRATE wire format added (MsgType 8, Section 8.5.9)
- Fragmentation TLV (0x08) and Section 15.3.1 added
- Ed25519 vs X25519 dual-key model documented
- IPv6 support added to relay mesh
- Erlang ETF replaced with mandatory sorted-key CBOR (RFC 8949)
- Anti-replay window default: 256 packets for single-path sessions
- CryptoSuite contradiction resolved (0x0001 mandatory in v1)
- Error codes RATE_LIMITED (0x0B) and QUOTA_EXCEEDED (0x0C) added
- Normative references added (RFC 7693, 8032, 8439, 8949)
- MTU calculation updated for 96-byte header

### Commit 3: `3163b10` — MEDIUM and LOW Fixes (26 items)

**Wire formats:**
- Compact data header: ExtLen + PayloadLen fields added
- PEER_EXCHANGE: RELAY_PEER_EXCHANGE (0x0A) with full wire format
- NS MsgType 0x02 overload resolved: REGISTER moved to 0x09
- Certificate wire format (Section 16.2.1): CBOR structure + signing
- RAT binary encoding: 88-byte format with HMAC-BLAKE2s MAC
- DNS `_ztlp` TXT record format defined
- Bootstrap relay list DNS fallback with DNSSEC

**Security & interop:**
- SAC hash specified as BLAKE2s-256
- Forwarding authenticator: truncated HMAC-BLAKE2s
- RELAY_BUSY (0x0D) error code added
- CryptoSuite registry ranges documented

**Record types:**
- ZTLP_OPERATOR registered (type byte 7)
- ZTLP_ATTEST CBOR format defined
- Delegation record CBOR fields specified

**Operational:**
- Key derivation: BLAKE2s unkeyed mode clarified
- Congestion control: end-to-end scope defined
- Certificate clock skew: 5-minute tolerance
- CryptoSuite rekeying intervals: 3,600s
- Max sessions per relay: configurable, default 65,536
- BPF map full behavior: RELAY_BUSY, no silent eviction
- NS record max 4,096 bytes, enrollment token max 512 bytes

**Editorial:**
- STRONGLY RECOMMENDS → SHOULD (RFC 2119)
- Rekey threshold 2^48 rationale
- SESSION_OPEN rekey interval constraint
- AUTH/SESSION_OK → HELLO Message 3/SESSION_OPEN

---

## Remaining Notes

### Content Redundancy (not a gap — structural choice)
The following sections cover overlapping material:
- Sections 33 and 34: Dual-lane architecture
- Sections 17, 25, and 43: Gateway-first deployment
- Sections 27 and 18.3: Handshake flood resistance
- Sections 26 and 12.2/15.1: Path scoring
- Sections 39–40 and 12.4/29.5: Admission/forwarding plane separation

These are deliberately left as-is — they serve as standalone reading entry points for different audiences (implementers vs. operators vs. architects). A future consolidation pass could reduce the spec from ~6,000 lines to ~4,500 by merging duplicates, but this is an editorial preference, not a protocol gap.

### Section 21 — Open Issues
12 items remain explicitly listed as open/future work in Section 21. These are acknowledged research and engineering topics (bandwidth reservation, post-quantum migration, IoT profile, etc.) and are appropriate for an experimental specification.

---

*Analysis performed and resolved 2026-03-12.*
