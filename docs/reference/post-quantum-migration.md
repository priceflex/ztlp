# Post-Quantum Migration for ZTLP

**Status: plan. None of the post-quantum work described here is implemented.**
Revised 2026-11-28. The earlier version of this document (2026-03-11) described
suite negotiation, a minimum-suite setting and a suite field on name-server
records as implemented, and quoted benchmark figures. Those statements were
wrong and have been removed. Work is tracked in
[issue #146](https://github.com/priceflex/ztlp/issues/146).

---

## 1. What ZTLP uses today

| Part | Algorithm | Where |
|------|-----------|-------|
| Tunnel handshake | `Noise_XX_25519_ChaChaPoly_BLAKE2s`, hard-coded | `proto/src/handshake.rs` |
| Tunnel data | ChaCha20-Poly1305 | same |
| Device identity and name-server record signatures | Ed25519 | `ns/lib/ztlp_ns/record.ex`, `enrollment.ex` |
| QUIC outer layer | TLS 1.3 (rustls) | `proto/src/quic_transport.rs` |
| Local browser certificates | ECDSA P-256 | `proto/src/agent/cert_mint.rs` |
| Name-server certificate authority | RSA-4096 by default, Ed25519 optional | `ns/lib/ztlp_ns/cert_authority.ex` |

What exists toward agility, and what does not:

- The original ZTLP packet header has a 16-bit `CryptoSuite` field
  (`proto/src/packet.rs`). It is always `0x0001`. No code negotiates it.
- The QUIC transport, which agents use today, does not carry a suite
  identifier. Stream 0 starts with one magic byte and then the Noise handshake.
- KEY records carry `"algorithm": "Ed25519"` as a label. Nothing branches on it.
- `proto/src/pqkem.rs` defines a `Kem` trait and a hybrid combiner. Its ML-KEM
  half is a placeholder that returns random bytes, and nothing outside the
  module uses it. It provides no security and must not be wired in as it is.
- There is no `min_crypto_suite` setting and no `crypto_suite` field on
  name-server records.

All public-key algorithms in use (X25519, Ed25519, P-256) are elliptic-curve.
RSA appears only as the certificate-authority default.

## 2. The threat

A large enough quantum computer running Shor's algorithm breaks every
public-key algorithm in section 1: X25519, Ed25519, ECDSA and RSA.

- **Recorded traffic.** The ephemeral X25519 public keys of a handshake travel
  in the clear. Someone who records a session today can recover its keys once
  such a computer exists. Forward secrecy does not help here: it protects past
  sessions from a later theft of long-term keys, not from a break of the key
  exchange itself. This is the "harvest now, decrypt later" risk, and it is
  the reason key exchange comes first.
- **Signatures.** A signature can only be forged while it is being relied on.
  Identities and records need post-quantum signatures before such a computer
  exists, not years ahead of it.
- **Symmetric primitives.** ChaCha20-Poly1305 with a 256-bit key and BLAKE2s
  are not affected in any practical way. Grover's algorithm halves the
  effective key length at most, leaving about 128 bits.

No one can say when such a computer will exist. A second reason to be able to
change algorithms is classical: advances in factoring and discrete-logarithm
algorithms, including AI-assisted work in 2026. Nothing published threatens
the algorithms in section 1, and none of that work concerns elliptic curves,
but it argues for the ability to replace an algorithm without upgrading every
device at once.

## 3. Target algorithms

Sizes are from the NIST standards, published August 2024.

| Algorithm | Standard | NIST category | Public key | Ciphertext or signature |
|-----------|----------|---------------|-----------:|------------------------:|
| ML-KEM-768 | FIPS 203 | 3 | 1,184 B | 1,088 B |
| ML-KEM-1024 | FIPS 203 | 5 | 1,568 B | 1,568 B |
| ML-DSA-65 | FIPS 204 | 3 | 1,952 B | 3,309 B |
| ML-DSA-87 | FIPS 204 | 5 | 2,592 B | 4,627 B |
| SLH-DSA-SHA2-128s | FIPS 205 | 1 | 32 B | 7,856 B |

ML-KEM and ML-DSA rest on lattice problems. SLH-DSA rests on hash functions
only, which makes it a candidate for the few long-lived keys (the zone
authority) where signature size matters less than independence from lattices.

Parameter choice (768 or 1024, 65 or 87) is open. NSA's CNSA 2.0 suite, which
applies to US national security systems, specifies ML-KEM-1024 and ML-DSA-87.

No performance figures are given here. They will be measured on the
implementation, on the platforms ZTLP ships for, including the iOS extension.

## 4. Plan

In order. Each step is useful without the next.

### 4.1 Negotiable suites

A suite is a fixed, named set of algorithms. Peers negotiate a whole suite,
never individual algorithms.

| Suite | Key exchange | Signatures | Status |
|-------|--------------|------------|--------|
| 1 | X25519 | Ed25519 | in use (implicit) |
| 2 | X25519 + ML-KEM | Ed25519 | planned |
| 3 | X25519 + ML-KEM | Ed25519 + ML-DSA | planned |

Requirements:

- The suite identifier is carried in the first handshake message on every
  transport and is covered by the handshake transcript, so a downgrade fails
  the handshake.
- The responder picks the best suite both sides support. An operator setting
  gives the minimum acceptable suite; the default stays suite 1 until a fleet
  is ready.
- A peer that sends no identifier is treated as suite 1, so existing devices
  keep working.
- Name-server records state which signature suite signed them, and verifiers
  act on it.
- An operator can see which suite each device last used.

### 4.2 Hybrid key exchange (suite 2)

Combine X25519 with ML-KEM so the session key holds if either holds.

Open design choices:

- **Construction.** Either a Noise pattern extended with a KEM (the Noise
  hybrid-forward-secrecy extension or the PQNoise patterns) or a specified
  hybrid KEM such as X-Wing (X25519 with ML-KEM-768). Prefer a published,
  analysed construction over a new one. The combiner in `pqkem.rs` has had no
  review.
- **Implementation.** A maintained ML-KEM library that builds for Linux,
  Windows, macOS and iOS, and one usable from the Elixir components.
- **Size.** The first two handshake messages each grow by roughly 1.1 to
  1.6 KB. The effect on the first QUIC flight, on relayed connections and on
  the original packet format has to be measured.

The QUIC outer layer can separately use the hybrid TLS group
`X25519MLKEM768` where the TLS library supports it.

### 4.3 Hybrid signatures (suite 3)

Sign device identities and name-server records with Ed25519 and ML-DSA; a
verifier on suite 3 requires both.

Known problems to solve:

- A record grows by several kilobytes. The name server's default packet limit
  is 8,192 bytes and unauthenticated replies are capped relative to the
  request size, so record transport needs rework before this can ship.
- It touches enrollment, every stored record, the admin panel and the
  gateways' identity checks.
- Whether a device holds two keys or one composite key during migration.

### 4.4 Retiring suite 1

Only after suites 2 and 3 have run in production and every supported client
can use them. No date is set.

### 4.5 Independent of the above

Change the name-server certificate authority default from RSA-4096 to
Ed25519 or ECDSA P-256.

## 5. Effect on each component

| Component | Suite negotiation | Hybrid key exchange | Hybrid signatures |
|-----------|-------------------|---------------------|-------------------|
| Agent and CLI (`proto/`) | yes | yes | yes |
| Rust and Elixir gateways | yes | yes | verify |
| Name server (`ns/`) | record suite field | no | sign, verify, store, larger packets |
| Relay (`relay/`) | none expected; it forwards handshakes without reading them (to confirm) | none expected | verify, if relay authorization moves to device signatures |
| Admin panel (`admin/`) | show suite per device, set minimum | no | verify |
| eBPF filter (`ebpf/`) | none | none | none |

The cryptographic code is currently written separately in Rust, Elixir and
Ruby. Adding suites three times over is a cost and a risk; sharing one
implementation is part of the design question.

## 6. What comparable protocols do

- **TLS 1.3:** the hybrid group `X25519MLKEM768` is deployed by major browsers
  and content networks.
- **OpenSSH:** hybrid key exchange has been the default since 9.0
  (`sntrup761x25519-sha512`); `mlkem768x25519-sha256` was added in 9.9.
- **Signal:** PQXDH adds a Kyber key encapsulation to its X25519 key
  agreement.
- **WireGuard:** no post-quantum key exchange in the protocol. An optional
  pre-shared key gives protection if it is distributed safely; separate
  projects such as Rosenpass supply one.

All of these chose hybrid key exchange first and left signatures for later,
which is the order proposed here.

## 7. References

1. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024.
2. NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard*, August 2024.
3. NIST FIPS 205, *Stateless Hash-Based Digital Signature Standard*, August 2024.
4. NSA, *Commercial National Security Algorithm Suite 2.0*.
5. The Noise Protocol Framework, https://noiseprotocol.org/
6. Angel, Dowling, Hülsing, Schwabe, Weber, *Post Quantum Noise*, ACM CCS 2022.
7. *X-Wing: general-purpose hybrid post-quantum KEM*, IETF CFRG draft.
8. Signal, *The PQXDH Key Agreement Protocol*.
