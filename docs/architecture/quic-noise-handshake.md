# QUIC + Noise_XX Handshake — Architecture Design

> **Status:** Production-ready (0.35.x). Phases 0–2 landed and the data
> pump throughput bug (large-transfer truncation ≥512 KB) is fixed and
> proven byte-exact over loopback (≈350 MB/s) and the live multi-hop AWS
> tunnel (256 KB–5 MB all PASS). The legacy raw-UDP path is DEPRECATED
> (warns at connect time, removed in 0.36).
> **Owner:** Steve Price.
> **Tracking:** `feature/quinn-noise-handshake`, handoff `hermes_session_handoff.md` §3 Task A.

---

## 1. Why This Document Exists

ZTLP's current `main` branch ships a hand-rolled UDP reliability and
flow-control stack (`mux.rs`, `send_controller.rs`, `congestion.rs`,
`recv_window.rs`, `pacing.rs`, `pmtu.rs`, `gso.rs`, `gro_batch.rs`,
`session_health.rs`). After the partial "nebula-pivot" demolition
(commits `531d69f`, `3b88c62`, `b7b468e`), this stack deadlocks at
roughly **10,657 bytes** — the size of the initial congestion window —
because the credit-return loop is no longer wired. The user-visible
symptom is `turbo.min.js` (105 KB) hanging mid-load.

Rather than continue to reinvent TCP-like reliability over UDP, we are
pivoting to **QUIC** for transport and keeping **Noise_XX** for
identity. This document specifies how the two interlock.

## 2. Goals & Non-Goals

**Goals**

- Replace `mux`/`send_controller`/`congestion`/`pacing`/`recv_window`
  with QUIC streams + QUIC's built-in flow control & congestion control.
- Preserve **Ed25519** node identity and **per-zone HMAC** tenant
  isolation. Cross-tenant hijack must remain cryptographically
  impossible on shared relay infrastructure.
- Fit the iOS Network Extension build (`ios-sync` feature) inside
  Apple's **15 MB** RAM ceiling.
- Support multi-stream loads (browser parallel asset fetch, SSH +
  HTTP simultaneously) without head-of-line blocking.

**Non-Goals (this document)**

- Connection migration / WiFi↔Cellular roaming. (Future; QUIC supports
  it natively but we wire it up later.)
- 0-RTT resumption. (Future; deferred until handshake is stable.)
- TCP Brutal-style congestion control. (Future; QUIC's `congestion`
  trait lets us swap algorithms without touching anything else.)

## 3. Stack Decomposition

```
┌─────────────────────────────────────────────────────────┐
│ Application: ztlp connect / iOS NE / Gateway forwarder  │
├─────────────────────────────────────────────────────────┤
│ Noise_XX_25519_ChaChaPoly_BLAKE2s                       │  ← identity layer (KEPT)
│   - 3-message handshake over QUIC stream 0              │
│   - Ed25519 static keys + HMAC zone secret              │
├─────────────────────────────────────────────────────────┤
│ QUIC streams (multiplexing, flow control, reliability)  │  ← replaces mux + send_controller
│   - Stream 0 : control + Noise handshake bytes          │
│   - Stream N : per-tunnel-stream payload (bidi)         │
├─────────────────────────────────────────────────────────┤
│ QUIC packetization (quinn on srv, quinn-proto on iOS)   │  ← replaces pacing + gso/gro
├─────────────────────────────────────────────────────────┤
│ TLS 1.3 (rustls) — vestigial, MUST-have for QUIC RFC    │  ← see §5 for why we still tunnel Noise
├─────────────────────────────────────────────────────────┤
│ UDP                                                     │
└─────────────────────────────────────────────────────────┘
```

## 4. Handshake Sequence (Bytes On Wire)

```
Initiator (client)                              Responder (gateway)
        │                                                │
        │ ──── UDP / QUIC Initial (ALPN="ztlp/1") ────▶ │
        │                                                │
        │           TLS 1.3 handshake (rustls)           │
        │ ◀───────── (QUIC connection up) ──────────── ▶ │
        │                                                │
        │ ─── open bidi stream 0 ───▶                    │
        │                                                │
        │ ─── send Noise msg1 (HELLO) ─────────────────▶ │
        │        [u8;32] e   (ephemeral pubkey)          │
        │        [u8;16] zone_hmac_tag                   │  ← prevents cross-zone replay
        │                                                │
        │ ◀── recv Noise msg2 (HELLO_ACK) ───────────── ─ │
        │        [u8;32] e                                │
        │        [u8;32+16] enc(s)                        │
        │        [u8;N+16] enc(payload: server identity)  │
        │                                                │
        │ ─── send Noise msg3 (final) ────────────────▶  │
        │        [u8;32+16] enc(s)                        │
        │        [u8;M+16] enc(payload: client identity   │
        │                 + cap token + zone_id)          │
        │                                                │
        │ ◀═══ TransportState established ═══════════ ═ │
        │                                                │
        │ ─── open stream N (per-tunnel-stream) ──▶     │
        │ ◀══════ app data, both directions ══════════▶ │
```

### Frame format on stream 0

Length-prefixed:

```
+--------+----------+----------------+
| 0xZ1   | u16 len  | Noise payload  |
+--------+----------+----------------+
```

`0xZ1` = magic byte (`Z` = ZTLP, `1` = handshake version 1). Reserves
`0xZ2..0xZF` for future control messages on stream 0 (rekey, keepalive,
graceful shutdown advertising the next QUIC connection ID).

## 5. Why Tunnel Noise Inside QUIC at All?

QUIC normally authenticates the peer via TLS 1.3 (`rustls` certificate
chain). We deliberately do **not** rely on that for ZTLP identity:

1. **Ed25519 is the tenant root.** Every ZTLP node is identified by an
   Ed25519 public key issued at enrollment. Replacing that with X.509
   would require re-tooling the NS, bootstrap server, claim flow, and
   every CLI — and weaken multi-tenant guarantees because we'd inherit
   webPKI's "any CA can mint any name" failure mode.
2. **Per-zone HMAC tag** in Noise msg1 prevents a leaked Ed25519 key in
   zone A from establishing a session in zone B. TLS has no equivalent.
3. **Pluggability.** Today Noise_XX. Tomorrow a post-quantum KEM (the
   crate already has `pqkem.rs`). Decoupling identity from transport
   lets us upgrade either independently.

The `rustls` TLS handshake is treated as a **transport-bound MAC** —
present because QUIC needs it, but the trust root is Noise. We pin the
TLS leaf cert fingerprint inside the Noise prologue so a MITM swapping
the rustls cert cannot succeed.

## 6. Stream Multiplexing Strategy

| Stream class | Direction | Purpose                                  |
|--------------|-----------|------------------------------------------|
| 0            | bidi      | Control: Noise handshake, rekey, ping    |
| 1..N (even)  | bidi      | Initiator-opened tunnel streams          |
| 1..N (odd)   | bidi      | Responder-opened tunnel streams          |

QUIC stream IDs already encode direction (`stream_id & 0b11`); we let
quinn assign them. Per-stream flow control is handled by QUIC's
`MAX_STREAM_DATA` frames — we no longer touch credit accounting.

## 7. iOS Sans-Io Constraints

The `libztlp_proto_ne.a` archive (`--no-default-features --features
ios-sync`) MUST stay under ~25 MB on disk and under 15 MB resident.
`quinn-proto` provides a sans-io state machine; the NE owns its own
`UdpSocket`s and feeds bytes in/out manually. **No `tokio` runtime, no
`quinn::Endpoint`** in the NE build — only the proto crate.

The `quic-transport` cargo feature must work in two configurations:

- `--features quic-transport,tokio-runtime` → quinn (preferred on
  servers and macOS).
- `--features quic-transport,ios-sync`      → quinn-proto only.

The `quic_transport` module gates by `#[cfg(feature = "tokio-runtime")]`
for the `Endpoint` type and exposes the bare proto state machine
unconditionally.

## 8. Migration Plan

| Phase | Deliverable                                              | Status      |
|-------|----------------------------------------------------------|-------------|
| 0     | Design doc + feature-gated scaffold + failing tests      | ✅ done     |
| 1     | quinn endpoint wired to Gateway (client + server)        | ✅ done     |
| 2     | Noise frames carried on QUIC stream 0; default path      | ✅ done     |
| 2.1   | **Data-pump throughput fix** — independent-direction drain, no per-chunk `println!`, quinn flow-control tuning (4 MiB stream window) | ✅ done (0.35.x) |
| 3     | Strip `send_controller`/`congestion`/`pacing` (legacy UDP) | DEPRECATED (kept compiling; removed in 0.36) |
| 4     | iOS NE path on `quinn-proto`                             | not started |
| 5     | Benchmark: ≥1 MiB byte-exact + ≥8 parallel streams      | ✅ done (`tests/quic_throughput_test.rs`) |
| 6     | Production rollout + version bump to **0.35.x** + tag    | in progress |

**0.35.x throughput proof** (post data-pump fix):

| Transport | Result |
|-----------|--------|
| Loopback Rust test (`one_mib_single_stream_is_byte_exact`) | ✅ 1 MiB byte-exact, ≈350 MB/s |
| Loopback Rust test (`eight_parallel_streams_distinct_payloads_no_hol`) | ✅ 8×105 KB byte-exact, no HOL |
| Live multi-hop AWS tunnel (client→relay1→relay2→gateway→backend) | ✅ 256 KB / 512 KB / 1 MiB / 2 MiB / 5 MiB all byte-exact (md5-verified), 1.5–3.4 MB/s (AWS network ceiling, not pump-bound) |

The 0.35.x release happens **after phase 6**. Anything before that
ships under point releases.

## 9. Open Questions

- **TLS cert provisioning.** Self-signed per-connection (rustls
  ephemeral) or per-node leaf cert pinned at enrollment time? Leaning
  ephemeral + Noise-prologue fingerprint pin.
- **ALPN string.** Proposing `ztlp/1`. Bikeshed welcome.
- **MTU / GSO.** quinn auto-handles, but we lose the explicit
  per-socket GSO tuning currently in `gso.rs`. Validate at phase 5.

## 10. Testing & Validation

Phase 0 (this PR) lands:

- `proto/tests/quic_transport_test.rs` — three TDD tests that compile
  but fail intentionally pending implementation:
  1. `multi_stream_loopback_roundtrip` — 8 parallel streams carry
     distinct payloads end-to-end with no head-of-line blocking.
  2. `noise_handshake_over_quic_stream_zero` — msg1/msg2/msg3 ride
     stream 0 and yield a `TransportState` on both sides.
  3. `sans_io_path_compiles_without_tokio` — compiled in the
     `ios-sync` configuration; fails CI if anyone pulls `tokio` into
     a NE code path.

Each test asserts `unimplemented!()` for now and is annotated
`#[ignore = "phase-0 scaffold; implementation lands in phase 1+"]` so
CI stays green. Removing the `ignore` is the first signal that an
implementer is starting a phase.

Later phases add a `bench/quic_multistream.rs` Criterion bench that
loads 105 KB through ≥8 parallel streams and asserts throughput
floor and tail-latency ceiling.
