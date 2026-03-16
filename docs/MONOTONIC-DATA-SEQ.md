# Monotonic Data Sequence Numbers (v1.0)

**Status:** Deferred — requires wire format break  
**Target:** v1.0  
**Inspired by:** QUIC packet numbers (RFC 9000 §12.3)

## Problem

ZTLP currently reuses the same `data_seq` when retransmitting a packet. This creates **retransmission ambiguity**: when an ACK arrives, the sender can't tell if it's acknowledging the original transmission or the retransmit. Karn's algorithm (RFC 6298 §2) works around this by skipping RTT samples from retransmitted packets, but that means RTT estimation degrades during loss recovery — exactly when you need it most.

## Solution

Assign every packet a **new, monotonically increasing `data_seq`** — even retransmissions. The receiver reassembles based on **byte offsets** carried in each packet, not sequence numbers.

### Wire Format Changes

Current DATA frame:
```
[0x00 | data_seq: u64 BE | payload]
```

Proposed DATA frame:
```
[0x00 | packet_seq: u64 BE | byte_offset: u64 BE | payload_len: u16 BE | payload]
```

- `packet_seq` — monotonic, never reused, even for retransmits
- `byte_offset` — position in the byte stream (replaces data_seq for reassembly)
- `payload_len` — explicit length (enables variable-size packets)

### ACK Format Changes

Current ACK:
```
[0x01 | acked_data_seq: u64 BE]
```

Proposed ACK:
```
[0x01 | acked_packet_seq: u64 BE | acked_byte_offset: u64 BE]
```

### NACK/SACK Changes

NACK and SACK must reference **byte ranges** instead of sequence numbers:
- NACK: "I'm missing bytes X through Y"
- SACK: "I have received byte ranges [A-B, C-D, ...]"

### Reassembly Buffer Changes

Current: `HashMap<u64, Vec<u8>>` keyed by `data_seq`  
Proposed: Interval-based reassembly tracking byte ranges (similar to TCP)

```rust
struct ReassemblyBuffer {
    /// Next expected byte offset
    next_byte: u64,
    /// Out-of-order segments: (byte_offset, data)
    segments: BTreeMap<u64, Vec<u8>>,
    /// Total bytes buffered out-of-order
    buffered_bytes: usize,
}
```

### RTT Estimation

With monotonic packet_seq, **every ACK provides an unambiguous RTT sample** — no need for Karn's filtering. The sender knows exactly which transmission the ACK refers to.

This also makes the dedicated RTT probes (FRAME_RTT_PING/PONG, added in v0.9.4) redundant for RTT measurement, though they remain useful as keepalive/liveness probes.

## Benefits

1. **Unambiguous RTT** — every ACK is a valid RTT sample
2. **Better loss detection** — can distinguish "packet lost" from "packet reordered" instantly
3. **Simpler CC** — no need for `was_retransmitted` flag, Karn's filtering, or Eifel detection
4. **QUIC compatibility** — aligns with the industry standard approach

## Migration / Backward Compatibility

This is a **protocol-breaking change**. Options:

1. **Version negotiation in handshake** — Noise_XX prologue carries protocol version. v1 = current, v2 = monotonic.
2. **Clean break** — v1.0 only speaks the new format. Old clients must upgrade.
3. **Dual-mode relay** — relay inspects version byte and routes accordingly.

**Recommendation:** Option 1 (version negotiation). Add a 1-byte version field to the prologue. Low overhead, clean migration path.

## Complexity Estimate

- **Reassembly buffer rewrite** — Medium (BTreeMap interval tracking replaces HashMap lookup)
- **NACK/SACK rewrite** — Medium (byte ranges instead of seq numbers)
- **Sender tracking** — Low (simpler — just increment counter)
- **Wire format** — Low (add fields, bump version)
- **RTT estimation** — Low (remove Karn's filtering, simplify)
- **Tests** — High (all tunnel tests reference data_seq semantics)

**Total estimate:** ~2-3 days of focused work + 1 day test updates

## Research References

- QUIC RFC 9000 §12.3 — Packet Numbers
- QUIC RFC 9002 §5.1 — Generating RTT Samples
- RFC 6298 §2 — Karn's Algorithm (what we're replacing)
- quiche (Cloudflare) — `packet::PacketNum` monotonic u64
- quinn (Rust QUIC) — `VarInt` packet numbers, `Assembler` byte-range reassembly

## Related Files

- `proto/src/tunnel.rs` — bridge logic, flow control, retransmit buffer
- `proto/src/congestion.rs` — CC state, RTT estimation
- `proto/src/pacing.rs` — system detection, socket buffers
- `docs/FIREWALL.md` — agent unlock protocol (uses same frame types)
