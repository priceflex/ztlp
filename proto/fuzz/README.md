# ZTLP Protocol Fuzz Testing

Fuzz testing for the ZTLP protocol prototype using [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (powered by libFuzzer).

## Prerequisites

- **Nightly Rust toolchain** (libFuzzer requires nightly)
- `cargo-fuzz` installed:

```bash
rustup install nightly
cargo +nightly install cargo-fuzz
```

## Available Fuzz Targets

| Target | Description | Key Functions |
|--------|-------------|---------------|
| `fuzz_packet_parsing` | Handshake & data header parsing | `HandshakeHeader::deserialize()`, `DataHeader::deserialize()`, `MsgType::from_u8()` |
| `fuzz_pipeline_admission` | Three-layer admission pipeline | `Pipeline::process()`, layer1/2/3 checks |
| `fuzz_handshake` | Noise_XX handshake state machine | `HandshakeContext::read_message()`, `write_message()` |
| `fuzz_nack_ack_decoding` | NACK/ACK frame decoding | `decode_nack_payload()`, ACK extraction |
| `fuzz_rat_parsing` | Relay Admission Token parsing | `RelayAdmissionToken::parse()`, `HandshakeExtension::parse()` |
| `fuzz_reassembly` | Reassembly buffer operations | `ReassemblyBuffer::insert()`, ordering, eviction |

## Running

From the `proto/` directory:

```bash
# Run a specific target (recommended: start with packet parsing)
cargo +nightly fuzz run fuzz_packet_parsing

# Run with a time limit (e.g., 5 minutes)
cargo +nightly fuzz run fuzz_packet_parsing -- -max_total_time=300

# Run with multiple jobs (parallel fuzzing)
cargo +nightly fuzz run fuzz_packet_parsing -- -jobs=4 -workers=4

# Run all targets sequentially for 2 minutes each
for target in fuzz_packet_parsing fuzz_pipeline_admission fuzz_handshake \
              fuzz_nack_ack_decoding fuzz_rat_parsing fuzz_reassembly; do
    echo "=== Fuzzing $target ==="
    cargo +nightly fuzz run "$target" -- -max_total_time=120
done
```

## Corpus Management

Corpus directories are created automatically under `fuzz/corpus/<target_name>/`.

```bash
# Minimize the corpus (remove redundant inputs)
cargo +nightly fuzz cmin fuzz_packet_parsing

# Show coverage info
cargo +nightly fuzz coverage fuzz_packet_parsing
```

## Interpreting Results

If a crash is found:
1. The crashing input is saved to `fuzz/artifacts/<target_name>/`
2. Reproduce it: `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`
3. Minimize it: `cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>`

## What Each Target Covers

### `fuzz_packet_parsing`
Tests that `HandshakeHeader::deserialize()` and `DataHeader::deserialize()` handle
all malformed inputs without panicking. Includes round-trip testing (parse → serialize → parse)
and handshake extension parsing.

### `fuzz_pipeline_admission`
Tests the full three-layer admission pipeline with registered sessions. Ensures that
arbitrary packets are rejected gracefully at each layer without memory corruption.

### `fuzz_handshake`
Tests the Noise_XX state machine with random message payloads. Covers both initiator
and responder roles, verifying that invalid Noise messages produce errors, not panics.

### `fuzz_nack_ack_decoding`
Tests the reliability layer's NACK payload decoder with random bytes. Ensures the
frame parser handles truncated, oversized, and corrupted NACK payloads safely.

### `fuzz_rat_parsing`
Tests Relay Admission Token parsing with random bytes. Covers the 93-byte token format,
HMAC verification, expiry checking, and HandshakeExtension parsing.

### `fuzz_reassembly`
Uses structured fuzzing (via `arbitrary`) to generate sequences of reassembly buffer
operations. Tests out-of-order delivery, duplicate handling, buffer overflow protection,
and eviction behavior.
