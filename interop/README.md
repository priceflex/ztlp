# ZTLP Cross-Language Interop Test Suite

Full-stack interop tests verifying the ZTLP protocol works correctly across
Rust (client/proto) ↔ Elixir (relay/gateway/NS) language boundaries.

## Quick Start

```bash
# Run ALL interop tests
bash interop/run_full_test.sh

# Run only the original relay tests
bash interop/run_test.sh
```

## Test Suites

### Suite 1: Noise_XX Handshake Interop (6 tests)

**Binary:** `ztlp-handshake-interop`  
**Server:** `handshake_server.exs` (runs within gateway Mix project)

Tests the complete Noise_XX_25519_ChaChaPoly_BLAKE2s handshake between
Rust's `snow` crate and the Elixir gateway's pure `:crypto` implementation.

| # | Test | Description |
|---|------|-------------|
| 1 | Full handshake | 3-message Noise_XX: → e, ← e/ee/s/es, → s/se |
| 2 | Transport key derivation | Verify both sides derive identical i2r/r2i keys |
| 3 | Encrypted data (r2i) | Elixir encrypts → Rust decrypts with ChaCha20-Poly1305 |
| 4 | Encrypted data (i2r) | Rust encrypts → Elixir decrypts with ChaCha20-Poly1305 |
| 5 | Wrong key handling | Handshake with unknown static key (auth above Noise) |
| 6 | Replay detection | Replayed msg1 rejected by server |

### Suite 2: Pipeline Header Validation (8 tests)

**Binary:** `ztlp-pipeline-interop`  
**Server:** `pipeline_server.exs` (standalone Elixir script)

Tests all 3 pipeline admission layers across languages:
- Layer 1: Magic bytes (`0x5A37`)
- Layer 2: SessionID lookup
- Layer 3: HeaderAuthTag (ChaCha20-Poly1305 AEAD)

| # | Test | Description |
|---|------|-------------|
| 1 | Rust data header → Elixir | Elixir validates Rust-generated data header + auth tag |
| 2 | Rust handshake header → Elixir | Elixir validates Rust-generated 95-byte handshake header |
| 3 | Wrong magic rejected | `0xDEAD` magic bytes rejected at Layer 1 |
| 4 | Wrong SessionID rejected | Unknown SessionID rejected at Layer 2 |
| 5 | Wrong auth tag rejected | Garbage HeaderAuthTag rejected at Layer 3 |
| 6 | Elixir data header → Rust | Rust validates Elixir-generated data header |
| 7 | Elixir handshake header → Rust | Rust validates Elixir-generated handshake header |
| 8 | Truncated packet | Partial header (3 bytes) rejected gracefully |

### Suite 3: Edge Cases & Error Handling (8 tests)

**Binary:** `ztlp-edge-cases`  
**Server:** `pipeline_server.exs` (reused from Suite 2)

Tests boundary conditions and error handling.

| # | Test | Description |
|---|------|-------------|
| 1 | Zero-length payload | Header-only packet (no payload) accepted |
| 2 | MTU boundary | Exactly 1500-byte packet handled correctly |
| 3 | Large packet | 8000-byte packet (within UDP limits) accepted |
| 4 | Minimum valid packet | Bare 42-byte data header accepted |
| 5 | Rapid burst | 10 packets in rapid succession all validated |
| 6 | Zero SessionID | All-zero SessionID correctly rejected |
| 7 | Truncation sweep | 8 truncation lengths (0–41 bytes) all rejected |
| 8 | Max sequence number | u64::MAX sequence number accepted |

### Suite 4: Gateway End-to-End (4 tests)

**Binary:** `ztlp-gateway-e2e`  
**Server:** `gateway_test_server.exs` (runs within gateway Mix project)

Tests the full flow: Rust client → Noise handshake → Elixir gateway → TCP backend → back.

| # | Test | Description |
|---|------|-------------|
| 1 | Full E2E | Handshake + encrypted data → gateway decrypts → TCP backend echoes → encrypted response |
| 2 | Bidirectional data | Gateway→client data flow (r2i direction) |
| 3 | Policy: denied | Unauthorized identity rejected by policy engine |
| 4 | Policy: allowed | Authorized identity allowed by policy engine |

### Suite 5: Original Relay Forwarding (5 tests)

**Binary:** `ztlp-interop-test`  
**Server:** `relay_server.exs` (runs within relay Mix project)

Original interop tests preserved for backward compatibility.

| # | Test | Description |
|---|------|-------------|
| 1 | A → Relay → B | Data packet forwarded correctly |
| 2 | B → Relay → A | Reverse direction forwarding |
| 3 | Handshake format | Handshake-format packet forwarded |
| 4 | 10 sequential packets | Burst forwarding through relay |
| 5 | Wrong SessionID | Packets with unknown SessionID dropped |

## Architecture

```
interop/
├── README.md                  # This file
├── run_test.sh                # Original relay-only test runner
├── run_full_test.sh           # Full suite test runner
├── orchestrate.py             # Original relay test orchestrator
├── orchestrate_full.py        # Full suite orchestrator
├── relay_server.exs           # Elixir relay test server (standalone)
├── pipeline_server.exs        # Elixir pipeline validation server (standalone)
├── handshake_server.exs       # Noise_XX test server (needs gateway Mix project)
├── gateway_test_server.exs    # Gateway E2E test server (needs gateway Mix project)
└── ns_test_server.exs         # NS test server (needs ns Mix project, future)

proto/src/bin/
├── ztlp-interop-test.rs       # Original relay interop binary
├── ztlp-handshake-interop.rs  # Noise_XX handshake tests
├── ztlp-pipeline-interop.rs   # Pipeline header validation tests
├── ztlp-edge-cases.rs         # Edge case / error handling tests
├── ztlp-gateway-e2e.rs        # Gateway end-to-end tests
└── ztlp-ns-interop.rs         # NS resolution tests (future)
```

## Protocol Details

- **Noise pattern:** `Noise_XX_25519_ChaChaPoly_BLAKE2s`
- **Magic:** `0x5A37`
- **Data header:** 42 bytes (Magic + Ver|HdrLen + Flags + SessionID + Seq + AuthTag)
- **Handshake header:** 95 bytes (extended header with crypto suite, node IDs, etc.)
- **SessionID:** 12 bytes (96 bits)
- **HeaderAuthTag:** 16 bytes — ChaCha20-Poly1305 AEAD tag (empty plaintext, header as AAD)
- **Nonce format:** 4 zero bytes + 8-byte little-endian counter

## Key Implementation Notes

The Rust side uses the `snow` crate for Noise_XX. The Elixir side (gateway) implements
Noise_XX from scratch using Erlang's `:crypto` module. Critical interop requirements:

1. **Prologue MixHash:** Both sides must call `MixHash(prologue)` after initializing h/ck,
   even with an empty prologue. This is per Noise spec Section 5.3.
   
2. **Empty Payload MixHash:** After processing all tokens in a handshake message,
   `EncryptAndHash(payload)` must be called even with empty payloads. With no key,
   this becomes `MixHash("")` which changes h.

3. **HeaderAuthTag computation:** Uses ChaCha20-Poly1305 AEAD with:
   - Key = shared auth key (32 bytes)
   - Nonce = all zeros (12 bytes)
   - Plaintext = empty
   - AAD = header bytes (26 for data, 79 for handshake)
   - Tag = the 16-byte output

4. **HKDF:** HMAC-BLAKE2s based, using RFC 5869 extract-expand pattern with
   counter bytes `<<1>>` and `<<output1 || 2>>`.
