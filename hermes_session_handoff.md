# Hermes Session Handoff

**Project Epic:** ZTLP Service Name Wire Decoupling (Option C) — **COMPLETE**
**Owner:** Hermes
**Date Updated:** 2026-05-19
**Release:** v0.26.0

---

## Outcome

Option C shipped on `feature/ztlp-wire-name-decoupling` and merged to `main`. The 16-byte ASCII limit on human-readable service names is gone. The on-wire `dst_svc_hash` field stays a fixed 16 bytes at the same offset, so packet parsing remains zero-allocation and O(1). Service names hash to 128 bits via a canonical truncated SHA-256 of `lowercase(zone)/lowercase(name)`.

## Tasks (all complete)

1. ✅ **Field rename** `dst_svc_id` → `dst_svc_hash` in `proto/src/packet.rs` and 10 other Rust files (44 occurrences). Added rustdoc explaining the field is an opaque hash. Wire layout unchanged.
2. ✅ **`encode_service_id(zone, name) -> [u8;16]`** in `proto/src/tunnel.rs`. Canonicalization: lowercase + strip trailing dots + `sha256(canonical_utf8)[..16]`. Hash-vector TDD tests pin the encoding.
3. ✅ **Caller migration**: CLI + FFI now produce the hash via `encode_service_name` (compat shim) which delegates to `encode_service_id(None, _)`. CLI REJECT error messages print `hex::encode(dst_svc_hash)` instead of UTF-8-decoding. `ServiceRegistry` now keys by hash with a `name_by_hash` reverse index.
4. ✅ **Elixir gateway harmonization**: `Packet.extract_service_hash/1` + `Packet.service_hash/1` mirror the Rust canonicalization. `Session.find_backend/2` resolves the wire hash against `Packet.service_hash(b.name)` for each configured backend. Relay & NS unchanged (already opaque).

## Verification

- proto: 898 lib + ~340 integration tests pass; both default-features (tokio) and `--no-default-features --features ios-sync` build paths clean.
- gateway: 809 tests, 0 failures.
- relay:   583 tests, 0 failures.
- ns:      726 tests, 0 failures.

## Decisions Recorded

- **Wire field width unchanged** at 16 bytes. We chose option C (hashed routing key) over option A (widen field) and option B (variable-length headers) precisely to preserve fixed-offset, zero-allocation parsing.
- **Truncated SHA-256, 128 bits.** Collision space = 2^128 (identical to IPv6 SLAAC), well beyond birthday bounds for any realistic service population.
- **Canonicalization rule** (must stay byte-identical across all implementations): `sha256( lowercase(zone) + "/" + lowercase(name) )[..16]`; or `sha256( lowercase(name) )[..16]` when no zone is in scope. Trailing dots stripped from each.
- **Sentinel** `[0u8; 16]` continues to mean "no service specified" and routes to `DEFAULT_SERVICE` / the backend named `"default"`.

## Files Touched

Rust (proto):
- `proto/Cargo.toml` — added `sha2 = "0.10"` (already transitively present)
- `proto/src/packet.rs` — field rename + rustdoc
- `proto/src/tunnel.rs` — `encode_service_id`, hash-keyed `ServiceRegistry`, hash-vector tests
- `proto/src/ffi.rs` — no-tokio fallback now uses SHA-256
- `proto/src/handshake.rs`, `proto/src/agent/{daemon,proxy}.rs`, `proto/src/bin/{ztlp-cli,ztlp-inspect,ztlp-fuzz}.rs` — caller rename
- `proto/tests/{packet_tests,edge_case_tests}.rs` — caller rename

Elixir (gateway):
- `gateway/lib/ztlp_gateway/packet.ex` — `extract_service_hash/1`, `service_hash/1`, deprecated `extract_service_name/1` shim
- `gateway/lib/ztlp_gateway/listener.ex` — pass raw hash through
- `gateway/lib/ztlp_gateway/session.ex` — hash-keyed `find_backend/2`

## Known Follow-ups (out of scope for v0.26.0)

- **Bootstrap Rails Model**: still uses a loose regex for Network/Zone validation. Tracked separately; not blocking.
- **Existing dev NS DB**: keys are still string-name-based at the NS layer; the gateway translates to hash at HELLO time so nothing actually broke, but a sweep to surface name-vs-hash in dashboards/logs would be nice.
- **Desktop UI text-field widths**: macOS/Windows UIs may benefit from wider inputs to reflect that names can now be DNS-class. Cosmetic.
