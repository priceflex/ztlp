# ZTLP Performance Regression Plan

## Status: IN PROGRESS

## Problem

Concurrent benchmark runs caused port contention and test timeouts, giving the
appearance of relay test failures. The tests themselves are correct — the issue
is resource contention when multiple heavy benchmarks run simultaneously.

## Plan

### Phase 1: Fix & Verify ✅

**Finding:** All 106 Rust tests pass (0 failures). The `test_simulated_relay_pairs_and_forwards`
and `test_relay_forwarded_packets_decrypt_correctly` failures were caused by concurrent
benchmark processes competing for the same ports and system resources, not by bugs.

- [x] Kill all lingering ZTLP processes
- [x] Verify all tests pass in isolation
- [x] Verify all tests pass as full suite (`cargo test --release` → 106 pass, 0 fail)

### Phase 2: Performance Baseline

Establish authoritative baseline numbers on the current hardware (AMD EPYC 4564P,
4 vCPU, 7.8 GiB RAM) with controlled conditions:

- [x] Existing benchmarks in `bench/RESULTS.md` (v3, 2026-03-12)
- [ ] Run `ztlp-throughput` with `--json` to generate machine-readable baseline
- [ ] Store baseline as `bench/baseline.json`

### Phase 3: Performance Regression Gate 🔧

Create `bench/perf-gate.sh` — a CI-friendly script that:

1. Runs a focused subset of benchmarks (not the full 20-minute suite)
2. Compares results against `bench/baseline.json`
3. Fails (exit 1) if any metric drops below the threshold
4. Outputs a clear pass/fail summary

**Metrics tracked:**
| Metric | Source | Threshold |
|--------|--------|-----------|
| Rust L1 reject latency | `ztlp-bench` | < 50 ns (2.5× baseline) |
| Rust full pipeline throughput | `ztlp-bench` | > 800K ops/s (90% of baseline) |
| Rust Noise_XX handshake | `ztlp-bench` | < 500 µs (166% of baseline) |
| ZTLP tunnel throughput (no GSO) | `ztlp-throughput` | > floor (set per-environment) |
| Elixir relay pipeline (valid) | relay bench | > 400K ops/s (70% of baseline) |
| Elixir gateway pipeline (valid) | gateway bench | > 200 ns median (2× baseline) |

**Thresholds are generous** — we're catching regressions (>2× slower), not noise.
CI environments have variable performance, so we use wide bands.

### Phase 4: CI Integration

Add a `perf-gate` job to `.github/workflows/ci.yml`:

```yaml
perf-gate:
  name: Performance Gate
  runs-on: ubuntu-latest
  needs: [rust, relay, gateway]
  steps:
    - Build release binaries
    - Run bench/perf-gate.sh
    - Upload results as artifact
    - Fail if regression detected
```

**Key design decisions:**
- Runs AFTER correctness tests (no point benchmarking broken code)
- Uses `--quick` mode (small transfers, 1 iteration) to keep CI fast (~2 min)
- Baseline thresholds are CI-environment-aware (different from dev box)
- Results uploaded as GitHub Actions artifacts for historical tracking
- **NOT a blocking gate initially** — runs as informational, promoted to required after baseline stabilizes

### Phase 5: Historical Tracking (Future)

- Store JSON results per commit in a `bench/history/` directory
- Simple HTML dashboard (like `docs/index.html`) showing trends
- Alert if 3 consecutive commits show downward trend

---

## Files

| File | Purpose |
|------|---------|
| `bench/perf-gate.sh` | CI regression gate script |
| `bench/baseline.json` | Baseline performance numbers |
| `bench/ci-baseline.json` | CI-environment baseline (GitHub Actions runners) |
| `.github/workflows/ci.yml` | CI workflow (updated with perf-gate job) |

## Notes

- The 60-second timeout in `test_relay_forwarded_packets_decrypt_correctly` is fine
  for normal runs. The hangs were from external resource contention.
- GSO/GRO may not be available on CI runners — the gate should handle this gracefully.
- Elixir benchmarks require `ZTLP_NS_STORAGE_MODE=ram` when not distributed.
