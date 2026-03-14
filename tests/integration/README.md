# ZTLP Integration Tests

Production-grade integration and stress tests for the full ZTLP stack.

## Prerequisites

- Rust toolchain (for building `ztlp` CLI)
- `socat` or `ncat` or Python3 (for TCP echo server in tunnel test)
- `nc` (netcat) for data transfer tests

## Build

```bash
cd proto && cargo build --release
```

## Run All Tests

```bash
# Full suite
./run_all.sh

# Quick mode (skip long-running tests)
./run_all.sh quick

# Custom binary path
ZTLP=/path/to/ztlp ./run_all.sh
```

## Individual Tests

| Test | File | Duration | Description |
|------|------|----------|-------------|
| Full E2E Tunnel | `test_full_tunnel.sh` | ~10s | Start listener, connect client with TCP forwarding, verify data integrity (SHA256) |
| Multi-Session Stress | `test_multi_session.sh` | ~30s | 50 concurrent clients connecting simultaneously |
| Connection Storm | `test_connection_storm.sh` | ~45s | 100 clients vs 10-slot listener, verify capacity enforcement |
| Long-Running Session | `test_long_session.sh` | ~120s | 2-min session with periodic data, RSS memory check |
| Policy Rejection | `test_policy_rejection.sh` | ~15s | Restrictive policy, unauthorized/authorized client behavior |
| Relay Failover | `test_relay_failover.sh` | ~20s | Kill relay mid-session, verify detection, reconnect |

## Rust Stress Tests

Additional stress tests in `proto/tests/stress_test.rs`:

```bash
cd proto && cargo test --test stress_test -- --nocapture
```

Covers:
- Reassembly buffer under 5%/10%/20% packet loss
- Burst loss patterns and duplicate handling
- Buffer overflow protection
- SACK range generation
- RTT estimator convergence and spike resilience
- Congestion window behavior under various loss rates
- SACK-driven retransmission recovery
- 1000-packet encrypted burst over real UDP sockets
- Session manager capacity enforcement
- 50 concurrent handshake stress test

## Environment Variables

- `ZTLP` — Path to the ztlp binary (default: `proto/target/release/ztlp`)
- `ZTLP_TEST_LONG_DURATION` — Duration for the long-running test in seconds (default: 120)
