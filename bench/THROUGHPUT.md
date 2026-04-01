# ZTLP Throughput Benchmark Results

## System Information

| Property | Value |
|----------|-------|
| Date | 2026-04-01 03:18 UTC |
| Commit | 62ab2b7 |
| OS | Linux 5.15.0-1044-kvm x86_64 |
| CPU | AMD EPYC 4564P 16-Core Processor |
| Cores | 2 |
| Memory | 7.8Gi |
| Rust | 1.94.1 |
| GSO | unavailable |
| GRO | available |

## Configuration

| Parameter | Value |
|-----------|-------|
| Transfer size | 10.0 MB |
| Iterations | 1 |
| Bind address | 127.0.0.1 |

## Results

| Mode | Throughput | Time | Overhead vs Raw | Notes |
|------|-----------|------|-----------------|-------|
| Raw TCP | 7.82 GB/s | 1.2ms | baseline | baseline |
| ZTLP (no opts) | 130 MB/s | 77.0ms | 98.4% | - |
| ZTLP (GRO) | 21 MB/s | 478.3ms | 99.7% | - |
| ZTLP (auto) | 36 MB/s | 275.7ms | 99.6% | auto-detected |

## Analysis

- GRO improvement: 0.2x over no-opts
- ZTLP overhead vs raw: 98.4% (no opts)

