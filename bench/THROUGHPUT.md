# ZTLP Throughput Benchmark Results

## System Information

| Property | Value |
|----------|-------|
| Date | 2026-05-16 17:39 UTC |
| Commit | c21073d |
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
| Raw TCP | 2.39 GB/s | 4.1ms | baseline | baseline |
| ZTLP (no opts) | 224 MB/s | 42.7ms | 90.8% | - |
| ZTLP (GRO) | 234 MB/s | 42.8ms | 90.4% | - |
| ZTLP (auto) | 206 MB/s | 45.7ms | 91.6% | auto-detected |

## Analysis

- GRO improvement: 1.0x over no-opts
- ZTLP overhead vs raw: 90.8% (no opts)

