# ZTLP Throughput Benchmark Results

## System Information

| Property | Value |
|----------|-------|
| Date | 2026-05-20 23:56 UTC |
| Commit | 9cca0f9 |
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
| Raw TCP | 6.05 GB/s | 1.6ms | baseline | baseline |
| ZTLP (no opts) | 0 MB/s | 45.9ms | 100.0% | - |
| ZTLP (GRO) | 0 MB/s | 45.7ms | 100.0% | - |
| ZTLP (auto) | 0 MB/s | 50.8ms | 100.0% | auto-detected |
