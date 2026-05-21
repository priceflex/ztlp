#!/usr/bin/env bash
set -e

cd ~/ztlp/proto

echo "=== ZTLP QUIC Throughput Benchmark (Phase 5) ==="
echo ""
echo "[+] Running QUIC Loopback Multi-stream Payload Criterion Benchmark..."
cargo bench --bench quic_multistream --features quic-transport

echo ""
echo "[+] Done. Benchmark code executes correctly."
