#!/bin/bash
# Multi-stream concurrent ZTLP throughput probe.
#
# Spawns N parallel ztlp-throughput processes (each its own session pair on
# distinct ephemeral ports) and measures aggregate throughput. This is the
# closest analog to a browser opening N independent connections.
#
# Each process: TCP client → ZTLP client bridge → ZTLP server bridge → TCP backend
# All on loopback. NO gateway, NO relay (those are separate stack layers).

set -euo pipefail

BIN="/home/trs/ztlp/proto/target/release/ztlp-throughput"
SIZE="${SIZE:-10485760}"  # 10 MB each
LOG_DIR="/tmp/ztlp-multistream"
mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.log

if [[ ! -x "$BIN" ]]; then
    echo "Building ztlp-throughput..." >&2
    (cd /home/trs/ztlp/proto && cargo build --release --bin ztlp-throughput) >&2
fi

run_n_parallel() {
    local n=$1
    local start_ns
    start_ns=$(date +%s%N)

    local pids=()
    for ((i = 0; i < n; i++)); do
        # Each process logs to its own file so we can parse independently.
        "$BIN" --mode ztlp --size "$SIZE" --repeat 1 \
            > "$LOG_DIR/stream-$i.log" 2>&1 &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done

    local end_ns
    end_ns=$(date +%s%N)
    local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

    local stalled=0
    local ok=0
    local sum_mbps=0
    local count=0
    for ((i = 0; i < n; i++)); do
        local mbps
        mbps=$(awk '/^ZTLP/ {
            for (j=1; j<=NF; j++) {
                if ($j == "MB/s") { print $(j-1); exit }
                if ($j == "GB/s") { print $(j-1)*1024; exit }
            }
        }' "$LOG_DIR/stream-$i.log" 2>/dev/null || echo 0)
        # bash arithmetic doesn't do floats; use awk for the running sum
        sum_mbps=$(awk -v s="$sum_mbps" -v m="$mbps" 'BEGIN{print s+m}')
        count=$((count + 1))

        # Classify: 0 MB/s = stalled, anything else = ok
        if awk -v m="$mbps" 'BEGIN{ exit !(m+0 < 1) }'; then
            stalled=$((stalled + 1))
        else
            ok=$((ok + 1))
        fi
    done

    # Aggregate throughput = (total bytes transferred) / elapsed time
    local total_bytes=$(( SIZE * n ))
    local agg_mbps
    agg_mbps=$(awk -v b="$total_bytes" -v ms="$elapsed_ms" \
        'BEGIN { if (ms > 0) printf "%.1f", (b / 1048576.0) * 1000.0 / ms; else print 0 }')

    printf "  %2d streams: aggregate=%7s MB/s   wall=%5d ms   per-stream-avg=%6.1f MB/s   stalled=%d   ok=%d\n" \
        "$n" "$agg_mbps" "$elapsed_ms" \
        "$(awk -v s="$sum_mbps" -v c="$count" 'BEGIN{ if (c > 0) print s/c; else print 0 }')" \
        "$stalled" \
        "$ok"
}

echo "═════════════════════════════════════════════════════════════════════════"
echo "  Multi-stream ZTLP throughput (size=$((SIZE / 1024 / 1024)) MB per stream)"
echo "═════════════════════════════════════════════════════════════════════════"
for n in 1 2 4 8 16 32; do
    run_n_parallel "$n"
done

echo
echo "Per-stream logs preserved in $LOG_DIR/"
