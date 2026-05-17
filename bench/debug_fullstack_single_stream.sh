#!/usr/bin/env bash
set -euo pipefail

SIZE=${1:-1048576}
TS=$(date +%Y%m%d-%H%M%S)
OUTDIR="/tmp/ztlp-fullstack/single-1m-${TS}"
SUMMARY="${OUTDIR}/summary.txt"

mkdir -p "$OUTDIR"
rm -f /tmp/ztlp-fullstack/single-1m-latest
ln -s "$OUTDIR" /tmp/ztlp-fullstack/single-1m-latest

echo "=== ZTLP Fullstack Debug Run ===" | tee -a "$SUMMARY"
echo "Time: $TS" | tee -a "$SUMMARY"
echo "Size: $SIZE bytes" | tee -a "$SUMMARY"
echo "Dir:  $OUTDIR" | tee -a "$SUMMARY"
echo "--------------------------------" | tee -a "$SUMMARY"

# 1. Capture BEFORE state
echo "Capturing baseline..."
cat /proc/net/snmp | grep ^Udp: > "$OUTDIR/client_udp_before.txt"
ssh -o ConnectTimeout=5 ubuntu@44.243.42.123 'cat /proc/net/snmp | grep ^Udp:' > "$OUTDIR/relay_udp_before.txt"
ssh -o ConnectTimeout=5 ubuntu@54.190.82.255 'cat /proc/net/snmp | grep ^Udp:' > "$OUTDIR/gateway_udp_before.txt"
ssh -o ConnectTimeout=5 ubuntu@44.243.42.123 'sudo docker logs ztlp-relay --tail 50' > "$OUTDIR/relay_logs_before.txt" 2>&1
ssh -o ConnectTimeout=5 ubuntu@54.190.82.255 'sudo docker logs ztlp-gateway --tail 50' > "$OUTDIR/gateway_logs_before.txt" 2>&1

# 2. Run benchmark
echo "Running client benchmark (expecting stalls if unfixed)..."
set +e
python3 /home/trs/ztlp/bench/run_fullstack_multistream.py --size "$SIZE" --ns 1 > "$OUTDIR/run.log" 2>&1
RC=$?
set -e
echo "Benchmark exit code: $RC" | tee -a "$SUMMARY"

# Extract results from the generated log (stream-0.log usually)
STREAM_LOG="/tmp/ztlp-fullstack/stream-0.log"
if [ -f "$STREAM_LOG" ]; then
    cp "$STREAM_LOG" "$OUTDIR/"
    GOT=$(grep 'got=' "$STREAM_LOG" | cut -d= -f2)
    ELAPSED=$(grep 'elapsed=' "$STREAM_LOG" | cut -d= -f2)
    MBPS=$(grep 'mbps=' "$STREAM_LOG" | cut -d= -f2)
    ERR=$(grep 'err=' "$STREAM_LOG" | cut -d= -f2-)
    
    echo "Result:  got=$GOT / $SIZE bytes" | tee -a "$SUMMARY"
    echo "Elapsed: $ELAPSED seconds" | tee -a "$SUMMARY"
    echo "Speed:   $MBPS MB/s" | tee -a "$SUMMARY"
    if [ "$GOT" == "$SIZE" ]; then
        echo "Status:  PASS" | tee -a "$SUMMARY"
    else
        echo "Status:  FAIL (Stalled)" | tee -a "$SUMMARY"
        echo "Error:   $ERR" | tee -a "$SUMMARY"
    fi
else
    echo "Status:  FAIL (No stream log generated)" | tee -a "$SUMMARY"
    GOT=0
fi

# 3. Capture AFTER state
echo "Capturing post-run state..."
cat /proc/net/snmp | grep ^Udp: > "$OUTDIR/client_udp_after.txt"
ssh -o ConnectTimeout=5 ubuntu@44.243.42.123 'cat /proc/net/snmp | grep ^Udp:' > "$OUTDIR/relay_udp_after.txt"
ssh -o ConnectTimeout=5 ubuntu@54.190.82.255 'cat /proc/net/snmp | grep ^Udp:' > "$OUTDIR/gateway_udp_after.txt"
ssh -o ConnectTimeout=5 ubuntu@44.243.42.123 'sudo docker logs ztlp-relay --since 2m --tail 200' > "$OUTDIR/relay_logs_after.txt" 2>&1
ssh -o ConnectTimeout=5 ubuntu@54.190.82.255 'sudo docker logs ztlp-gateway --since 2m --tail 300' > "$OUTDIR/gateway_logs_after.txt" 2>&1

# 4. Compute Deltas
echo "--------------------------------" | tee -a "$SUMMARY"
echo "UDP Deltas:" | tee -a "$SUMMARY"

compute_delta() {
    local host=$1
    local file_before="$OUTDIR/${host}_udp_before.txt"
    local file_after="$OUTDIR/${host}_udp_after.txt"
    
    if [[ ! -f "$file_before" ]] || [[ ! -f "$file_after" ]]; then
        echo "  $host: missing data" | tee -a "$SUMMARY"
        return
    fi
    
    # Parse standard SNMP UDP lines: Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors ...
    local in_b=$(awk '/^Udp:/ && NR==2 {print $2}' "$file_before")
    local err_b=$(awk '/^Udp:/ && NR==2 {print $4}' "$file_before")
    local rcv_b=$(awk '/^Udp:/ && NR==2 {print $8}' "$file_before")
    local out_b=$(awk '/^Udp:/ && NR==2 {print $5}' "$file_before")
    
    local in_a=$(awk '/^Udp:/ && NR==2 {print $2}' "$file_after")
    local err_a=$(awk '/^Udp:/ && NR==2 {print $4}' "$file_after")
    local rcv_a=$(awk '/^Udp:/ && NR==2 {print $8}' "$file_after")
    local out_a=$(awk '/^Udp:/ && NR==2 {print $5}' "$file_after")
    
    # Default to 0 if empty
    in_b=${in_b:-0}; err_b=${err_b:-0}; rcv_b=${rcv_b:-0}; out_b=${out_b:-0}
    in_a=${in_a:-0}; err_a=${err_a:-0}; rcv_a=${rcv_a:-0}; out_a=${out_a:-0}
    
    echo "  $host: dIn=$(($in_a - $in_b)), dErr=$(($err_a - $err_b)), dRcvbuf=$(($rcv_a - $rcv_b)), dOut=$(($out_a - $out_b))" | tee -a "$SUMMARY"
}

compute_delta "client"
compute_delta "relay"
compute_delta "gateway"

echo "--------------------------------" | tee -a "$SUMMARY"
echo "Done. Results in $OUTDIR"
