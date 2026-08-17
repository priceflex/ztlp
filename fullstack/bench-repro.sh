#!/usr/bin/env bash
# Benchmark repro: run INSIDE the ztlp-client container.
# Mirrors the harness benchmark exactly (fresh tunnel + piped-stdin ssh).
set -uo pipefail
KEY_FILE=/home/ztlp/.ztlp/client-identity.json
SERVER_ADDR="${SERVER_ADDR:-server:23095}"
LOCAL_PORT="${LOCAL_PORT:-2223}"
SIZE_MB="${SIZE_MB:-1}"

echo "=== start fresh tunnel (-L ${LOCAL_PORT}:127.0.0.1:22) ==="
ztlp connect "$SERVER_ADDR" --key "$KEY_FILE" --service ssh -L "${LOCAL_PORT}:127.0.0.1:22" -vv 2>/tmp/tunnel.log &
TPID=$!

# Wait for the tunnel to bind the local port
for i in $(seq 1 15); do
  if ss -tln 2>/dev/null | grep -q ":${LOCAL_PORT}"; then
    echo "tunnel listening on :${LOCAL_PORT} after ${i}s"; break
  fi
  sleep 1
done
sleep 1

FILE=/tmp/bench-${SIZE_MB}m.bin
dd if=/dev/urandom of="$FILE" bs=1M count="$SIZE_MB" 2>/dev/null
LOCAL_MD5=$(md5sum "$FILE" | awk '{print $1}')
echo "local_md5=${LOCAL_MD5} size=$(stat -c%s "$FILE") bytes"

echo "=== piped-stdin ssh transfer (single connection) ==="
SSHPASS=ztlptest timeout 40 sshpass -e ssh -v \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -p "$LOCAL_PORT" \
  testuser@127.0.0.1 \
  "cat > /tmp/test-recv.bin && md5sum /tmp/test-recv.bin | awk '{print \$1}'" \
  < "$FILE" > /tmp/remote-md5.txt 2>/tmp/ssh-verbose.log
RC=$?
echo "ssh_exit=${RC}"
REMOTE_MD5=$(tr -d '[:space:]' < /tmp/remote-md5.txt 2>/dev/null)
echo "remote_md5=${REMOTE_MD5}"

echo "=== verdict ==="
if [ "$LOCAL_MD5" = "$REMOTE_MD5" ] && [ "$REMOTE_MD5" != "" ]; then
  echo "RESULT: PASS (checksums match)"
else
  echo "RESULT: FAIL (local=${LOCAL_MD5} remote=${REMOTE_MD5})"
fi

kill "$TPID" 2>/dev/null || true

echo
echo "=== ssh -v tail (auth + data channel) ==="
tail -30 /tmp/ssh-verbose.log
echo
echo "=== tunnel log: connection + session events (last 20) ==="
grep -iE "session|TCP connection|spawn|accept|data|forward|close|error|handshake" /tmp/tunnel.log | tail -20
