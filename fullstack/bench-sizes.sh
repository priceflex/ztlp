#!/usr/bin/env bash
# Parameterized throughput test: run INSIDE ztlp-client. For each size,
# transfer through the tunnel and print the LOCAL md5. (Backend md5 is
# compared by the orchestrator on the box side.)
set -uo pipefail
KEY_FILE=/home/ztlp/.ztlp/client-identity.json
SERVER_ADDR="${SERVER_ADDR:-server:23095}"

for SIZE_KB in "${@:-32 64 96 128 192 256}"; do
  PORT=$((2000 + SIZE_KB))
  FILE=/tmp/s${SIZE_KB}.bin
  dd if=/dev/urandom of="$FILE" bs=1K count="$SIZE_KB" 2>/dev/null
  LM=$(md5sum "$FILE" | awk '{print $1}')
  WANT=$((SIZE_KB*1024))

  ztlp connect "$SERVER_ADDR" --key "$KEY_FILE" --service ssh -L "${PORT}:127.0.0.1:22" -vv 2>/tmp/t${SIZE_KB}.log &
  TPID=$!
  for i in $(seq 1 12); do
    ss -tln 2>/dev/null | grep -q ":${PORT}" && break
    sleep 1
  done
  sleep 1

  SSHPASS=ztlptest timeout 40 sshpass -e ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -p "$PORT" testuser@127.0.0.1 \
    "cat > /tmp/r${SIZE_KB}.bin && md5sum /tmp/r${SIZE_KB}.bin | awk '{print \$1}'" \
    < "$FILE" >/tmp/om${SIZE_KB}.txt 2>/dev/null
  RC=$?
  kill "$TPID" 2>/dev/null || true
  sleep 1

  echo "SIZE_KB=${SIZE_KB} WANT=${WANT} LOCAL_MD5=${LM} SSH_RC=$RC"
done
