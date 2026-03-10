#!/usr/bin/env bash
# Chaos container entrypoint — just keeps running
# Actual chaos operations are invoked via docker exec
echo "[chaos] Network chaos container ready"
echo "[chaos] Interfaces:"
ip link show 2>/dev/null | grep -E "^[0-9]+" | awk '{print "  " $2}'
exec sleep infinity
