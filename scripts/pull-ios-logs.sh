#!/bin/bash
# Pull ZTLP iOS logs from the device's app group container
# Usage: ./pull-ios-logs.sh [output_file]
#
# Requires: Mac with Xcode + iPhone connected via USB
# Pulls from: group.com.ztlp.shared/ztlp.log

set -e

DEVICE="iPhone"
GROUP_ID="group.com.ztlp.shared"
SOURCE="ztlp.log"
DEST="${1:-/tmp/ztlp-ios-logs.txt}"

echo "Pulling ZTLP logs from device..."
xcrun devicectl device copy from \
  --device "$DEVICE" \
  --source "$SOURCE" \
  --destination "$DEST" \
  --domain-type appGroupDataContainer \
  --domain-identifier "$GROUP_ID" \
  2>&1

if [ -f "$DEST" ]; then
  LINES=$(wc -l < "$DEST")
  SIZE=$(du -h "$DEST" | cut -f1)
  echo ""
  echo "Saved: $DEST ($LINES lines, $SIZE)"
  echo ""
  echo "=== Last 30 lines ==="
  tail -30 "$DEST"
else
  echo "ERROR: Failed to pull log file"
  exit 1
fi
