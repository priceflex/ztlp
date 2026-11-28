#!/usr/bin/env bash
# Regenerate ios/ZTLP/ZTLP.xcodeproj from ios/ZTLP/project.yml with XcodeGen.
#
# XcodeGen can be built without Homebrew:
#   git clone https://github.com/yonaskolb/XcodeGen ~/ztlp-ios-tools/XcodeGen
#   (cd ~/ztlp-ios-tools/XcodeGen && swift build -c release)
# Set XCODEGEN to the binary if it lives somewhere else.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
XCODEGEN="${XCODEGEN:-}"
if [ -z "$XCODEGEN" ]; then
  if command -v xcodegen >/dev/null 2>&1; then
    XCODEGEN="$(command -v xcodegen)"
  else
    XCODEGEN="$HOME/ztlp-ios-tools/XcodeGen/.build/release/xcodegen"
  fi
fi
[ -x "$XCODEGEN" ] || { echo "error: xcodegen not found (looked at $XCODEGEN). See the comment at the top of this script." >&2; exit 1; }

cd "$HERE/../ZTLP"
"$XCODEGEN" generate --spec project.yml
