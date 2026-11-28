#!/usr/bin/env bash
# Build a stub libztlp_proto.a (see ztlp_ios_stub.c) for compile checks and
# simulator unit tests.
#   usage: make-stub-lib.sh iphoneos|iphonesimulator <output-dir>
set -euo pipefail

SDK="${1:-}"
OUT="${2:-}"
case "$SDK" in
  iphoneos) TARGET="arm64-apple-ios16.0" ;;
  iphonesimulator) TARGET="arm64-apple-ios16.0-simulator" ;;
  *) echo "usage: $0 iphoneos|iphonesimulator <output-dir>" >&2; exit 2 ;;
esac
[ -n "$OUT" ] || { echo "usage: $0 iphoneos|iphonesimulator <output-dir>" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
xcrun --sdk "$SDK" clang -target "$TARGET" -Os -Wall -Werror \
  -I "$HERE/../ZTLP/Libraries" -c "$HERE/ztlp_ios_stub.c" -o "$OUT/ztlp_ios_stub.o"
xcrun libtool -static -o "$OUT/libztlp_proto.a" "$OUT/ztlp_ios_stub.o" 2>/dev/null
rm -f "$OUT/ztlp_ios_stub.o"
echo "$OUT/libztlp_proto.a"
