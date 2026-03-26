#!/bin/bash
# Build libztlp_proto.a for iOS (arm64)
# Run this on macOS with Xcode installed.
#
# Usage: ./scripts/build-ios.sh [--release]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PROTO_DIR="$ROOT_DIR/proto"
IOS_LIBS="$ROOT_DIR/ios/ZTLP/Libraries"

PROFILE="release"
PROFILE_FLAG="--release"
if [ "${1:-}" != "--release" ]; then
    PROFILE="debug"
    PROFILE_FLAG=""
    echo "Building in DEBUG mode (pass --release for optimized build)"
fi

# Ensure iOS target is installed
echo "=== Checking iOS toolchain ==="
if ! rustup target list --installed | grep -q "aarch64-apple-ios"; then
    echo "Installing aarch64-apple-ios target..."
    rustup target add aarch64-apple-ios
fi

# Also add simulator target for testing
if ! rustup target list --installed | grep -q "aarch64-apple-ios-sim"; then
    echo "Installing aarch64-apple-ios-sim target..."
    rustup target add aarch64-apple-ios-sim
fi

# Build for iOS device (arm64)
echo "=== Building for iOS (aarch64-apple-ios) ==="
cd "$PROTO_DIR"
cargo build $PROFILE_FLAG --lib --target aarch64-apple-ios 2>&1

# Build for iOS simulator (arm64 — for Apple Silicon Macs)
echo "=== Building for iOS Simulator (aarch64-apple-ios-sim) ==="
cargo build $PROFILE_FLAG --lib --target aarch64-apple-ios-sim 2>&1

# Copy to iOS Libraries/
echo "=== Copying to Xcode project ==="
mkdir -p "$IOS_LIBS"
cp "$PROTO_DIR/target/aarch64-apple-ios/$PROFILE/libztlp_proto.a" "$IOS_LIBS/libztlp_proto.a"

echo ""
echo "=== Build complete ==="
echo "  Device lib: $PROTO_DIR/target/aarch64-apple-ios/$PROFILE/libztlp_proto.a"
echo "  Simulator:  $PROTO_DIR/target/aarch64-apple-ios-sim/$PROFILE/libztlp_proto.a"
echo "  Xcode copy: $IOS_LIBS/libztlp_proto.a"
echo ""
echo "NOTE: For simulator builds on Apple Silicon, use the sim lib:"
echo "  cp $PROTO_DIR/target/aarch64-apple-ios-sim/$PROFILE/libztlp_proto.a $IOS_LIBS/"
echo "For device builds, use the device lib:"
echo "  cp $PROTO_DIR/target/aarch64-apple-ios/$PROFILE/libztlp_proto.a $IOS_LIBS/"
echo ""
echo "project.yml excludes x86_64 from simulator builds (Apple Silicon only)."
echo ""
ls -lh "$IOS_LIBS/libztlp_proto.a"
echo ""
echo "Symbols check:"
nm "$IOS_LIBS/libztlp_proto.a" 2>/dev/null | grep "T _ztlp_" | head -5
echo "  ($(nm "$IOS_LIBS/libztlp_proto.a" 2>/dev/null | grep -c "T _ztlp_") public symbols)"
