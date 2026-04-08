#!/usr/bin/env bash
#
# build-ios.sh — Cross-compile the ZTLP Rust crate for iOS targets,
# create a universal (fat) static library, and copy the C header.
#
# Prerequisites:
#   - Xcode + command-line tools installed
#   - Rust installed via rustup
#   - iOS targets added:
#       rustup target add aarch64-apple-ios
#       rustup target add aarch64-apple-ios-sim
#       rustup target add x86_64-apple-ios
#
# Usage:
#   ./build-ios.sh [release|debug]
#
# Output:
#   ios/ZTLP/Libraries/libztlp_proto.a   — Universal static library
#   ios/ZTLP/Libraries/ztlp.h            — C header
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_DIR="$REPO_ROOT/proto"

# Build profile
PROFILE="${1:-release}"
if [[ "$PROFILE" == "release" ]]; then
    CARGO_FLAGS="--release"
    TARGET_DIR="release"
else
    CARGO_FLAGS=""
    TARGET_DIR="debug"
fi

# iOS targets
TARGETS=(
    "aarch64-apple-ios"         # Device (arm64)
    "aarch64-apple-ios-sim"     # Simulator on Apple Silicon
    "x86_64-apple-ios"          # Simulator on Intel Mac
)

# Output directory
LIB_DIR="$SCRIPT_DIR/ZTLP/Libraries"
mkdir -p "$LIB_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== ZTLP iOS Build ===${NC}"
echo "Profile: $PROFILE"
echo "Crate:   $CRATE_DIR"
echo "Output:  $LIB_DIR"
echo ""

# Step 1: Ensure targets are installed
echo -e "${BLUE}[1/4] Checking Rust targets...${NC}"
for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed | grep -q "$target"; then
        echo "  Installing $target..."
        rustup target add "$target"
    else
        echo "  ✓ $target"
    fi
done
echo ""

# Step 2: Build for each target
echo -e "${BLUE}[2/4] Building for iOS targets...${NC}"
BUILT_LIBS=()
for target in "${TARGETS[@]}"; do
    echo "  Building $target..."
    cargo build \
        --manifest-path "$CRATE_DIR/Cargo.toml" \
        --target "$target" \
        $CARGO_FLAGS \
        --lib \
        2>&1 | sed 's/^/    /'

    LIB_PATH="$CRATE_DIR/target/$target/$TARGET_DIR/libztlp_proto.a"
    if [[ ! -f "$LIB_PATH" ]]; then
        echo -e "${RED}ERROR: Library not found at $LIB_PATH${NC}"
        exit 1
    fi
    BUILT_LIBS+=("$LIB_PATH")
    echo "  ✓ $target"
done
echo ""

# Step 3: Create universal binary
echo -e "${BLUE}[3/4] Creating universal (fat) library...${NC}"

# For xcframework support, we need separate device and simulator libraries.
# The simulator library combines arm64-sim + x86_64.
DEVICE_LIB="${BUILT_LIBS[0]}"  # aarch64-apple-ios
SIM_ARM64="${BUILT_LIBS[1]}"    # aarch64-apple-ios-sim
SIM_X86="${BUILT_LIBS[2]}"      # x86_64-apple-ios

# Create fat simulator library (arm64-sim + x86_64)
FAT_SIM_LIB="$LIB_DIR/libztlp_proto_sim.a"
lipo -create "$SIM_ARM64" "$SIM_X86" -output "$FAT_SIM_LIB"
echo "  ✓ Fat simulator library: $FAT_SIM_LIB"

# Copy device library
cp "$DEVICE_LIB" "$LIB_DIR/libztlp_proto_device.a"
echo "  ✓ Device library: $LIB_DIR/libztlp_proto_device.a"

# Also create a single fat library for simple Xcode project setups
# (Note: This can't include both arm64-device and arm64-sim in one .a)
# For device builds (Xcode default), use the device library.
# Use libztlp_proto_sim.a for simulator builds.
cp "$DEVICE_LIB" "$LIB_DIR/libztlp_proto.a"

# Create xcframework (the modern approach)
XCFRAMEWORK_PATH="$LIB_DIR/libztlp_proto.xcframework"
rm -rf "$XCFRAMEWORK_PATH"

HEADER_DIR="$CRATE_DIR/include"
if [[ -f "$HEADER_DIR/ztlp.h" ]]; then
    xcodebuild -create-xcframework \
        -library "$LIB_DIR/libztlp_proto_device.a" -headers "$HEADER_DIR" \
        -library "$FAT_SIM_LIB" -headers "$HEADER_DIR" \
        -output "$XCFRAMEWORK_PATH" \
        2>&1 | sed 's/^/    /'
    echo "  ✓ XCFramework: $XCFRAMEWORK_PATH"
else
    echo "  ⚠ Header not found at $HEADER_DIR/ztlp.h — skipping xcframework"
fi
echo ""

# Step 4: Copy header
echo -e "${BLUE}[4/4] Copying C header...${NC}"
if [[ -f "$HEADER_DIR/ztlp.h" ]]; then
    cp "$HEADER_DIR/ztlp.h" "$LIB_DIR/ztlp.h"
    echo "  ✓ Copied ztlp.h"
else
    echo -e "${RED}  ✗ ztlp.h not found at $HEADER_DIR/ztlp.h${NC}"
    exit 1
fi
echo ""

# Summary
echo -e "${GREEN}=== Build Complete ===${NC}"
echo "Files:"
ls -lah "$LIB_DIR/"*.a "$LIB_DIR/ztlp.h" 2>/dev/null | sed 's/^/  /'
if [[ -d "$XCFRAMEWORK_PATH" ]]; then
    echo "  $XCFRAMEWORK_PATH/"
fi
echo ""
echo "Next steps:"
echo "  1. Open ios/ZTLP/ZTLP.xcodeproj in Xcode"
echo "  2. Add Libraries/libztlp_proto.xcframework to both targets"
echo "  3. Set Header Search Paths to \$(PROJECT_DIR)/Libraries"
echo "  4. Build & run"
