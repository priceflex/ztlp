#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────
# Build ZTLP static library for iOS
# ──────────────────────────────────────────────────────────────────────────
#
# Prerequisites:
#   - Rust toolchain: https://rustup.rs
#   - cargo-lipo: cargo install cargo-lipo
#   - Xcode + iOS SDK
#   - iOS targets:
#       rustup target add aarch64-apple-ios          # arm64 device
#       rustup target add x86_64-apple-ios           # simulator (Intel Mac)
#       rustup target add aarch64-apple-ios-sim      # simulator (Apple Silicon)
#
# Usage:
#   ./build-ios.sh
#
# Output:
#   target/universal/release/libztlp_proto.a   — universal static library
#   include/ztlp.h                              — C header
#
# Integration:
#   1. Drag libztlp_proto.a into your Xcode project
#   2. Add include/ztlp.h to your header search paths
#   3. Link Security.framework (for Secure Enclave support)
#   4. Set "Other Linker Flags": -lztlp_proto
#   5. Use the C API from Swift via a bridging header
#
# ──────────────────────────────────────────────────────────────────────────

set -euo pipefail

echo "==> Building ZTLP for iOS (universal static library)..."

# Build universal (arm64 + x86_64) static library
cargo lipo --release

echo "==> Build complete!"
echo ""
echo "Output:"
echo "  Static lib: target/universal/release/libztlp_proto.a"
echo "  C header:   include/ztlp.h"
echo ""
echo "Copy both files to your Xcode project."
echo "Link against Security.framework for Secure Enclave support."
