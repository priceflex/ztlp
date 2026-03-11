#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────
# Build ZTLP static library for Android
# ──────────────────────────────────────────────────────────────────────────
#
# Prerequisites:
#   - Rust toolchain: https://rustup.rs
#   - Android NDK (r26+): via Android Studio SDK Manager or standalone
#   - cargo-ndk: cargo install cargo-ndk
#   - Android targets:
#       rustup target add aarch64-linux-android       # arm64-v8a
#       rustup target add armv7-linux-androideabi      # armeabi-v7a
#       rustup target add x86_64-linux-android         # x86_64 (emulator)
#       rustup target add i686-linux-android           # x86 (emulator)
#
# Usage:
#   export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.1.10909125
#   ./build-android.sh
#
# Output:
#   jniLibs/arm64-v8a/libztlp_proto.so
#   jniLibs/armeabi-v7a/libztlp_proto.so
#   jniLibs/x86_64/libztlp_proto.so
#   include/ztlp.h
#
# Integration:
#   1. Copy jniLibs/ to your Android project's app/src/main/jniLibs/
#   2. Add include/ztlp.h to your NDK header search paths
#   3. In CMakeLists.txt: add_library(ztlp_proto SHARED IMPORTED)
#   4. Use JNI or JNA to call the C API from Kotlin/Java
#   5. For Android Keystore identity: implement JNI callbacks
#
# Min API level: 23 (Android 6.0) for Keystore support
# ──────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Verify ANDROID_NDK_HOME is set
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "ERROR: ANDROID_NDK_HOME is not set."
    echo "Set it to your NDK path, e.g.:"
    echo "  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/26.1.10909125"
    exit 1
fi

echo "==> Using NDK: $ANDROID_NDK_HOME"
echo "==> Building ZTLP for Android (arm64-v8a, armeabi-v7a, x86_64)..."

cargo ndk \
    -t armeabi-v7a \
    -t arm64-v8a \
    -t x86_64 \
    -o ./jniLibs \
    build --release

echo "==> Build complete!"
echo ""
echo "Output:"
echo "  jniLibs/arm64-v8a/libztlp_proto.so"
echo "  jniLibs/armeabi-v7a/libztlp_proto.so"
echo "  jniLibs/x86_64/libztlp_proto.so"
echo "  include/ztlp.h"
echo ""
echo "Copy jniLibs/ and include/ztlp.h to your Android project."
