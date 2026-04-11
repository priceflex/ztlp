# ZTLP iOS Build Guide

## Critical: Two Separate Libraries

The main app (ZTLP) and the tunnel (ZTLPTunnel) require **different build configurations**:

| Target | Library | Features | Why |
|--------|---------|----------|-----|
| **Main App (ZTLP)** | `libztlp_proto.a` (48MB) | Default (includes tokio) | Uses tokio FFI: `ztlp_client_new`, `ztlp_connect`, `ztlp_send`, `ztlp_vip_start`, etc. |
| **Tunnel (ZTLPTunnel)** | `libztlp_proto_ne.a` (25MB) | `--no-default-features --features ios-sync` | NE memory limit (15MB). Uses sync FFI: `ztlp_connect_sync`, relay pool, packet router sync. |

**⚠️ They CANNOT use the same library.** If you build only one, one of the two targets will fail with 20+ linker errors.

## Full Build Commands (run from `~/ztlp/ios`)

```bash
cd ~/ztlp/ios
CRATE=../proto
LIB=./ZTLP/Libraries

echo "=== Step 1: Build Tunnel lib (ios-sync, no tokio) - SEPARATE target-dir ==="
cargo build \
  --manifest-path $CRATE/Cargo.toml \
  --target aarch64-apple-ios \
  --release --lib \
  --no-default-features \
  --features ios-sync \
  --target-dir $CRATE/target-ios-sync

cp $CRATE/target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a \
  $LIB/libztlp_proto_ne.a
echo "→ libztlp_proto_ne.a (ios-sync) done"

echo ""
echo "=== Step 2: Build Main App lib (default features, tokio) ==="
# Touch to force recompilation if switching from ios-sync
touch $CRATE/src/ffi.rs
cargo build \
  --manifest-path $CRATE/Cargo.toml \
  --target aarch64-apple-ios \
  --release --lib

cp $CRATE/target/aarch64-apple-ios/release/libztlp_proto.a \
  $LIB/libztlp_proto.a
echo "→ libztlp_proto.a (default/tokio) done"

echo ""
echo "=== Step 3: Simulator libs (both) ==="
# Main app sim (tokio)
lipo -create \
  $CRATE/target/aarch64-apple-ios-sim/release/libztlp_proto.a \
  $CRATE/target/x86_64-apple-ios/release/libztlp_proto.a \
  -output $LIB/libztlp_proto_sim.a

# Tunnel sim (ios-sync) - separate target-dir
cargo build \
  --manifest-path $CRATE/Cargo.toml \
  --target aarch64-apple-ios-sim --target x86_64-apple-ios \
  --release --lib \
  --no-default-features --features ios-sync \
  --target-dir $CRATE/target-ios-sync 2>/dev/null

lipo -create \
  $CRATE/target-ios-sync/aarch64-apple-ios-sim/release/libztlp_proto.a \
  $CRATE/target-ios-sync/x86_64-apple-ios/release/libztlp_proto.a \
  -output $LIB/libztlp_proto_ne_sim.a 2>/dev/null

echo ""
echo "=== Step 4: Copy header ==="
cp $CRATE/include/ztlp.h $LIB/ztlp.h

echo ""
echo "=== Step 5: Rebuild xcframework ==="
rm -rf $LIB/libztlp_proto.xcframework
xcodebuild -create-xcframework \
  -library $LIB/libztlp_proto.a -headers $CRATE/include \
  -library $LIB/libztlp_proto_sim.a -headers $CRATE/include \
  -output $LIB/libztlp_proto.xcframework

echo ""
echo "=== Done ==="
ls -lh $LIB/libztlp_proto.*.a $LIB/ztlp.h
```

## File Sizes (sanity check)

| File | Size | Target |
|------|------|--------|
| `libztlp_proto.a` | ~48MB | Main app (tokio) |
| `libztlp_proto_ne.a` | ~25MB | Tunnel (ios-sync) |
| `libztlp_proto_sim.a` | ~96MB | Main app sim (fat) |
| `libztlp_proto_ne_sim.a` | ~51MB | Tunnel sim (fat) |

## Xcode Build Step

After rebuilding libs:
1. Open Xcode: `open ~/ztlp/ios/ZTLP/ZTLP.xcodeproj`
2. **Product → Clean Build Folder** (⌘⇧K)
3. Then **Build** (⌘B)

## Common Errors

**"Undefined symbols for architecture arm64: _ztlp_client_new, _ztlp_connect, etc."**
→ You overwrote `libztlp_proto.a` with the ios-sync build. Rebuild with default features.

**"Undefined symbols for architecture arm64: _ztlp_relay_pool_new, _ztlp_ns_resolve_relays_sync, etc."**
→ Tunnel is linking an old library. Make sure `libztlp_proto_ne.a` is 25MB (ios-sync build).

**"nm shows 0 symbols"**
→ Apple `nm` on arm64 can't read newer LLVM archives. Use `ar t` to check contents instead.
