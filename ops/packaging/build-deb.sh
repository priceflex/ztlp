#!/bin/bash
# ──────────────────────────────────────────────────────────────────────
# ZTLP Debian Package Builder
#
# Builds Elixir releases and Rust CLI, then assembles .deb packages.
#
# Usage:
#   ./build-deb.sh [--version 0.1.0] [--arch amd64] [--skip-build]
#
# Prerequisites:
#   - Elixir 1.12+, Erlang/OTP 24+
#   - Rust (cargo) for CLI
#   - dpkg-deb
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="0.1.0"
ARCH="amd64"
SKIP_BUILD=false
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --version) VERSION="$2"; shift 2 ;;
        --arch) ARCH="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--version VERSION] [--arch ARCH] [--skip-build]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=== Building ZTLP ${VERSION} for ${ARCH} ==="
echo ""

# ── Step 1: Build releases ──────────────────────────────────────────

if [ "$SKIP_BUILD" = false ]; then
    echo "Building Elixir releases..."

    for component in relay gateway ns; do
        echo "  → Building ${component}..."
        cd "$REPO_ROOT/$component"
        MIX_ENV=prod mix release --overwrite 2>&1 | tail -3
    done

    echo "  → Building Rust CLI..."
    cd "$REPO_ROOT/proto"
    cargo build --release 2>&1 | tail -3

    echo "Builds complete."
    echo ""
fi

# ── Step 2: Assemble package structure ──────────────────────────────

echo "Assembling package structure..."
rm -rf "$BUILD_DIR"

# --- ztlp-relay ---
PKG="$BUILD_DIR/ztlp-relay_${VERSION}_${ARCH}"
mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/usr/lib/ztlp/relay"
mkdir -p "$PKG/lib/systemd/system"
mkdir -p "$PKG/etc/logrotate.d"
mkdir -p "$PKG/usr/share/ztlp/examples"

cp -r "$REPO_ROOT/relay/_build/prod/rel/ztlp_relay/." "$PKG/usr/lib/ztlp/relay/"
cp "$SCRIPT_DIR/../systemd/ztlp-relay.service" "$PKG/lib/systemd/system/"
cp "$SCRIPT_DIR/../logrotate/ztlp-relay" "$PKG/etc/logrotate.d/"
cp "$REPO_ROOT/config/examples/relay.yaml" "$PKG/usr/share/ztlp/examples/"
cp "$SCRIPT_DIR/debian/ztlp-relay.postinst" "$PKG/DEBIAN/postinst"
cp "$SCRIPT_DIR/debian/ztlp-relay.prerm" "$PKG/DEBIAN/prerm"
chmod 755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm"

cat > "$PKG/DEBIAN/control" << EOF
Package: ztlp-relay
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Steven Price <steve@techrockstars.com>
Depends: adduser, erlang-base (>= 1:24)
Section: net
Priority: optional
Homepage: https://ztlp.org
Description: ZTLP Relay - Zero Trust Layer Protocol relay node
 The ZTLP relay forwards encrypted traffic between nodes in a Zero
 Trust Layer Protocol network. Supports standalone and mesh
 configurations.
EOF

# --- ztlp-gateway ---
PKG="$BUILD_DIR/ztlp-gateway_${VERSION}_${ARCH}"
mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/usr/lib/ztlp/gateway"
mkdir -p "$PKG/lib/systemd/system"
mkdir -p "$PKG/etc/logrotate.d"
mkdir -p "$PKG/usr/share/ztlp/examples"

cp -r "$REPO_ROOT/gateway/_build/prod/rel/ztlp_gateway/." "$PKG/usr/lib/ztlp/gateway/"
cp "$SCRIPT_DIR/../systemd/ztlp-gateway.service" "$PKG/lib/systemd/system/"
cp "$SCRIPT_DIR/../logrotate/ztlp-gateway" "$PKG/etc/logrotate.d/"
cp "$REPO_ROOT/config/examples/gateway.yaml" "$PKG/usr/share/ztlp/examples/"
cp "$SCRIPT_DIR/debian/ztlp-gateway.postinst" "$PKG/DEBIAN/postinst"
cp "$SCRIPT_DIR/debian/ztlp-gateway.prerm" "$PKG/DEBIAN/prerm"
chmod 755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm"

cat > "$PKG/DEBIAN/control" << EOF
Package: ztlp-gateway
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Steven Price <steve@techrockstars.com>
Depends: adduser, erlang-base (>= 1:24)
Section: net
Priority: optional
Homepage: https://ztlp.org
Description: ZTLP Gateway - Zero Trust Layer Protocol TCP bridge
 The ZTLP gateway bridges ZTLP sessions to TCP backend services.
EOF

# --- ztlp-ns ---
PKG="$BUILD_DIR/ztlp-ns_${VERSION}_${ARCH}"
mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/usr/lib/ztlp/ns"
mkdir -p "$PKG/lib/systemd/system"
mkdir -p "$PKG/etc/logrotate.d"
mkdir -p "$PKG/usr/share/ztlp/examples"

cp -r "$REPO_ROOT/ns/_build/prod/rel/ztlp_ns/." "$PKG/usr/lib/ztlp/ns/"
cp "$SCRIPT_DIR/../systemd/ztlp-ns.service" "$PKG/lib/systemd/system/"
cp "$SCRIPT_DIR/../logrotate/ztlp-ns" "$PKG/etc/logrotate.d/"
cp "$REPO_ROOT/config/examples/ns.yaml" "$PKG/usr/share/ztlp/examples/"
cp "$SCRIPT_DIR/debian/ztlp-ns.postinst" "$PKG/DEBIAN/postinst"
cp "$SCRIPT_DIR/debian/ztlp-ns.prerm" "$PKG/DEBIAN/prerm"
chmod 755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm"

cat > "$PKG/DEBIAN/control" << EOF
Package: ztlp-ns
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Steven Price <steve@techrockstars.com>
Depends: adduser, erlang-base (>= 1:24)
Section: net
Priority: optional
Homepage: https://ztlp.org
Description: ZTLP-NS - Zero Trust Layer Protocol namespace server
 Distributed namespace server for ZTLP identity resolution.
EOF

# --- ztlp-cli ---
PKG="$BUILD_DIR/ztlp-cli_${VERSION}_${ARCH}"
mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/usr/bin"

cp "$REPO_ROOT/proto/target/release/ztlp-cli" "$PKG/usr/bin/ztlp"
chmod 755 "$PKG/usr/bin/ztlp"

cat > "$PKG/DEBIAN/control" << EOF
Package: ztlp-cli
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Steven Price <steve@techrockstars.com>
Section: net
Priority: optional
Homepage: https://ztlp.org
Description: ZTLP CLI - Zero Trust Layer Protocol command-line tool
 Unified CLI for ZTLP operations: key generation, peer connections,
 packet inspection, and relay management.
EOF

# --- ztlp (meta-package) ---
PKG="$BUILD_DIR/ztlp_${VERSION}_all"
mkdir -p "$PKG/DEBIAN"

cat > "$PKG/DEBIAN/control" << EOF
Package: ztlp
Version: ${VERSION}
Architecture: all
Maintainer: Steven Price <steve@techrockstars.com>
Depends: ztlp-relay (= ${VERSION}), ztlp-gateway (= ${VERSION}), ztlp-ns (= ${VERSION}), ztlp-cli (= ${VERSION})
Section: net
Priority: optional
Homepage: https://ztlp.org
Description: ZTLP - Zero Trust Layer Protocol (meta-package)
 Installs all ZTLP components: relay, gateway, namespace server, and CLI.
EOF

# ── Step 3: Build .deb files ────────────────────────────────────────

echo ""
echo "Building .deb packages..."

OUTPUT_DIR="$SCRIPT_DIR/dist"
mkdir -p "$OUTPUT_DIR"

for pkg_dir in "$BUILD_DIR"/ztlp*; do
    pkg_name=$(basename "$pkg_dir")
    echo "  → ${pkg_name}.deb"
    dpkg-deb --build "$pkg_dir" "$OUTPUT_DIR/${pkg_name}.deb"
done

echo ""
echo "=== Done! Packages in $OUTPUT_DIR ==="
ls -lh "$OUTPUT_DIR"/*.deb
