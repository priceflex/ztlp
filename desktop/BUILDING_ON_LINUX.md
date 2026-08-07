# ZTLP Desktop — Building on Linux (Kali / Debian-based)

## Status

The Tauri desktop app builds and runs correctly on Linux. Verified on Kali
GNU/Linux Rolling (2024.2) — produces working `.deb`, `.rpm`, and
`.AppImage` bundles, and the built app launches and renders correctly,
including the Setup Wizard's live CA/DNS status detection
(see commit `d90c3c3`).

## Prerequisites

```bash
# Runtime libs (often already present on a desktop Kali install)
sudo apt-get install -y \
  libwebkit2gtk-4.1-0 libjavascriptcoregtk-4.1-0 \
  libayatana-appindicator3-1 librsvg2-2

# Build-time dev headers (NOT installed by default — this is the gap
# that blocks a fresh build with cryptic linker/pkg-config errors)
sudo apt-get install -y \
  libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev \
  libayatana-appindicator3-dev librsvg2-dev libssl-dev libgtk-3-dev \
  libsoup-3.0-dev libzstd-dev pkg-config patchelf build-essential

# Node/npm — NOT needed for npm deps (the frontend is plain HTML/JS/CSS,
# no build step), but the `cargo tauri` CLI's own build process expects
# node/npm to exist on PATH. Install via nvm (avoids Kali's apt node
# version conflicts):
curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.nvm/nvm.sh
nvm install --lts
```

## Known toolchain pitfall: GCC 15 miscompiles some crates' C code on Kali Rolling

Kali Rolling ships GCC 15.3.0, which emits an assembly `.base64` pseudo-op
that Kali's `binutils` assembler (2.42) doesn't recognize:

```
Error: unknown pseudo-op: `.base64'
```

This breaks `cargo install tauri-cli` (fails compiling `zstd-sys` and then
`ring`) and will break `cargo tauri build` itself if any dependency in the
build needs `cc` for C code. **Fix: force clang instead of gcc** for any
cargo build/install on this box:

```bash
export CC=clang
export CXX=clang++
```

Clang 17/18 (`/usr/bin/clang`) is already installed on Kali by default and
compiles the same code without issue — this is a GCC codegen regression,
not a problem with the crates themselves.

## Installing the Tauri CLI

`cargo install tauri-cli` compiling from source hits the GCC issue above
even with `CC=clang` set for large dependency trees, and can take 10+
minutes. **Faster and more reliable: use the prebuilt binary release**
instead of compiling from source:

```bash
cd /tmp
curl -fsSL -o cargo-tauri.tgz \
  https://github.com/tauri-apps/tauri/releases/download/tauri-cli-v2.9.1/cargo-tauri-x86_64-unknown-linux-gnu.tgz
tar xzf cargo-tauri.tgz
mkdir -p ~/.cargo/bin
cp cargo-tauri ~/.cargo/bin/
chmod +x ~/.cargo/bin/cargo-tauri
cargo tauri --version   # should print e.g. "tauri-cli 2.9.1"
```

(Check https://github.com/tauri-apps/tauri/releases for the current
`tauri-cli-v*` tag if 2.9.1 is stale.)

## The sidecar binary gotcha

`desktop/src-tauri/tauri.conf.json` declares an `externalBin` sidecar:

```json
"externalBin": ["binaries/ztlp"]
```

Tauri's build step looks for this file suffixed with the **exact target
triple**, not the bare name — i.e. it wants
`desktop/src-tauri/binaries/ztlp-x86_64-unknown-linux-gnu`, not
`desktop/src-tauri/binaries/ztlp`. If it's missing you'll get:

```
resource path `binaries/ztlp-x86_64-unknown-linux-gnu` doesn't exist
```

Fix: build (or copy an already-built) `ztlp` CLI binary into place with the
triple suffix:

```bash
cp proto/target/release/ztlp \
   desktop/src-tauri/binaries/ztlp-x86_64-unknown-linux-gnu
chmod +x desktop/src-tauri/binaries/ztlp-x86_64-unknown-linux-gnu
```

This isn't committed to the repo (binaries shouldn't be checked in) — every
fresh clone needs this step before `cargo tauri build` will succeed.

## Building

```bash
cd desktop
CC=clang CXX=clang++ cargo tauri build
```

First build compiles the whole dependency tree (~5-10 min); the AppImage
bundling step also downloads `linuxdeploy` + plugins on first run (small,
one-time). Output lands in:

```
desktop/src-tauri/target/release/bundle/deb/ZTLP_<version>_amd64.deb
desktop/src-tauri/target/release/bundle/rpm/ZTLP-<version>-1.x86_64.rpm
desktop/src-tauri/target/release/bundle/appimage/ZTLP_<version>_amd64.AppImage
```

## Running headless (for CI / remote verification without a real display)

```bash
Xvfb :99 -screen 0 1280x800x24 &
DISPLAY=:99 ./ZTLP_<version>_amd64.AppImage --appimage-extract-and-run &
sleep 5
DISPLAY=:99 import -window root screenshot.png   # ImageMagick
```

Verified this way on 2026-08-06: the app launches, renders the sidebar nav
(Home/Setup/Services/Identity/Enrollment/Settings), and the Setup Wizard
correctly shows live, non-hardcoded CA/DNS status (CA chain
generated ✓ / CA not installed in system trust ✗ / DNS routes missing ✗ for
a fresh unenrolled test identity) — confirming the Linux status-detector
fix from commit `d90c3c3` actually works end-to-end, not just in code
review.
