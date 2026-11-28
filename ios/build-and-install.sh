#!/usr/bin/env bash
#
# Build the ZTLP iOS app (Rust agent + Swift app + packet tunnel extension)
# and install it on the attached iPhone.
#
# Run it in Terminal on the Mac (a normal GUI login, so the keychain is
# unlocked for signing):
#
#   ios/build-and-install.sh                     build, sign, install
#   ios/build-and-install.sh --launch            ... and start the app
#   ios/build-and-install.sh --device <udid|name>
#   ios/build-and-install.sh --rust-dir <path-to-proto>
#   ios/build-and-install.sh --no-sign           compile check, real Rust lib, no signing
#   ios/build-and-install.sh --no-sign --stub    compile check against a stub library
#   ios/build-and-install.sh --test              unit tests on an iOS Simulator (stub library)
#
# Environment:
#   ZTLP_RUST_DIR   same as --rust-dir (default: <repo>/proto)
#   ZTLP_TEAM       Apple developer team id (default: 5527A7TH5P)
#   ZTLP_SIMULATOR  simulator name for --test (default: first available iPhone)
#
set -euo pipefail

IOS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$IOS_DIR/.." && pwd)"
PROJECT="$IOS_DIR/ZTLP/ZTLP.xcodeproj"
LIB_DIR="$IOS_DIR/ZTLP/Libraries"
BUILD_DIR="$IOS_DIR/build"
DERIVED="$BUILD_DIR/DerivedData"
RUST_TARGET="aarch64-apple-ios"
APP_BUNDLE_ID="com.ztlp.app"
CONTRACT_SYMBOLS="ztlp_ios_init ztlp_ios_is_enrolled ztlp_ios_enroll ztlp_ios_ensure_ca
ztlp_ios_ca_root_pem ztlp_ios_agent_start ztlp_ios_agent_stop ztlp_ios_status_json
ztlp_ios_last_error ztlp_ios_network_changed"

RUST_DIR="${ZTLP_RUST_DIR:-$REPO_ROOT/proto}"
TEAM="${ZTLP_TEAM:-5527A7TH5P}"
DEVICE=""
NO_SIGN=0
STUB=0
TEST=0
LAUNCH=0

step() { printf '\n==> %s\n' "$*"; }
die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --rust-dir) [ $# -ge 2 ] || die "--rust-dir needs a path"; RUST_DIR="$2"; shift 2 ;;
    --device)   [ $# -ge 2 ] || die "--device needs a udid or name"; DEVICE="$2"; shift 2 ;;
    --no-sign)  NO_SIGN=1; shift ;;
    --stub)     STUB=1; shift ;;
    --test)     TEST=1; shift ;;
    --launch)   LAUNCH=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

if [ "$STUB" = 1 ] && [ "$NO_SIGN" = 0 ] && [ "$TEST" = 0 ]; then
  die "--stub builds an app that cannot work. Use it only with --no-sign (or use --test)."
fi

command -v xcodebuild >/dev/null 2>&1 || die "xcodebuild not found. Install Xcode and run: sudo xcode-select -s /Applications/Xcode.app"
[ -d "$PROJECT" ] || die "missing $PROJECT"

# Run xcodebuild, keep the full log, show the lines that matter.
run_xcodebuild() {
  local log="$1"; shift
  mkdir -p "$BUILD_DIR"
  set +e
  xcodebuild "$@" 2>&1 | tee "$log" \
    | grep -E --line-buffered '(error:|warning: unre|\*\* (BUILD|TEST) |^Test Suite .* (passed|failed)|Executed [0-9]+ tests|No profiles|requires a provisioning|No signing certificate|errSec)'
  local rc="${PIPESTATUS[0]}"
  set -e
  return "$rc"
}

# ---------------------------------------------------------------- unit tests
if [ "$TEST" = 1 ]; then
  step "Building the stub library for the simulator"
  STUB_DIR="$BUILD_DIR/stub/iphonesimulator"
  "$IOS_DIR/scripts/make-stub-lib.sh" iphonesimulator "$STUB_DIR"

  SIM="${ZTLP_SIMULATOR:-}"
  if [ -z "$SIM" ]; then
    SIM="$(xcrun simctl list devices available | sed -n 's/^ *\(iPhone[^(]*[^ (]\) *(.*/\1/p' | head -n 1)"
  fi
  [ -n "$SIM" ] || die "no iPhone simulator found. Install one in Xcode > Settings > Components, or set ZTLP_SIMULATOR."

  step "Running unit tests on the '$SIM' simulator"
  LOG="$BUILD_DIR/xcodebuild-test.log"
  if ! run_xcodebuild "$LOG" -project "$PROJECT" -scheme ZTLP -configuration Debug \
      -sdk iphonesimulator -destination "platform=iOS Simulator,name=$SIM" \
      -derivedDataPath "$DERIVED" ZTLP_LIB_DIR="$STUB_DIR" \
      CODE_SIGNING_ALLOWED=NO test; then
    tail -n 40 "$LOG" >&2
    die "unit tests failed. Full log: $LOG"
  fi
  echo "Unit tests passed. Full log: $LOG"
  exit 0
fi

# ------------------------------------------------------------- Rust library
XCODE_LIB_DIR="$LIB_DIR"
if [ "$STUB" = 1 ]; then
  step "Building the stub library (compile check only, not the real agent)"
  XCODE_LIB_DIR="$BUILD_DIR/stub/iphoneos"
  "$IOS_DIR/scripts/make-stub-lib.sh" iphoneos "$XCODE_LIB_DIR"
else
  step "Building the Rust agent for $RUST_TARGET (release) in $RUST_DIR"
  [ -f "$RUST_DIR/Cargo.toml" ] || die "no Cargo.toml in $RUST_DIR. Pass --rust-dir <path-to-proto> or set ZTLP_RUST_DIR."
  # Prefer the rustup toolchain: a Homebrew cargo earlier on PATH has no iOS target.
  if [ -x "$HOME/.cargo/bin/cargo" ]; then
    PATH="$HOME/.cargo/bin:$PATH"
  fi
  command -v cargo >/dev/null 2>&1 || die "cargo not found. Install Rust from https://rustup.rs, then: rustup target add $RUST_TARGET"
  if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed 2>/dev/null | grep -qx "$RUST_TARGET"; then
    die "Rust target $RUST_TARGET is not installed. Run: rustup target add $RUST_TARGET"
  fi
  (cd "$RUST_DIR" && IPHONEOS_DEPLOYMENT_TARGET=16.0 cargo build --release --lib --target "$RUST_TARGET") \
    || die "the Rust agent did not compile for $RUST_TARGET (errors above). If this tree is not the iOS agent branch, pass --rust-dir <path-to-proto>."

  RUST_LIB="$RUST_DIR/target/$RUST_TARGET/release/libztlp_proto.a"
  [ -f "$RUST_LIB" ] || die "cargo finished but $RUST_LIB is missing."

  step "Checking the library implements the iOS contract"
  # Apple's nm cannot read the Rust objects in the archive, so prove the
  # symbols by linking a probe that references every contract function.
  mkdir -p "$BUILD_DIR"
  PROBE_C="$BUILD_DIR/contract_probe.c"
  {
    for sym in $CONTRACT_SYMBOLS; do echo "extern void $sym(void);"; done
    echo "int main(void) { void (*f[])(void) = {"
    for sym in $CONTRACT_SYMBOLS; do echo "  $sym,"; done
    echo "}; return f[0] == 0; }"
  } > "$PROBE_C"
  if ! xcrun --sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 "$PROBE_C" "$RUST_LIB" \
      -lresolv -framework Foundation -framework Security -framework SystemConfiguration -framework CoreFoundation \
      -o "$BUILD_DIR/contract_probe" > "$BUILD_DIR/contract_probe.log" 2>&1; then
    tail -15 "$BUILD_DIR/contract_probe.log" >&2
    die "$RUST_LIB does not link with every function in ztlp_ios.h (see $BUILD_DIR/contract_probe.log).
Point --rust-dir at a Rust tree that implements the iOS contract."
  fi
  rm -f "$BUILD_DIR/contract_probe"

  step "Copying the library and header into ios/ZTLP/Libraries"
  mkdir -p "$LIB_DIR"
  cp "$RUST_LIB" "$LIB_DIR/libztlp_proto.a"
  if [ -f "$RUST_DIR/include/ztlp_ios.h" ]; then
    if ! cmp -s "$RUST_DIR/include/ztlp_ios.h" "$LIB_DIR/ztlp_ios.h"; then
      echo "note: ios/ZTLP/Libraries/ztlp_ios.h differed from the Rust header and was replaced. Commit the change."
      cp "$RUST_DIR/include/ztlp_ios.h" "$LIB_DIR/ztlp_ios.h"
    fi
  else
    echo "note: $RUST_DIR/include/ztlp_ios.h not found; keeping ios/ZTLP/Libraries/ztlp_ios.h"
  fi
  ls -lh "$LIB_DIR/libztlp_proto.a"
fi

# ------------------------------------------------------------------- Xcode
APP="$DERIVED/Build/Products/Release-iphoneos/ZTLP.app"
LOG="$BUILD_DIR/xcodebuild.log"
COMMON=(-project "$PROJECT" -scheme ZTLP -configuration Release -sdk iphoneos
        -destination 'generic/platform=iOS' -derivedDataPath "$DERIVED"
        ZTLP_LIB_DIR="$XCODE_LIB_DIR")

if [ "$NO_SIGN" = 1 ]; then
  step "Building the app without signing (compile check)"
  if ! run_xcodebuild "$LOG" "${COMMON[@]}" CODE_SIGNING_ALLOWED=NO build; then
    tail -n 40 "$LOG" >&2
    die "build failed. Full log: $LOG"
  fi
else
  step "Building and signing the app (team $TEAM)"
  if ! run_xcodebuild "$LOG" "${COMMON[@]}" -allowProvisioningUpdates \
      DEVELOPMENT_TEAM="$TEAM" CODE_SIGN_STYLE=Automatic build; then
    tail -n 40 "$LOG" >&2
    die "build failed. Full log: $LOG
If the errors mention signing or provisioning:
  - run this script in Terminal on the Mac itself, not over SSH (the keychain must be unlocked)
  - open Xcode > Settings > Accounts and check the Apple ID for team $TEAM is signed in
  - connect and unlock the iPhone once so Xcode can register it
Use --no-sign to check that the code compiles without signing."
  fi
fi

[ -d "$APP" ] || die "build reported success but $APP is missing."
[ -d "$APP/PlugIns/ZTLPTunnel.appex" ] || die "the app was built without its tunnel extension ($APP/PlugIns/ZTLPTunnel.appex is missing)."
echo "App:       $APP"
echo "Extension: $APP/PlugIns/ZTLPTunnel.appex"
ls -l "$APP/ZTLP" "$APP/PlugIns/ZTLPTunnel.appex/ZTLPTunnel" | awk '{printf "  %10d bytes  %s\n", $5, $NF}'

if [ "$NO_SIGN" = 1 ]; then
  echo
  echo "Compile check finished. Nothing was signed or installed."
  exit 0
fi

# ----------------------------------------------------------------- install
if [ -z "$DEVICE" ]; then
  step "Looking for a connected iPhone"
  DEVICES_JSON="$BUILD_DIR/devices.json"
  xcrun devicectl list devices --json-output "$DEVICES_JSON" >/dev/null 2>&1 \
    || die "could not list devices (xcrun devicectl list devices failed)."
  # One line per usable device: <identifier><TAB><name>
  FOUND="$(/usr/bin/python3 - "$DEVICES_JSON" 2>"$BUILD_DIR/devices.err" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    devices = json.load(f).get("result", {}).get("devices", [])
for d in devices:
    hw = d.get("hardwareProperties", {})
    conn = d.get("connectionProperties", {})
    if hw.get("platform") != "iOS" or hw.get("reality", "physical") != "physical":
        continue
    if conn.get("pairingState") != "paired":
        print("UNPAIRED\t%s\t%s" % (d.get("identifier", ""), d.get("deviceProperties", {}).get("name", "?")), file=sys.stderr)
        continue
    if conn.get("tunnelState", "unavailable") == "unavailable":
        continue
    print("%s\t%s" % (d.get("identifier", ""), d.get("deviceProperties", {}).get("name", "?")))
PY
)"
  rm -f "$DEVICES_JSON"
  UNPAIRED="$(grep '^UNPAIRED' "$BUILD_DIR/devices.err" 2>/dev/null | head -1 || true)"
  if [ -z "$FOUND" ] && [ -n "$UNPAIRED" ]; then
    UP_ID="$(printf '%s' "$UNPAIRED" | cut -f2)"
    die "$(printf '%s' "$UNPAIRED" | cut -f3) is plugged in but not paired with this Mac.
Unlock the phone, then run:   xcrun devicectl manage pair --device $UP_ID
Tap Trust on the phone and enter its passcode, then run this script again.
The app is built and signed at: $APP"
  fi
  COUNT="$(printf '%s' "$FOUND" | grep -c . || true)"
  if [ "$COUNT" = 0 ]; then
    xcrun devicectl list devices 2>/dev/null || true
    die "no iPhone is connected. Plug it in with a cable, unlock it, tap Trust if asked, and make sure Developer Mode is on (Settings > Privacy & Security > Developer Mode). Then run this again.
The app is built and signed at: $APP"
  fi
  if [ "$COUNT" != 1 ]; then
    printf '%s\n' "$FOUND" >&2
    die "more than one iPhone is connected. Pick one with --device <identifier or name>."
  fi
  DEVICE="$(printf '%s' "$FOUND" | cut -f1)"
  echo "Using $(printf '%s' "$FOUND" | cut -f2) ($DEVICE)"
fi

step "Installing on $DEVICE"
xcrun devicectl device install app --device "$DEVICE" "$APP" \
  || die "install failed. Unlock the iPhone and keep it connected, then run this again. If iOS says the developer is not trusted, open Settings > General > VPN & Device Management on the phone and trust the developer."

if [ "$LAUNCH" = 1 ]; then
  step "Starting ZTLP on the iPhone"
  xcrun devicectl device process launch --device "$DEVICE" "$APP_BUNDLE_ID" \
    || die "the app is installed but could not be started. Unlock the iPhone and open ZTLP by hand."
fi

echo
echo "Done. Open ZTLP on the iPhone and scan your enrollment code."
