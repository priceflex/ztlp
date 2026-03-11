#!/usr/bin/env bash
#
# Build ZTLP OTP releases.
#
# Usage:
#   ./rel/build-release.sh [relay|ns|gateway|all] [--upgrade]
#
# Options:
#   --upgrade   Build upgrade tarballs (requires a prior release to diff against)
#
# Examples:
#   ./rel/build-release.sh all            # Build all 3 releases
#   ./rel/build-release.sh relay          # Build relay only
#   ./rel/build-release.sh gateway --upgrade  # Build gateway upgrade tarball

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

SERVICES=()
UPGRADE=false

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --upgrade)
      UPGRADE=true
      ;;
    relay|ns|gateway)
      SERVICES+=("$arg")
      ;;
    all)
      SERVICES=(relay ns gateway)
      ;;
    -h|--help)
      echo "Usage: $0 [relay|ns|gateway|all] [--upgrade]"
      echo ""
      echo "Build ZTLP OTP releases."
      echo ""
      echo "Options:"
      echo "  --upgrade   Build upgrade tarballs (requires prior release)"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [relay|ns|gateway|all] [--upgrade]" >&2
      exit 1
      ;;
  esac
done

# Default to all if no services specified
if [ ${#SERVICES[@]} -eq 0 ]; then
  SERVICES=(relay ns gateway)
fi

# Map service names to release names
declare -A RELEASE_NAMES=(
  [relay]=ztlp_relay
  [ns]=ztlp_ns
  [gateway]=ztlp_gateway
)

build_service() {
  local svc="$1"
  local release_name="${RELEASE_NAMES[$svc]}"
  local svc_dir="$ROOT_DIR/$svc"

  echo "=========================================="
  echo "Building release: $release_name"
  echo "=========================================="

  if [ ! -d "$svc_dir" ]; then
    echo "ERROR: Service directory not found: $svc_dir" >&2
    return 1
  fi

  cd "$svc_dir"

  # Validate appup file exists if building upgrade
  if [ "$UPGRADE" = true ]; then
    local appup_file="rel/appups/${release_name}.appup"
    if [ ! -f "$appup_file" ]; then
      echo "WARNING: No appup file found at $appup_file" >&2
      echo "  Hot upgrade will not work without appup instructions." >&2
      echo "  Create one before building upgrade tarballs." >&2
    else
      echo "  ✓ Appup file found: $appup_file"
    fi
  fi

  # Clean and compile
  echo "  Compiling..."
  MIX_ENV=prod mix compile --force

  # Build release
  if [ "$UPGRADE" = true ]; then
    echo "  Building upgrade release..."
    MIX_ENV=prod mix release "$release_name" --overwrite --upgrade 2>&1 || {
      echo "  NOTE: --upgrade requires a prior release. Building standard release instead." >&2
      MIX_ENV=prod mix release "$release_name" --overwrite
    }
  else
    echo "  Building release..."
    MIX_ENV=prod mix release "$release_name" --overwrite
  fi

  echo "  ✓ Release built: _build/prod/rel/$release_name"
  echo ""
}

echo "ZTLP Release Builder"
echo "Services: ${SERVICES[*]}"
echo "Upgrade:  $UPGRADE"
echo ""

FAILED=()
for svc in "${SERVICES[@]}"; do
  if ! build_service "$svc"; then
    FAILED+=("$svc")
  fi
done

echo "=========================================="
if [ ${#FAILED[@]} -gt 0 ]; then
  echo "FAILED: ${FAILED[*]}"
  exit 1
else
  echo "All releases built successfully."
fi
