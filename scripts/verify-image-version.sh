#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# verify-image-version.sh — assert image tag == mix.exs version == built OTP
#                           application vsn for a ztlp Elixir component.
#
# WHY THIS EXISTS
#   The prod relay once shipped under the image tag `stevenprice/ztlp-node:v0.35.0`
#   while the OTP application baked into that image was actually `0.30.0` (and no
#   `v0.35.0` git tag existed at all). Nothing asserted that the three things that
#   MUST agree actually agreed:
#       (1) the Docker image TAG,
#       (2) the component's mix.exs `version:`,
#       (3) the OTP application vsn compiled INTO the image.
#   So a "newer" tag silently shipped ancient code, and a behind-NAT box was the
#   first to exercise relay-forwarding and expose it. This script makes (2)==(3)
#   a hard gate, and (1)==(2) a hard gate whenever the image ref carries a
#   vX.Y.Z tag. Run it in CI (image-version-gate.yml) and from the build/publish
#   wrapper before any push.
#
# USAGE
#   scripts/verify-image-version.sh <component> <image-ref>
#     <component>  one of: relay | ns | gateway
#     <image-ref>  a built local image, e.g. ztlp-relay:dev  or
#                  stevenprice/ztlp-node:v0.34.11
#
#   Exit 0  => image tag (if any) == mix.exs version == built OTP app vsn.
#   Exit !0 => mismatch (prints which pair disagreed) or boot/read failure.
#
# EXAMPLES
#   scripts/verify-image-version.sh relay ztlp-relay:dev
#   scripts/verify-image-version.sh relay stevenprice/ztlp-node:v0.34.11
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

COMPONENT="${1:?usage: verify-image-version.sh <relay|ns|gateway> <image-ref>}"
IMAGE_REF="${2:?usage: verify-image-version.sh <relay|ns|gateway> <image-ref>}"

case "$COMPONENT" in
  relay|ns|gateway) ;;
  *) echo "ERROR: component must be relay|ns|gateway, got '$COMPONENT'" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIX_EXS="${REPO_ROOT}/${COMPONENT}/mix.exs"
APP="ztlp_${COMPONENT}"          # OTP application atom: ztlp_relay / ztlp_ns / ztlp_gateway
BIN="/app/bin/${APP}"            # release bin inside the image

[ -f "$MIX_EXS" ] || { echo "ERROR: $MIX_EXS not found" >&2; exit 2; }

# (2) the declared source version — first `version: "X.Y.Z"` in mix.exs
MIX_VERSION="$(grep -oE 'version:[[:space:]]*"[^"]+"' "$MIX_EXS" | head -1 | grep -oE '"[^"]+"' | tr -d '"')"
[ -n "$MIX_VERSION" ] || { echo "ERROR: could not parse version from $MIX_EXS" >&2; exit 2; }

# (3) the OTP application vsn actually compiled into the image. `eval` boots a
# one-off BEAM with the release's code loaded; load the app so its .app metadata
# is readable, then print its :vsn. Override the entrypoint because the image's
# default ENTRYPOINT is the bin itself with CMD ["start"].
echo ">> Reading OTP app vsn from image '${IMAGE_REF}' (${APP}) ..."
APP_VSN="$(
  docker run --rm --entrypoint "$BIN" "$IMAGE_REF" \
    eval "Application.load(:${APP}); IO.puts(Application.spec(:${APP}, :vsn))" \
    2>/dev/null | tr -d '\r' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$' | head -1 || true
)"
[ -n "$APP_VSN" ] || {
  echo "ERROR: could not read OTP app vsn for ${APP} from ${IMAGE_REF}." >&2
  echo "       (image failed to boot, or ${BIN} is not present)" >&2
  exit 1
}

# (1) the image TAG, if the ref carries a vX.Y.Z tag (strip leading 'v').
IMAGE_TAG="${IMAGE_REF##*:}"
TAG_VERSION=""
if [[ "$IMAGE_TAG" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  TAG_VERSION="${IMAGE_TAG#v}"
fi

echo "   component : ${COMPONENT}"
echo "   mix.exs   : ${MIX_VERSION}"
echo "   OTP app   : ${APP_VSN}"
echo "   image tag : ${IMAGE_TAG}${TAG_VERSION:+ (=> ${TAG_VERSION})}"

FAIL=0

# Hard gate: (2) == (3). This is the one that would have caught v0.35.0/0.30.0.
if [ "$MIX_VERSION" != "$APP_VSN" ]; then
  echo "MISMATCH: mix.exs version (${MIX_VERSION}) != OTP app vsn in image (${APP_VSN})" >&2
  echo "          The image was built from code whose mix.exs vsn differs from the" >&2
  echo "          source tree's. Rebuild the image from this commit's ${COMPONENT}/." >&2
  FAIL=1
fi

# Hard gate: (1) == (2), only when the ref carries a vX.Y.Z tag.
if [ -n "$TAG_VERSION" ] && [ "$TAG_VERSION" != "$MIX_VERSION" ]; then
  echo "MISMATCH: image tag (${TAG_VERSION}) != mix.exs version (${MIX_VERSION})" >&2
  echo "          Never hand-type the tag. Derive it from mix.exs (see" >&2
  echo "          scripts/build-and-publish-relay.sh)." >&2
  FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
  echo "RESULT: FAIL" >&2
  exit 1
fi

echo "RESULT: OK — tag == mix.exs == OTP app vsn (${APP_VSN})"
