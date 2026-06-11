#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build-and-publish-relay.sh — build the relay image, DERIVE its tag from
#                              relay/mix.exs (never hand-typed), verify
#                              tag == mix.exs == OTP app vsn, then optionally push.
#
# THE BUG THIS PREVENTS
#   `stevenprice/ztlp-node:v0.35.0` once shipped running OTP app 0.30.0, with no
#   matching git tag — because the publish tag was typed by hand and nothing
#   asserted it matched the code. This wrapper removes the human from the tag:
#   the tag is COMPUTED from relay/mix.exs, and the image is rejected (never
#   pushed) unless scripts/verify-image-version.sh confirms all three agree.
#
# USAGE
#   scripts/build-and-publish-relay.sh [--push] [--repo <name>] [--component <c>]
#     --push            also `docker push` the verified tags (default: build+verify only)
#     --repo  <name>    image repo (default: stevenprice/ztlp-node)
#     --component <c>   relay | ns | gateway (default: relay)
#
# OUTPUT TAGS (computed, not typed)
#   <repo>:v<mix.exs version>      e.g. stevenprice/ztlp-node:v0.34.11
#   <repo>:<component>-v<version>  e.g. stevenprice/ztlp-node:relay-v0.34.11
#
# EXAMPLES
#   scripts/build-and-publish-relay.sh                 # build relay + verify, no push
#   scripts/build-and-publish-relay.sh --push          # build relay + verify + push
#   scripts/build-and-publish-relay.sh --component ns --push
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PUSH=0
REPO="stevenprice/ztlp-node"
COMPONENT="relay"

while [ $# -gt 0 ]; do
  case "$1" in
    --push) PUSH=1; shift ;;
    --repo) REPO="${2:?--repo needs a value}"; shift 2 ;;
    --component) COMPONENT="${2:?--component needs a value}"; shift 2 ;;
    *) echo "ERROR: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

case "$COMPONENT" in
  relay|ns|gateway) ;;
  *) echo "ERROR: component must be relay|ns|gateway, got '$COMPONENT'" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIX_EXS="${REPO_ROOT}/${COMPONENT}/mix.exs"
[ -f "$MIX_EXS" ] || { echo "ERROR: $MIX_EXS not found" >&2; exit 2; }

# DERIVE the version from mix.exs — single source of truth, never hand-typed.
VERSION="$(grep -oE 'version:[[:space:]]*"[^"]+"' "$MIX_EXS" | head -1 | grep -oE '"[^"]+"' | tr -d '"')"
[ -n "$VERSION" ] || { echo "ERROR: could not parse version from $MIX_EXS" >&2; exit 2; }

VERSION_TAG="${REPO}:v${VERSION}"
COMPONENT_TAG="${REPO}:${COMPONENT}-v${VERSION}"
BUILD_TAG="ztlp-${COMPONENT}-build:v${VERSION}"

echo ">> Building ${COMPONENT} image from ${REPO_ROOT}/${COMPONENT} (version ${VERSION}) ..."
docker build -t "$BUILD_TAG" "${REPO_ROOT}/${COMPONENT}"

echo ">> Verifying tag == mix.exs == OTP app vsn ..."
# Verify against the COMPUTED version tag so the (1)==(2) tag gate is also exercised.
docker tag "$BUILD_TAG" "$VERSION_TAG"
"${REPO_ROOT}/scripts/verify-image-version.sh" "$COMPONENT" "$VERSION_TAG"

docker tag "$BUILD_TAG" "$COMPONENT_TAG"
echo ">> Tagged: ${VERSION_TAG}"
echo ">>         ${COMPONENT_TAG}"

if [ "$PUSH" -eq 1 ]; then
  echo ">> Pushing verified images ..."
  docker push "$VERSION_TAG"
  docker push "$COMPONENT_TAG"
  echo ">> Pushed ${VERSION_TAG} and ${COMPONENT_TAG}"
else
  echo ">> --push not given; built + verified only. Re-run with --push to publish."
fi
