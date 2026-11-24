#!/usr/bin/env bash
# build-server-images: build the image bundle ztlp-bootstrap installs.
#
# Builds the name server, relay and admin panel from this checkout, wraps the released
# ztlp CLI as the admin gateway image, pulls the panel's database, and saves all five
# into one tarball you copy to your server:
#
#   scripts/build-server-images.sh                 # -> ztlp-server-images-<tag>.tar
#   scp ztlp-server-images-<tag>.tar scripts/ztlp-bootstrap you@server:~
#   ssh you@server ./ztlp-bootstrap --load-from ztlp-server-images-<tag>.tar
#
# Needs Docker and about 3 GB free, on x86_64 Linux (the images are linux/amd64, like
# most cloud servers).
#
# Options (env):
#   ZTLP_CLI_VERSION   released ztlp CLI for the gateway image (default: v0.37.2)
#   ZTLP_IMAGE_TAG     tag for ns/relay/admin (default: the one ztlp-bootstrap expects)
#   OUT                output file (default: ./ztlp-server-images-<tag>.tar)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BOOT="$ROOT/scripts/ztlp-bootstrap"
CLI_VERSION="${ZTLP_CLI_VERSION:-v0.37.2}"
TAG="${ZTLP_IMAGE_TAG:-$(sed -n 's/^IMAGE_TAG="\${ZTLP_IMAGE_TAG:-\(.*\)}"$/\1/p' "$BOOT")}"
DB_IMAGE="$(sed -n 's/^DB_IMAGE="\(.*\)"$/\1/p' "$BOOT")"; DB_IMAGE="${DB_IMAGE:-mariadb:11.4.7}"
GATEWAY_IMAGE="ztlp-gateway:${CLI_VERSION}"
[[ -n "$TAG" ]] || { echo "could not read the image tag from $BOOT" >&2; exit 1; }
OUT="${OUT:-$PWD/ztlp-server-images-${TAG}.tar}"

say() { printf '\033[1;36m[build]\033[0m %s\n' "$*"; }
command -v docker >/dev/null || { echo "Docker is required" >&2; exit 1; }

say "name server -> ztlp-ns:${TAG}";    docker build -q -t "ztlp-ns:${TAG}" "$ROOT/ns" >/dev/null
say "relay -> ztlp-relay:${TAG}";       docker build -q -t "ztlp-relay:${TAG}" "$ROOT/relay" >/dev/null
say "admin panel -> ztlp-admin:${TAG}"; docker build -q -t "ztlp-admin:${TAG}" "$ROOT/admin" >/dev/null

say "admin gateway -> ${GATEWAY_IMAGE} (released ztlp CLI ${CLI_VERSION})"
ctx="$(mktemp -d)"; trap 'rm -rf "$ctx"' EXIT
asset="ztlp-${CLI_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
curl -fsSL -o "$ctx/cli.tar.gz" "https://github.com/priceflex/ztlp/releases/download/${CLI_VERSION}/${asset}"
tar xzf "$ctx/cli.tar.gz" -C "$ctx"
bin="$(find "$ctx" -type f -name ztlp -perm -u+x | head -1)"
[[ -n "$bin" ]] || { echo "no ztlp binary in ${asset}" >&2; exit 1; }
[[ "$bin" == "$ctx/ztlp" ]] || cp "$bin" "$ctx/ztlp"
cat > "$ctx/Dockerfile" <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY ztlp /usr/local/bin/ztlp
USER 1000:1000
ENTRYPOINT ["ztlp"]
EOF
docker build -q -t "$GATEWAY_IMAGE" "$ctx" >/dev/null

say "database -> ${DB_IMAGE}"; docker pull -q "$DB_IMAGE" >/dev/null

say "saving bundle -> ${OUT}"
docker save -o "$OUT" "ztlp-ns:${TAG}" "ztlp-relay:${TAG}" "ztlp-admin:${TAG}" "$GATEWAY_IMAGE" "$DB_IMAGE"
say "done: $(du -h "$OUT" | cut -f1). Copy it and scripts/ztlp-bootstrap to your server."
