#!/usr/bin/env bash
# Run gateway `mix test --cover` inside the same OTP-26 image the prod
# Dockerfile uses (sandbox only has OTP 25; quicer needs 26+).
# Mounts ztlp/ read-write at /src so ns (path dep ../ns) resolves; uses a
# separate _build/deps dir so it doesn't clobber host builds.
set -euo pipefail
cd "$(dirname "$0")/.."
exec docker run --rm \
  -v "$PWD":/src -w /src/gateway \
  -e MIX_ENV=test -e ZTLP_CA_PASSPHRASE=docker-cover-test \
  -e MIX_BUILD_PATH=/src/gateway/_build_docker \
  -e MIX_DEPS_PATH=/src/gateway/deps_docker \
  -e HEX_HOME=/src/gateway/.hex_docker -e MIX_HOME=/src/gateway/.mix_docker \
  hexpm/elixir:1.15.7-erlang-26.2.5-debian-bookworm-20240423 \
  bash -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends build-essential cmake git curl patch pkg-config libssl-dev perl ca-certificates >/dev/null && \
    mix local.hex --force && mix local.rebar --force && \
    mix deps.get && mix test --cover 2>&1 | tail -80'
