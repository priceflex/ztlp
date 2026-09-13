# ─────────────────────────────────────────────────────────────
# ZTLP Gateway — Elixir OTP release (multi-stage)
# Zero external deps — pure Elixir/OTP
#
# Build context is the gateway/ directory (consistent with relay/NS):
#   docker build -t ztlp-gateway ./gateway
# ─────────────────────────────────────────────────────────────

# ── Stage 1: Build ──────────────────────────────────────────
# Bumped bullseye/OTP-24 -> bookworm/OTP-26 for Task Q1 (Session 3):
# quicer (msquic NIF) states OTP >= 25 and its CI/prebuilts only cover
# OTP 26/27/28. msquic is compiled from source at deps.compile time
# (network access to github.com needed), which needs cmake >= 3.16 —
# not present in the old bullseye-based builder image. See
# ztlp-rust-elixir-interop skill / SESSION 3 status update in
# ztlp-cloud-demo-plan.md for the OTP-24->26 bump rationale and R4
# (re-run the FULL mix test suite after the bump before touching QUIC).
FROM hexpm/elixir:1.15.7-erlang-26.2.5-debian-bookworm-20240423 AS builder

ENV MIX_ENV=prod
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git curl patch pkg-config libssl-dev perl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mix local.hex --force && mix local.rebar --force

# Copy gateway manifest first (layer caching)
COPY mix.exs ./

# NS is a test-only dep — not needed for prod release, but mix.exs
# references it at path "../ns". Create a minimal stub so mix doesn't fail.
# The stub is created at /ns (outside WORKDIR) because mix resolves
# path: "../ns" relative to the gateway project root (/build).
RUN mkdir -p /ns/lib && \
    echo 'defmodule ZtlpNs.MixProject do\n  use Mix.Project\n  def project, do: [app: :ztlp_ns, version: "0.1.0"]\nend' > /ns/mix.exs && \
    echo "defmodule ZtlpNs do\nend" > /ns/lib/stub.ex

# Create app stub for compile
RUN mkdir -p lib && echo "defmodule ZtlpGateway do\nend" > lib/stub.ex && \
    mix deps.get --only prod 2>/dev/null || true && \
    rm lib/stub.ex

# Copy config and source
COPY config/ config/
COPY lib/ lib/
COPY rel/ rel/

# Compile and build release
RUN mix compile && \
    mix release ztlp_gateway

# ── Stage 2: Runtime ────────────────────────────────────────
# Runtime bumped bullseye -> bookworm to match the builder's glibc/OpenSSL
# ABI (Task Q1, Session 3 — see builder stage comment). quicer's msquic NIF
# needs libstdc++6/libnuma1 in addition to the OTP/crypto libs the legacy
# gateway already required.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libncurses6 libtinfo6 libssl3 libstdc++6 libnuma1 locales ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
    && locale-gen

ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

RUN useradd --system --create-home ztlp
COPY --from=builder /build/_build/prod/rel/ztlp_gateway/ /app/

# Health check script
RUN printf '#!/bin/sh\n/app/bin/ztlp_gateway rpc "IO.puts(:ok)" 2>/dev/null | grep -q "ok"\n' > /app/healthcheck.sh \
    && chmod +x /app/healthcheck.sh

RUN chown -R ztlp:ztlp /app
USER ztlp
WORKDIR /app

# Default environment
ENV ZTLP_GATEWAY_PORT=23097
ENV ZTLP_LOG_FORMAT=json
ENV ZTLP_LOG_LEVEL=info
ENV ZTLP_GATEWAY_METRICS_ENABLED=true
ENV ZTLP_GATEWAY_METRICS_PORT=9102
# Erlang distribution cookie — set via -e RELEASE_COOKIE at deploy time.
# No default: Mix generates a unique random cookie at build time when
# RELEASE_COOKIE is not provided, preventing cookie-guessing attacks.

EXPOSE 23097/udp
EXPOSE 9102

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD /app/healthcheck.sh

ENTRYPOINT ["/app/bin/ztlp_gateway"]
CMD ["start"]
