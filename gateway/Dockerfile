# ─────────────────────────────────────────────────────────────
# ZTLP Gateway — Elixir OTP release (multi-stage)
# Zero external deps — pure Elixir/OTP
#
# Build context must be repo root (gateway depends on ../ns at test time):
#   docker build -f gateway/Dockerfile -t ztlp-gateway .
# ─────────────────────────────────────────────────────────────

# ── Stage 1: Build ──────────────────────────────────────────
FROM elixir:1.12.3-otp-24 AS builder

ENV MIX_ENV=prod
WORKDIR /build

RUN mix local.hex --force && mix local.rebar --force

# Copy gateway manifest first (layer caching)
COPY gateway/mix.exs ./

# NS is a test-only dep — not needed for prod release, but mix.exs
# references it. Create a minimal stub so mix doesn't fail.
RUN mkdir -p /ns/lib && \
    echo 'defmodule ZtlpNs.MixProject do\n  use Mix.Project\n  def project, do: [app: :ztlp_ns, version: "0.1.0"]\nend' > /ns/mix.exs && \
    echo "defmodule ZtlpNs do\nend" > /ns/lib/stub.ex

# Create app stub for compile
RUN mkdir -p lib && echo "defmodule ZtlpGateway do\nend" > lib/stub.ex && \
    mix deps.get --only prod 2>/dev/null || true && \
    rm lib/stub.ex

# Copy config and source
COPY gateway/config/ config/
COPY gateway/lib/ lib/
COPY gateway/rel/ rel/

# Compile and build release
RUN mix compile --warnings-as-errors && \
    mix release ztlp_gateway

# ── Stage 2: Runtime ────────────────────────────────────────
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libncurses6 libtinfo6 libssl1.1 locales \
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
ENV RELEASE_COOKIE=ztlp_gateway_docker

EXPOSE 23097/udp
EXPOSE 9102

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD /app/healthcheck.sh

ENTRYPOINT ["/app/bin/ztlp_gateway"]
CMD ["start"]
