# ─────────────────────────────────────────────────────────────
# ZTLP Relay — Elixir OTP release (multi-stage)
# Zero external deps — pure Elixir/OTP
#
# Build:  docker build -t ztlp-relay ./relay
# Run:    docker run -p 23095:23095/udp -p 9101:9101 ztlp-relay
# ─────────────────────────────────────────────────────────────

# ── Stage 1: Build ──────────────────────────────────────────
FROM elixir:1.12.3-otp-24 AS builder

ENV MIX_ENV=prod
WORKDIR /build

# Install hex + rebar (no deps, but good practice)
RUN mix local.hex --force && mix local.rebar --force

# Copy manifest first for layer caching
COPY mix.exs ./

# Create stub so mix doesn't complain about missing app module
RUN mkdir -p lib && echo "defmodule ZtlpRelay do\nend" > lib/stub.ex && \
    mix deps.get --only prod 2>/dev/null || true && \
    rm lib/stub.ex

# Copy config and source
COPY config/ config/
COPY lib/ lib/
COPY rel/ rel/

# Compile and build release
RUN mix compile --warnings-as-errors && \
    mix release ztlp_relay

# ── Stage 2: Runtime ────────────────────────────────────────
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libncurses6 libtinfo6 libssl1.1 locales \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
    && locale-gen

ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

RUN useradd --system --create-home ztlp
COPY --from=builder /build/_build/prod/rel/ztlp_relay/ /app/

# Health check script
RUN printf '#!/bin/sh\n/app/bin/ztlp_relay rpc "IO.puts(:ok)" 2>/dev/null | grep -q "ok"\n' > /app/healthcheck.sh \
    && chmod +x /app/healthcheck.sh

RUN chown -R ztlp:ztlp /app
USER ztlp
WORKDIR /app

# Default environment
ENV ZTLP_RELAY_PORT=23095
ENV ZTLP_LOG_FORMAT=json
ENV ZTLP_LOG_LEVEL=info
ENV ZTLP_RELAY_METRICS_ENABLED=true
ENV ZTLP_RELAY_METRICS_PORT=9101
ENV RELEASE_COOKIE=ztlp_relay_docker

EXPOSE 23095/udp
EXPOSE 9101

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD /app/healthcheck.sh

ENTRYPOINT ["/app/bin/ztlp_relay"]
CMD ["start"]
