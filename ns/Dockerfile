# ─────────────────────────────────────────────────────────────
# ZTLP-NS — Elixir namespace server OTP release (multi-stage)
# Zero external deps — pure Elixir/OTP
#
# Build:  docker build -t ztlp-ns ./ns
# Run:    docker run -p 23096:23096/udp -p 9103:9103 ztlp-ns
# ─────────────────────────────────────────────────────────────

# ── Stage 1: Build ──────────────────────────────────────────
FROM elixir:1.12.3-otp-24 AS builder

ENV MIX_ENV=prod
WORKDIR /build

RUN mix local.hex --force && mix local.rebar --force

# Copy manifest first for layer caching
COPY mix.exs ./

# Create stub so mix doesn't complain
RUN mkdir -p lib && echo "defmodule ZtlpNs do\nend" > lib/stub.ex && \
    mix deps.get --only prod 2>/dev/null || true && \
    rm lib/stub.ex

# Copy config and source
COPY config/ config/
COPY lib/ lib/
COPY rel/ rel/

# Compile and build release
RUN mix compile --warnings-as-errors && \
    mix release ztlp_ns

# ── Stage 2: Runtime ────────────────────────────────────────
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libncurses6 libtinfo6 libssl1.1 locales \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
    && locale-gen

ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

RUN useradd --system --create-home ztlp
COPY --from=builder /build/_build/prod/rel/ztlp_ns/ /app/

# Health check script
RUN printf '#!/bin/sh\n/app/bin/ztlp_ns rpc "IO.puts(:ok)" 2>/dev/null | grep -q "ok"\n' > /app/healthcheck.sh \
    && chmod +x /app/healthcheck.sh

# Mnesia data directory (for disc_copies mode)
RUN mkdir -p /app/data && chown -R ztlp:ztlp /app
USER ztlp
WORKDIR /app

# Default environment
ENV ZTLP_NS_PORT=23096
ENV ZTLP_NS_MAX_RECORDS=100000
ENV ZTLP_NS_STORAGE_MODE=ram_copies
ENV ZTLP_LOG_FORMAT=json
ENV ZTLP_LOG_LEVEL=info
ENV ZTLP_NS_METRICS_ENABLED=true
ENV ZTLP_NS_METRICS_PORT=9103
ENV ZTLP_NS_MNESIA_DIR=/app/data
ENV RELEASE_COOKIE=ztlp_ns_docker

EXPOSE 23096/udp
EXPOSE 9103

VOLUME /app/data

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD /app/healthcheck.sh

ENTRYPOINT ["/app/bin/ztlp_ns"]
CMD ["start"]
