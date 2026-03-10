# ─────────────────────────────────────────────────────────────
# ZTLP Gateway — Elixir gateway/proxy server
# Single-stage build: elixir base image (small enough for prototype)
# Zero external deps — pure Elixir/OTP
#
# Build context must be the repo root (gateway test-depends on ns):
#   docker build -f gateway/Dockerfile -t ztlp-gateway .
# ─────────────────────────────────────────────────────────────

FROM elixir:1.12.3-otp-24

WORKDIR /app

# Copy NS source (test-only path dependency at ../ns)
COPY ns/ /ns/

# Copy gateway project files
COPY gateway/mix.exs ./
COPY gateway/config/ config/
COPY gateway/lib/ lib/
COPY gateway/test/ test/

RUN mix local.hex --force && \
    mix local.rebar --force

# Compile for test (includes NS path dependency for integration tests)
RUN MIX_ENV=test mix deps.get && MIX_ENV=test mix compile

# Compile for prod (the default runtime mode)
RUN MIX_ENV=prod mix compile

ENV MIX_ENV=prod

# Default environment variables (can be overridden at runtime)
ENV ZTLP_GATEWAY_PORT=23097
ENV ZTLP_GATEWAY_NS_HOST=ns
ENV ZTLP_GATEWAY_NS_PORT=23096
ENV ZTLP_GATEWAY_MAX_SESSIONS=10000

EXPOSE 23097/udp

CMD ["elixir", "--no-halt", "-S", "mix", "run"]
