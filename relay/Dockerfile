# ─────────────────────────────────────────────────────────────
# ZTLP Relay — Elixir UDP relay server
# Single-stage build: elixir base image (small enough for prototype)
# Zero external deps — pure Elixir/OTP
# ─────────────────────────────────────────────────────────────

FROM elixir:1.12.3-otp-24

ENV MIX_ENV=prod

WORKDIR /app

# Copy project files
COPY mix.exs ./
COPY config/ config/
COPY lib/ lib/
COPY test/ test/

# Compile the project
RUN mix local.hex --force && \
    mix local.rebar --force && \
    mix compile

# Default environment variables (can be overridden at runtime)
ENV ZTLP_RELAY_PORT=23095
ENV ZTLP_RELAY_MAX_SESSIONS=10000
ENV ZTLP_RELAY_SESSION_TIMEOUT_MS=300000

EXPOSE 23095/udp

CMD ["elixir", "--no-halt", "-S", "mix", "run"]
