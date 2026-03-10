# ─────────────────────────────────────────────────────────────
# ZTLP-NS — Elixir namespace server
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
ENV ZTLP_NS_PORT=23096
ENV ZTLP_NS_MAX_RECORDS=100000

EXPOSE 23096/udp

CMD ["elixir", "--no-halt", "-S", "mix", "run"]
