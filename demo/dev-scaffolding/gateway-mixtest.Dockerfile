FROM hexpm/elixir:1.15.7-erlang-26.2.5-debian-bookworm-20240423 AS builder
ENV MIX_ENV=test
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git curl patch pkg-config libssl-dev perl ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*
RUN mix local.hex --force && mix local.rebar --force

COPY ns /ns

COPY gateway/mix.exs ./
RUN mkdir -p lib && echo "defmodule ZtlpGateway do\nend" > lib/stub.ex && \
    mix deps.get && \
    mix deps.compile
COPY gateway/config/ config/
COPY gateway/lib/ lib/
COPY gateway/test/ test/
COPY gateway/rel/ rel/
RUN rm -f lib/stub.ex && mix compile
