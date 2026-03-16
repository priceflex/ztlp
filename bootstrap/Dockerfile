# syntax = docker/dockerfile:1

ARG RUBY_VERSION=3.2.7
FROM registry.docker.com/library/ruby:$RUBY_VERSION-slim AS base

WORKDIR /rails

ENV RAILS_ENV="production" \
    BUNDLE_DEPLOYMENT="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_WITHOUT="development:test"

# ---------- Build stage ----------
FROM base AS build

RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y \
      build-essential git pkg-config libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*

COPY Gemfile Gemfile.lock ./
RUN bundle install && \
    rm -rf ~/.bundle/ "${BUNDLE_PATH}"/ruby/*/cache "${BUNDLE_PATH}"/ruby/*/bundler/gems/*/.git && \
    bundle exec bootsnap precompile --gemfile

COPY . .

RUN bundle exec bootsnap precompile app/ lib/

# Precompile assets without needing real secrets
RUN SECRET_KEY_BASE_DUMMY=1 ./bin/rails assets:precompile

# ---------- Runtime stage ----------
FROM base

# openssh-client: needed by SshProvisioner (net-ssh connects to remote machines)
# curl: health checks
# libsqlite3-0: SQLite runtime
# docker.io CLI: optional, for local Docker commands (the app SSHes into remote hosts mostly)
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y \
      curl libsqlite3-0 openssh-client && \
    rm -rf /var/lib/apt/lists /var/cache/apt/archives

# Copy built gems + app
COPY --from=build /usr/local/bundle /usr/local/bundle
COPY --from=build /rails /rails

# Copy ZTLP CLI binary for ZTLP-native health checks and metrics tunneling.
# The binary is pre-built for x86_64-linux from proto/target/release/ztlp.
# If the binary doesn't exist, the health checker falls back to SSH.
COPY bin/ztlp /usr/local/bin/ztlp

# Create data directory for SQLite persistence and ensure Rails directories exist
RUN mkdir -p /data /rails/log /rails/storage /rails/tmp /rails/db && \
    useradd rails --create-home --shell /bin/bash && \
    chown -R rails:rails /rails/db /rails/log /rails/storage /rails/tmp /data && \
    chmod +x /usr/local/bin/ztlp && \
    mkdir -p /home/rails/.ztlp && \
    chown rails:rails /home/rails/.ztlp

USER rails:rails

ENTRYPOINT ["/rails/bin/docker-entrypoint"]

EXPOSE 3000

# Health check — Rails /up endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/up || exit 1

CMD ["./bin/rails", "server", "-b", "0.0.0.0"]
