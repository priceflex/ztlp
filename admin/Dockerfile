# syntax=docker/dockerfile:1
# ZTLP Admin panel (Rails 7.1 + MariaDB). See docs/ADMIN-PANEL-SPEC.md §10.
ARG RUBY_VERSION=3.2.7
FROM ruby:$RUBY_VERSION-slim-bookworm AS base
WORKDIR /rails
ENV RAILS_ENV=production BUNDLE_DEPLOYMENT=1 BUNDLE_PATH=/usr/local/bundle BUNDLE_WITHOUT="development:test"
RUN apt-get update -qq && apt-get install --no-install-recommends -y curl libmariadb3 && rm -rf /var/lib/apt/lists /var/cache/apt/archives

FROM base AS build
RUN apt-get update -qq && apt-get install --no-install-recommends -y build-essential git libmariadb-dev pkg-config libyaml-dev && rm -rf /var/lib/apt/lists /var/cache/apt/archives
COPY Gemfile Gemfile.lock ./
RUN bundle install && rm -rf ~/.bundle/ "${BUNDLE_PATH}"/ruby/*/cache "${BUNDLE_PATH}"/ruby/*/bundler/gems/*/.git
COPY . .
RUN SECRET_KEY_BASE_DUMMY=1 bundle exec rails assets:precompile

FROM base
COPY --from=build /usr/local/bundle /usr/local/bundle
COPY --from=build /rails /rails
RUN groupadd --system --gid 1000 rails && useradd rails --uid 1000 --gid 1000 --create-home --shell /bin/bash && \
    mkdir -p /data && chown -R rails:rails /data /rails/log /rails/tmp
USER 1000:1000
ENTRYPOINT ["/rails/bin/docker-entrypoint"]
EXPOSE 3000
CMD ["./bin/rails", "server", "-b", "0.0.0.0"]
