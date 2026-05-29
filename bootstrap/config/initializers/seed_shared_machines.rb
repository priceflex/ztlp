# frozen_string_literal: true

# When the bootstrap container is running as a real tenant deployment
# (Launch-provisioned, `ZTLP_INSTANCE_SLUG` or `ZONE` env var set), enable
# the Network#after_create_commit callback that auto-seeds the shared
# production NS+Relay Machine rows.
#
# ## Why this is a runtime flag, not always-on
#
# Many existing test cases create Networks via `Network.create!` and assert
# that `Machine.count` doesn't change, or that the new Network is "empty"
# (e.g. `network_test.rb` asserts `deployable?` is false for a freshly-
# created network). Auto-seeding 2 Machine rows on every Network creation
# would break those assertions across dozens of test files.
#
# Test envs leave the flag at the default `false`. The single test that
# exercises the callback (`network_after_create_seeds_test.rb`) flips it
# locally in its `setup` and restores in `teardown`.
#
# ## Why ZTLP_INSTANCE_SLUG / ZONE specifically
#
# Both env vars are injected by the ztlp.net launch app when it
# provisions a tenant container. Their presence is the canonical
# "I am a real tenant deployment" signal — same logic
# `EnsureNetworkFromEnv` and `EnsureSharedMachines` already use.
#
# In dev (`bin/rails server` from a developer laptop) neither is typically
# set, so the flag stays off. Developers who want to dogfood the auto-seed
# path can export ZTLP_INSTANCE_SLUG=dev before starting the server.

Rails.application.config.after_initialize do
  if ENV["ZTLP_INSTANCE_SLUG"].present? || ENV["ZONE"].present?
    Network.seed_shared_machines_on_create = true
    Rails.logger.info(
      "[init] Network.seed_shared_machines_on_create = true " \
      "(detected ZTLP_INSTANCE_SLUG=#{ENV['ZTLP_INSTANCE_SLUG'].inspect} " \
      "ZONE=#{ENV['ZONE'].inspect})"
    )
  end
end
