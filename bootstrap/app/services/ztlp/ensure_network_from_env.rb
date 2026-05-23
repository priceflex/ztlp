# frozen_string_literal: true

# Ztlp::EnsureNetworkFromEnv — boot-time auto-creation of the per-tenant
# Network row from the env vars the ztlp.net launch app injects when it
# provisions a tenant's bootstrap container.
#
# ## Why this exists (BS-PR-4)
#
# When a customer onboards through ztlp.net, the launch app
# (`ztlp.net/launch_app/app.py`) spins up a per-tenant
# `ztlp-bootstrap-<slug>` container with at minimum the following
# environment:
#
#     ZONE=acme.ztlp
#     ORG_NAME=Acme Inc
#     ZTLP_INSTANCE_SLUG=acme-c4f6e1
#
# Previously the tenant's super-admin had to click into the dashboard
# and manually create a Network row before any of the device-management
# / enrollment-token features worked (and `POST /api/v1/enrollment_tokens`
# from BS-PR-3 returned 503 until then). That's a paper cut for
# every customer onboarding and a footgun for our own dogfood
# deployments.
#
# This service runs once at container start (called from
# `bin/docker-entrypoint`) and creates the matching Network row if
# none yet exists for the zone. The result is that when the operator
# first signs into the dashboard, the network they just registered
# at ztlp.net is already there.
#
# ## Idempotency contract
#
# The entrypoint runs this on EVERY container start (restarts,
# image upgrades, env-only `docker compose up`). The service MUST be
# a no-op on the second and subsequent runs. We enforce this by
# looking up the existing row by zone — the schema's `UNIQUE (zone)`
# index is the source of truth.
#
# Specifically we do NOT overwrite the `name`, `status`, or `notes`
# of an existing row. Operators may have renamed it via the dashboard
# (BS-PR-5) and we won't clobber their edits on a restart.
#
# ## Failure modes
#
#   * `ZONE` unset / blank → :skipped result. Legacy / dev / test boots
#     still work — the entrypoint logs a notice and continues.
#   * Malformed `ZONE` → `InvalidZoneError` raised. Boot fails loud.
#     The wrapper `.call_safely` is what the entrypoint actually uses
#     so a bad env var doesn't permanently break the container; the
#     error is logged and audited but the rails server still starts.
#   * Name collision (an existing row in a different zone already
#     uses this name) → disambiguate by appending the zone string.
#     The UNIQUE (name) index would otherwise raise; disambiguation
#     is preferred over crashing.
#
# ## Audit log
#
# A successful creation writes one AuditLog row with action
# `network.auto_created_from_env` and details
# `{ zone, name, instance_slug }`. Idempotent re-runs write nothing.
module Ztlp
  class EnsureNetworkFromEnv
    InvalidZoneError = Class.new(StandardError)

    # Same validator the Network model uses (matches the migration's
    # DNS-label-ish format).
    ZONE_FORMAT = /\A[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?\z/.freeze

    Result = Struct.new(:status, :network, :message, keyword_init: true) do
      def created?  = status == :created
      def existing? = status == :existing
      def skipped?  = status == :skipped
      def error?    = status == :error
    end

    # @param env [Hash] env-var snapshot (defaults to ENV.to_h so callers
    #   can inject a synthetic env in tests).
    # @return [Result]
    def self.call(env: ENV.to_h)
      new(env).call
    end

    # Wrapped variant: never raises. Catches both InvalidZoneError and
    # any unexpected ActiveRecord error so the bootstrap container can
    # still come up if the launch app passes garbage.
    def self.call_safely(env: ENV.to_h)
      call(env: env)
    rescue InvalidZoneError => e
      Result.new(status: :error, message: e.message)
    rescue => e
      Rails.logger.error("[EnsureNetworkFromEnv] unexpected error: #{e.class}: #{e.message}")
      Result.new(status: :error, message: "#{e.class}: #{e.message}")
    end

    def initialize(env)
      @env = env || {}
    end

    def call
      zone = @env["ZONE"].to_s.strip
      return Result.new(status: :skipped, message: "ZONE not set; nothing to do") if zone.empty?

      raise InvalidZoneError, "zone #{zone.inspect} does not match #{ZONE_FORMAT.source}" unless zone.match?(ZONE_FORMAT)

      existing = Network.find_by(zone: zone)
      return Result.new(status: :existing, network: existing, message: "zone already present") if existing

      org_name = @env["ORG_NAME"].to_s.strip
      slug     = @env["ZTLP_INSTANCE_SLUG"].to_s.strip
      base_name = if !org_name.empty?
        org_name
      elsif !slug.empty?
        "Network #{slug}"
      else
        "Network #{zone}"
      end

      name = unique_name_for(base_name, zone)

      network = Network.create!(
        name: name,
        zone: zone,
        status: "created",
        notes: auto_creation_note(zone: zone, slug: slug)
      )

      audit_creation(network: network, slug: slug)

      Result.new(status: :created, network: network, message: "created Network ##{network.id}")
    end

    private

    # Resolve UNIQUE (name) by appending the zone when the bare name is
    # already taken by a different zone. Two stage so the common case
    # (no collision) stays clean in the UI.
    def unique_name_for(base, zone)
      return base unless Network.exists?(name: base)
      candidate = "#{base} (#{zone})"
      return candidate unless Network.exists?(name: candidate)
      # Pathological: the candidate is also taken. Append a numeric
      # suffix as the last resort. Cap at 10 attempts.
      (2..10).each do |n|
        suffix = "#{candidate} ##{n}"
        return suffix unless Network.exists?(name: suffix)
      end
      raise "could not synthesize a unique Network.name for zone=#{zone}"
    end

    def auto_creation_note(zone:, slug:)
      [
        "Auto-created from launch_app env at boot.",
        "Zone: #{zone}.",
        ("Slug: #{slug}." if !slug.empty?),
        "Source: ztlp.net BS-PR-4."
      ].compact.join(" ")
    end

    def audit_creation(network:, slug:)
      details = {
        zone:          network.zone,
        name:          network.name,
        network_id:    network.id,
        instance_slug: slug,
      }.compact
      AuditLog.create!(
        action: "network.auto_created_from_env",
        target_type: "Network",
        target_id: network.id,
        status: "success",
        details: details.to_json
      )
    rescue => e
      # The audit row is bookkeeping — don't roll back the Network
      # creation if the audit table is missing a column or otherwise
      # broken. Log it so we can fix it on the next deploy.
      Rails.logger.warn("[EnsureNetworkFromEnv] failed to write audit log: #{e.class}: #{e.message}")
    end
  end
end
