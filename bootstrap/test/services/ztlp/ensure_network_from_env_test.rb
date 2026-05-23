# frozen_string_literal: true

require "test_helper"

# BS-PR-4: tests for the boot-time service that ensures a Network row
# exists for the zone the bootstrap container was provisioned with.
#
# The contract is straightforward but the edge cases matter:
#
#   * Missing env => no-op, no exception (legacy boots, dev, tests).
#   * Existing zone row => idempotent no-op (don't clobber operator edits).
#   * New zone => create + audit log entry.
#   * Invalid zone format => raise, fail boot loudly (better to crash than
#     ship a half-provisioned container).
#   * Duplicate name collision => disambiguate, never crash.
#
# Boot-time idempotency is the key property — `bin/docker-entrypoint`
# runs this on every container start; it must do nothing on the second
# run and onwards.
class Ztlp::EnsureNetworkFromEnvTest < ActiveSupport::TestCase
  setup do
    # Wipe any default fixtures that could collide with the test zones
    # we mint below — the fixtures live in different zones but the
    # service's "find by zone" path needs a clean slate to assert on
    # creation.
    @test_zone = "acme-test.ztlp"
    @test_org  = "Acme Test Corp"
    @test_slug = "acmetest12"
    Network.where(zone: @test_zone).destroy_all
  end

  test "no-op when ZONE env var is unset" do
    assert_no_difference -> { Network.count } do
      result = Ztlp::EnsureNetworkFromEnv.call(env: { "ZONE" => nil })
      assert_equal :skipped, result.status
      assert_match(/ZONE.*not set/i, result.message)
    end
  end

  test "no-op when ZONE env var is blank" do
    assert_no_difference -> { Network.count } do
      result = Ztlp::EnsureNetworkFromEnv.call(env: { "ZONE" => "  " })
      assert_equal :skipped, result.status
    end
  end

  test "creates a Network row when zone does not yet exist" do
    env = { "ZONE" => @test_zone, "ORG_NAME" => @test_org, "ZTLP_INSTANCE_SLUG" => @test_slug }

    assert_difference -> { Network.count }, 1 do
      result = Ztlp::EnsureNetworkFromEnv.call(env: env)
      assert_equal :created, result.status
      assert_kind_of Network, result.network
    end

    n = Network.find_by!(zone: @test_zone)
    assert_equal @test_org, n.name
    assert_equal "created", n.status
    assert_match(/auto.created/i, n.notes.to_s)
    assert_match(/ztlp\.net/i, n.notes.to_s)
  end

  test "is idempotent when the zone already exists" do
    Network.create!(name: "Manually Renamed", zone: @test_zone, status: "active")
    env = { "ZONE" => @test_zone, "ORG_NAME" => @test_org }

    assert_no_difference -> { Network.count } do
      result = Ztlp::EnsureNetworkFromEnv.call(env: env)
      assert_equal :existing, result.status
      assert_equal "Manually Renamed", result.network.name,
        "must not clobber an operator-edited name"
      assert_equal "active", result.network.status,
        "must not regress an operator-edited status"
    end
  end

  test "writes an AuditLog entry on creation" do
    env = { "ZONE" => @test_zone, "ORG_NAME" => @test_org, "ZTLP_INSTANCE_SLUG" => @test_slug }

    assert_difference -> { AuditLog.count }, 1 do
      Ztlp::EnsureNetworkFromEnv.call(env: env)
    end

    log = AuditLog.where(action: "network.auto_created_from_env").order(:created_at).last
    assert_not_nil log
    details = JSON.parse(log.details.to_s)
    assert_equal @test_zone, details["zone"]
    assert_equal @test_slug, details["instance_slug"]
  end

  test "writes no AuditLog entry on idempotent re-run" do
    Network.create!(name: @test_org, zone: @test_zone, status: "created")
    env = { "ZONE" => @test_zone, "ORG_NAME" => @test_org }

    assert_no_difference -> { AuditLog.where(action: "network.auto_created_from_env").count } do
      Ztlp::EnsureNetworkFromEnv.call(env: env)
    end
  end

  test "falls back to a synthesized name when ORG_NAME is missing" do
    env = { "ZONE" => @test_zone, "ZTLP_INSTANCE_SLUG" => @test_slug }

    Ztlp::EnsureNetworkFromEnv.call(env: env)

    n = Network.find_by!(zone: @test_zone)
    assert_not_empty n.name
    assert_match(/#{Regexp.escape(@test_zone)}|#{Regexp.escape(@test_slug)}/, n.name,
      "synthesized name should reference the zone or slug so it's recognizable")
  end

  test "disambiguates a duplicate name by appending the zone" do
    existing = Network.create!(name: @test_org, zone: "another-zone.ztlp", status: "created")
    env = { "ZONE" => @test_zone, "ORG_NAME" => @test_org }

    result = Ztlp::EnsureNetworkFromEnv.call(env: env)
    assert_equal :created, result.status
    refute_equal existing.id, result.network.id
    refute_equal existing.name, result.network.name,
      "must disambiguate to satisfy the UNIQUE index on name"
    assert_match(/#{Regexp.escape(@test_zone)}/, result.network.name,
      "the disambiguated name should include the zone for traceability"
    )
  end

  test "raises on a malformed zone string so boot fails loudly" do
    env = { "ZONE" => "WHITESPACE INVALID UPPERCASE" }

    assert_raises(Ztlp::EnsureNetworkFromEnv::InvalidZoneError) do
      Ztlp::EnsureNetworkFromEnv.call(env: env)
    end

    assert_nil Network.find_by(zone: env["ZONE"])
  end

  test ".call_safely swallows exceptions and returns an :error result" do
    env = { "ZONE" => "WHITESPACE INVALID UPPERCASE" }

    result = Ztlp::EnsureNetworkFromEnv.call_safely(env: env)
    assert_equal :error, result.status
    assert_match(/zone/i, result.message)
  end
end
