# frozen_string_literal: true

require "test_helper"

# Tests for the Network#after_create_commit auto-seed callback.
#
# Background: prior to this change, the shared production NS+Relay Machine
# rows were seeded only at container boot by `bin/docker-entrypoint`
# calling `Ztlp::EnsureSharedMachines.call`. That worked for the single
# `ENV['ZONE']` network the launch app created at startup, but Networks
# created LATER via the dashboard (per-customer sub-zones, e.g.
# `tech-rockstars.trs.ztlp` alongside the parent `trs.ztlp`) had no
# Machine rows and `TokenGenerator` failed with HTTP 503:
#   "Network must have at least one NS machine"
#
# The fix: a feature-flagged `after_create_commit` callback on Network
# that calls `Ztlp::EnsureSharedMachines.call_for_network_safely(network: self)`
# whenever `Network.seed_shared_machines_on_create` is true. The flag is
# flipped at boot by `config/initializers/seed_shared_machines.rb` when
# the container is running as a real tenant (ZTLP_INSTANCE_SLUG or ZONE set).
#
# Pinned behaviour:
#   * Flag off (default): Network.create! does NOT seed Machine rows.
#     Critical for existing tests like network_test.rb#deployable?.
#   * Flag on: Network.create! seeds 2 Machine rows (primary-ns + primary-relay)
#     via the existing EnsureSharedMachines service.
#   * Seeding failure does NOT roll back the Network creation.
#   * The callback only fires once (after_create_commit, not after_save).

class NetworkAfterCreateSeedsTest < ActiveSupport::TestCase
  setup do
    @zone = "callback-seed-test.ztlp"
    Network.where(zone: @zone).destroy_all
    # Save the global flag state so we can restore it cleanly even on
    # assertion failures (other tests rely on the default :false).
    @prior_flag = Network.seed_shared_machines_on_create
  end

  teardown do
    Network.seed_shared_machines_on_create = @prior_flag
    Network.where(zone: @zone).destroy_all
  end

  # ── Default-off behaviour ────────────────────────────────────────────

  test "default flag is false (regression: protects existing test suite)" do
    # The bare class default must stay false. Flipping this to true
    # without a migration of every Network.create! in the existing test
    # suite would break dozens of unrelated assertions.
    assert_equal false, Network.seed_shared_machines_on_create
  end

  test "creating a Network with the flag off does NOT seed Machine rows" do
    Network.seed_shared_machines_on_create = false

    assert_no_difference -> { Machine.count } do
      Network.create!(name: "No Seed Net", zone: @zone, status: "created")
    end
  end

  # ── Flag-on behaviour (the actual feature) ───────────────────────────

  test "creating a Network with the flag on seeds primary-ns + primary-relay" do
    Network.seed_shared_machines_on_create = true

    network = nil
    assert_difference -> { Machine.count }, 2 do
      network = Network.create!(name: "Auto Seed Net", zone: @zone, status: "created")
    end

    ns    = network.machines.find_by(hostname: "primary-ns")
    relay = network.machines.find_by(hostname: "primary-relay")
    assert ns,    "after_create_commit must seed a primary-ns Machine"
    assert relay, "after_create_commit must seed a primary-relay Machine"
    assert_equal "ns",    ns.roles
    assert_equal "relay", relay.roles
    assert ns.shared?,    "seeded NS row must be marked as shared production"
    assert relay.shared?, "seeded Relay row must be marked as shared production"
  end

  test "callback fires exactly once (does not double-seed on subsequent saves)" do
    Network.seed_shared_machines_on_create = true

    network = Network.create!(name: "Once Seed Net", zone: @zone, status: "created")
    initial_count = network.machines.count
    assert_equal 2, initial_count, "sanity: initial create should have seeded 2 rows"

    # An after_create_commit callback must NOT fire on subsequent updates.
    # If it did (e.g. someone changed the callback to after_save), we'd
    # see duplicate seed attempts. Idempotency in EnsureSharedMachines
    # would catch the rows but it would still write audit log entries.
    assert_no_difference -> { Machine.count } do
      assert_no_difference -> { AuditLog.where(action: "machine.seeded_from_shared_env").count } do
        network.update!(name: "Once Seed Net (renamed)")
      end
    end
  end

  test "seeding failure does NOT roll back the Network creation" do
    Network.seed_shared_machines_on_create = true

    # Simulate a downstream explosion inside the service — the Network
    # row must still persist; operator can manually add Machines later.
    Ztlp::EnsureSharedMachines.stubs(:call_for_network_safely).raises(
      StandardError.new("synthetic seeding failure")
    )

    network = nil
    assert_nothing_raised do
      network = Network.create!(name: "Failure Tolerant Net", zone: @zone, status: "created")
    end

    assert network.persisted?, "Network must survive a seeding-callback exception"
    assert_equal 0, network.machines.count, "no Machines because seeding blew up"
  end

  test "graceful Result.error from the service is logged but doesn't crash" do
    Network.seed_shared_machines_on_create = true

    error_result = Ztlp::EnsureSharedMachines::Result.new(
      status: :error, message: "synthetic graceful error"
    )
    Ztlp::EnsureSharedMachines.stubs(:call_for_network_safely).returns(error_result)

    network = nil
    assert_nothing_raised do
      network = Network.create!(name: "Graceful Error Net", zone: @zone, status: "created")
    end
    assert network.persisted?
  end
end
