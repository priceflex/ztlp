# frozen_string_literal: true

require "test_helper"

# Tests for Ztlp::EnsureSharedMachines — the boot-time service that auto-seeds
# the per-tenant Network with shared production NS + Relay Machine rows so
# token-mint works on first dashboard click.
#
# Pinned behaviour:
#   * Missing ZONE env => skipped, no rows.
#   * Network for that zone doesn't exist yet => skipped (EnsureNetworkFromEnv
#     hasn't run yet; entrypoint orders the calls so this only fires when
#     the network exists).
#   * Fresh Network => 2 Machine rows created (primary-ns + primary-relay),
#     2 AuditLog entries, ssh_user="unmanaged" so Machine#shared? is true.
#   * Re-run on an already-seeded Network => :existing, no new rows, no audit.
#   * Falls back to ZTLP_NS_SERVER / ZTLP_BOOTSTRAP_LISTENER_ADDR when the
#     new ZTLP_SHARED_*_ADDR vars are missing (legacy Launch versions).
#   * Falls back to hardcoded defaults when both env shapes are missing
#     (dev / test runs without a real Launch container).
class Ztlp::EnsureSharedMachinesTest < ActiveSupport::TestCase
  setup do
    @test_zone = "shared-machines-test.ztlp"
    Network.where(zone: @test_zone).destroy_all
    @network = Network.create!(name: "Shared Machines Test", zone: @test_zone, status: "created")
  end

  test "skipped when ZONE env var is missing" do
    assert_no_difference -> { Machine.count } do
      result = Ztlp::EnsureSharedMachines.call(env: {})
      assert_equal :skipped, result.status
    end
  end

  test "skipped when no Network exists for the zone yet" do
    @network.destroy
    assert_no_difference -> { Machine.count } do
      result = Ztlp::EnsureSharedMachines.call(env: { "ZONE" => @test_zone })
      assert_equal :skipped, result.status
      assert_match(/no Network for zone/i, result.message)
    end
  end

  test "seeds primary-ns + primary-relay on a fresh network" do
    env = {
      "ZONE"                    => @test_zone,
      "ZTLP_SHARED_NS_ADDR"     => "35.91.88.177:23096",
      "ZTLP_SHARED_RELAY_ADDR"  => "34.218.240.106:23095",
    }

    assert_difference -> { Machine.count }, 2 do
      result = Ztlp::EnsureSharedMachines.call(env: env)
      assert_equal :created, result.status
      assert_equal 2, result.machines.length
    end

    ns = @network.machines.find_by(hostname: "primary-ns")
    relay = @network.machines.find_by(hostname: "primary-relay")
    assert_equal "35.91.88.177", ns.ip_address
    assert_equal "34.218.240.106", relay.ip_address
    assert_equal "ns", ns.roles
    assert_equal "relay", relay.roles
    assert ns.shared?, "primary-ns should be marked shared"
    assert relay.shared?, "primary-relay should be marked shared"
    assert_equal "ready", ns.status
    assert_equal "agent", ns.ssh_auth_method
  end

  test "writes an AuditLog entry per seeded machine" do
    env = { "ZONE" => @test_zone }
    assert_difference -> { AuditLog.where(action: "machine.seeded_from_shared_env").count }, 2 do
      Ztlp::EnsureSharedMachines.call(env: env)
    end
  end

  test "is idempotent — second run creates no new rows or audit entries" do
    env = { "ZONE" => @test_zone }
    Ztlp::EnsureSharedMachines.call(env: env)

    assert_no_difference -> { Machine.count } do
      assert_no_difference -> { AuditLog.where(action: "machine.seeded_from_shared_env").count } do
        result = Ztlp::EnsureSharedMachines.call(env: env)
        assert_equal :existing, result.status
      end
    end
  end

  test "falls back to ZTLP_NS_SERVER and ZTLP_BOOTSTRAP_LISTENER_ADDR when shared-specific vars missing" do
    env = {
      "ZONE"                          => @test_zone,
      "ZTLP_NS_SERVER"                => "35.91.88.177:23096",
      "ZTLP_BOOTSTRAP_LISTENER_ADDR"  => "34.218.240.106:23095",
    }
    Ztlp::EnsureSharedMachines.call(env: env)
    assert_equal "35.91.88.177", @network.machines.find_by(hostname: "primary-ns").ip_address
    assert_equal "34.218.240.106", @network.machines.find_by(hostname: "primary-relay").ip_address
  end

  test "falls back to hardcoded defaults when no env vars given" do
    env = { "ZONE" => @test_zone }
    Ztlp::EnsureSharedMachines.call(env: env)
    # The DEFAULT_* constants in EnsureSharedMachines pin the production IPs.
    assert_equal Ztlp::EnsureSharedMachines::DEFAULT_NS_ADDR.split(":").first,
                 @network.machines.find_by(hostname: "primary-ns").ip_address
    assert_equal Ztlp::EnsureSharedMachines::DEFAULT_RELAY_ADDR.split(":").first,
                 @network.machines.find_by(hostname: "primary-relay").ip_address
  end

  test "tolerates hostname collision by appending -shared suffix" do
    # An operator already added a machine called primary-ns pointing at a
    # different IP (e.g. their own self-hosted NS). We must not crash on
    # the UNIQUE (network_id, hostname) constraint.
    @network.machines.create!(
      hostname: "primary-ns", ip_address: "10.0.0.99",
      ssh_port: 22, ssh_user: "root", ssh_auth_method: "key",
      roles: "ns", status: "pending"
    )

    env = { "ZONE" => @test_zone }
    assert_difference -> { Machine.count }, 2 do
      Ztlp::EnsureSharedMachines.call(env: env)
    end

    assert @network.machines.exists?(hostname: "primary-ns-shared")
    refute @network.machines.find_by(hostname: "primary-ns").shared?, "operator-added row must NOT be flagged shared"
    assert @network.machines.find_by(hostname: "primary-ns-shared").shared?
  end

  test "tolerates ip collision by skipping that machine (idempotent across IP)" do
    # If an operator already added a machine with the same IP as the shared
    # NS, we treat the network as already having that machine. This is the
    # primary idempotency key.
    @network.machines.create!(
      hostname: "operator-ns", ip_address: "35.91.88.177",
      ssh_port: 22, ssh_user: "root", ssh_auth_method: "key",
      roles: "ns", status: "ready"
    )

    env = { "ZONE" => @test_zone }
    # Only the relay should be added; the NS row already exists at that IP.
    assert_difference -> { Machine.count }, 1 do
      result = Ztlp::EnsureSharedMachines.call(env: env)
      assert_equal :partial, result.status
    end
  end

  test "call_safely swallows unexpected exceptions" do
    # Simulate a Network model that blows up — wrap should return :error.
    Network.stubs(:find_by).raises(StandardError.new("synthetic"))
    result = Ztlp::EnsureSharedMachines.call_safely(env: { "ZONE" => @test_zone })
    assert_equal :error, result.status
    assert_match(/synthetic/, result.message)
  end

  # ── call_for_network (per-network entrypoint for the Network callback) ──

  test "call_for_network seeds the given network without consulting ZONE env" do
    # No ZONE env var — this previously short-circuited .call, but
    # call_for_network should ignore that and seed the network it was passed.
    assert_difference -> { Machine.count }, 2 do
      result = Ztlp::EnsureSharedMachines.call_for_network(network: @network, env: {})
      assert_equal :created, result.status
    end
  end

  test "call_for_network returns :skipped when network is nil" do
    assert_no_difference -> { Machine.count } do
      result = Ztlp::EnsureSharedMachines.call_for_network(network: nil)
      assert_equal :skipped, result.status
      assert_match(/network is nil/i, result.message)
    end
  end

  test "call_for_network is idempotent on the same network" do
    Ztlp::EnsureSharedMachines.call_for_network(network: @network, env: {})
    assert_no_difference -> { Machine.count } do
      result = Ztlp::EnsureSharedMachines.call_for_network(network: @network, env: {})
      assert_equal :existing, result.status
    end
  end

  test "call_for_network_safely swallows unexpected exceptions" do
    # Force the inner call_for_network to raise (something downstream of
    # the nil-guard) — wrapper must convert to :error, not propagate.
    Ztlp::EnsureSharedMachines.any_instance.stubs(:call_for_network)
                              .raises(StandardError.new("synthetic"))
    result = Ztlp::EnsureSharedMachines.call_for_network_safely(network: @network)
    assert_equal :error, result.status
    assert_match(/synthetic/, result.message)
  end
end
