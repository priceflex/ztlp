require "test_helper"

class NetworkTest < ActiveSupport::TestCase
  test "valid network" do
    network = Network.new(name: "Test Net", zone: "test.ztlp", status: "created")
    assert network.valid?
  end

  test "requires name" do
    network = Network.new(zone: "test.ztlp")
    assert_not network.valid?
    assert_includes network.errors[:name], "can't be blank"
  end

  test "requires zone" do
    network = Network.new(name: "Test")
    assert_not network.valid?
    assert_includes network.errors[:zone], "can't be blank"
  end

  test "validates zone format" do
    network = Network.new(name: "Bad Zone", zone: "INVALID ZONE!", status: "created")
    assert_not network.valid?
    assert network.errors[:zone].any?
  end

  test "accepts valid zone formats" do
    %w[test1.acme.ztlp my-zone test.us-east.ztlp a].each do |zone|
      network = Network.new(name: "Net #{zone}", zone: zone, status: "created")
      assert network.valid?, "Expected #{zone} to be valid but got: #{network.errors.full_messages}"
    end
  end

  test "validates status inclusion" do
    network = Network.new(name: "Bad", zone: "bad.ztlp", status: "bogus")
    assert_not network.valid?
    assert network.errors[:status].any?
  end

  test "uniqueness of name" do
    network = networks(:office)
    dupe = Network.new(name: network.name, zone: "unique.ztlp", status: "created")
    assert_not dupe.valid?
  end

  test "uniqueness of zone" do
    network = networks(:office)
    dupe = Network.new(name: "Different Name", zone: network.zone, status: "created")
    assert_not dupe.valid?
  end

  test "role_list aggregates machine roles" do
    network = networks(:office)
    roles = network.roles_in_use
    assert_includes roles, "ns"
    assert_includes roles, "relay"
    assert_includes roles, "gateway"
  end

  test "machine_count_by_role" do
    network = networks(:office)
    counts = network.machine_count_by_role
    assert counts["ns"] >= 1
    assert counts["relay"] >= 1
    assert counts["gateway"] >= 1
  end

  test "ns_machines returns only NS role machines" do
    network = networks(:office)
    ns = network.ns_machines
    assert ns.all? { |m| m.has_role?("ns") }
  end

  # --- Policy methods ---

  test "export_policy_config returns gateway rules" do
    network = networks(:office)
    config = network.export_policy_config
    assert_kind_of Array, config
    # Should only include enabled, non-expired policies
    assert config.all? { |r| r.is_a?(Hash) }
    assert config.all? { |r| r.key?(:subject) && r.key?(:resource) && r.key?(:action) }
    # Expired policy should not be included
    expired_values = config.select { |r| r[:resource][:value] == "temp.internal" }
    assert_empty expired_values
  end

  test "policy_summary returns counts" do
    network = networks(:office)
    summary = network.policy_summary
    assert summary[:total] > 0
    assert summary[:active] > 0
    assert summary[:allow_count] >= 0
    assert summary[:deny_count] >= 0
  end

  test "policies association" do
    network = networks(:office)
    assert network.policies.count > 0
    assert network.policies.first.is_a?(Policy)
  end

  test "destroying network destroys policies" do
    network = networks(:office)
    policy_count = network.policies.count
    assert policy_count > 0
    assert_difference "Policy.count", -policy_count do
      network.destroy
    end
  end

  test "deployable? requires machines with roles" do
    network = Network.create!(name: "Empty", zone: "empty.ztlp", status: "created")
    assert_not network.deployable?

    network = networks(:office)
    assert network.deployable?
  end
end
