require "test_helper"

class MachineTest < ActiveSupport::TestCase
  test "valid machine" do
    machine = Machine.new(
      network: networks(:office),
      hostname: "test-host",
      ip_address: "10.0.1.99",
      roles: "ns"
    )
    assert machine.valid?
  end

  test "requires hostname" do
    machine = Machine.new(network: networks(:office), ip_address: "10.0.1.99", roles: "ns")
    assert_not machine.valid?
    assert machine.errors[:hostname].any?
  end

  test "requires valid IP address" do
    machine = Machine.new(
      network: networks(:office), hostname: "bad-ip",
      ip_address: "not-an-ip", roles: "ns"
    )
    assert_not machine.valid?
    assert machine.errors[:ip_address].any?
  end

  test "validates SSH port range" do
    machine = machines(:ns1)
    machine.ssh_port = 0
    assert_not machine.valid?
    machine.ssh_port = 70000
    assert_not machine.valid?
    machine.ssh_port = 2222
    assert machine.valid?
  end

  test "validates roles" do
    machine = machines(:ns1)
    machine.roles = "ns,bogus"
    assert_not machine.valid?
    assert machine.errors[:roles].any?
  end

  test "requires at least one role" do
    machine = machines(:ns1)
    machine.roles = ""
    assert_not machine.valid?
  end

  test "role_list parses comma-separated roles" do
    machine = machines(:multi_role)
    assert_equal %w[ns relay], machine.role_list
  end

  test "role_list= sets roles from array" do
    machine = machines(:ns1)
    machine.role_list = %w[ns gateway]
    assert_equal "ns,gateway", machine.roles
  end

  test "has_role?" do
    machine = machines(:multi_role)
    assert machine.has_role?("ns")
    assert machine.has_role?("relay")
    assert_not machine.has_role?("gateway")
  end

  test "hostname unique within network" do
    existing = machines(:ns1)
    dupe = Machine.new(
      network: existing.network,
      hostname: existing.hostname,
      ip_address: "10.0.1.99",
      roles: "ns"
    )
    assert_not dupe.valid?
  end

  test "ip unique within network" do
    existing = machines(:ns1)
    dupe = Machine.new(
      network: existing.network,
      hostname: "unique-host",
      ip_address: existing.ip_address,
      roles: "ns"
    )
    assert_not dupe.valid?
  end

  test "same hostname allowed in different networks" do
    machine = Machine.new(
      network: networks(:production),
      hostname: "ns1.office",  # same hostname as office network
      ip_address: "10.0.2.10",
      roles: "ns"
    )
    assert machine.valid?
  end

  test "latest_deployment_for returns most recent" do
    machine = machines(:ns1)
    dep = machine.latest_deployment_for("ns")
    assert_equal "success", dep.status
  end

  test "ready?" do
    assert machines(:relay1).ready?
    assert_not machines(:ns1).ready?
  end
end
