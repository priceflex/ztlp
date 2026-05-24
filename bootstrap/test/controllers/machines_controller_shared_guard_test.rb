# frozen_string_literal: true

require "test_helper"

# Integration tests for the v0.30.2 shared-machine destroy guard on
# MachinesController. The guard prevents an operator from accidentally
# deleting the shared production NS/Relay machine rows that
# Ztlp::EnsureSharedMachines auto-seeded.
#
# Token-mint depends on `network.ns_machines.first` — deleting the
# seeded NS row breaks every future enrollment for the tenant.
class MachinesControllerSharedGuardTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    @admin   = admin_users(:regular_admin)
    # Seed one shared machine and one operator-added machine for symmetry.
    @shared_ns = @network.machines.create!(
      hostname: "primary-ns", ip_address: "35.91.88.177",
      ssh_port: 22, ssh_user: Machine::SHARED_SSH_USER,
      ssh_auth_method: "agent", roles: "ns", status: "ready",
      last_error: "Shared production NS — seeded by ztlp.net."
    )
    @operator_relay = @network.machines.create!(
      hostname: "my-relay", ip_address: "10.0.5.4",
      ssh_port: 22, ssh_user: "root", ssh_auth_method: "key",
      roles: "relay", status: "pending"
    )
  end

  def sign_in_as(admin_user)
    post login_path, params: { email: admin_user.email, password: "password123" }
  end

  test "Machine#shared? identifies seeded rows" do
    assert @shared_ns.shared?
    refute @operator_relay.shared?
  end

  test "DELETE on a shared machine is blocked with an alert and the row survives" do
    sign_in_as(@admin)

    assert_no_difference -> { Machine.count } do
      delete network_machine_path(@network, @shared_ns)
    end
    assert_redirected_to network_machine_path(@network, @shared_ns)
    follow_redirect!
    assert_match(/shared production/i, response.body)
    assert Machine.exists?(@shared_ns.id), "shared machine must not be destroyed"
  end

  test "DELETE on an operator-added machine still works" do
    sign_in_as(@admin)

    assert_difference -> { Machine.count }, -1 do
      delete network_machine_path(@network, @operator_relay)
    end
    refute Machine.exists?(@operator_relay.id)
  end

  test "POST provision on a shared machine is blocked" do
    sign_in_as(@admin)

    post provision_network_machine_path(@network, @shared_ns), params: { component: "ns" }
    assert_redirected_to network_machine_path(@network, @shared_ns)
    follow_redirect!
    assert_match(/shared production/i, response.body)
  end

  test "POST test_connection on a shared machine is blocked" do
    sign_in_as(@admin)

    post test_connection_network_machine_path(@network, @shared_ns)
    assert_redirected_to network_machine_path(@network, @shared_ns)
    follow_redirect!
    assert_match(/shared production/i, response.body)
  end

  test "GET on a shared machine still renders (operator can view config)" do
    sign_in_as(@admin)
    get network_machine_path(@network, @shared_ns)
    assert_response :success
    assert_match @shared_ns.hostname, response.body
  end

  test "Network#deployable? returns true once shared machines are seeded" do
    # This is the regression check for the original bug: token-mint was
    # blocked because no NS machine existed. With shared machines seeded,
    # the network deploys.
    assert @network.deployable?
    # The shared NS row is now present and reachable via ns_machines.
    # (The :office fixture also has its own NS rows — assert presence
    # of the seeded one rather than total count.)
    assert_includes @network.ns_machines.map(&:ip_address), "35.91.88.177"
  end
end
