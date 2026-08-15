# frozen_string_literal: true

require "test_helper"

# Integration tests for the read_only write-access guard on
# MachinesController. The guard prevents read_only users from
# mutating machines or triggering SSH operations (provision,
# test_connection, health_check, check_ztlp_tunnel).
class MachinesControllerWriteAccessTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    @machine = machines(:ns1)
    @readonly = admin_users(:read_only_admin)
    @admin = admin_users(:regular_admin)
  end

  def sign_in_as(admin_user)
    post login_path, params: { email: admin_user.email, password: "password123" }
  end

  # -- read_only user must be blocked from all write actions --

  test "read_only user is blocked from create" do
    sign_in_as(@readonly)
    post network_machines_path(@network), params: {
      machine: {
        hostname: "blocked",
        ip_address: "10.0.0.1",
        ssh_port: 22,
        ssh_user: "root",
        ssh_auth_method: "key",
        ssh_private_key_ciphertext: "fake",
        roles: "relay"
      }
    }
    assert_redirected_to network_machines_path(@network)
    follow_redirect!
    assert_match(/permission/i, response.body)
  end

  test "read_only user is blocked from update" do
    sign_in_as(@readonly)
    patch network_machine_path(@network, @machine), params: {
      machine: { hostname: "hacked" }
    }
    assert_redirected_to network_machines_path(@network)
    follow_redirect!
    assert_match(/permission/i, response.body)
    assert_not_equal "hacked", @machine.reload.hostname
  end

  test "read_only user is blocked from destroy" do
    sign_in_as(@readonly)
    assert_no_difference "Machine.count" do
      delete network_machine_path(@network, @machine)
    end
    assert_redirected_to network_machines_path(@network)
    follow_redirect!
    assert_match(/permission/i, response.body)
  end

  test "read_only user is blocked from provision" do
    sign_in_as(@readonly)
    post provision_network_machine_path(@network, @machine, component: "ns")
    assert_redirected_to network_machines_path(@network)
    follow_redirect!
    assert_match(/permission/i, response.body)
  end

  test "read_only user is blocked from test_connection" do
    sign_in_as(@readonly)
    post test_connection_network_machine_path(@network, @machine)
    assert_redirected_to network_machines_path(@network)
    follow_redirect!
    assert_match(/permission/i, response.body)
  end

  test "read_only user is blocked from health_check" do
    sign_in_as(@readonly)
    post health_check_network_machine_path(@network, @machine)
    assert_redirected_to network_machines_path(@network)
    follow_redirect!
    assert_match(/permission/i, response.body)
  end

  test "read_only user is blocked from check_ztlp_tunnel" do
    sign_in_as(@readonly)
    post check_ztlp_tunnel_network_machine_path(@network, @machine)
    assert_redirected_to network_machines_path(@network)
    follow_redirect!
    assert_match(/permission/i, response.body)
  end

  # -- read_only user can still read --

  test "read_only user can view index" do
    sign_in_as(@readonly)
    get network_machines_path(@network)
    assert_response :success
  end

  test "read_only user can view show" do
    sign_in_as(@readonly)
    get network_machine_path(@network, @machine)
    assert_response :success
  end

  test "read_only user can view new (but create is blocked)" do
    sign_in_as(@readonly)
    get new_network_machine_path(@network)
    assert_response :success
  end

  test "read_only user can view edit (but update is blocked)" do
    sign_in_as(@readonly)
    get edit_network_machine_path(@network, @machine)
    assert_response :success
  end

  # -- regular admin can still write --

  test "regular admin can create" do
    sign_in_as(@admin)
    assert_difference "Machine.count" do
      post network_machines_path(@network), params: {
        machine: {
          hostname: "admin-host",
          ip_address: "10.0.1.50",
          ssh_port: 22,
          ssh_user: "root",
          ssh_auth_method: "key",
          ssh_private_key_ciphertext: "fake",
          roles: "relay"
        }
      }
    end
    assert_redirected_to network_machine_path(@network, Machine.last)
  end

  test "regular admin can update" do
    sign_in_as(@admin)
    patch network_machine_path(@network, @machine), params: {
      machine: { hostname: "admin-updated" }
    }
    assert_redirected_to network_machine_path(@network, @machine)
  end

  test "regular admin can destroy" do
    sign_in_as(@admin)
    assert_difference "Machine.count", -1 do
      delete network_machine_path(@network, @machine)
    end
  end
end
