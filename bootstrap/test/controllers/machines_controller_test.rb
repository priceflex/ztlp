require "test_helper"

class MachinesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    @machine = machines(:ns1)
  end

  test "index" do
    get network_machines_path(@network)
    assert_response :success
    assert_includes response.body, "ns1.office"
  end

  test "show" do
    get network_machine_path(@network, @machine)
    assert_response :success
    assert_includes response.body, "10.0.1.10"
  end

  test "new" do
    get new_network_machine_path(@network)
    assert_response :success
  end

  test "create" do
    assert_difference "Machine.count" do
      post network_machines_path(@network), params: {
        machine: {
          hostname: "new-host",
          ip_address: "10.0.1.99",
          ssh_port: 22,
          ssh_user: "root",
          ssh_auth_method: "key",
          ssh_private_key_ciphertext: "fake-key",
          roles: "relay"
        }
      }
    end
    assert_redirected_to network_machine_path(@network, Machine.last)
  end

  test "create with invalid data" do
    assert_no_difference "Machine.count" do
      post network_machines_path(@network), params: {
        machine: { hostname: "", ip_address: "bad" }
      }
    end
    assert_response :unprocessable_entity
  end

  test "edit" do
    get edit_network_machine_path(@network, @machine)
    assert_response :success
  end

  test "update" do
    patch network_machine_path(@network, @machine), params: {
      machine: { hostname: "updated-ns1" }
    }
    assert_redirected_to network_machine_path(@network, @machine)
    assert_equal "updated-ns1", @machine.reload.hostname
  end

  test "destroy" do
    assert_difference "Machine.count", -1 do
      delete network_machine_path(@network, @machine)
    end
    assert_redirected_to network_machines_path(@network)
  end

  test "test_connection with SSH failure" do
    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)

    post test_connection_network_machine_path(@network, @machine)
    assert_redirected_to network_machine_path(@network, @machine)
    assert flash[:alert].present?
  end

  test "provision with invalid component" do
    post provision_network_machine_path(@network, @machine, component: "bogus")
    assert_redirected_to network_machine_path(@network, @machine)
    assert_includes flash[:alert], "Invalid component"
  end
end
