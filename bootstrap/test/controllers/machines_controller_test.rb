require "test_helper"

class MachinesControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
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

  test "check_ztlp_tunnel when unreachable" do
    ZtlpConnectivity.stubs(:check).returns(
      ZtlpConnectivity::Result.new(reachable: false, latency_ms: 500, error: "Handshake timeout")
    )
    post check_ztlp_tunnel_network_machine_path(@network, @machine)
    assert_redirected_to network_machine_path(@network, @machine)
    assert_includes flash[:alert], "ZTLP tunnel"
    @machine.reload
    assert_not @machine.ztlp_tunnel_reachable
    assert_equal "Handshake timeout", @machine.ztlp_tunnel_error
  end

  test "check_ztlp_tunnel when reachable" do
    ZtlpConnectivity.stubs(:check).returns(
      ZtlpConnectivity::Result.new(reachable: true, latency_ms: 42, metrics_source: "ztlp")
    )
    post check_ztlp_tunnel_network_machine_path(@network, @machine)
    assert_redirected_to network_machine_path(@network, @machine)
    assert_includes flash[:notice], "Connected"
    @machine.reload
    assert @machine.ztlp_tunnel_reachable
    assert_equal 42, @machine.ztlp_tunnel_latency_ms
  end
end
