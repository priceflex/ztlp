require "test_helper"

class Api::HealthControllerTest < ActionDispatch::IntegrationTest
  def valid_office_headers
    @office_token ||= networks(:office).read_attribute(:enrollment_secret_ciphertext)
    { "Authorization" => "Bearer #{@office_token}" }
  end

  # --- Authentication (lmb-gquu fix) ---

  test "network health rejects requests without Authorization header" do
    get api_network_health_path(network_id: networks(:office).id)
    assert_response :unauthorized
  end

  test "machine health rejects requests without Authorization header" do
    get api_machine_health_path(id: machines(:ns1).id)
    assert_response :unauthorized
  end

  test "network health rejects an invalid bearer token" do
    get api_network_health_path(network_id: networks(:office).id),
        headers: { "Authorization" => "Bearer not-a-real-token" }
    assert_response :unauthorized
  end

  test "network health rejects a token that does not match the requested network_id (cross-tenant)" do
    other_network = Network.create!(
      name: "Other Co",
      zone: "other.ztlp",
      status: "created",
      enrollment_secret_ciphertext: "f" * 64
    )

    get api_network_health_path(network_id: other_network.id), headers: valid_office_headers
    assert_response :not_found
  end

  test "machine health rejects a machine belonging to a different network than the token" do
    other_network = Network.create!(
      name: "Other Co",
      zone: "other.ztlp",
      status: "created",
      enrollment_secret_ciphertext: "f" * 64
    )
    other_machine = Machine.create!(
      network: other_network,
      hostname: "evil.other",
      ip_address: "10.9.9.9",
      ssh_port: 22,
      ssh_user: "root",
      ssh_auth_method: "key",
      roles: "ns",
      status: "pending"
    )

    get api_machine_health_path(id: other_machine.id), headers: valid_office_headers
    assert_response :not_found
  end

  # --- Happy path ---

  test "network health returns JSON" do
    get api_network_health_path(network_id: networks(:office).id), headers: valid_office_headers
    assert_response :success
    data = JSON.parse(response.body)

    assert data.key?("network")
    assert data.key?("machines")

    network_data = data["network"]
    assert_equal "Office Network", network_data["name"]
    assert_equal "office.acme.ztlp", network_data["zone"]
    assert network_data.key?("status")
    assert network_data.key?("summary")

    summary = network_data["summary"]
    assert summary.key?("total")
    assert summary.key?("healthy")
    assert summary.key?("degraded")
    assert summary.key?("down")
    assert summary.key?("unknown")
  end

  test "network health lists all machines" do
    get api_network_health_path(network_id: networks(:office).id), headers: valid_office_headers
    data = JSON.parse(response.body)

    machines = data["machines"]
    assert machines.length > 0

    machine = machines.first
    assert machine.key?("id")
    assert machine.key?("hostname")
    assert machine.key?("ip_address")
    assert machine.key?("status")
    assert machine.key?("components")
  end

  test "machine health returns JSON" do
    get api_machine_health_path(id: machines(:ns1).id), headers: valid_office_headers
    assert_response :success
    data = JSON.parse(response.body)

    assert data.key?("machine")
    assert data.key?("components")
    assert data.key?("recent_checks")

    machine_data = data["machine"]
    assert_equal "ns1.office", machine_data["hostname"]
    assert_equal "10.0.1.10", machine_data["ip_address"]
  end

  test "machine health includes recent checks" do
    get api_machine_health_path(id: machines(:ns1).id), headers: valid_office_headers
    data = JSON.parse(response.body)

    checks = data["recent_checks"]
    assert checks.is_a?(Array)
    assert checks.length > 0

    check = checks.first
    assert check.key?("component")
    assert check.key?("status")
    assert check.key?("metrics")
    assert check.key?("checked_at")
  end

  test "machine health includes component summary" do
    get api_machine_health_path(id: machines(:ns1).id), headers: valid_office_headers
    data = JSON.parse(response.body)

    components = data["components"]
    assert components.key?("ns")
    assert components["ns"].key?("status")
  end

  test "network health returns 404 for missing network" do
    get api_network_health_path(network_id: 999999), headers: valid_office_headers
    assert_response :not_found
  end

  test "machine health returns 404 for missing machine" do
    get api_machine_health_path(id: 999999), headers: valid_office_headers
    assert_response :not_found
  end
end
