require "test_helper"

class HealthControllerTest < ActionDispatch::IntegrationTest
  test "network_health shows health overview" do
    get network_health_path(networks(:office))
    assert_response :success
    assert_includes response.body, "Health"
    assert_includes response.body, networks(:office).name
  end

  test "network_health shows machine health cards" do
    get network_health_path(networks(:office))
    assert_response :success
    assert_includes response.body, "ns1.office"
    assert_includes response.body, "relay1.office"
    assert_includes response.body, "gw1.office"
  end

  test "network_health shows summary stats" do
    get network_health_path(networks(:office))
    assert_response :success
    assert_includes response.body, "Total Machines"
    assert_includes response.body, "Healthy"
    assert_includes response.body, "Degraded"
    assert_includes response.body, "Down"
  end

  test "machine_health shows detailed health" do
    network = networks(:office)
    machine = machines(:ns1)
    get health_network_machine_path(network, machine)
    assert_response :success
    assert_includes response.body, machine.hostname
    assert_includes response.body, "Health"
  end

  test "machine_health shows health history table" do
    network = networks(:office)
    machine = machines(:ns1)
    get health_network_machine_path(network, machine)
    assert_response :success
    assert_includes response.body, "Health History"
  end

  test "machine_health shows component cards" do
    network = networks(:office)
    machine = machines(:ns1)
    get health_network_machine_path(network, machine)
    assert_response :success
    assert_includes response.body, "NS"
  end

  test "check_health enqueues job and redirects" do
    network = networks(:office)

    assert_enqueued_with(job: HealthCheckJob) do
      post network_check_health_path(network)
    end

    assert_redirected_to network_health_path(network)
    follow_redirect!
    assert_includes response.body, "Health check started"
  end

  test "check_machine_health runs health check" do
    network = networks(:office)
    machine = machines(:ns1)

    HealthChecker.any_instance.stubs(:check_all).returns([
      HealthChecker::Result.new(
        machine: machine, component: "ns", status: "healthy",
        details: "{}", metrics: {}, container_state: "running",
        error_message: nil, response_time_ms: 100
      )
    ])

    post check_health_network_machine_path(network, machine)
    assert_redirected_to health_network_machine_path(network, machine)
  end

  test "check_machine_health handles errors" do
    network = networks(:office)
    machine = machines(:ns1)

    HealthChecker.any_instance.stubs(:check_all).raises(StandardError.new("connection failed"))

    post check_health_network_machine_path(network, machine)
    assert_redirected_to health_network_machine_path(network, machine)
    follow_redirect!
    assert_includes response.body, "Health check failed"
  end

  test "network_health for network with no machines" do
    get network_health_path(networks(:production))
    assert_response :success
    assert_includes response.body, "No machines"
  end

  test "machine_health shows alerts" do
    network = networks(:office)
    machine = machines(:gateway1)
    get health_network_machine_path(network, machine)
    assert_response :success
    # gateway1 has an active alert
    assert_includes response.body, "Recent Alerts"
  end
end
