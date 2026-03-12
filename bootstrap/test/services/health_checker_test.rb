require "test_helper"

class HealthCheckerTest < ActiveSupport::TestCase
  setup do
    @machine = machines(:relay1)
    @checker = HealthChecker.new(@machine)
  end

  test "check_component returns result struct for healthy component" do
    mock_ssh_session = mock("ssh_session")

    # Container inspect
    mock_ssh_session.expects(:open_channel).at_least_once.yields(mock_channel_for(
      "docker inspect --format '{{.State.Status}}|{{.State.Running}}|{{.State.StartedAt}}|{{.State.Pid}}' ztlp-relay 2>/dev/null",
      stdout: "running|true|2026-03-10T00:00:00Z|1234"
    ))

    Net::SSH.expects(:start).with(
      @machine.ip_address, @machine.ssh_user, anything
    ).yields(mock_ssh_session)

    result = @checker.check_component("relay")

    assert_kind_of HealthChecker::Result, result
    assert_equal @machine, result.machine
    assert_equal "relay", result.component
  end

  test "check_component returns down when SSH connection refused" do
    Net::SSH.expects(:start).raises(Errno::ECONNREFUSED.new("Connection refused"))

    result = @checker.check_component("relay")
    assert_equal "down", result.status
    assert_includes result.error_message, "Connection refused"
  end

  test "check_component returns down when SSH fails" do
    Net::SSH.expects(:start).raises(Net::SSH::AuthenticationFailed.new("auth failed"))

    result = @checker.check_component("relay")
    assert_equal "down", result.status
    assert_includes result.error_message, "auth failed"
  end

  test "check_component raises for unknown component" do
    assert_raises(HealthChecker::HealthCheckError) do
      @checker.check_component("bogus")
    end
  end

  test "check_all checks all roles and stores results" do
    machine = machines(:multi_role)
    checker = HealthChecker.new(machine)

    # Mock SSH to return down for everything (simplest mock)
    Net::SSH.expects(:start).at_least_once.raises(Errno::ECONNREFUSED.new("refused"))

    results = checker.check_all

    assert_equal 2, results.length
    assert_equal %w[ns relay].sort, results.map(&:component).sort
    results.each { |r| assert_equal "down", r.status }

    # Should have stored health checks
    assert machine.health_checks.where("checked_at >= ?", 1.minute.ago).count >= 2
  end

  test "check_all updates machine last_health_check_at" do
    Net::SSH.expects(:start).at_least_once.raises(Errno::ECONNREFUSED.new)

    assert_nil @machine.last_health_check_at
    @checker.check_all
    @machine.reload
    assert_not_nil @machine.last_health_check_at
  end

  test "check_all creates alerts on status change to down" do
    machine = machines(:relay1)
    checker = HealthChecker.new(machine)

    # Create a previous healthy check
    HealthCheck.create!(machine: machine, component: "relay", status: "healthy", checked_at: 10.minutes.ago)

    Net::SSH.expects(:start).at_least_once.raises(Errno::ECONNREFUSED.new)

    assert_difference "Alert.count" do
      checker.check_all
    end

    alert = Alert.where(machine: machine, component: "relay").order(created_at: :desc).first
    assert_equal "critical", alert.severity
  end

  test "store_result auto-resolves alerts when status is healthy" do
    machine = machines(:gateway1)
    alert = alerts(:gateway_down)
    assert_nil alert.resolved_at

    checker = HealthChecker.new(machine)

    # Store a healthy result which should trigger auto-resolve
    result = HealthChecker::Result.new(
      machine: machine, component: "gateway", status: "healthy",
      details: '{}', metrics: {}, container_state: "running",
      error_message: nil, response_time_ms: 100
    )

    checker.send(:store_result, result)

    alert.reload
    assert_not_nil alert.resolved_at
  end

  test "HEALTH_CHECKS defines all three components" do
    assert_equal %w[gateway ns relay], HealthChecker::HEALTH_CHECKS.keys.sort
  end

  test "CONTAINER_NAMES defines all three components" do
    assert_equal %w[gateway ns relay], HealthChecker::CONTAINER_NAMES.keys.sort
  end

  test "parse_prometheus_metrics extracts ZTLP metrics" do
    text = <<~PROM
      # HELP ztlp_sessions_active Active sessions
      ztlp_sessions_active 42
      # HELP ztlp_packets_per_sec Packets per second
      ztlp_packets_per_sec 1234.5
      ztlp_ns_records_count 100
      process_cpu_seconds_total 3.14
      process_resident_memory_bytes 52428800
    PROM

    result = @checker.send(:parse_prometheus_metrics, text)
    assert_equal 42, result[:sessions_active]
    assert_in_delta 1234.5, result[:packets_per_sec], 0.1
    assert_equal 100, result[:ns_records_count]
    assert_in_delta 3.14, result[:cpu_seconds], 0.01
    assert_equal 52428800, result[:memory_bytes]
  end

  test "parse_prometheus_metrics handles empty text" do
    assert_equal({}, @checker.send(:parse_prometheus_metrics, ""))
    assert_equal({}, @checker.send(:parse_prometheus_metrics, nil))
  end

  test "parse_prometheus_metrics ignores comments and blank lines" do
    text = "# This is a comment\n\n# Another comment\n"
    assert_equal({}, @checker.send(:parse_prometheus_metrics, text))
  end

  test "store_result creates health check record" do
    result = HealthChecker::Result.new(
      machine: @machine, component: "relay", status: "healthy",
      details: '{"test": true}', metrics: { test: true },
      container_state: "running", error_message: nil, response_time_ms: 100
    )

    assert_difference "HealthCheck.count" do
      @checker.send(:store_result, result)
    end

    hc = HealthCheck.last
    assert_equal "relay", hc.component
    assert_equal "healthy", hc.status
    assert_equal "running", hc.container_state
    assert_equal 100, hc.response_time_ms
  end

  private

  def mock_channel_for(_command, stdout: "", stderr: "", exit_status: 0)
    channel = mock("channel")
    channel.stubs(:exec).yields(channel, true)
    channel.stubs(:on_data).yields(channel, stdout)
    channel.stubs(:on_extended_data).yields(channel, nil, stderr)
    channel.stubs(:on_request).with("exit-status").yields(channel, stub(read_long: exit_status))
    channel.stubs(:wait)
    channel
  end

  def mock_healthy_session(ssh, component)
    # For a healthy check, we need multiple commands to succeed
    channel = mock("channel")
    channel.stubs(:exec).yields(channel, true)
    channel.stubs(:on_data).yields(channel, "running|true|2026-03-10T00:00:00Z|1234")
    channel.stubs(:on_extended_data)
    channel.stubs(:on_request).with("exit-status").yields(channel, stub(read_long: 0))
    channel.stubs(:wait)

    ssh.stubs(:open_channel).yields(channel)
  end
end
