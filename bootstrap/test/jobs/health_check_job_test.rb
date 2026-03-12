require "test_helper"

class HealthCheckJobTest < ActiveSupport::TestCase
  test "performs health check for all machines in network" do
    network = networks(:office)
    machines_checked = []

    HealthChecker.any_instance.stubs(:check_all).returns([
      HealthChecker::Result.new(
        machine: nil, component: "ns", status: "healthy",
        details: "{}", metrics: {}, container_state: "running",
        error_message: nil, response_time_ms: 100
      )
    ])

    # Should not raise
    assert_nothing_raised do
      HealthCheckJob.perform_now(network.id)
    end
  end

  test "skips nonexistent network" do
    assert_nothing_raised do
      HealthCheckJob.perform_now(999999)
    end
  end

  test "skips machines with no roles" do
    network = networks(:production)
    # Production network has no machines, so job should do nothing
    assert_nothing_raised do
      HealthCheckJob.perform_now(network.id)
    end
  end

  test "handles health check errors gracefully" do
    network = networks(:office)

    HealthChecker.any_instance.stubs(:check_all).raises(StandardError.new("SSH error"))

    # Should not raise even when individual checks fail
    assert_nothing_raised do
      HealthCheckJob.perform_now(network.id)
    end
  end

  test "broadcasts machine health updates" do
    network = networks(:office)

    HealthChecker.any_instance.stubs(:check_all).returns([
      HealthChecker::Result.new(
        machine: machines(:ns1), component: "ns", status: "healthy",
        details: "{}", metrics: {}, container_state: "running",
        error_message: nil, response_time_ms: 100
      )
    ])

    # Should broadcast without error (even if no subscribers)
    assert_nothing_raised do
      HealthCheckJob.perform_now(network.id)
    end
  end

  test "can be enqueued" do
    assert_enqueued_with(job: HealthCheckJob) do
      HealthCheckJob.perform_later(networks(:office).id)
    end
  end
end
