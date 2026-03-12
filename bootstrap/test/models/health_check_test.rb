require "test_helper"

class HealthCheckTest < ActiveSupport::TestCase
  test "valid health check" do
    hc = HealthCheck.new(
      machine: machines(:ns1),
      component: "ns",
      status: "healthy",
      checked_at: Time.current
    )
    assert hc.valid?
  end

  test "requires machine" do
    hc = HealthCheck.new(component: "ns", status: "healthy", checked_at: Time.current)
    assert_not hc.valid?
  end

  test "requires component" do
    hc = HealthCheck.new(machine: machines(:ns1), status: "healthy", checked_at: Time.current)
    assert_not hc.valid?
    assert hc.errors[:component].any?
  end

  test "validates component values" do
    hc = HealthCheck.new(
      machine: machines(:ns1), component: "bogus", status: "healthy", checked_at: Time.current
    )
    assert_not hc.valid?
    assert hc.errors[:component].any?
  end

  test "requires status" do
    hc = HealthCheck.new(machine: machines(:ns1), component: "ns", status: nil, checked_at: Time.current)
    assert_not hc.valid?
    assert hc.errors[:status].any?
  end

  test "validates status values" do
    hc = HealthCheck.new(
      machine: machines(:ns1), component: "ns", status: "bogus", checked_at: Time.current
    )
    assert_not hc.valid?
    assert hc.errors[:status].any?
  end

  test "requires checked_at" do
    hc = HealthCheck.new(machine: machines(:ns1), component: "ns", status: "healthy")
    assert_not hc.valid?
    assert hc.errors[:checked_at].any?
  end

  test "healthy?" do
    assert health_checks(:ns1_healthy).healthy?
    assert_not health_checks(:gateway1_down).healthy?
  end

  test "degraded?" do
    assert health_checks(:ns1_degraded_old).degraded?
    assert_not health_checks(:ns1_healthy).degraded?
  end

  test "down?" do
    assert health_checks(:gateway1_down).down?
    assert_not health_checks(:ns1_healthy).down?
  end

  test "parsed_metrics returns hash" do
    hc = health_checks(:ns1_healthy)
    metrics = hc.parsed_metrics
    assert_kind_of Hash, metrics
    assert_equal true, metrics["port_listening"]
  end

  test "parsed_metrics returns empty hash for nil" do
    hc = HealthCheck.new(machine: machines(:ns1), component: "ns", status: "healthy", checked_at: Time.current)
    assert_equal({}, hc.parsed_metrics)
  end

  test "parsed_metrics returns empty hash for invalid JSON" do
    hc = HealthCheck.new(
      machine: machines(:ns1), component: "ns", status: "healthy",
      checked_at: Time.current, metrics: "not json"
    )
    assert_equal({}, hc.parsed_metrics)
  end

  test "recent scope orders by checked_at desc" do
    checks = HealthCheck.recent.to_a
    assert checks.length >= 2
    checks.each_cons(2) do |a, b|
      assert a.checked_at >= b.checked_at
    end
  end

  test "for_component scope filters" do
    ns_checks = HealthCheck.for_component("ns").to_a
    assert ns_checks.all? { |c| c.component == "ns" }
  end

  test "healthy scope filters" do
    healthy = HealthCheck.healthy.to_a
    assert healthy.all? { |c| c.status == "healthy" }
  end

  test "down scope filters" do
    down = HealthCheck.down.to_a
    assert down.all? { |c| c.status == "down" }
  end

  test "degraded scope filters" do
    degraded = HealthCheck.degraded.to_a
    assert degraded.all? { |c| c.status == "degraded" }
  end

  test "since scope filters by time" do
    recent = HealthCheck.since(30.minutes.ago).to_a
    assert recent.all? { |c| c.checked_at >= 30.minutes.ago }
  end

  test "status_counts returns hash" do
    counts = HealthCheck.status_counts
    assert_kind_of Hash, counts
    assert counts.key?("healthy")
  end

  test "belongs to machine" do
    hc = health_checks(:ns1_healthy)
    assert_equal machines(:ns1), hc.machine
  end

  test "valid components" do
    %w[ns relay gateway].each do |comp|
      hc = HealthCheck.new(machine: machines(:ns1), component: comp, status: "healthy", checked_at: Time.current)
      assert hc.valid?, "#{comp} should be valid"
    end
  end

  test "valid statuses" do
    %w[healthy degraded down unknown].each do |status|
      hc = HealthCheck.new(machine: machines(:ns1), component: "ns", status: status, checked_at: Time.current)
      assert hc.valid?, "#{status} should be valid"
    end
  end
end
