require "test_helper"

# Tests for the health-related methods added to Network in Phase C
class NetworkHealthTest < ActiveSupport::TestCase
  test "health_checks through association" do
    network = networks(:office)
    assert network.health_checks.any?
  end

  test "alerts association" do
    network = networks(:office)
    assert network.alerts.any?
  end

  test "health_status returns overall network health" do
    network = networks(:office)
    # office has mixed statuses (healthy, degraded, down)
    status = network.health_status
    assert_includes %w[healthy degraded down unknown], status
  end

  test "health_status returns unknown for empty network" do
    network = networks(:production)
    assert_equal "unknown", network.health_status
  end

  test "health_summary returns counts" do
    network = networks(:office)
    summary = network.health_summary
    assert summary.key?(:total)
    assert summary.key?(:healthy)
    assert summary.key?(:degraded)
    assert summary.key?(:down)
    assert summary.key?(:unknown)
    assert_equal network.machines.count, summary[:total]
    assert_equal summary[:total], summary[:healthy] + summary[:degraded] + summary[:down] + summary[:unknown]
  end

  test "health_summary for empty network" do
    network = networks(:production)
    summary = network.health_summary
    assert_equal 0, summary[:total]
    assert_equal 0, summary[:healthy]
  end

  test "destroying network cascades to alerts" do
    network = networks(:office)
    assert network.alerts.any?

    alert_ids = network.alerts.pluck(:id)
    network.destroy
    assert_equal 0, Alert.where(id: alert_ids).count
  end
end
