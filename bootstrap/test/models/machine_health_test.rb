require "test_helper"

# Tests for the health-related methods added to Machine in Phase C
class MachineHealthTest < ActiveSupport::TestCase
  test "health_checks association" do
    machine = machines(:ns1)
    assert machine.health_checks.any?
  end

  test "alerts association" do
    machine = machines(:gateway1)
    assert machine.alerts.any?
  end

  test "latest_health_check_for returns most recent" do
    machine = machines(:ns1)
    latest = machine.latest_health_check_for("ns")
    assert_not_nil latest
    assert_equal "ns", latest.component
    # ns1_healthy is more recent than ns1_degraded_old
    assert_equal "healthy", latest.status
  end

  test "latest_health_check_for returns nil when no checks" do
    machine = machines(:relay1)
    assert_nil machine.latest_health_check_for("ns") # relay1 only has relay checks
  end

  test "health_status returns healthy when all components healthy" do
    machine = machines(:ns1)
    assert_equal "healthy", machine.health_status
  end

  test "health_status returns degraded when any component degraded" do
    machine = machines(:multi_role)
    # multi has ns healthy + relay degraded
    assert_equal "degraded", machine.health_status
  end

  test "health_status returns down when any component down" do
    machine = machines(:gateway1)
    assert_equal "down", machine.health_status
  end

  test "health_status returns unknown when no checks" do
    # Create a fresh machine with no health checks
    machine = Machine.create!(
      network: networks(:office),
      hostname: "fresh-machine",
      ip_address: "10.0.1.99",
      roles: "ns"
    )
    assert_equal "unknown", machine.health_status
  end

  test "health_summary returns hash with all roles" do
    machine = machines(:multi_role)
    summary = machine.health_summary
    assert summary.key?("ns")
    assert summary.key?("relay")
    assert_equal "healthy", summary["ns"][:status]
    assert_equal "degraded", summary["relay"][:status]
  end

  test "health_summary returns unknown for unchecked role" do
    machine = Machine.create!(
      network: networks(:office),
      hostname: "unchecked",
      ip_address: "10.0.1.98",
      roles: "gateway"
    )
    summary = machine.health_summary
    assert_equal "unknown", summary["gateway"][:status]
    assert_nil summary["gateway"][:checked_at]
  end

  test "destroying machine cascades to health checks" do
    machine = machines(:ns1)
    hc_count = machine.health_checks.count
    assert hc_count > 0

    machine.destroy
    assert_equal 0, HealthCheck.where(machine_id: machine.id).count
  end

  test "destroying machine cascades to alerts" do
    machine = machines(:gateway1)
    assert machine.alerts.count > 0

    machine.destroy
    assert_equal 0, Alert.where(machine_id: machine.id).count
  end
end
