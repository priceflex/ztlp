require "test_helper"

class AlertTest < ActiveSupport::TestCase
  test "valid alert" do
    alert = Alert.new(
      network: networks(:office),
      machine: machines(:ns1),
      component: "ns",
      severity: "warning",
      message: "Test alert"
    )
    assert alert.valid?
  end

  test "requires network" do
    alert = Alert.new(machine: machines(:ns1), component: "ns", severity: "warning", message: "Test")
    assert_not alert.valid?
  end

  test "requires machine" do
    alert = Alert.new(network: networks(:office), component: "ns", severity: "warning", message: "Test")
    assert_not alert.valid?
  end

  test "requires component" do
    alert = Alert.new(network: networks(:office), machine: machines(:ns1), severity: "warning", message: "Test")
    assert_not alert.valid?
    assert alert.errors[:component].any?
  end

  test "validates component values" do
    alert = Alert.new(
      network: networks(:office), machine: machines(:ns1),
      component: "bogus", severity: "warning", message: "Test"
    )
    assert_not alert.valid?
  end

  test "requires severity" do
    alert = Alert.new(
      network: networks(:office), machine: machines(:ns1),
      component: "ns", severity: nil, message: "Test"
    )
    assert_not alert.valid?
    assert alert.errors[:severity].any?
  end

  test "validates severity values" do
    alert = Alert.new(
      network: networks(:office), machine: machines(:ns1),
      component: "ns", severity: "bogus", message: "Test"
    )
    assert_not alert.valid?
  end

  test "requires message" do
    alert = Alert.new(
      network: networks(:office), machine: machines(:ns1),
      component: "ns", severity: "warning"
    )
    assert_not alert.valid?
    assert alert.errors[:message].any?
  end

  test "acknowledge!" do
    alert = alerts(:gateway_down)
    assert_not alert.acknowledged
    alert.acknowledge!
    assert alert.acknowledged
    assert_not_nil alert.acknowledged_at
  end

  test "resolve!" do
    alert = alerts(:gateway_down)
    assert_nil alert.resolved_at
    alert.resolve!
    assert_not_nil alert.resolved_at
  end

  test "active?" do
    assert alerts(:gateway_down).active?
    assert_not alerts(:old_resolved).active?
  end

  test "resolved?" do
    assert alerts(:old_resolved).resolved?
    assert_not alerts(:gateway_down).resolved?
  end

  test "active scope" do
    active = Alert.active.to_a
    assert active.all? { |a| !a.acknowledged && a.resolved_at.nil? }
    assert active.include?(alerts(:gateway_down))
    assert_not active.include?(alerts(:old_resolved))
  end

  test "acknowledged_alerts scope" do
    acked = Alert.acknowledged_alerts.to_a
    assert acked.all?(&:acknowledged)
  end

  test "resolved scope" do
    resolved = Alert.resolved.to_a
    assert resolved.all? { |a| a.resolved_at.present? }
  end

  test "critical scope" do
    critical = Alert.critical.to_a
    assert critical.all? { |a| a.severity == "critical" }
  end

  test "warnings scope" do
    warnings = Alert.warnings.to_a
    assert warnings.all? { |a| a.severity == "warning" }
  end

  test "for_network scope" do
    office_alerts = Alert.for_network(networks(:office)).to_a
    assert office_alerts.all? { |a| a.network_id == networks(:office).id }
  end

  test "for_machine scope" do
    machine_alerts = Alert.for_machine(machines(:gateway1)).to_a
    assert machine_alerts.all? { |a| a.machine_id == machines(:gateway1).id }
  end

  test "active_count" do
    count = Alert.active_count
    assert count > 0
    assert_equal Alert.active.count, count
  end

  test "create_for_status_change creates alert on degraded" do
    assert_difference "Alert.count", 1 do
      Alert.create_for_status_change(
        machine: machines(:ns1),
        component: "ns",
        new_status: "degraded",
        old_status: "healthy"
      )
    end
    alert = Alert.last
    assert_equal "warning", alert.severity
    assert_includes alert.message, "degraded"
  end

  test "create_for_status_change creates critical alert on down" do
    assert_difference "Alert.count", 1 do
      Alert.create_for_status_change(
        machine: machines(:ns1),
        component: "ns",
        new_status: "down",
        old_status: "healthy"
      )
    end
    assert_equal "critical", Alert.last.severity
  end

  test "create_for_status_change does nothing when status unchanged" do
    assert_no_difference "Alert.count" do
      Alert.create_for_status_change(
        machine: machines(:ns1),
        component: "ns",
        new_status: "healthy",
        old_status: "healthy"
      )
    end
  end

  test "create_for_status_change does nothing when new status is healthy" do
    assert_no_difference "Alert.count" do
      Alert.create_for_status_change(
        machine: machines(:ns1),
        component: "ns",
        new_status: "healthy",
        old_status: "degraded"
      )
    end
  end

  test "auto_resolve resolves active alerts" do
    alert = alerts(:gateway_down)
    assert_nil alert.resolved_at

    Alert.auto_resolve(machine: machines(:gateway1), component: "gateway")

    alert.reload
    assert_not_nil alert.resolved_at
  end

  test "auto_resolve does not affect already resolved alerts" do
    alert = alerts(:old_resolved)
    original_resolved_at = alert.resolved_at

    Alert.auto_resolve(machine: machines(:ns1), component: "ns")

    alert.reload
    assert_equal original_resolved_at, alert.resolved_at
  end

  test "valid severities" do
    %w[warning critical].each do |sev|
      alert = Alert.new(
        network: networks(:office), machine: machines(:ns1),
        component: "ns", severity: sev, message: "Test"
      )
      assert alert.valid?, "#{sev} should be valid"
    end
  end

  test "valid components" do
    %w[ns relay gateway].each do |comp|
      alert = Alert.new(
        network: networks(:office), machine: machines(:ns1),
        component: comp, severity: "warning", message: "Test"
      )
      assert alert.valid?, "#{comp} should be valid"
    end
  end

  test "recent scope orders by created_at desc" do
    alerts_list = Alert.recent.to_a
    alerts_list.each_cons(2) do |a, b|
      assert a.created_at >= b.created_at
    end
  end
end
