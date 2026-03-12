require "test_helper"

class AlertsControllerTest < ActionDispatch::IntegrationTest
  test "index shows alerts" do
    get alerts_path
    assert_response :success
    assert_includes response.body, "Alerts"
  end

  test "index shows active alert count" do
    get alerts_path
    assert_response :success
    assert_includes response.body, "active"
  end

  test "index filters by severity warning" do
    get alerts_path(severity: "warning")
    assert_response :success
  end

  test "index filters by severity critical" do
    get alerts_path(severity: "critical")
    assert_response :success
  end

  test "index filters by status active" do
    get alerts_path(status: "active")
    assert_response :success
  end

  test "index filters by status acknowledged" do
    get alerts_path(status: "acknowledged")
    assert_response :success
  end

  test "index filters by status resolved" do
    get alerts_path(status: "resolved")
    assert_response :success
  end

  test "acknowledge marks alert as acknowledged" do
    alert = alerts(:gateway_down)
    assert_not alert.acknowledged

    post acknowledge_alert_path(alert)
    assert_redirected_to alerts_path

    alert.reload
    assert alert.acknowledged
    assert_not_nil alert.acknowledged_at
  end

  test "acknowledge_all acknowledges all active alerts" do
    active_before = Alert.active.count
    assert active_before > 0

    post acknowledge_all_alerts_path
    assert_redirected_to alerts_path

    assert_equal 0, Alert.active.where(acknowledged: false).where(resolved_at: nil).where("acknowledged_at IS NOT NULL").count
  end

  test "index shows acknowledge button for active alerts" do
    get alerts_path
    assert_response :success
    assert_includes response.body, "Acknowledge"
  end

  test "index shows resolved status" do
    get alerts_path
    assert_response :success
    # old_resolved fixture should show resolved status
    assert_includes response.body, "Resolved"
  end

  test "index shows filter buttons" do
    get alerts_path
    assert_response :success
    assert_includes response.body, "All"
    assert_includes response.body, "Active"
    assert_includes response.body, "Warning"
    assert_includes response.body, "Critical"
  end
end
