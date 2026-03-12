require "test_helper"

class Api::AlertsControllerTest < ActionDispatch::IntegrationTest
  test "index returns JSON" do
    get api_alerts_path
    assert_response :success
    data = JSON.parse(response.body)

    assert data.key?("alerts")
    assert data.key?("meta")
    assert data["meta"].key?("total_active")
  end

  test "index returns alert details" do
    get api_alerts_path
    data = JSON.parse(response.body)

    alerts = data["alerts"]
    assert alerts.length > 0

    alert = alerts.first
    assert alert.key?("id")
    assert alert.key?("network")
    assert alert.key?("machine")
    assert alert.key?("component")
    assert alert.key?("severity")
    assert alert.key?("message")
    assert alert.key?("acknowledged")
    assert alert.key?("created_at")
  end

  test "index filters by severity" do
    get api_alerts_path(severity: "critical")
    data = JSON.parse(response.body)

    data["alerts"].each do |alert|
      assert_equal "critical", alert["severity"]
    end
  end

  test "index filters by status active" do
    get api_alerts_path(status: "active")
    data = JSON.parse(response.body)

    data["alerts"].each do |alert|
      assert_equal false, alert["acknowledged"]
      assert_nil alert["resolved_at"]
    end
  end

  test "index filters by status resolved" do
    get api_alerts_path(status: "resolved")
    data = JSON.parse(response.body)

    data["alerts"].each do |alert|
      assert_not_nil alert["resolved_at"]
    end
  end

  test "index respects limit parameter" do
    get api_alerts_path(limit: 1)
    data = JSON.parse(response.body)

    assert_equal 1, data["alerts"].length
  end

  test "meta includes active count" do
    get api_alerts_path
    data = JSON.parse(response.body)

    assert data["meta"]["total_active"] > 0
    assert_equal Alert.active_count, data["meta"]["total_active"]
  end
end
