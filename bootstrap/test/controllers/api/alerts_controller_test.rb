# frozen_string_literal: true

require "test_helper"

class Api::AlertsControllerTest < ActionDispatch::IntegrationTest
  def valid_office_headers
    @office_token ||= networks(:office).read_attribute(:enrollment_secret_ciphertext)
    { "Authorization" => "Bearer #{@office_token}" }
  end

  # --- Authentication ---

  test "index rejects requests without Authorization header" do
    get api_alerts_path
    assert_response :unauthorized
    assert_equal "Unauthorized", JSON.parse(response.body)["error"]
  end

  test "index rejects requests with an invalid token" do
    get api_alerts_path, headers: { "Authorization" => "Bearer invalid-token" }
    assert_response :unauthorized
  end

  # --- Tenant scoping ---

  test "index returns only alerts for the authenticated tenant" do
    get api_alerts_path, headers: valid_office_headers
    assert_response :success
    data = JSON.parse(response.body)

    # Office network has 3 alerts; production has 1 — must not leak it
    assert data["alerts"].all? { |a| a["network"] == "Office Network" }
    assert_equal networks(:office).alerts.active.count, data["meta"]["total_active"]
  end

  # --- Response shape ---

  test "index returns JSON with expected keys" do
    get api_alerts_path, headers: valid_office_headers
    assert_response :success
    data = JSON.parse(response.body)

    assert data.key?("alerts")
    assert data.key?("meta")
    assert data["meta"].key?("total_active")
  end

  test "index returns alert details" do
    get api_alerts_path, headers: valid_office_headers
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

  # --- Filtering ---

  test "index filters by severity" do
    get api_alerts_path(severity: "critical"), headers: valid_office_headers
    data = JSON.parse(response.body)

    data["alerts"].each do |alert|
      assert_equal "critical", alert["severity"]
    end
  end

  test "index filters by status active" do
    get api_alerts_path(status: "active"), headers: valid_office_headers
    data = JSON.parse(response.body)

    data["alerts"].each do |alert|
      assert_equal false, alert["acknowledged"]
      assert_nil alert["resolved_at"]
    end
  end

  test "index filters by status resolved" do
    get api_alerts_path(status: "resolved"), headers: valid_office_headers
    data = JSON.parse(response.body)

    data["alerts"].each do |alert|
      assert_not_nil alert["resolved_at"]
    end
  end

  test "index respects limit parameter" do
    get api_alerts_path(limit: 1), headers: valid_office_headers
    data = JSON.parse(response.body)

    assert_equal 1, data["alerts"].length
  end

  test "meta includes tenant-scoped active count" do
    get api_alerts_path, headers: valid_office_headers
    data = JSON.parse(response.body)

    # Must count only office alerts, not all alerts across tenants
    assert_equal networks(:office).alerts.active.count, data["meta"]["total_active"]
  end
end
