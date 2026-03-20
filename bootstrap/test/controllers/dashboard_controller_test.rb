require "test_helper"

class DashboardControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
  end

  test "index loads dashboard" do
    get root_path
    assert_response :success
    assert_includes response.body, "ZTLP Bootstrap Dashboard"
    assert_includes response.body, "Networks"
    assert_includes response.body, "Machines"
  end

  test "index shows health overview section" do
    get root_path
    assert_response :success
    assert_includes response.body, "Health Overview"
  end

  test "index shows health stat cards" do
    get root_path
    assert_response :success
    assert_includes response.body, "Healthy"
    assert_includes response.body, "Degraded"
    assert_includes response.body, "Down"
  end

  test "index shows alerts nav link" do
    get root_path
    assert_response :success
    assert_includes response.body, "Alerts"
  end

  test "index shows active alerts when present" do
    get root_path
    assert_response :success
    # There are active alerts in fixtures
    assert_includes response.body, "active alert"
  end

  test "index shows network health summaries" do
    get root_path
    assert_response :success
    assert_includes response.body, "Office Network"
  end
end
