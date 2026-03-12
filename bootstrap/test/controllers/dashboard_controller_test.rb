require "test_helper"

class DashboardControllerTest < ActionDispatch::IntegrationTest
  test "index loads dashboard" do
    get root_path
    assert_response :success
    assert_includes response.body, "ZTLP Bootstrap Dashboard"
    assert_includes response.body, "Networks"
    assert_includes response.body, "Machines"
  end
end
