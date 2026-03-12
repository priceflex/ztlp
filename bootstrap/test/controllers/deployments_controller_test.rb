require "test_helper"

class DeploymentsControllerTest < ActionDispatch::IntegrationTest
  test "index" do
    get deployments_path
    assert_response :success
  end

  test "show" do
    dep = deployments(:ns1_deploy)
    get deployment_path(dep)
    assert_response :success
    assert_includes response.body, "ns"
  end
end
