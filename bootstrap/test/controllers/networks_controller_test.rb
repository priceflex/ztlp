require "test_helper"

class NetworksControllerTest < ActionDispatch::IntegrationTest
  test "index" do
    get networks_path
    assert_response :success
    assert_includes response.body, "Office Network"
  end

  test "show" do
    get network_path(networks(:office))
    assert_response :success
    assert_includes response.body, "office.acme.ztlp"
  end

  test "new" do
    get new_network_path
    assert_response :success
  end

  test "create" do
    assert_difference "Network.count" do
      post networks_path, params: {
        network: { name: "New Net", zone: "new.ztlp" }
      }
    end
    assert_redirected_to network_path(Network.last)
    follow_redirect!
    assert_includes response.body, "New Net"
  end

  test "create with invalid data" do
    assert_no_difference "Network.count" do
      post networks_path, params: {
        network: { name: "", zone: "" }
      }
    end
    assert_response :unprocessable_entity
  end

  test "edit" do
    get edit_network_path(networks(:office))
    assert_response :success
  end

  test "update" do
    patch network_path(networks(:office)), params: {
      network: { name: "Updated Name" }
    }
    assert_redirected_to network_path(networks(:office))
    assert_equal "Updated Name", networks(:office).reload.name
  end

  test "destroy" do
    assert_difference "Network.count", -1 do
      delete network_path(networks(:production))
    end
    assert_redirected_to networks_path
  end

  test "register_ns redirects with alert when BOOTSTRAP_URL not set" do
    ENV.delete("BOOTSTRAP_URL")
    post register_ns_network_path(networks(:office))
    assert_redirected_to network_path(networks(:office))
    follow_redirect!
    assert_includes response.body, "BOOTSTRAP_URL not configured"
  end

  test "run_health_check redirects with notice" do
    # Health check will fail (no SSH access to test fixtures) but should redirect gracefully
    post run_health_check_network_path(networks(:office))
    assert_redirected_to network_path(networks(:office))
  end
end
