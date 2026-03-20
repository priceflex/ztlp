require "test_helper"

class TokensControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
    @network = networks(:office)
  end

  test "index" do
    get network_tokens_path(@network)
    assert_response :success
    assert_includes response.body, "abc123def456"
  end

  test "show" do
    token = enrollment_tokens(:active_token)
    get network_token_path(@network, token)
    assert_response :success
    assert_includes response.body, token.token_id
  end

  test "new" do
    get new_network_token_path(@network)
    assert_response :success
  end

  test "create generates token" do
    assert_difference "EnrollmentToken.count" do
      post network_tokens_path(@network), params: {
        expires_in: "24h",
        max_uses: 5,
        notes: "test"
      }
    end
    assert_redirected_to network_token_path(@network, EnrollmentToken.last)
  end

  test "revoke" do
    token = enrollment_tokens(:active_token)
    post revoke_network_token_path(@network, token)
    assert_redirected_to network_tokens_path(@network)
    assert_equal "revoked", token.reload.status
  end
end
