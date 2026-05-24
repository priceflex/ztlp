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

  # ── Phase A: target_kind = "device" path ────────────────────────
  #
  # The form rewrite (`tokens/new.html.erb`) adds a Device/User radio.
  # On submit:
  #   * device  → require `computer_name`; mint a token with
  #               target_kind="device", target_label=computer_name.
  #   * user    → require `ztlp_user_id` OR inline-create from
  #               `new_username` + optional `new_email`; mint a token
  #               with target_kind="user", target_label=user.name,
  #               and ztlp_user_id populated.
  # Existing fields (expires_in/max_uses/notes) keep flowing through.

  test "create with target_kind=device mints a device-bound token" do
    assert_difference "EnrollmentToken.count", 1 do
      post network_tokens_path(@network), params: {
        target_kind: "device",
        computer_name: "alice-laptop",
        expires_in: "24h",
        max_uses: 1
      }
    end

    token = EnrollmentToken.order(:id).last
    assert_equal "device", token.target_kind
    assert_equal "alice-laptop", token.target_label
    assert_nil token.ztlp_user_id
    assert_redirected_to network_token_path(@network, token)
  end

  test "create with target_kind=device rejects missing computer_name" do
    assert_no_difference "EnrollmentToken.count" do
      post network_tokens_path(@network), params: {
        target_kind: "device",
        computer_name: "",
        expires_in: "24h"
      }
    end
    assert_redirected_to network_tokens_path(@network)
    follow_redirect!
    assert_match(/computer name/i, response.body)
  end

  test "create with target_kind=device rejects malformed computer_name" do
    assert_no_difference "EnrollmentToken.count" do
      post network_tokens_path(@network), params: {
        target_kind: "device",
        computer_name: "alice's laptop!",  # not a DNS label
        expires_in: "24h"
      }
    end
    assert_redirected_to network_tokens_path(@network)
  end

  # ── Phase A: target_kind = "user" path ──────────────────────────

  test "create with target_kind=user + existing ztlp_user_id mints a user-bound token" do
    user = ztlp_users(:alice)

    assert_difference "EnrollmentToken.count", 1 do
      post network_tokens_path(@network), params: {
        target_kind: "user",
        ztlp_user_id: user.id,
        expires_in: "24h",
        max_uses: 1
      }
    end

    token = EnrollmentToken.order(:id).last
    assert_equal "user", token.target_kind
    assert_equal user.name, token.target_label
    assert_equal user.id, token.ztlp_user_id
  end

  test "create with target_kind=user inline-creates a new ZtlpUser when ztlp_user_id is blank" do
    new_name = "phase-a-new-user"

    assert_difference -> { ZtlpUser.count }, 1 do
      assert_difference -> { EnrollmentToken.count }, 1 do
        post network_tokens_path(@network), params: {
          target_kind: "user",
          new_username: new_name,
          new_email: "newuser@example.com",
          expires_in: "24h"
        }
      end
    end

    user = ZtlpUser.find_by(network_id: @network.id, name: new_name)
    assert_not_nil user
    assert_equal "newuser@example.com", user.email

    token = EnrollmentToken.order(:id).last
    assert_equal "user", token.target_kind
    assert_equal new_name, token.target_label
    assert_equal user.id, token.ztlp_user_id
  end

  test "create with target_kind=user rejects when neither ztlp_user_id nor new_username present" do
    assert_no_difference "EnrollmentToken.count" do
      post network_tokens_path(@network), params: {
        target_kind: "user",
        expires_in: "24h"
      }
    end
    assert_redirected_to network_tokens_path(@network)
  end

  # ── Phase A: cross-tenant safety ────────────────────────────────

  test "create with target_kind=user rejects ztlp_user from a different network" do
    eve = ztlp_users(:other_network_user)  # in :production network
    refute_equal @network.id, eve.network_id

    assert_no_difference "EnrollmentToken.count" do
      post network_tokens_path(@network), params: {
        target_kind: "user",
        ztlp_user_id: eve.id,
        expires_in: "24h"
      }
    end
    assert_redirected_to network_tokens_path(@network)
  end

  # ── Phase A: legacy back-compat ─────────────────────────────────

  test "create without target_kind still works (legacy / un-bound mint)" do
    # The old form posts without target_kind. We don't want to break
    # any deployment that runs against an un-migrated bookmarklet or
    # external integration that drives the dashboard form directly.
    assert_difference "EnrollmentToken.count", 1 do
      post network_tokens_path(@network), params: {
        expires_in: "24h",
        max_uses: 1,
        notes: "legacy-shaped POST"
      }
    end

    token = EnrollmentToken.order(:id).last
    assert_nil token.target_kind
    assert_nil token.target_label
  end
end
