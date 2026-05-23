# frozen_string_literal: true

require "test_helper"

class Api::EnrollmentControllerTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    @token = enrollment_tokens(:active_token)
  end

  test "confirm increments current_uses" do
    initial_uses = @token.current_uses
    assert_equal "active", @token.status

    post api_enrollment_confirm_path, params: {
      token_id: @token.token_id,
      node_id: "abcdef1234567890",
      name: "device1.office.acme.ztlp"
    }

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "confirmed", json["status"]
    assert_equal initial_uses + 1, json["current_uses"]

    @token.reload
    assert_equal initial_uses + 1, @token.current_uses
  end

  test "confirm marks token as exhausted when max_uses reached" do
    @token.update!(max_uses: 1, current_uses: 0)

    post api_enrollment_confirm_path, params: {
      token_id: @token.token_id,
      node_id: "abcdef1234567890",
      name: "device1.office.acme.ztlp"
    }

    assert_response :success
    json = JSON.parse(response.body)
    assert json["exhausted"]

    @token.reload
    assert_equal "exhausted", @token.status
  end

  test "confirm returns 404 for unknown token" do
    post api_enrollment_confirm_path, params: {
      token_id: "nonexistent",
      node_id: "abcdef1234567890",
      name: "device1.office.acme.ztlp"
    }

    assert_response :not_found
  end

  test "confirm rejects already exhausted token" do
    @token.update!(current_uses: @token.max_uses, status: "exhausted")

    post api_enrollment_confirm_path, params: {
      token_id: @token.token_id,
      node_id: "abcdef1234567890",
      name: "device1.office.acme.ztlp"
    }

    assert_response :unprocessable_entity
  end

  test "confirm rejects expired token" do
    @token.update!(expires_at: 1.hour.ago, status: "active")

    post api_enrollment_confirm_path, params: {
      token_id: @token.token_id,
      node_id: "abcdef1234567890",
      name: "device1.office.acme.ztlp"
    }

    assert_response :unprocessable_entity
  end

  test "confirm rejects revoked token" do
    @token.update!(status: "revoked")

    post api_enrollment_confirm_path, params: {
      token_id: @token.token_id,
      node_id: "abcdef1234567890",
      name: "device1.office.acme.ztlp"
    }

    assert_response :unprocessable_entity
  end

  # BS-PR-1 regression pin: the "Z2LS issues a single-use token, device A
  # enrolls, device B tries the same token" sequence MUST end with B
  # rejected. Steve's brief: "After successful enrollment, the token is
  # consumed and cannot be reused."
  test "confirm a second device on a now-exhausted token returns 422" do
    @token.update!(max_uses: 1, current_uses: 0, status: "active")

    # Device A enrolls successfully.
    post api_enrollment_confirm_path, params: {
      token_id: @token.token_id,
      node_id: "aaaaaaaaaaaaaaaa",
      name: "device-a.office.acme.ztlp"
    }
    assert_response :success

    # Device B attempts to reuse the same token — must be rejected.
    post api_enrollment_confirm_path, params: {
      token_id: @token.token_id,
      node_id: "bbbbbbbbbbbbbbbb",
      name: "device-b.office.acme.ztlp"
    }
    assert_response :unprocessable_entity

    # And device B must NOT exist as an enrolled device.
    assert_nil @token.network.ztlp_devices.find_by(node_id: "bbbbbbbbbbbbbbbb")
  end
end
