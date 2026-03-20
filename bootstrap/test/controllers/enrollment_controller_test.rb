# frozen_string_literal: true

require "test_helper"

class EnrollmentControllerTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    sign_in_as_admin
  end

  test "index renders enrollment page" do
    get network_enrollment_index_path(@network)
    assert_response :success
    assert_match "Enrollment", response.body
  end

  test "index shows active tokens" do
    get network_enrollment_index_path(@network)
    assert_response :success
    assert_match "Active Tokens", response.body
  end

  test "index shows all tokens table" do
    get network_enrollment_index_path(@network)
    assert_response :success
    assert_match "All Tokens", response.body
  end

  test "index shows recent enrollments" do
    get network_enrollment_index_path(@network)
    assert_response :success
    assert_match "Recent Enrollments", response.body
  end

  test "create generates new enrollment token" do
    assert_difference "EnrollmentToken.count", 1 do
      post network_enrollment_index_path(@network)
    end
    assert_redirected_to network_enrollment_index_path(@network)
  end

  test "create records audit log" do
    # TokenGenerator creates its own audit log, plus our controller creates one = 2
    assert_difference "AuditLog.count", 2 do
      post network_enrollment_index_path(@network)
    end
  end

  test "create with custom duration" do
    post network_enrollment_index_path(@network), params: { expires_in: "48h", max_uses: 5 }
    assert_redirected_to network_enrollment_index_path(@network)
    token = EnrollmentToken.last
    assert_equal 5, token.max_uses
  end

  test "create with notes" do
    post network_enrollment_index_path(@network), params: { notes: "For new hire" }
    assert_redirected_to network_enrollment_index_path(@network)
    token = EnrollmentToken.last
    assert_equal "For new hire", token.notes
  end
end
