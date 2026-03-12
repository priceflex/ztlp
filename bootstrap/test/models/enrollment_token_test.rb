require "test_helper"

class EnrollmentTokenTest < ActiveSupport::TestCase
  test "active token is usable" do
    token = enrollment_tokens(:active_token)
    assert token.usable?
  end

  test "expired token is not usable" do
    token = enrollment_tokens(:expired_token)
    assert token.expired?
    assert_not token.usable?
  end

  test "exhausted token is not usable" do
    token = enrollment_tokens(:exhausted_token)
    assert token.exhausted?
    assert_not token.usable?
  end

  test "use! increments counter" do
    token = enrollment_tokens(:active_token)
    old_uses = token.current_uses
    assert token.use!
    assert_equal old_uses + 1, token.reload.current_uses
  end

  test "use! marks exhausted when max reached" do
    token = enrollment_tokens(:active_token)
    token.update!(current_uses: token.max_uses - 1)
    token.use!
    assert_equal "exhausted", token.reload.status
  end

  test "use! returns false when not usable" do
    token = enrollment_tokens(:expired_token)
    assert_not token.use!
  end

  test "revoke! sets status to revoked" do
    token = enrollment_tokens(:active_token)
    token.revoke!
    assert_equal "revoked", token.reload.status
    assert_not token.usable?
  end

  test "refresh_status! marks expired tokens" do
    token = enrollment_tokens(:expired_token)
    token.refresh_status!
    assert_equal "expired", token.reload.status
  end

  test "generates token_id if not provided" do
    token = EnrollmentToken.new(
      network: networks(:office),
      max_uses: 1,
      expires_at: 24.hours.from_now,
      status: "active"
    )
    token.save!
    assert token.token_id.present?
    assert_equal 16, token.token_id.length  # hex(8) = 16 chars
  end

  test "scopes" do
    assert EnrollmentToken.active.all? { |t| t.status == "active" && t.expires_at > Time.current }
    assert EnrollmentToken.usable.all?(&:usable?)
  end
end
