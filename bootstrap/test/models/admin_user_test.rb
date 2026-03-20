# frozen_string_literal: true

require "test_helper"

class AdminUserTest < ActiveSupport::TestCase
  setup do
    @admin = admin_users(:super_admin)
  end

  # --- Validations ---

  test "valid admin user" do
    admin = AdminUser.new(
      email: "new@example.com",
      name: "New Admin",
      password: "securepass123",
      password_confirmation: "securepass123",
      role: "admin"
    )
    assert admin.valid?
  end

  test "requires email" do
    @admin.email = nil
    assert_not @admin.valid?
    assert_includes @admin.errors[:email], "can't be blank"
  end

  test "requires valid email format" do
    @admin.email = "notanemail"
    assert_not @admin.valid?
    assert_includes @admin.errors[:email], "must be a valid email address"
  end

  test "requires unique email case insensitive" do
    dupe = AdminUser.new(
      email: @admin.email.upcase,
      name: "Dupe",
      password: "password123",
      role: "admin"
    )
    assert_not dupe.valid?
    assert_includes dupe.errors[:email], "has already been taken"
  end

  test "requires name" do
    @admin.name = nil
    assert_not @admin.valid?
    assert_includes @admin.errors[:name], "can't be blank"
  end

  test "requires valid role" do
    @admin.role = "invalid"
    assert_not @admin.valid?
    assert_includes @admin.errors[:role], "is not included in the list"
  end

  test "allows all valid roles" do
    %w[super_admin admin read_only].each do |role|
      @admin.role = role
      assert @admin.valid?, "Expected role '#{role}' to be valid"
    end
  end

  # --- Role methods ---

  test "super_admin?" do
    assert admin_users(:super_admin).super_admin?
    assert_not admin_users(:regular_admin).super_admin?
  end

  test "admin?" do
    assert admin_users(:regular_admin).admin?
    assert_not admin_users(:super_admin).admin?
  end

  test "read_only?" do
    assert admin_users(:read_only_admin).read_only?
    assert_not admin_users(:regular_admin).read_only?
  end

  # --- Locking ---

  test "locked? returns false for unlocked user" do
    assert_not @admin.locked?
  end

  test "locked? returns true for locked user" do
    assert admin_users(:locked_admin).locked?
  end

  test "locked? returns false if locked_until is in the past" do
    @admin.update!(locked_until: 1.minute.ago)
    assert_not @admin.locked?
  end

  test "lock! sets locked_until to 15 minutes from now" do
    freeze_time do
      @admin.lock!
      assert_in_delta 15.minutes.from_now, @admin.locked_until, 1
    end
  end

  test "unlock! clears lock and failed attempts" do
    locked = admin_users(:locked_admin)
    locked.unlock!
    assert_nil locked.locked_until
    assert_equal 0, locked.failed_login_attempts
    assert_not locked.locked?
  end

  # --- Login recording ---

  test "record_login! updates login fields and clears failures" do
    @admin.update!(failed_login_attempts: 3)
    freeze_time do
      @admin.record_login!("1.2.3.4")
      assert_equal 0, @admin.failed_login_attempts
      assert_equal Time.current, @admin.last_login_at
      assert_equal "1.2.3.4", @admin.last_login_ip
      assert_nil @admin.locked_until
    end
  end

  test "record_failed_login! increments failed attempts" do
    @admin.update!(failed_login_attempts: 0)
    @admin.record_failed_login!
    assert_equal 1, @admin.failed_login_attempts
  end

  test "record_failed_login! locks after 5 failures" do
    @admin.update!(failed_login_attempts: 4)
    @admin.record_failed_login!
    assert_equal 5, @admin.failed_login_attempts
    assert @admin.locked?
  end

  test "record_failed_login! does not lock before threshold" do
    @admin.update!(failed_login_attempts: 2)
    @admin.record_failed_login!
    assert_not @admin.locked?
  end

  # --- lockout_minutes_remaining ---

  test "lockout_minutes_remaining returns 0 when not locked" do
    assert_equal 0, @admin.lockout_minutes_remaining
  end

  test "lockout_minutes_remaining returns minutes remaining" do
    @admin.update!(locked_until: 10.minutes.from_now)
    assert_in_delta 10, @admin.lockout_minutes_remaining, 1
  end

  # --- Password ---

  test "authenticate with correct password" do
    admin = AdminUser.create!(
      email: "auth@example.com",
      name: "Auth Test",
      password: "testpass123",
      password_confirmation: "testpass123",
      role: "admin"
    )
    assert admin.authenticate("testpass123")
    assert_not admin.authenticate("wrongpassword")
  end
end
