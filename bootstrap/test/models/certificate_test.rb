# frozen_string_literal: true

require "test_helper"

class CertificateTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
    @certificate = Certificate.new(
      network: @network,
      hostname: "webapp.corp.ztlp",
      serial: "TESTSERIAL001",
      status: "active",
      assurance_level: "software",
      issued_at: 1.day.ago,
      expires_at: 89.days.from_now
    )
  end

  test "valid certificate" do
    assert @certificate.valid?
  end

  test "requires hostname" do
    @certificate.hostname = nil
    assert_not @certificate.valid?
    assert_includes @certificate.errors[:hostname], "can't be blank"
  end

  test "requires serial" do
    @certificate.serial = nil
    assert_not @certificate.valid?
  end

  test "serial must be unique" do
    @certificate.save!
    dup = @certificate.dup
    dup.hostname = "other.ztlp"
    assert_not dup.valid?
    assert_includes dup.errors[:serial], "has already been taken"
  end

  test "requires valid status" do
    @certificate.status = "invalid"
    assert_not @certificate.valid?
  end

  test "requires valid assurance level" do
    @certificate.assurance_level = "invalid"
    assert_not @certificate.valid?
  end

  test "active? returns true for active non-expired cert" do
    assert @certificate.active?
  end

  test "active? returns false for expired cert" do
    @certificate.expires_at = 1.day.ago
    assert_not @certificate.active?
  end

  test "active? returns false for revoked cert" do
    @certificate.status = "revoked"
    assert_not @certificate.active?
  end

  test "expired_cert? detects expired certs" do
    @certificate.expires_at = 1.hour.ago
    assert @certificate.expired_cert?
  end

  test "expiring_soon? detects certs expiring within 30 days" do
    @certificate.expires_at = 15.days.from_now
    assert @certificate.expiring_soon?
  end

  test "expiring_soon? returns false for certs with more than 30 days" do
    @certificate.expires_at = 60.days.from_now
    assert_not @certificate.expiring_soon?
  end

  test "days_until_expiry calculates correctly" do
    @certificate.expires_at = 45.days.from_now
    assert_equal 45, @certificate.days_until_expiry
  end

  test "days_until_expiry returns 0 for expired" do
    @certificate.expires_at = 1.day.ago
    assert_equal 0, @certificate.days_until_expiry
  end

  test "revoke! updates status and timestamp" do
    @certificate.save!
    @certificate.revoke!(reason: "compromised")
    @certificate.reload
    assert_equal "revoked", @certificate.status
    assert_not_nil @certificate.revoked_at
    assert_equal "compromised", @certificate.revocation_reason
  end

  test "expiry_status returns correct status" do
    @certificate.expires_at = 60.days.from_now
    assert_equal "ok", @certificate.expiry_status

    @certificate.expires_at = 15.days.from_now
    assert_equal "warning", @certificate.expiry_status

    @certificate.expires_at = 3.days.from_now
    assert_equal "critical", @certificate.expiry_status

    @certificate.expires_at = 1.day.ago
    assert_equal "expired", @certificate.expiry_status
  end

  test "mark_expired! updates expired active certs" do
    @certificate.expires_at = 1.day.ago
    @certificate.save!
    Certificate.mark_expired!
    @certificate.reload
    assert_equal "expired", @certificate.status
  end

  test "scopes filter correctly" do
    @certificate.save!
    assert_includes Certificate.active, @certificate

    revoked_cert = Certificate.create!(
      network: @network,
      hostname: "revoked-scope-test.ztlp",
      serial: "REVOKED_SCOPE_001",
      status: "revoked",
      issued_at: 1.day.ago,
      expires_at: 89.days.from_now,
      revoked_at: Time.current
    )
    assert_includes Certificate.revoked, revoked_cert
    assert_not_includes Certificate.active, revoked_cert
  end
end
