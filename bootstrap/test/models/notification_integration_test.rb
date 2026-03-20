# frozen_string_literal: true

require "test_helper"

class NotificationIntegrationTest < ActiveSupport::TestCase
  test "creating an alert triggers notification to matching channels" do
    # Stub all delivery methods to avoid external calls
    NotificationService.stubs(:deliver_email)
    NotificationService.stubs(:deliver_webhook)
    NotificationService.stubs(:deliver_slack)

    # The email_channel (severity: all, no event filter) should receive a notification
    email_channel = notification_channels(:email_channel)
    initial_log_count = NotificationLog.count

    alert = Alert.create!(
      network: networks(:office),
      machine: machines(:gateway1),
      component: "gateway",
      severity: "critical",
      message: "Gateway is down"
    )

    # Notification was attempted (logs created)
    assert NotificationLog.count > initial_log_count,
      "Expected notification logs to be created when alert is created"
  end

  test "creating a health check with down status triggers notification" do
    NotificationService.stubs(:deliver_email)
    NotificationService.stubs(:deliver_webhook)
    NotificationService.stubs(:deliver_slack)

    initial_log_count = NotificationLog.count

    HealthCheck.create!(
      machine: machines(:gateway1),
      component: "gateway",
      status: "down",
      checked_at: Time.current
    )

    assert NotificationLog.count > initial_log_count,
      "Expected notification logs to be created when health check goes down"
  end

  test "creating a healthy health check does not trigger notification" do
    initial_log_count = NotificationLog.count

    HealthCheck.create!(
      machine: machines(:gateway1),
      component: "gateway",
      status: "healthy",
      checked_at: Time.current
    )

    assert_equal initial_log_count, NotificationLog.count,
      "Expected no notification logs for healthy health check"
  end

  test "revoking a user triggers notification" do
    NotificationService.stubs(:deliver_email)
    NotificationService.stubs(:deliver_webhook)
    NotificationService.stubs(:deliver_slack)

    user = ztlp_users(:alice)
    initial_log_count = NotificationLog.count

    user.revoke!(reason: "Test revocation")

    assert NotificationLog.count > initial_log_count,
      "Expected notification logs when user is revoked"
  end

  test "suspending a user triggers notification" do
    NotificationService.stubs(:deliver_email)
    NotificationService.stubs(:deliver_webhook)
    NotificationService.stubs(:deliver_slack)

    user = ztlp_users(:alice)
    initial_log_count = NotificationLog.count

    user.suspend!

    assert NotificationLog.count > initial_log_count,
      "Expected notification logs when user is suspended"
  end

  test "revoking a device triggers notification" do
    NotificationService.stubs(:deliver_email)
    NotificationService.stubs(:deliver_webhook)
    NotificationService.stubs(:deliver_slack)

    device = ztlp_devices(:alice_laptop)
    initial_log_count = NotificationLog.count

    device.revoke!(reason: "Test revocation")

    assert NotificationLog.count > initial_log_count,
      "Expected notification logs when device is revoked"
  end
end
