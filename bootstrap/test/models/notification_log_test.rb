# frozen_string_literal: true

require "test_helper"

class NotificationLogTest < ActiveSupport::TestCase
  test "valid with required attributes" do
    log = NotificationLog.new(
      notification_channel: notification_channels(:email_channel),
      event_type: "alert_created",
      status: "pending"
    )
    assert log.valid?
  end

  test "requires event_type" do
    log = notification_logs(:email_sent)
    log.event_type = nil
    assert_not log.valid?
  end

  test "requires status" do
    log = notification_logs(:email_sent)
    log.status = nil
    assert_not log.valid?
  end

  test "validates status inclusion" do
    log = notification_logs(:email_sent)
    log.status = "invalid"
    assert_not log.valid?
  end

  test "mark_sent! updates status and sent_at" do
    log = notification_logs(:slack_pending)
    assert log.pending?
    log.mark_sent!
    log.reload
    assert log.sent?
    assert_not_nil log.sent_at
  end

  test "mark_failed! updates status and error" do
    log = notification_logs(:slack_pending)
    log.mark_failed!("Connection timeout")
    log.reload
    assert log.failed?
    assert_equal "Connection timeout", log.error_message
  end

  test "sent? returns correct value" do
    assert notification_logs(:email_sent).sent?
    assert_not notification_logs(:email_failed).sent?
  end

  test "failed? returns correct value" do
    assert notification_logs(:email_failed).failed?
    assert_not notification_logs(:email_sent).failed?
  end

  test "pending? returns correct value" do
    assert notification_logs(:slack_pending).pending?
    assert_not notification_logs(:email_sent).pending?
  end

  test "recent scope orders by created_at desc" do
    logs = NotificationLog.recent
    dates = logs.map(&:created_at)
    assert_equal dates, dates.sort.reverse
  end

  test "scopes filter correctly" do
    assert NotificationLog.sent.all?(&:sent?)
    assert NotificationLog.failed.all?(&:failed?)
    assert NotificationLog.pending.all?(&:pending?)
  end

  test "belongs to notification_channel" do
    log = notification_logs(:email_sent)
    assert_equal notification_channels(:email_channel), log.notification_channel
  end
end
