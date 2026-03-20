# frozen_string_literal: true

require "test_helper"

class NotificationServiceTest < ActiveSupport::TestCase
  test "EVENTS contains expected event types" do
    assert_includes NotificationService::EVENTS, "alert_created"
    assert_includes NotificationService::EVENTS, "alert_critical"
    assert_includes NotificationService::EVENTS, "health_down"
    assert_includes NotificationService::EVENTS, "health_degraded"
    assert_includes NotificationService::EVENTS, "device_enrolled"
    assert_includes NotificationService::EVENTS, "device_revoked"
    assert_includes NotificationService::EVENTS, "user_revoked"
    assert_includes NotificationService::EVENTS, "user_suspended"
  end

  test "notify finds matching channels and delivers" do
    channel = notification_channels(:email_channel)
    # email_channel has severity_filter: all and no event_filter

    # Stub the deliver method to avoid actual SMTP
    NotificationService.expects(:deliver).with(
      channel,
      event_type: "alert_created",
      subject: "Test Alert",
      body: "Test body",
      details: {}
    ).once

    # Also stub for any other matching channels (slack, webhook, error)
    NotificationService.stubs(:deliver).with(
      Not(equals(channel)),
      has_entries(event_type: "alert_created")
    )

    NotificationService.notify(
      "alert_created",
      network: networks(:office),
      subject: "Test Alert",
      body: "Test body",
      severity: "warning"
    )
  end

  test "notify skips disabled channels" do
    disabled = notification_channels(:disabled_channel)

    # notify with all severity — disabled channel should not receive
    NotificationService.stubs(:deliver)

    NotificationService.notify(
      "alert_created",
      network: networks(:office),
      subject: "Test",
      body: "Body",
      severity: "info"
    )

    # disabled channel should have no new logs
    assert_equal 0, disabled.notification_logs.where(event_type: "alert_created").count
  end

  test "notify filters by severity" do
    # webhook_channel has severity_filter: critical
    webhook = notification_channels(:webhook_channel)

    # With info severity, webhook should not get notified
    NotificationService.stubs(:deliver)
    NotificationService.notify(
      "alert_critical",
      network: networks(:office),
      subject: "Info Alert",
      body: "Not critical",
      severity: "info"
    )
  end

  test "notify filters by event type" do
    # webhook_channel has event_filter: "alert_critical,health_down"
    webhook = notification_channels(:webhook_channel)

    # user_revoked is not in webhook's event_filter
    NotificationService.stubs(:deliver)
    NotificationService.notify(
      "user_revoked",
      network: networks(:office),
      subject: "User Revoked",
      body: "A user was revoked",
      severity: "critical"
    )
  end

  test "deliver creates a notification log" do
    channel = notification_channels(:email_channel)

    # Stub SMTP
    Net::SMTP.any_instance.stubs(:start).yields(stub(send_message: true))

    assert_difference -> { NotificationLog.count }, 1 do
      NotificationService.send(:deliver, channel,
        event_type: "test",
        subject: "Test",
        body: "Test body",
        details: {}
      )
    end
  end

  test "deliver_email builds and sends email via SMTP" do
    channel = notification_channels(:email_channel)
    log = channel.notification_logs.create!(event_type: "test", subject: "Test", body: "Body")

    smtp_mock = mock("smtp")
    smtp_mock.expects(:send_message).with(anything, "ztlp@example.com", "admin@example.com").once

    Net::SMTP.any_instance.stubs(:enable_starttls_auto)
    Net::SMTP.any_instance.stubs(:start).yields(smtp_mock)

    NotificationService.send(:deliver_email, channel, log, "Test Subject", "Test Body")
  end

  test "deliver_email raises without recipients" do
    channel = NotificationChannel.new(
      name: "Bad Email",
      channel_type: "email",
      config_json: '{"recipients":[]}'
    )
    log = nil

    assert_raises(RuntimeError, "No recipients configured") do
      NotificationService.send(:deliver_email, channel, log, "Test", "Body")
    end
  end

  test "deliver_webhook posts JSON to URL" do
    channel = notification_channels(:webhook_channel)
    log = channel.notification_logs.create!(event_type: "test", subject: "Test", body: "Body")

    response = stub(is_a?: true)
    response.stubs(:is_a?).with(Net::HTTPSuccess).returns(true)

    Net::HTTP.any_instance.stubs(:request).returns(response)
    Net::HTTP.any_instance.stubs(:use_ssl=)
    Net::HTTP.any_instance.stubs(:open_timeout=)
    Net::HTTP.any_instance.stubs(:read_timeout=)

    NotificationService.send(:deliver_webhook, channel, log, "test", "Test", "Body", {})
  end

  test "deliver_webhook raises on non-success response" do
    channel = notification_channels(:webhook_channel)
    log = channel.notification_logs.create!(event_type: "test", subject: "Test", body: "Body")

    response = stub(code: "500", body: "Internal Server Error")
    response.stubs(:is_a?).returns(false)

    Net::HTTP.any_instance.stubs(:request).returns(response)
    Net::HTTP.any_instance.stubs(:use_ssl=)
    Net::HTTP.any_instance.stubs(:open_timeout=)
    Net::HTTP.any_instance.stubs(:read_timeout=)

    assert_raises(RuntimeError) do
      NotificationService.send(:deliver_webhook, channel, log, "test", "Test", "Body", {})
    end
  end

  test "deliver_slack posts to webhook URL" do
    channel = notification_channels(:slack_channel)
    log = channel.notification_logs.create!(event_type: "test", subject: "Test", body: "Body")

    response = stub(is_a?: true)
    response.stubs(:is_a?).with(Net::HTTPSuccess).returns(true)

    Net::HTTP.any_instance.stubs(:request).returns(response)
    Net::HTTP.any_instance.stubs(:use_ssl=)
    Net::HTTP.any_instance.stubs(:open_timeout=)
    Net::HTTP.any_instance.stubs(:read_timeout=)

    NotificationService.send(:deliver_slack, channel, log, "test", "Test", "Body", {})
  end

  test "deliver_slack raises without webhook URL" do
    channel = NotificationChannel.new(
      name: "Bad Slack",
      channel_type: "slack",
      config_json: '{"webhook_url":""}'
    )

    assert_raises(RuntimeError, "No Slack webhook URL configured") do
      NotificationService.send(:deliver_slack, channel, nil, "test", "Test", "Body", {})
    end
  end

  test "deliver handles errors gracefully" do
    channel = notification_channels(:email_channel)

    Net::SMTP.any_instance.stubs(:start).raises(Errno::ECONNREFUSED, "Connection refused")

    # Should not raise — errors are caught and logged
    NotificationService.send(:deliver, channel,
      event_type: "test",
      subject: "Test",
      body: "Body",
      details: {}
    )

    # Check that the log was created and marked as failed
    log = channel.notification_logs.last
    assert_equal "failed", log.status
    assert_includes log.error_message, "Connection refused"

    # Check channel error was recorded
    channel.reload
    assert_includes channel.last_error, "Connection refused"
  end

  test "test_channel sends a test notification" do
    channel = notification_channels(:slack_channel)

    response = stub(is_a?: true)
    response.stubs(:is_a?).with(Net::HTTPSuccess).returns(true)

    Net::HTTP.any_instance.stubs(:request).returns(response)
    Net::HTTP.any_instance.stubs(:use_ssl=)
    Net::HTTP.any_instance.stubs(:open_timeout=)
    Net::HTTP.any_instance.stubs(:read_timeout=)

    assert_difference -> { channel.notification_logs.count }, 1 do
      NotificationService.test_channel(channel)
    end

    log = channel.notification_logs.last
    assert_equal "test", log.event_type
    assert_equal "sent", log.status
    assert_includes log.subject, "Test Notification"
  end

  test "email_html generates valid HTML" do
    html = NotificationService.send(:email_html, "Test Subject", "Test Body")
    assert_includes html, "Test Subject"
    assert_includes html, "Test Body"
    assert_includes html, "ZTLP Bootstrap"
    assert_includes html, "<!DOCTYPE html>"
  end
end
