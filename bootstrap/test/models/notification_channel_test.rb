# frozen_string_literal: true

require "test_helper"

class NotificationChannelTest < ActiveSupport::TestCase
  test "valid with all required attributes" do
    channel = NotificationChannel.new(
      network: networks(:office),
      name: "Test Channel",
      channel_type: "email",
      config_json: '{"recipients":["test@example.com"]}'
    )
    assert channel.valid?
  end

  test "requires name" do
    channel = notification_channels(:email_channel)
    channel.name = nil
    assert_not channel.valid?
    assert_includes channel.errors[:name], "can't be blank"
  end

  test "requires channel_type" do
    channel = notification_channels(:email_channel)
    channel.channel_type = nil
    assert_not channel.valid?
  end

  test "validates channel_type inclusion" do
    channel = notification_channels(:email_channel)
    channel.channel_type = "sms"
    assert_not channel.valid?
  end

  test "requires config_json" do
    channel = notification_channels(:email_channel)
    channel.config_json = nil
    assert_not channel.valid?
  end

  test "validates severity_filter inclusion" do
    channel = notification_channels(:email_channel)
    channel.severity_filter = "invalid"
    assert_not channel.valid?
  end

  test "network is optional for global channels" do
    channel = NotificationChannel.new(
      name: "Global Channel",
      channel_type: "email",
      config_json: '{"recipients":["global@example.com"]}'
    )
    assert channel.valid?
    assert_nil channel.network_id
  end

  test "parsed_config returns parsed JSON" do
    channel = notification_channels(:email_channel)
    config = channel.parsed_config
    assert_kind_of Hash, config
    assert_includes config["recipients"], "admin@example.com"
  end

  test "parsed_config returns empty hash on invalid JSON" do
    channel = notification_channels(:email_channel)
    channel.config_json = "not json"
    assert_equal({}, channel.parsed_config)
  end

  test "toggle! switches enabled status" do
    channel = notification_channels(:email_channel)
    assert channel.enabled?
    channel.toggle!
    assert_not channel.enabled?
    channel.toggle!
    assert channel.enabled?
  end

  test "event_types parses comma-separated list" do
    channel = notification_channels(:webhook_channel)
    assert_equal %w[alert_critical health_down], channel.event_types
  end

  test "event_types returns empty array when blank" do
    channel = notification_channels(:email_channel)
    assert_equal [], channel.event_types
  end

  test "matches_event? returns true when no filter" do
    channel = notification_channels(:email_channel)
    assert channel.matches_event?("alert_created")
    assert channel.matches_event?("anything")
  end

  test "matches_event? filters by event_filter" do
    channel = notification_channels(:webhook_channel)
    assert channel.matches_event?("alert_critical")
    assert channel.matches_event?("health_down")
    assert_not channel.matches_event?("user_revoked")
  end

  test "matches_severity? with all filter" do
    channel = notification_channels(:email_channel)
    assert channel.matches_severity?("info")
    assert channel.matches_severity?("warning")
    assert channel.matches_severity?("critical")
  end

  test "matches_severity? with critical filter" do
    channel = notification_channels(:webhook_channel)
    assert channel.matches_severity?("critical")
    assert_not channel.matches_severity?("warning")
    assert_not channel.matches_severity?("info")
  end

  test "matches_severity? with warning_and_above filter" do
    channel = notification_channels(:slack_channel)
    assert channel.matches_severity?("critical")
    assert channel.matches_severity?("warning")
    assert_not channel.matches_severity?("info")
  end

  test "healthy? returns true when enabled and no error" do
    channel = notification_channels(:email_channel)
    assert channel.healthy?
  end

  test "healthy? returns false when has error" do
    channel = notification_channels(:error_channel)
    assert_not channel.healthy?
  end

  test "healthy? returns false when disabled" do
    channel = notification_channels(:disabled_channel)
    assert_not channel.healthy?
  end

  test "status_label returns correct values" do
    assert_equal "healthy", notification_channels(:email_channel).status_label
    assert_equal "disabled", notification_channels(:disabled_channel).status_label
    assert_equal "error", notification_channels(:error_channel).status_label
  end

  test "type_icon returns correct icons" do
    assert_equal "📧", notification_channels(:email_channel).type_icon
    assert_equal "🔗", notification_channels(:webhook_channel).type_icon
    assert_equal "💬", notification_channels(:slack_channel).type_icon
  end

  test "enabled scope returns only enabled channels" do
    enabled = NotificationChannel.enabled
    enabled.each { |ch| assert ch.enabled? }
  end

  test "disabled scope returns only disabled channels" do
    disabled = NotificationChannel.disabled
    disabled.each { |ch| assert_not ch.enabled? }
  end

  test "for_network includes network-specific and global channels" do
    global = NotificationChannel.create!(name: "Global", channel_type: "email", config_json: '{}')
    channels = NotificationChannel.for_network(networks(:office))
    assert_includes channels, notification_channels(:email_channel)
    assert_includes channels, global
    assert_not_includes channels, notification_channels(:production_channel)
    global.destroy
  end

  test "record_success! updates tracking fields" do
    channel = notification_channels(:email_channel)
    original_count = channel.send_count
    channel.record_success!
    channel.reload
    assert_equal original_count + 1, channel.send_count
    assert_not_nil channel.last_sent_at
    assert_nil channel.last_error
  end

  test "record_error! sets last_error" do
    channel = notification_channels(:email_channel)
    channel.record_error!("test error")
    channel.reload
    assert_equal "test error", channel.last_error
  end

  test "destroying channel destroys logs" do
    channel = notification_channels(:email_channel)
    log_count = channel.notification_logs.count
    assert log_count > 0
    channel.destroy
    assert_equal 0, NotificationLog.where(notification_channel_id: channel.id).count
  end

  test "network association" do
    channel = notification_channels(:email_channel)
    assert_equal networks(:office), channel.network
  end
end
