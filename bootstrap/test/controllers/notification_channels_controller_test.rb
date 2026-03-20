# frozen_string_literal: true

require "test_helper"

class NotificationChannelsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    @channel = notification_channels(:email_channel)
    # Sign in as admin
    post login_path, params: { email: "admin@example.com", password: "password123" }
  end

  # --- Index ---

  test "index lists notification channels" do
    get network_notification_channels_path(@network)
    assert_response :success
    assert_includes response.body, "Notification Channels"
    assert_includes response.body, "Team Email Alerts"
  end

  test "index shows channel types" do
    get network_notification_channels_path(@network)
    assert_response :success
    assert_includes response.body, "Email"
    assert_includes response.body, "Webhook"
    assert_includes response.body, "Slack"
  end

  test "index shows empty state when no channels" do
    network = networks(:production)
    # Production has one channel; delete it first
    network.notification_channels.destroy_all
    get network_notification_channels_path(network)
    assert_response :success
    assert_includes response.body, "No notification channels configured"
  end

  # --- New ---

  test "new renders form for email type" do
    get new_network_notification_channel_path(@network, type: "email")
    assert_response :success
    assert_includes response.body, "New Notification Channel"
    assert_includes response.body, "Email Configuration"
  end

  test "new renders form for webhook type" do
    get new_network_notification_channel_path(@network, type: "webhook")
    assert_response :success
    assert_includes response.body, "Webhook Configuration"
  end

  test "new renders form for slack type" do
    get new_network_notification_channel_path(@network, type: "slack")
    assert_response :success
    assert_includes response.body, "Slack Configuration"
  end

  # --- Create ---

  test "create email channel" do
    assert_difference "NotificationChannel.count", 1 do
      post network_notification_channels_path(@network), params: {
        notification_channel: {
          name: "New Email",
          channel_type: "email",
          severity_filter: "all"
        },
        config: {
          recipients: "test@example.com, test2@example.com",
          from: "ztlp@test.com",
          smtp_server: "smtp.test.com",
          smtp_port: "587"
        }
      }
    end
    assert_redirected_to network_notification_channels_path(@network)

    channel = NotificationChannel.last
    assert_equal "New Email", channel.name
    assert_equal "email", channel.channel_type
    config = channel.parsed_config
    assert_equal ["test@example.com", "test2@example.com"], config["recipients"]
  end

  test "create webhook channel" do
    assert_difference "NotificationChannel.count", 1 do
      post network_notification_channels_path(@network), params: {
        notification_channel: {
          name: "New Webhook",
          channel_type: "webhook",
          severity_filter: "critical"
        },
        config: {
          url: "https://hooks.example.com/test",
          method: "POST"
        }
      }
    end
    assert_redirected_to network_notification_channels_path(@network)
  end

  test "create slack channel" do
    assert_difference "NotificationChannel.count", 1 do
      post network_notification_channels_path(@network), params: {
        notification_channel: {
          name: "New Slack",
          channel_type: "slack",
          severity_filter: "warning_and_above"
        },
        config: {
          webhook_url: "https://hooks.slack.com/services/T00/B00/test",
          channel: "#test"
        }
      }
    end
    assert_redirected_to network_notification_channels_path(@network)
  end

  test "create with invalid data renders form" do
    assert_no_difference "NotificationChannel.count" do
      post network_notification_channels_path(@network), params: {
        notification_channel: {
          name: "",
          channel_type: "email",
          severity_filter: "all"
        },
        config: { recipients: "test@example.com" }
      }
    end
    assert_response :unprocessable_entity
  end

  # --- Show ---

  test "show displays channel details" do
    get network_notification_channel_path(@network, @channel)
    assert_response :success
    assert_includes response.body, "Team Email Alerts"
    assert_includes response.body, "Email"
  end

  # --- Edit ---

  test "edit renders form" do
    get edit_network_notification_channel_path(@network, @channel)
    assert_response :success
    assert_includes response.body, "Edit Notification Channel"
  end

  # --- Update ---

  test "update changes channel" do
    patch network_notification_channel_path(@network, @channel), params: {
      notification_channel: {
        name: "Updated Email",
        channel_type: "email",
        severity_filter: "critical"
      },
      config: {
        recipients: "updated@example.com",
        from: "ztlp@updated.com"
      }
    }
    assert_redirected_to network_notification_channels_path(@network)

    @channel.reload
    assert_equal "Updated Email", @channel.name
    assert_equal "critical", @channel.severity_filter
    assert_includes @channel.parsed_config["recipients"], "updated@example.com"
  end

  test "update with invalid data renders form" do
    patch network_notification_channel_path(@network, @channel), params: {
      notification_channel: {
        name: "",
        channel_type: "email"
      },
      config: { recipients: "test@example.com" }
    }
    assert_response :unprocessable_entity
  end

  # --- Destroy ---

  test "destroy deletes channel" do
    assert_difference "NotificationChannel.count", -1 do
      delete network_notification_channel_path(@network, @channel)
    end
    assert_redirected_to network_notification_channels_path(@network)
  end

  # --- Test Notification ---

  test "test sends test notification" do
    # Stub SMTP
    Net::SMTP.any_instance.stubs(:start).yields(stub(send_message: true))
    Net::SMTP.any_instance.stubs(:enable_starttls_auto)

    assert_difference -> { @channel.notification_logs.count }, 1 do
      post test_network_notification_channel_path(@network, @channel)
    end
    assert_redirected_to network_notification_channels_path(@network)
    assert_includes flash[:notice], "Test notification sent"
  end

  test "test shows error on failure" do
    Net::SMTP.any_instance.stubs(:start).raises(Errno::ECONNREFUSED, "Connection refused")

    post test_network_notification_channel_path(@network, @channel)
    assert_redirected_to network_notification_channels_path(@network)
    assert_includes flash[:alert], "Test failed"
  end

  # --- Toggle ---

  test "toggle disables enabled channel" do
    assert @channel.enabled?
    post toggle_network_notification_channel_path(@network, @channel)
    assert_redirected_to network_notification_channels_path(@network)
    @channel.reload
    assert_not @channel.enabled?
  end

  test "toggle enables disabled channel" do
    disabled = notification_channels(:disabled_channel)
    assert_not disabled.enabled?
    post toggle_network_notification_channel_path(@network, disabled)
    assert_redirected_to network_notification_channels_path(@network)
    disabled.reload
    assert disabled.enabled?
  end

  # --- Logs ---

  test "logs shows notification history" do
    get logs_network_notification_channels_path(@network)
    assert_response :success
    assert_includes response.body, "Notification Logs"
  end

  test "logs filters by channel" do
    get logs_network_notification_channels_path(@network, channel_id: @channel.id)
    assert_response :success
  end

  test "logs filters by status" do
    get logs_network_notification_channels_path(@network, status: "sent")
    assert_response :success
  end

  test "logs filters by event type" do
    get logs_network_notification_channels_path(@network, event_type: "alert_created")
    assert_response :success
  end

  test "logs paginates results" do
    get logs_network_notification_channels_path(@network, page: 1)
    assert_response :success
  end
end
