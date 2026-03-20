# frozen_string_literal: true

require "net/http"
require "net/smtp"
require "json"
require "uri"

class NotificationService
  EVENTS = %w[
    alert_created alert_critical
    health_down health_degraded
    device_enrolled device_revoked
    user_created user_revoked user_suspended
    login_failed_lockout
  ].freeze

  # Main entry point: send notifications for an event to all matching channels
  def self.notify(event_type, network: nil, subject:, body:, severity: "info", details: {})
    channels = find_channels(event_type, network: network, severity: severity)
    channels.each do |channel|
      deliver(channel, event_type: event_type, subject: subject, body: body, details: details)
    end
  end

  # Send a test notification to a specific channel
  def self.test_channel(channel)
    deliver(
      channel,
      event_type: "test",
      subject: "🔔 ZTLP Test Notification",
      body: "This is a test notification from ZTLP Bootstrap sent at #{Time.current.strftime('%Y-%m-%d %H:%M UTC')}.",
      details: { test: true }
    )
  end

  private

  def self.find_channels(event_type, network: nil, severity: "info")
    channels = NotificationChannel.enabled
    channels = channels.for_network(network) if network
    channels = channels.enabled

    channels.select do |ch|
      ch.matches_event?(event_type) && ch.matches_severity?(severity)
    end
  end

  def self.deliver(channel, event_type:, subject:, body:, details:)
    log = channel.notification_logs.create!(
      event_type: event_type,
      subject: subject,
      body: body,
      status: "pending"
    )

    case channel.channel_type
    when "email"
      deliver_email(channel, log, subject, body)
    when "webhook"
      deliver_webhook(channel, log, event_type, subject, body, details)
    when "slack"
      deliver_slack(channel, log, event_type, subject, body, details)
    end

    log.mark_sent!
    channel.record_success!
  rescue => e
    log&.mark_failed!(e.message)
    channel.record_error!(e.message)
  end

  def self.deliver_email(channel, _log, subject, body)
    config = channel.parsed_config
    recipients = Array(config["recipients"])
    raise "No recipients configured" if recipients.empty?

    from = config["from"] || "ztlp@localhost"
    smtp_server = config["smtp_server"] || "localhost"
    smtp_port = (config["smtp_port"] || 25).to_i
    smtp_user = config["smtp_user"]
    smtp_password = config["smtp_password"]

    boundary = "ZTLPBoundary#{SecureRandom.hex(16)}"
    html_body = email_html(subject, body)

    message = <<~MSG
      From: ZTLP Bootstrap <#{from}>
      To: #{recipients.join(', ')}
      Subject: #{subject}
      MIME-Version: 1.0
      Content-Type: multipart/alternative; boundary="#{boundary}"

      --#{boundary}
      Content-Type: text/plain; charset=UTF-8

      #{subject}

      #{body}

      --
      ZTLP Bootstrap Notification System

      --#{boundary}
      Content-Type: text/html; charset=UTF-8

      #{html_body}

      --#{boundary}--
    MSG

    smtp = Net::SMTP.new(smtp_server, smtp_port)
    smtp.enable_starttls_auto if smtp_port == 587

    if smtp_user.present? && smtp_password.present?
      smtp.start("localhost", smtp_user, smtp_password, :plain) do |s|
        recipients.each { |r| s.send_message(message, from, r) }
      end
    else
      smtp.start("localhost") do |s|
        recipients.each { |r| s.send_message(message, from, r) }
      end
    end
  end

  def self.deliver_webhook(channel, _log, event_type, subject, body, details)
    config = channel.parsed_config
    url = config["url"]
    raise "No webhook URL configured" if url.blank?

    method = (config["method"] || "POST").upcase
    headers = config["headers"] || { "Content-Type" => "application/json" }

    payload = {
      event: event_type,
      subject: subject,
      body: body,
      details: details,
      timestamp: Time.current.iso8601,
      source: "ztlp-bootstrap"
    }

    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == "https")
    http.open_timeout = 10
    http.read_timeout = 10

    request = case method
              when "POST"
                Net::HTTP::Post.new(uri.request_uri)
              when "PUT"
                Net::HTTP::Put.new(uri.request_uri)
              else
                Net::HTTP::Post.new(uri.request_uri)
              end

    headers.each { |k, v| request[k] = v }
    request.body = payload.to_json

    response = http.request(request)
    raise "Webhook returned #{response.code}: #{response.body&.truncate(200)}" unless response.is_a?(Net::HTTPSuccess)
  end

  def self.deliver_slack(channel, _log, event_type, subject, body, _details)
    config = channel.parsed_config
    webhook_url = config["webhook_url"]
    raise "No Slack webhook URL configured" if webhook_url.blank?

    payload = {
      text: subject,
      blocks: [
        {
          type: "header",
          text: { type: "plain_text", text: "🔐 ZTLP Alert", emoji: true }
        },
        {
          type: "section",
          text: { type: "mrkdwn", text: "*#{subject}*\n#{body}" }
        },
        {
          type: "context",
          elements: [{
            type: "mrkdwn",
            text: "Event: `#{event_type}` | #{Time.current.strftime('%Y-%m-%d %H:%M UTC')}"
          }]
        }
      ]
    }

    # Add channel override if specified
    payload[:channel] = config["channel"] if config["channel"].present?

    uri = URI.parse(webhook_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == "https")
    http.open_timeout = 10
    http.read_timeout = 10

    request = Net::HTTP::Post.new(uri.request_uri)
    request["Content-Type"] = "application/json"
    request.body = payload.to_json

    response = http.request(request)
    raise "Slack webhook returned #{response.code}: #{response.body&.truncate(200)}" unless response.is_a?(Net::HTTPSuccess)
  end

  def self.email_html(subject, body)
    <<~HTML
      <!DOCTYPE html>
      <html>
      <head><meta charset="UTF-8"></head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background-color: #f3f4f6;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #6366f1, #4f46e5); border-radius: 8px 8px 0 0; padding: 24px; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 20px;">🔐 ZTLP Bootstrap</h1>
          </div>
          <div style="background: white; padding: 24px; border-radius: 0 0 8px 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h2 style="color: #1f2937; margin-top: 0;">#{ERB::Util.html_escape(subject)}</h2>
            <p style="color: #4b5563; line-height: 1.6;">#{ERB::Util.html_escape(body)}</p>
            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
            <p style="color: #9ca3af; font-size: 12px; margin: 0;">
              This notification was sent by ZTLP Bootstrap.
            </p>
          </div>
        </div>
      </body>
      </html>
    HTML
  end
end
