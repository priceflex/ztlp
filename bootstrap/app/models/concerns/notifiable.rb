# frozen_string_literal: true

# Provides notification hooks for models that should trigger
# notifications on certain lifecycle events.
module Notifiable
  extend ActiveSupport::Concern

  private

  def notify_event(event_type, subject:, body:, severity: "info", details: {})
    network = respond_to?(:network) ? network : nil
    NotificationService.notify(
      event_type,
      network: network,
      subject: subject,
      body: body,
      severity: severity,
      details: details
    )
  rescue => e
    Rails.logger.error("[Notifiable] Failed to send notification: #{e.message}")
  end
end
