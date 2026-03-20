# frozen_string_literal: true

class ConnectionEvent < ApplicationRecord
  VALID_EVENT_TYPES = %w[connected disconnected reconnected handshake_failed].freeze
  VALID_DISCONNECT_REASONS = %w[user_initiated timeout revoked network_change].freeze

  belongs_to :ztlp_device
  belongs_to :network
  belongs_to :ztlp_user, optional: true

  validates :event_type, presence: true, inclusion: { in: VALID_EVENT_TYPES }
  validates :disconnect_reason, inclusion: { in: VALID_DISCONNECT_REASONS }, allow_nil: true, allow_blank: true

  scope :recent, -> { order(created_at: :desc) }
  scope :for_network, ->(network_id) { where(network_id: network_id) }
  scope :for_device, ->(device_id) { where(ztlp_device_id: device_id) }
  scope :for_user, ->(user_id) { where(ztlp_user_id: user_id) }
  scope :of_type, ->(type) { where(event_type: type) }
  scope :since, ->(time) { where("created_at > ?", time) }

  def connected?
    event_type == "connected"
  end

  def disconnected?
    event_type == "disconnected"
  end

  def reconnected?
    event_type == "reconnected"
  end

  def handshake_failed?
    event_type == "handshake_failed"
  end

  def event_color
    case event_type
    when "connected"        then "green"
    when "disconnected"     then "red"
    when "reconnected"      then "yellow"
    when "handshake_failed" then "gray"
    else "gray"
    end
  end

  def event_icon
    case event_type
    when "connected"        then "🟢"
    when "disconnected"     then "🔴"
    when "reconnected"      then "🟡"
    when "handshake_failed" then "⚪"
    else "📋"
    end
  end
end
