# frozen_string_literal: true

class NotificationChannel < ApplicationRecord
  belongs_to :network, optional: true
  has_many :notification_logs, dependent: :destroy

  CHANNEL_TYPES = %w[email webhook slack].freeze
  SEVERITY_FILTERS = %w[all critical warning_and_above].freeze

  validates :name, presence: true
  validates :channel_type, presence: true, inclusion: { in: CHANNEL_TYPES }
  validates :config_json, presence: true
  validates :severity_filter, inclusion: { in: SEVERITY_FILTERS }, allow_nil: true

  scope :enabled, -> { where(enabled: true) }
  scope :disabled, -> { where(enabled: false) }
  scope :for_network, ->(network) { where(network_id: [network&.id, nil]) }
  scope :by_type, ->(type) { where(channel_type: type) }

  def parsed_config
    @parsed_config = nil if config_json_changed?
    @parsed_config ||= JSON.parse(config_json)
  rescue JSON::ParserError
    {}
  end

  def config=(hash)
    self.config_json = hash.to_json
    @parsed_config = nil
  end

  def toggle!
    update!(enabled: !enabled)
  end

  def event_types
    return [] if event_filter.blank?
    event_filter.split(",").map(&:strip).reject(&:empty?)
  end

  def matches_event?(event_type)
    return true if event_filter.blank?
    event_types.include?(event_type)
  end

  def matches_severity?(severity)
    case severity_filter
    when "all", nil
      true
    when "critical"
      severity == "critical"
    when "warning_and_above"
      %w[warning critical].include?(severity)
    else
      true
    end
  end

  def healthy?
    enabled? && last_error.blank?
  end

  def status_label
    return "disabled" unless enabled?
    last_error.present? ? "error" : "healthy"
  end

  def type_icon
    case channel_type
    when "email" then "📧"
    when "webhook" then "🔗"
    when "slack" then "💬"
    else "📨"
    end
  end

  def record_success!
    update!(
      last_sent_at: Time.current,
      send_count: send_count + 1,
      last_error: nil
    )
  end

  def record_error!(message)
    update!(last_error: message)
  end
end
