# frozen_string_literal: true

class Policy < ApplicationRecord
  belongs_to :network

  POLICY_TYPES     = %w[access time_based network_segment].freeze
  PRIORITIES       = %w[high normal low].freeze
  SUBJECT_TYPES    = %w[user group role everyone].freeze
  RESOURCE_TYPES   = %w[service zone ip_range].freeze
  ACTIONS          = %w[allow deny].freeze
  AUTH_MODES       = %w[passthrough identity enforce].freeze
  ASSURANCE_LEVELS = %w[unknown software device-bound hardware].freeze

  PRIORITY_WEIGHTS = { "high" => 100, "normal" => 50, "low" => 10 }.freeze

  validates :name, presence: true
  validates :policy_type, presence: true, inclusion: { in: POLICY_TYPES }
  validates :priority, inclusion: { in: PRIORITIES }
  validates :subject_type, presence: true, inclusion: { in: SUBJECT_TYPES }
  validates :subject_value, presence: true, unless: -> { subject_type == "everyone" }
  validates :resource_type, presence: true, inclusion: { in: RESOURCE_TYPES }
  validates :resource_value, presence: true
  validates :action, presence: true, inclusion: { in: ACTIONS }
  validates :auth_mode, inclusion: { in: AUTH_MODES }, allow_nil: true
  validates :min_assurance, inclusion: { in: ASSURANCE_LEVELS }, allow_nil: true
  validates :timezone, presence: true
  validate :validate_cidr_notation, if: -> { resource_type == "ip_range" }
  validate :validate_time_schedule, if: -> { time_schedule.present? }
  validate :validate_subject_role, if: -> { subject_type == "role" }

  scope :enabled, -> { where(enabled: true) }
  scope :disabled, -> { where(enabled: false) }
  scope :allow_rules, -> { where(action: "allow") }
  scope :deny_rules, -> { where(action: "deny") }
  scope :by_type, ->(type) { where(policy_type: type) }
  scope :not_expired, -> { where("expires_at IS NULL OR expires_at > ?", Time.current) }
  scope :expired, -> { where("expires_at IS NOT NULL AND expires_at <= ?", Time.current) }
  scope :search, ->(query) {
    where("name LIKE ? OR resource_value LIKE ?", "%#{query}%", "%#{query}%")
  }

  def priority_weight
    PRIORITY_WEIGHTS[priority] || 50
  end

  def allow?
    action == "allow"
  end

  def deny?
    action == "deny"
  end

  def expired?
    expires_at.present? && expires_at <= Time.current
  end

  def active?
    enabled? && !expired?
  end

  def subject_display
    case subject_type
    when "everyone" then "Everyone"
    when "role" then "Role: #{subject_value}"
    when "group" then "Group: #{subject_value}"
    when "user" then "User: #{subject_value}"
    else subject_type
    end
  end

  def resource_display
    case resource_type
    when "service" then "Service: #{resource_value}"
    when "zone" then "Zone: #{resource_value}"
    when "ip_range" then "IP Range: #{resource_value}"
    else resource_value
    end
  end

  def priority_emoji
    case priority
    when "high" then "🔴"
    when "normal" then "🟡"
    when "low" then "🟢"
    end
  end

  def to_gateway_rule
    base = {
      subject: { type: subject_type, value: subject_value },
      resource: { type: resource_type, value: resource_value },
      action: action,
      schedule: time_schedule,
      priority: priority_weight
    }
    base[:auth_mode] = auth_mode if auth_mode.present?
    base[:min_assurance] = min_assurance if min_assurance.present?
    base
  end

  def passwordless_enabled?
    auth_mode.present? && auth_mode != "passthrough"
  end

  def auth_mode_display
    case auth_mode
    when "enforce" then "🔒 Enforce (mTLS required)"
    when "identity" then "🪪 Identity (inject headers)"
    when "passthrough" then "🔓 Passthrough"
    else "—"
    end
  end

  def min_assurance_display
    case min_assurance
    when "hardware" then "🔑 Hardware"
    when "device-bound" then "📱 Device-bound"
    when "software" then "💻 Software"
    else "—"
    end
  end

  # Duplicate this policy with a new name
  def duplicate!
    dup_policy = dup
    dup_policy.name = "#{name} (copy)"
    dup_policy.save!
    dup_policy
  end

  # Find conflicting policies in the same network (same subject+resource, different action)
  def conflicting_policies
    scope = network.policies.where(
      subject_type: subject_type,
      resource_type: resource_type,
      resource_value: resource_value
    ).where.not(action: action).where.not(id: id)

    # Match on subject_value too (or null for everyone)
    if subject_type == "everyone"
      scope.where(subject_value: [nil, ""])
    else
      scope.where(subject_value: subject_value)
    end
  end

  def has_conflicts?
    conflicting_policies.exists?
  end

  # Resolve the effective users this policy applies to
  def effective_users
    case subject_type
    when "everyone"
      network.ztlp_users.active
    when "user"
      network.ztlp_users.active.where(name: subject_value)
    when "group"
      group = network.ztlp_groups.find_by(name: subject_value)
      group ? group.ztlp_users.merge(ZtlpUser.active) : ZtlpUser.none
    when "role"
      network.ztlp_users.active.where(role: subject_value)
    else
      ZtlpUser.none
    end
  end

  private

  def validate_cidr_notation
    return if resource_value.blank?
    # Basic CIDR validation: x.x.x.x/nn
    unless resource_value.match?(%r{\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\z})
      errors.add(:resource_value, "must be valid CIDR notation (e.g., 10.42.0.0/16)")
      return
    end
    ip, prefix = resource_value.split("/")
    octets = ip.split(".")
    unless octets.all? { |o| o.to_i.between?(0, 255) } && prefix.to_i.between?(0, 32)
      errors.add(:resource_value, "must be valid CIDR notation (e.g., 10.42.0.0/16)")
    end
  end

  def validate_time_schedule
    return if time_schedule.blank?
    # Expected format: "MON-FRI 09:00-17:00" or "MON,WED,FRI 08:00-18:00"
    unless time_schedule.match?(/\A[A-Z]{3}[\-,A-Z]* \d{2}:\d{2}-\d{2}:\d{2}\z/)
      errors.add(:time_schedule, "must be in format like 'MON-FRI 09:00-17:00'")
    end
  end

  def validate_subject_role
    unless %w[user tech admin].include?(subject_value)
      errors.add(:subject_value, "must be a valid role (user, tech, or admin)")
    end
  end
end
