# frozen_string_literal: true

class Alert < ApplicationRecord
  include Notifiable

  belongs_to :network
  belongs_to :machine

  after_create_commit :notify_alert_created

  VALID_COMPONENTS = %w[ns relay gateway].freeze
  VALID_SEVERITIES = %w[warning critical].freeze

  validates :component, presence: true, inclusion: { in: VALID_COMPONENTS }
  validates :severity, presence: true, inclusion: { in: VALID_SEVERITIES }
  validates :message, presence: true

  scope :recent, -> { order(created_at: :desc) }
  scope :active, -> { where(acknowledged: false, resolved_at: nil) }
  scope :acknowledged_alerts, -> { where(acknowledged: true) }
  scope :resolved, -> { where.not(resolved_at: nil) }
  scope :unresolved, -> { where(resolved_at: nil) }
  scope :critical, -> { where(severity: "critical") }
  scope :warnings, -> { where(severity: "warning") }
  scope :for_network, ->(network) { where(network: network) }
  scope :for_machine, ->(machine) { where(machine: machine) }
  scope :for_component, ->(comp) { where(component: comp) }

  def acknowledge!
    update!(acknowledged: true, acknowledged_at: Time.current)
  end

  def resolve!
    update!(resolved_at: Time.current)
  end

  def active?
    !acknowledged && resolved_at.nil?
  end

  def resolved?
    resolved_at.present?
  end

  # Create an alert when status transitions to degraded/down
  def self.create_for_status_change(machine:, component:, new_status:, old_status:)
    return if new_status == old_status
    return if new_status == "healthy" || new_status == "unknown"

    severity = new_status == "down" ? "critical" : "warning"
    message = "#{component.upcase} on #{machine.hostname} changed from #{old_status} to #{new_status}"

    create!(
      network: machine.network,
      machine: machine,
      component: component,
      severity: severity,
      message: message
    )
  end

  # Auto-resolve alerts when a component returns to healthy
  def self.auto_resolve(machine:, component:)
    active.where(machine: machine, component: component).find_each(&:resolve!)
  end

  # Count of active (unresolved, unacknowledged) alerts
  def self.active_count
    active.count
  end

  private

  def notify_alert_created
    event = severity == "critical" ? "alert_critical" : "alert_created"
    notify_event(event,
      subject: "#{severity.upcase}: #{message}",
      body: "Alert on #{machine&.hostname || 'unknown'} (#{component}): #{message}",
      severity: severity,
      details: { component: component, machine: machine&.hostname, network: network&.name }
    )
  end
end
