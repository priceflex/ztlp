# frozen_string_literal: true

# Mirrors a ZTLP NS DEVICE record.
class ZtlpDevice < ApplicationRecord
  include Notifiable

  belongs_to :network
  belongs_to :ztlp_user, optional: true
  belongs_to :machine, optional: true
  has_many :device_heartbeats, dependent: :destroy
  has_many :connection_events, dependent: :destroy

  validates :name, presence: true, uniqueness: { scope: :network_id }
  validates :status, inclusion: { in: %w[enrolled revoked] }

  scope :enrolled, -> { where(status: "enrolled") }
  scope :revoked, -> { where(status: "revoked") }
  scope :online, -> { where("last_seen_at > ?", 5.minutes.ago) }
  scope :offline, -> { where("last_seen_at <= ? OR last_seen_at IS NULL", 5.minutes.ago) }
  scope :recently_seen, -> { where("last_seen_at > ?", 24.hours.ago) }

  def online?
    last_seen_at.present? && last_seen_at > 5.minutes.ago
  end

  def offline?
    !online?
  end

  def status_with_presence
    return "revoked" if revoked?
    online? ? "online" : "offline"
  end

  def revoke!(reason: nil)
    update!(status: "revoked", revoked_at: Time.current, revocation_reason: reason)
    notify_event("device_revoked", subject: "Device revoked: #{name}", body: "Device #{name} was revoked. Reason: #{reason || 'none'}", severity: "warning")
  end

  def enrolled?
    status == "enrolled"
  end

  def revoked?
    status == "revoked"
  end

  def owner_name
    ztlp_user&.name || "Unassigned"
  end
end
