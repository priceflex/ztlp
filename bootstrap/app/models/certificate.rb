# frozen_string_literal: true

# Tracks TLS certificates issued by the ZTLP internal CA.
class Certificate < ApplicationRecord
  belongs_to :network

  STATUSES = %w[active revoked expired].freeze
  ASSURANCE_LEVELS = %w[unknown software device-bound hardware].freeze

  validates :hostname, presence: true
  validates :serial, presence: true, uniqueness: true
  validates :status, presence: true, inclusion: { in: STATUSES }
  validates :issued_at, presence: true
  validates :expires_at, presence: true
  validates :assurance_level, inclusion: { in: ASSURANCE_LEVELS }, allow_nil: true

  scope :active, -> { where(status: "active") }
  scope :revoked, -> { where(status: "revoked") }
  scope :expired, -> { where(status: "expired") }
  scope :expiring_soon, -> { active.where("expires_at < ?", 30.days.from_now) }
  scope :for_hostname, ->(hostname) { where(hostname: hostname) }

  def active?
    status == "active" && !expired_cert?
  end

  def expired_cert?
    expires_at.present? && expires_at <= Time.current
  end

  def expiring_soon?
    active? && expires_at < 30.days.from_now
  end

  def revoke!(reason: nil)
    update!(
      status: "revoked",
      revoked_at: Time.current,
      revocation_reason: reason
    )
  end

  def days_until_expiry
    return 0 if expired_cert?
    ((expires_at - Time.current) / 1.day).ceil
  end

  def expiry_status
    return "expired" if expired_cert?
    return "critical" if days_until_expiry <= 7
    return "warning" if days_until_expiry <= 30
    "ok"
  end

  # Check and auto-mark expired certificates
  def self.mark_expired!
    active.where("expires_at <= ?", Time.current).update_all(status: "expired")
  end
end
