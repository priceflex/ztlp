# frozen_string_literal: true

# Mirrors a ZTLP NS USER record. Not a Rails auth user.
class ZtlpUser < ApplicationRecord
  include Notifiable

  belongs_to :network
  has_many :ztlp_devices, foreign_key: :ztlp_user_id, dependent: :nullify
  has_many :connection_events, dependent: :nullify
  has_many :group_memberships, dependent: :destroy
  has_many :ztlp_groups, through: :group_memberships

  validates :name, presence: true, uniqueness: { scope: :network_id }
  validates :role, inclusion: { in: %w[user tech admin] }
  validates :status, inclusion: { in: %w[active suspended revoked] }

  scope :active, -> { where(status: "active") }
  scope :suspended, -> { where(status: "suspended") }
  scope :revoked, -> { where(status: "revoked") }
  scope :not_revoked, -> { where.not(status: "revoked") }

  def revoke!(reason: nil)
    update!(status: "revoked", revoked_at: Time.current, revocation_reason: reason)
    notify_event("user_revoked", subject: "User revoked: #{name}", body: "User #{name} was revoked. Reason: #{reason || 'none'}", severity: "warning")
  end

  def suspend!
    update!(status: "suspended", suspended_at: Time.current)
    notify_event("user_suspended", subject: "User suspended: #{name}", body: "User #{name} was suspended.", severity: "warning")
  end

  def reactivate!
    update!(status: "active", suspended_at: nil)
  end

  # Revoke this user and all their enrolled devices
  def cascade_revoke!(reason: nil)
    transaction do
      revoke!(reason: reason)
      ztlp_devices.enrolled.find_each do |device|
        device.revoke!(reason: "Owner revoked: #{reason}")
      end
    end
  end

  def active?
    status == "active"
  end

  def suspended?
    status == "suspended"
  end

  def revoked?
    status == "revoked"
  end

  def initials
    parts = name.to_s.split(/[\s._-]+/)
    if parts.length >= 2
      (parts[0][0].to_s + parts[1][0].to_s).upcase
    else
      name.to_s[0..1].upcase
    end
  end
end
