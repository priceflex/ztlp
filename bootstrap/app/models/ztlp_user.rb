# frozen_string_literal: true

# Mirrors a ZTLP NS USER record. Not a Rails auth user.
class ZtlpUser < ApplicationRecord
  belongs_to :network
  has_many :ztlp_devices, foreign_key: :ztlp_user_id, dependent: :nullify
  has_many :group_memberships, dependent: :destroy
  has_many :ztlp_groups, through: :group_memberships

  validates :name, presence: true, uniqueness: { scope: :network_id }
  validates :role, inclusion: { in: %w[user tech admin] }
  validates :status, inclusion: { in: %w[active revoked] }

  scope :active, -> { where(status: "active") }
  scope :revoked, -> { where(status: "revoked") }

  def revoke!(reason: nil)
    update!(status: "revoked", revoked_at: Time.current, revocation_reason: reason)
  end

  def active?
    status == "active"
  end

  def revoked?
    status == "revoked"
  end
end
