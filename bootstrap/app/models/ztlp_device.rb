# frozen_string_literal: true

# Mirrors a ZTLP NS DEVICE record.
class ZtlpDevice < ApplicationRecord
  belongs_to :network
  belongs_to :ztlp_user, optional: true
  belongs_to :machine, optional: true

  validates :name, presence: true, uniqueness: { scope: :network_id }
  validates :status, inclusion: { in: %w[enrolled revoked] }

  scope :enrolled, -> { where(status: "enrolled") }
  scope :revoked, -> { where(status: "revoked") }

  def revoke!(reason: nil)
    update!(status: "revoked", revoked_at: Time.current, revocation_reason: reason)
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
