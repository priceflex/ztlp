# frozen_string_literal: true

# A DeviceCommunicationGrant records that ZtlpDevice A is permitted
# to initiate communication to ZtlpDevice B on the ZTLP overlay.
#
# Grants are **directional** — A → B is independent of B → A. This
# matches how the gateway will enforce them (the request initiator's
# identity is what we authorize). To express bidirectional permission
# create two rows.
#
# Lifecycle:
#
#                        revoke!
#   active (revoked_at = nil) ──────► revoked (revoked_at = Time.current)
#
# Revoke is a soft-delete — the row stays so audit log queries can
# still reference it. Restoring a revoked grant requires creating a
# new grant (we don't reset `revoked_at` to nil because that would
# erase the original grant's chronology).
#
# Validations:
#
#   * source_device_id and target_device_id must reference valid
#     ZtlpDevices
#   * the pair must be unique (one row per ordered pair)
#   * source != target (a grant for self is meaningless)
#   * source and target must belong to the same Network
#     (cross-network grants are deliberately not allowed — they
#     conflate the network boundary which IS the security envelope)
#
# Audit: every successful create + revoke writes an AuditLog row
# under actions `device_grant.created` and `device_grant.revoked`.
class DeviceCommunicationGrant < ApplicationRecord
  belongs_to :source_device, class_name: "ZtlpDevice"
  belongs_to :target_device, class_name: "ZtlpDevice"

  validates :source_device_id,
            uniqueness: { scope: :target_device_id,
                          message: "already has a grant to this target device" }
  validate :source_and_target_are_different
  validate :devices_in_same_network

  before_validation :set_granted_at, on: :create

  scope :active, -> { where(revoked_at: nil) }
  scope :revoked, -> { where.not(revoked_at: nil) }
  scope :between, ->(src_id, tgt_id) {
    where(source_device_id: src_id, target_device_id: tgt_id)
  }

  def active?
    revoked_at.nil?
  end

  def revoked?
    revoked_at.present?
  end

  # Idempotent soft-delete. Returns false if already revoked (no
  # state change, no audit log churn). On success writes a
  # device_grant.revoked audit log entry.
  def revoke!(admin_user: nil)
    return false if revoked?

    update!(revoked_at: Time.current)

    AuditLog.record(
      action: "device_grant.revoked",
      target: self,
      status: "success",
      details: {
        source_device_id: source_device_id,
        target_device_id: target_device_id,
        revoked_by_admin_user_id: admin_user&.id
      }
    )

    true
  end

  private

  def set_granted_at
    self.granted_at ||= Time.current
  end

  def source_and_target_are_different
    return if source_device_id.nil? || target_device_id.nil?

    if source_device_id == target_device_id
      errors.add(:target_device_id, "must differ from source device")
    end
  end

  def devices_in_same_network
    return if source_device.nil? || target_device.nil?

    if source_device.network_id != target_device.network_id
      errors.add(:target_device_id,
                 "must belong to the same network as the source device")
    end
  end
end
