class AuditLog < ApplicationRecord
  validates :action, presence: true
  # Phase C — added "skipped" so jobs that legitimately skip work on a
  # shared production Machine row (see `DeployComponentJob`) can still
  # write a forensic-grade audit entry without forcing the entry into
  # the misleading `"failure"` bucket.
  VALID_STATUSES = %w[success failure skipped].freeze
  validates :status, inclusion: { in: VALID_STATUSES }

  scope :recent, -> { order(created_at: :desc) }
  scope :for_target, ->(type, id) { where(target_type: type, target_id: id) }
  scope :failures, -> { where(status: "failure") }
  scope :skips, -> { where(status: "skipped") }

  def self.record(action:, target: nil, status: "success", details: nil, ip_address: nil)
    create!(
      action: action,
      target_type: target&.class&.name,
      target_id: target&.id,
      status: status,
      details: details.is_a?(Hash) ? details.to_json : details,
      ip_address: ip_address
    )
  end

  def parsed_details
    return nil if details.blank?
    JSON.parse(details)
  rescue JSON::ParserError
    details
  end
end
