class AuditLog < ApplicationRecord
  validates :action, presence: true
  validates :status, inclusion: { in: %w[success failure] }

  scope :recent, -> { order(created_at: :desc) }
  scope :for_target, ->(type, id) { where(target_type: type, target_id: id) }
  scope :failures, -> { where(status: "failure") }

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
