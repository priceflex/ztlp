# frozen_string_literal: true

class AuditLog < ApplicationRecord
  belongs_to :admin, optional: true
  serialize :details, coder: JSON

  def self.record!(action, admin: nil, target: nil, status: "ok", details: {}, ip: nil)
    create!(action: action, admin: admin, target_type: target&.class&.name, target_id: target&.id,
            status: status, details: details.presence, ip: ip, created_at: Time.current)
  end
end
