# frozen_string_literal: true

# A service exposed on a gateway. The gateway's allow-list entries are its
# policy rules (decision 7); the default is deny.
class Application < ApplicationRecord
  ASSURANCE_LEVELS = (1..4).freeze

  belongs_to :gateway
  has_many :policy_rules, dependent: :destroy

  validates :name, presence: true, length: { maximum: 63 },
                   format: { with: Admin::USERNAME, message: "must be a lowercase DNS label" },
                   uniqueness: { scope: :gateway_id }
  validates :min_assurance, inclusion: { in: ASSURANCE_LEVELS }

  def ztlp_name = "#{name}.#{gateway.zone.name}"
end
