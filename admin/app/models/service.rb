# frozen_string_literal: true

# A service exposed on a gateway. The gateway's allow-list entries are its
# policy rules (decision 7); the default is deny.
class Service < ApplicationRecord
  ASSURANCE_LEVELS = (1..4).freeze

  belongs_to :gateway
  has_many :policy_rules, dependent: :destroy
  # The edit form also edits the gateway's settings (one gateway per service, slice 4).
  accepts_nested_attributes_for :gateway, update_only: true

  validates :name, presence: true, length: { maximum: 63 },
                   format: { with: Admin::USERNAME, message: "must be a lowercase DNS label" },
                   uniqueness: { scope: :gateway_id }
  validates :min_assurance, inclusion: { in: ASSURANCE_LEVELS }
  # host:port (optional http(s):// scheme, IPv6 in brackets). It is interpolated into the rendered
  # gateway policy and the --forward flag, so no whitespace/newlines/markup can ever get in.
  BACKEND_FORMAT = %r{\A(?:https?://)?(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252})|\[[0-9A-Fa-f:]+\]):\d{1,5}\z}
  validates :backend, format: { with: BACKEND_FORMAT, message: "must be host:port" }, allow_blank: true

  def ztlp_name = "#{name}.#{gateway.zone.name}"
end
