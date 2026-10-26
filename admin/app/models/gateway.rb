# frozen_string_literal: true

# A gateway that fronts zone services and stamps requests with ZTLP
# identity headers (G3). `kind` selects the policy rendering target.
class Gateway < ApplicationRecord
  KINDS = %w[rust_listen elixir].freeze
  STATUSES = %w[planned registered online stale].freeze

  belongs_to :zone
  has_many :services, dependent: :destroy
  serialize :addresses, coder: JSON

  before_validation :normalize_name

  def normalize_name
    self.name = name.to_s.strip.downcase
    self.ns_name = "#{name}.#{zone&.name}" if name.present? && zone&.name.present?
  end

  validates :name, presence: true, length: { maximum: 63 },
                   format: { with: Admin::USERNAME, message: "must be a lowercase DNS label" },
                   uniqueness: { scope: :zone_id }
  validates :kind, inclusion: { in: KINDS }
  validates :status, inclusion: { in: STATUSES }
end
