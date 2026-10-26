# frozen_string_literal: true

# A device enrolled (or to be enrolled) into the zone. Identity fields come
# from the NS DEVICE record (G7); PII lives only on the owner User.
class Device < ApplicationRecord
  KEY_SOURCES = %w[yubikey tpm secure-enclave strongbox file unknown].freeze
  ASSURANCE_LEVELS = (1..4).freeze
  STATUSES = %w[pending enrolled disabled revoked].freeze

  belongs_to :zone
  belongs_to :user, optional: true
  belongs_to :enrollment, optional: true

  before_validation :normalize_name

  def normalize_name
    self.name = name.to_s.strip.downcase
    self.ns_name = "#{name}.#{zone&.name}" if name.present? && zone&.name.present?
  end

  validates :name, presence: true, length: { maximum: 63 },
                   format: { with: Admin::USERNAME, message: "must be a lowercase DNS label" },
                   uniqueness: { scope: :zone_id }
  validates :ns_name, presence: true, length: { maximum: 255 }, allow_nil: true
  validates :key_source, inclusion: { in: KEY_SOURCES }
  validates :assurance, inclusion: { in: ASSURANCE_LEVELS }
  validates :status, inclusion: { in: STATUSES }

  def revoked? = status == "revoked"
  def enrolled? = status == "enrolled"
  def disabled? = status == "disabled"

  # Disabled/revoked, or owned by a disabled/revoked user: the zone stops vouching for it
  # (no owner in its DEVICE record, dropped from rendered policy). Pending devices are not suspended.
  def suspended? = disabled? || revoked? || (user.present? && (user.disabled? || user.revoked?))
end
