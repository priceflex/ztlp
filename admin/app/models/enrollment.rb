# frozen_string_literal: true

# An enrollment token that a new person/device redeems to join the zone.
class Enrollment < ApplicationRecord
  KINDS = %w[user_device device_only].freeze
  STATUSES = %w[pending redeemed expired revoked].freeze
  TOKEN_ID = /\A[0-9a-f]{32}\z/ # 16 bytes, hex
  CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" # no I/O/0/1/L

  belongs_to :zone
  belongs_to :user, optional: true
  belongs_to :created_by_admin, class_name: "Admin", optional: true
  belongs_to :redeemed_device, class_name: "Device", optional: true

  before_validation :fill_code

  def fill_code
    self.code ||= self.class.generate_code
    self.token_id = token_id.to_s.downcase
  end

  validates :token_id, presence: true, format: { with: TOKEN_ID, message: "must be 32 hex characters (16 bytes)" },
                       uniqueness: true
  validates :kind, inclusion: { in: KINDS }
  validates :status, inclusion: { in: STATUSES }
  validates :code, presence: true, format: { with: /\A[A-Z2-9]{8}\z/ }, uniqueness: true

  def self.generate_code
    loop do
      candidate = Array.new(8) { CODE_ALPHABET[SecureRandom.random_number(CODE_ALPHABET.length)] }.join
      return candidate unless exists?(code: candidate)
    end
  end

  def self.generate_token_id
    loop do
      candidate = SecureRandom.hex(16)
      return candidate unless exists?(token_id: candidate)
    end
  end

  def pending? = status == "pending"
  def expired? = status == "expired" || (expires_at.present? && expires_at < Time.current)
  def revocable? = pending?
end
