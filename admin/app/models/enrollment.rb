# frozen_string_literal: true

# An enrollment token that a new person/device redeems to join the zone.
class Enrollment < ApplicationRecord
  KINDS = %w[user_device device_only].freeze
  STATUSES = %w[pending redeemed redeemed_unverified expired revoked].freeze
  TOKEN_ID = /\A[0-9a-f]{32}\z/ # 16 bytes, hex
  CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" # no I/O/0/1/L

  # The token URI is shown exactly once (the result page) and then never
  # rendered again. It is encrypted at rest so a DB read is not a token leak.
  encrypts :token_uri_ct

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
  def revoked? = status == "revoked"
  def expired? = status == "expired" || (expires_at.present? && expires_at < Time.current)
  def revocable? = pending?

  # Slice 5b: sweep pending enrollment tokens past expires_at. Flips them to
  # `expired` (idempotent — pending rows only). Returns the count of rows
  # flipped. `now:` is the wall clock (default: Time.current).
  #
  # NOTE: `where(...).count { update_all }` would run update_all UNSCOPED
  # (the block ignores the receiver's where-clauses) — the query and the
  # update must use the SAME relation.
  def self.expire_due!(now = Time.current)
    relation = where(status: "pending").where.not(expires_at: nil).where(expires_at: ..now)
    ids = relation.pluck(:id)
    where(id: ids).update_all(status: "expired")
  end
end
