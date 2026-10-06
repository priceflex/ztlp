# frozen_string_literal: true

class Admin < ApplicationRecord
  ROLES = %w[super_admin admin helpdesk read_only].freeze
  USERNAME = /\A[a-z0-9]([a-z0-9-]*[a-z0-9])?\z/

  has_many :login_challenges, dependent: :delete_all
  has_many :session_tokens, dependent: :delete_all
  has_many :audit_logs

  before_validation do
    self.username = username.to_s.strip.downcase
    self.pubkey_hex = pubkey_hex.to_s.strip.downcase
  end

  validates :username, presence: true, uniqueness: true, length: { maximum: 63 },
                       format: { with: USERNAME, message: "must be a lowercase DNS label" }
  validates :display_name, presence: true
  validates :role, inclusion: { in: ROLES }
  validates :pubkey_hex, presence: true, uniqueness: true, format: { with: Ztlp::Ed25519::HEX32, message: "must be 64 hex characters" }
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }, allow_blank: true

  scope :active, -> { where(disabled_at: nil) }

  def super_admin? = role == "super_admin"
  def write_access? = role != "read_only"
  def disabled? = disabled_at.present?

  def self.exists_any? = unscoped.exists?
end
