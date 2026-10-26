# frozen_string_literal: true

class Admin < ApplicationRecord
  belongs_to :default_zone, class_name: "Zone", optional: true
  ROLES = %w[super_admin admin helpdesk read_only].freeze
  USERNAME = /\A[a-z0-9]([a-z0-9-]*[a-z0-9])?\z/

  belongs_to :user, optional: true
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
  # Operational functions (policy, services, gateways, groups, roles, permanent revokes, zone).
  # helpdesk manages people only: add/edit users, add devices, disable/enable (spec 4.3).
  def operator? = %w[super_admin admin].include?(role)
  def helpdesk? = role == "helpdesk"
  def disabled? = disabled_at.present?

  def self.exists_any? = unscoped.exists?
end
