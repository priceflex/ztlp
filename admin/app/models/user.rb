# frozen_string_literal: true

class User < ApplicationRecord
  belongs_to :zone
  has_many :group_memberships, dependent: :destroy
  has_many :groups, through: :group_memberships
  has_many :devices, foreign_key: :user_id

  encrypts :email, deterministic: true
  encrypts :phone

  KINDS = %w[person service].freeze
  ROLES = %w[user tech admin].freeze
  STATUSES = %w[invited active disabled revoked].freeze
  USERNAME = Admin::USERNAME
  NS_NAME_MAX = 255

  before_validation :normalize_username

  def normalize_username
    self.username = username.to_s.strip.downcase
    self.display_name ||= username.to_s.capitalize
    self.ns_name = "#{username}.users.#{zone&.name}" if username.present? && zone&.name.present?
  end

  validates :username, presence: true, length: { maximum: 63 },
                       format: { with: USERNAME, message: "must be a lowercase DNS label" },
                       uniqueness: { scope: :zone_id }
  validates :ns_name, presence: true, length: { maximum: NS_NAME_MAX }, allow_nil: true
  validates :kind, inclusion: { in: KINDS }
  validates :role, inclusion: { in: ROLES }
  validates :status, inclusion: { in: STATUSES }
end
