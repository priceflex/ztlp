class Machine < ApplicationRecord
  belongs_to :network
  has_many :deployments, dependent: :destroy

  encrypts :ssh_private_key_ciphertext
  encrypts :ssh_password_ciphertext

  validates :hostname, presence: true, uniqueness: { scope: :network_id }
  validates :ip_address, presence: true, uniqueness: { scope: :network_id },
    format: { with: /\A(\d{1,3}\.){3}\d{1,3}\z/, message: "must be a valid IPv4 address" }
  validates :ssh_port, numericality: { in: 1..65535 }
  validates :ssh_user, presence: true
  validates :ssh_auth_method, inclusion: { in: %w[key password agent] }
  validates :status, inclusion: { in: %w[pending provisioning ready error offline] }
  validates :roles, presence: { message: "must have at least one role assigned" }

  validate :validate_roles

  scope :ready, -> { where(status: "ready") }
  scope :with_role, ->(role) { where("roles LIKE ?", "%#{role}%") }

  VALID_ROLES = %w[ns relay gateway].freeze

  def role_list
    roles.split(",").map(&:strip).reject(&:empty?)
  end

  def role_list=(list)
    self.roles = Array(list).map(&:strip).reject(&:empty?).join(",")
  end

  def has_role?(role)
    role_list.include?(role.to_s)
  end

  def ready?
    status == "ready"
  end

  def latest_deployment_for(component)
    deployments.where(component: component).order(created_at: :desc).first
  end

  def all_components_deployed?
    role_list.all? do |role|
      dep = latest_deployment_for(role)
      dep&.status == "success"
    end
  end

  private

  def validate_roles
    invalid = role_list - VALID_ROLES
    if invalid.any?
      errors.add(:roles, "contains invalid roles: #{invalid.join(', ')}. Valid roles: #{VALID_ROLES.join(', ')}")
    end
  end
end
