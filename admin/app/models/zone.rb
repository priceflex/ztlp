# frozen_string_literal: true

class Zone < ApplicationRecord
  serialize :relay_addrs, coder: JSON
  encrypts :authority_seed_ct, :enrollment_secret_ct, :relay_secret_ct, :ns_admin_api_secret_ct

  has_many :users
  has_many :groups
  has_many :devices
  has_many :enrollments
  has_many :gateways

  validates :name, presence: true, uniqueness: true
  validates :ns_addr, presence: true

  # First use creates the zone from the deployment env (docker-compose.yml sets both).
  # No ZTLP_ZONE = misconfigured deployment: raise rather than invent a zone name.
  def self.primary
    order(:id).first ||
      create!(name: ENV.fetch("ZTLP_ZONE"), ns_addr: ENV.fetch("ZTLP_NS_ADDR", "127.0.0.1:23096"))
  end

  def authority_configured? = authority_seed_ct.present?
end
