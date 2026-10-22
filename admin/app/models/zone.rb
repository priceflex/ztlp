# frozen_string_literal: true

class Zone < ApplicationRecord
  serialize :relay_addrs, coder: JSON
  encrypts :authority_seed_ct, :enrollment_secret_ct, :relay_secret_ct, :ns_admin_api_secret_ct

  has_many :users
  has_many :groups
  has_many :devices
  has_many :enrollments
  has_many :gateways
  has_many :applications
  # PolicyRule has no zone_id (rules belong to an application's gateway);
  # zone-scoped rule lookups must go through the gateway join.

  validates :name, presence: true, uniqueness: true
  validates :ns_addr, presence: true
  # 64-hex Ed25519 seed, exactly identity.json's signing_key_seed.
  validates :authority_seed_ct, format: { with: /\A\h{64}\z/ }, allow_nil: true

  # First use creates the zone from the deployment env (docker-compose.yml sets both).
  # No ZTLP_ZONE = misconfigured deployment: raise rather than invent a zone name.
  def self.primary
    order(:id).first ||
      create!(name: ENV.fetch("ZTLP_ZONE"), ns_addr: ENV.fetch("ZTLP_NS_ADDR", "127.0.0.1:23096"))
  end

  def authority_configured? = authority_seed_ct.present?
end
