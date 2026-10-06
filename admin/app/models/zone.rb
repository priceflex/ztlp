# frozen_string_literal: true

class Zone < ApplicationRecord
  serialize :relay_addrs, coder: JSON
  encrypts :authority_seed_ct, :enrollment_secret_ct, :relay_secret_ct, :ns_admin_api_secret_ct

  validates :name, presence: true, uniqueness: true
  validates :ns_addr, presence: true

  def self.primary = order(:id).first

  def authority_configured? = authority_seed_ct.present?
end
