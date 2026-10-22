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

  def self.primary
    order(:id).first || create!(name: "trs.ztlp", ns_addr: "0.0.0.0:23095")
  end

  def authority_configured? = authority_seed_ct.present?
end
