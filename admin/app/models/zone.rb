# frozen_string_literal: true

class Zone < ApplicationRecord
  serialize :relay_addrs, coder: JSON
  encrypts :authority_seed_ct, :enrollment_secret_ct, :relay_secret_ct, :ns_admin_api_secret_ct

  has_many :users
  has_many :groups
  has_many :devices
  has_many :enrollments
  has_many :gateways
  has_many :services
  # PolicyRule has no zone_id (rules belong to a service's gateway);
  # zone-scoped rule lookups must go through the gateway join.

  DNS_NAME = /\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\z/

  validates :name, presence: true, uniqueness: true,
                   format: { with: DNS_NAME, message: "must be a lowercase dotted DNS name (e.g. chooseforce.ztlp)" }
  validates :ns_addr, presence: true
  # 64-hex Ed25519 seed, exactly identity.json's signing_key_seed.
  validates :authority_seed_ct, format: { with: /\A\h{64}\z/ }, allow_nil: true
  # Home NS Ed25519 PUBLIC key (the NS logs it as "NS registration public key"). Enrollment tokens
  # carry it (flag 0x10) so devices trust only answers this NS signs.
  validates :ns_pubkey_hex, format: { with: /\A\h{64}\z/, message: "must be 64 hex characters" }, allow_nil: true

  def ns_pubkey_hex=(value)
    super(value.to_s.strip.downcase.presence)
  end

  # First use creates the zone from the deployment env (docker-compose.yml sets both).
  # No ZTLP_ZONE = misconfigured deployment: raise rather than invent a zone name.
  def self.primary
    order(:id).first ||
      create!(name: ENV.fetch("ZTLP_ZONE"), ns_addr: ENV.fetch("ZTLP_NS_ADDR", "127.0.0.1:23096"))
  end

  # The deployment's home zone (ZTLP_ZONE): the fallback when an admin has no default zone, the
  # zone tunnel SSO maps subjects in, and the default for rake tasks.
  def self.default
    find_by(name: ENV["ZTLP_ZONE"].to_s) || primary
  end

  # Rake/CLI helper: a zone by name (ZONE=...), or the home zone when none is given.
  def self.resolve!(name)
    name.to_s.strip.empty? ? default : find_by!(name: name.to_s.strip.downcase)
  end

  # The NS admin API secret belongs to the NS, not to a zone: one NS serves every zone, so a zone
  # without its own copy uses the home zone's.
  def ns_admin_secret
    ns_admin_api_secret_ct.presence || (Zone.default == self ? nil : Zone.default&.ns_admin_api_secret_ct.presence)
  end

  # Form helper for "Add zone": comma/space separated host:port list.
  def relay_addrs_text = Array(relay_addrs).join(", ")

  def relay_addrs_text=(text)
    self.relay_addrs = text.to_s.split(/[\s,]+/).map(&:strip).reject(&:empty?).presence
  end

  def authority_configured? = authority_seed_ct.present?

  # zone.ns_addr is the PUBLIC NS address (devices dial it; enrollment tokens embed it). The panel
  # may reach the NS on an internal address instead (prod: ztlp-ns:23096 on a docker network):
  # ZTLP_NS_PUBLISH_ADDR. Publishing uses this; tokens never do.
  def ns_publish_addr = ENV["ZTLP_NS_PUBLISH_ADDR"].presence || ns_addr
end
