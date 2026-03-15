# frozen_string_literal: true

# Stores per-network OIDC/OAuth2 identity provider configuration.
# Used for self-service enrollment via external IdPs (Google, Azure AD, etc.)
class IdentityProvider < ApplicationRecord
  belongs_to :network

  PROVIDER_TYPES = %w[google_oauth2 openid_connect].freeze
  VALID_ROLES = %w[user tech admin].freeze

  encrypts :client_secret_ciphertext

  validates :name, presence: true
  validates :provider_type, presence: true, inclusion: { in: PROVIDER_TYPES }
  validates :client_id, presence: true
  validates :client_secret_ciphertext, presence: true
  validates :role_default, inclusion: { in: VALID_ROLES }
  validates :issuer_url, presence: true, if: -> { provider_type == "openid_connect" }

  scope :enabled, -> { where(enabled: true) }

  # Virtual attribute for setting the secret (stored encrypted)
  def client_secret=(value)
    self.client_secret_ciphertext = value
  end

  def client_secret
    client_secret_ciphertext
  end

  def allowed_domain_list
    return [] if allowed_domains.blank?
    allowed_domains.split(",").map(&:strip).reject(&:empty?)
  end

  def domain_allowed?(email)
    domains = allowed_domain_list
    return true if domains.empty?
    domain = email.to_s.split("@").last&.downcase
    domains.any? { |d| d.downcase == domain }
  end

  # Build OmniAuth strategy name for routing
  def omniauth_strategy
    provider_type
  end

  def google?
    provider_type == "google_oauth2"
  end

  def openid_connect?
    provider_type == "openid_connect"
  end

  def display_type
    case provider_type
    when "google_oauth2" then "Google Workspace"
    when "openid_connect" then "OIDC (#{issuer_url})"
    else provider_type.titleize
    end
  end
end
