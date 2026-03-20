# frozen_string_literal: true

# Handles self-service enrollment via external identity providers.
# Users authenticate via OIDC/OAuth2, then receive a single-use enrollment token.
class IdpEnrollmentController < ApplicationController
  skip_before_action :require_authentication
  # OmniAuth callbacks bypass CSRF by design (redirected from external IdP)
  skip_forgery_protection only: :callback

  # GET /networks/:network_id/enroll
  def new
    @network = Network.find(params[:network_id])
    @identity_providers = @network.identity_providers.enabled

    if @identity_providers.empty?
      redirect_to network_enrollment_index_path(@network),
                  alert: "No identity providers configured for self-service enrollment."
      return
    end

    # Store network_id in session so the OmniAuth callback can find it
    session[:idp_network_id] = @network.id
  end

  # GET/POST /auth/:provider/callback
  def callback
    auth = request.env["omniauth.auth"]
    network_id = session.delete(:idp_network_id)

    unless auth && network_id
      redirect_to root_path, alert: "Authentication failed: missing auth data."
      return
    end

    @network = Network.find_by(id: network_id)
    unless @network
      redirect_to root_path, alert: "Network not found."
      return
    end

    provider_type = auth.provider.to_s
    @idp = @network.identity_providers.enabled.find_by(provider_type: provider_type)
    unless @idp
      log_idp_event("idp_login_failed", @network, details: { reason: "no_idp_config", provider: provider_type })
      redirect_to root_path, alert: "Identity provider not configured."
      return
    end

    email = auth.info&.email
    name = auth.info&.name || email&.split("@")&.first || "Unknown"
    external_id = auth.uid

    # Domain restriction
    unless @idp.domain_allowed?(email)
      log_idp_event("idp_login_failed", @network,
                    details: { reason: "domain_rejected", email: email, allowed: @idp.allowed_domains })
      redirect_to network_enroll_path(@network),
                  alert: "Your email domain is not authorized for this network."
      return
    end

    # Find or create user
    @user = find_or_create_user!(email: email, name: name, external_id: external_id, issuer: issuer_url(auth))

    unless @user
      redirect_to network_enroll_path(@network),
                  alert: "Unable to create user account. Auto-provisioning may be disabled."
      return
    end

    unless @user.active?
      log_idp_event("idp_login_failed", @network,
                    details: { reason: "user_revoked", email: email, user: @user.name })
      redirect_to network_enroll_path(@network), alert: "Your account has been revoked."
      return
    end

    # Update last login
    @user.update(last_login_at: Time.current)
    log_idp_event("idp_login", @network, details: { email: email, user: @user.name })

    # Generate single-use enrollment token for this user
    @token = generate_enrollment_token!(@user)
    log_idp_event("idp_enrollment_token_generated", @network,
                  details: { user: @user.name, token_id: @token.token_id })

    render :show
  end

  # GET /auth/failure
  def failure
    message = params[:message] || "unknown error"
    network_id = session.delete(:idp_network_id)

    if network_id
      network = Network.find_by(id: network_id)
      log_idp_event("idp_login_failed", network, details: { reason: "omniauth_failure", message: message }) if network
      redirect_to network ? network_enroll_path(network) : root_path,
                  alert: "Authentication failed: #{message.humanize}"
    else
      redirect_to root_path, alert: "Authentication failed: #{message.humanize}"
    end
  end

  private

  def find_or_create_user!(email:, name:, external_id:, issuer:)
    # Try to find by external_id + issuer first
    user = @network.ztlp_users.find_by(external_id: external_id, idp_issuer: issuer) if external_id.present?
    # Fall back to email match
    user ||= @network.ztlp_users.find_by(email: email) if email.present?

    if user
      # Update IdP fields if not set
      user.update(external_id: external_id, idp_issuer: issuer) if user.external_id.blank? && external_id.present?
      return user
    end

    # Auto-create if enabled
    return nil unless @idp.auto_create_users

    user = @network.ztlp_users.new(
      name: sanitize_username(name, email),
      email: email,
      role: @idp.role_default,
      status: "active",
      external_id: external_id,
      idp_issuer: issuer
    )

    if user.save
      log_idp_event("idp_user_created", @network,
                    details: { name: user.name, email: email, role: user.role })

      # Sync to NS (best-effort — don't fail enrollment if NS is unreachable)
      sync_user_to_ns(user)

      user
    else
      Rails.logger.error("IdP auto-create user failed: #{user.errors.full_messages.join(', ')}")
      nil
    end
  end

  def sanitize_username(name, email)
    # ZtlpUser name must be unique per network. Use name, fall back to email prefix.
    base = name.present? ? name.downcase.gsub(/[^a-z0-9._-]/, ".") : email.split("@").first
    candidate = base
    counter = 1
    while @network.ztlp_users.exists?(name: candidate)
      candidate = "#{base}.#{counter}"
      counter += 1
    end
    candidate
  end

  def issuer_url(auth)
    # Google's issuer
    return "https://accounts.google.com" if auth.provider == "google_oauth2"
    # OIDC providers include issuer in extra info
    auth.extra&.raw_info&.dig("iss") || @idp&.issuer_url || auth.provider.to_s
  end

  def generate_enrollment_token!(user)
    generator = TokenGenerator.new(@network)
    generator.generate!(
      expires_in: 1.hour,
      max_uses: 1,
      roles: user.role,
      notes: "Self-service enrollment for #{user.name} (#{user.email}) via #{@idp.name}"
    )
  end

  def sync_user_to_ns(user)
    admin = ZtlpAdmin.new(@network)
    admin.create_user(user.name, role: user.role, email: user.email)
  rescue ZtlpAdmin::AdminError => e
    Rails.logger.warn("Failed to sync IdP user to NS: #{e.message}")
  rescue StandardError => e
    Rails.logger.warn("Failed to sync IdP user to NS: #{e.message}")
  end

  def log_idp_event(action, network, details: {})
    AuditLog.record(
      action: action,
      target: network,
      status: action.include?("failed") ? "failure" : "success",
      details: details,
      ip_address: request.remote_ip
    )
  end
end
