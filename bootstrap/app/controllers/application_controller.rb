class ApplicationController < ActionController::Base
  before_action :require_authentication
  helper_method :current_admin, :admin_signed_in?

  private

  def require_authentication
    unless current_admin
      store_intended_url
      redirect_to login_path, alert: "Please sign in to continue."
    end
  end

  def current_admin
    return @current_admin if @current_admin

    @current_admin = AdminUser.find_by(id: session[:admin_user_id])
    @current_admin ||= trusted_gateway_admin
    @current_admin ||= orchestrator_onboarding_admin
  end

  def trusted_gateway_admin
    return unless ActiveModel::Type::Boolean.new.cast(ENV["ZTLP_TRUST_GATEWAY_AUTH"])

    secret = ENV["ZTLP_GATEWAY_HEADER_SECRET"].to_s
    if secret.empty?
      ApplicationController.warn_gateway_secret_missing!
      return nil
    end

    status, payload = Ztlp::HeaderVerifier.verify_request(request.headers, secret: secret)
    if status != :ok
      Rails.logger.warn("[gateway-auth] rejected gateway header set: #{payload}")
      return nil
    end

    return unless payload["authenticated"].to_s == "1" || payload["authenticated"].to_s.downcase == "true"

    email = payload["admin-email"].to_s.downcase.strip
    return if email.blank?

    admin = AdminUser.find_by("LOWER(email) = ?", email)
    return unless admin && !admin.locked?

    session[:admin_user_id] = admin.id
    admin.record_login!(request.remote_ip)
    AuditLog.record(
      action: "admin_gateway_login",
      target: admin,
      status: "success",
      details: { email: admin.email, gateway: "ztlp" },
      ip_address: request.remote_ip
    )
    admin
  end

  # Log the "secret missing" warning at most once per process, so a
  # misconfigured deployment isn't drowned in repeated entries.
  def self.warn_gateway_secret_missing!
    @gateway_secret_warning_logged ||= begin
      Rails.logger.warn("[gateway-auth] disabled: ZTLP_GATEWAY_HEADER_SECRET not set")
      true
    end
  end

  def orchestrator_onboarding_admin
    return unless ENV["ZTLP_ORCHESTRATOR_ONBOARDING"] == "true"

    # [SAST: cpr-zkri fix] X-ZTLP-User was trusted with zero signature or
    # proxy verification — anyone able to reach this app (directly, or via
    # a gateway route not stripping client headers) could mint a fresh
    # super_admin account just by sending the header. Require the same
    # trusted-proxy shared-secret check that trusted_gateway_admin already
    # uses (ZTLP_GATEWAY_HEADER_SECRET via Ztlp::HeaderVerifier), so this
    # path only fires for requests actually signed by our own orchestrator/
    # gateway, never a bare client-supplied header.
    secret = ENV["ZTLP_GATEWAY_HEADER_SECRET"].to_s
    if secret.empty?
      ApplicationController.warn_gateway_secret_missing!
      return nil
    end

    status, payload = Ztlp::HeaderVerifier.verify_request(request.headers, secret: secret)
    if status != :ok
      Rails.logger.warn("[orchestrator-onboarding] rejected unverified onboarding header set: #{payload}")
      return nil
    end

    header_user = request.headers["X-ZTLP-User"].to_s.downcase.strip
    return if header_user.blank?

    existing = AdminUser.find_by(email: header_user)
    if existing
      admin = existing
    else
      # Never auto-mint super_admin from an onboarding header — an
      # orchestrator-provisioned account starts at the lowest privilege
      # role and must be explicitly promoted by an existing super_admin.
      admin = AdminUser.create!(
        email: header_user,
        name: header_user.split("@").first || "Orchestrator User",
        role: "read_only",
        password: SecureRandom.hex(16)
      )
      Rails.logger.info("[orchestrator-onboarding] auto-created read_only account for #{header_user}")
    end

    session[:admin_user_id] = admin.id
    admin
  end

  def admin_signed_in?
    current_admin.present?
  end

  def store_intended_url
    session[:intended_url] = request.fullpath if request.get?
  end

  def require_super_admin
    unless current_admin&.super_admin?
      redirect_to root_path, alert: "Not authorized."
    end
  end
end
