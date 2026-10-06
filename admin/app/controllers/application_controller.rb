# frozen_string_literal: true

class ApplicationController < ActionController::Base
  helper_method :current_admin, :signed_in?

  before_action :redirect_to_claim_if_unclaimed
  before_action :require_sign_in

  IDLE_TIMEOUT = 8.hours
  ABSOLUTE_TIMEOUT = 24.hours

  private

  def current_admin
    return @current_admin if defined?(@current_admin)

    @current_admin = nil
    gateway_sign_in! if session[:admin_id].blank?
    if (id = session[:admin_id])
      started = session[:started_at].to_i
      seen = session[:seen_at].to_i
      if started.positive? && Time.current.to_i - started <= ABSOLUTE_TIMEOUT && Time.current.to_i - seen <= IDLE_TIMEOUT
        @current_admin = Admin.active.find_by(id: id)
        session[:seen_at] = Time.current.to_i if @current_admin
      end
      reset_session unless @current_admin
    end
    @current_admin
  end

  def signed_in? = current_admin.present?

  # Tunnel SSO: the ZTLP gateway stamps HMAC-signed X-ZTLP-* headers on every
  # request from an authenticated tunnel. If the bundle's subject is a known,
  # active administrator, start a session for them (spec §4.2, "use ZTLP to
  # sign in"). A verified bundle is only ever produced by our own gateway.
  def gateway_sign_in!
    return if session[:no_sso_until].to_i > Time.current.to_i

    r = Ztlp::GatewayIdentity.verify(request.headers)
    return unless r.ok

    admin = Admin.active.find_by(username: r.subject.to_s.downcase)
    return unless admin

    sign_in!(admin)
    session[:via] = "ztlp"
    session[:device] = r.device_name
    AuditLog.record!("auth.login_ztlp", admin: admin, ip: request.remote_ip,
                     details: { device: r.device_name, zone: r.zone })
  end

  def sign_in!(admin)
    reset_session
    session[:admin_id] = admin.id
    session[:started_at] = Time.current.to_i
    session[:seen_at] = Time.current.to_i
    admin.update_columns(last_login_at: Time.current, last_login_ip: request.remote_ip)
  end

  def redirect_to_claim_if_unclaimed
    redirect_to claim_path if Claim.needed?
  end

  def require_sign_in
    redirect_to login_path, alert: "Please sign in." unless signed_in?
  end

  def require_write_access
    head :forbidden unless current_admin&.write_access?
  end

  def require_super_admin
    head :forbidden unless current_admin&.super_admin?
  end

  def audit!(action, target: nil, status: "ok", **details)
    AuditLog.record!(action, admin: current_admin, target: target, status: status, details: details,
                             ip: request.remote_ip)
  end
end
