# frozen_string_literal: true

class ApplicationController < ActionController::Base
  helper_method :current_admin, :signed_in?

  before_action :require_gateway_identity
  before_action :redirect_to_claim_if_unclaimed
  before_action :require_sign_in
  before_action :load_zone

  IDLE_TIMEOUT = 8.hours
  ABSOLUTE_TIMEOUT = 24.hours

  private

  # Mandatory gateway gate (decision D5): in production the panel only answers
  # requests that carry a verified ZTLP gateway identity bundle. A verified
  # session is NOT sufficient on its own — every request must still come
  # through the gateway, so a stolen session cookie from another network is
  # dead. ZTLP_REQUIRE_GATEWAY defaults on in production; tests/dev default
  # off so the challenge/claim flow stays reachable locally.
  def require_gateway_identity
    return unless gateway_required?

    r = Ztlp::GatewayIdentity.verify(request.headers)
    unless r.ok
      AuditLog.record!("auth.gateway_rejected", ip: request.remote_ip, status: "denied", details: { error: r.error })
      return render "errors/connect_through_ztlp", status: :forbidden, layout: "bare"
    end

    @gateway_identity = r
    return if Ztlp::Assurance.level(r.assurance) >= Ztlp::Assurance.level(ENV.fetch("ZTLP_MIN_ASSURANCE", "unknown"))

    @gate_actual, @gate_required = r.assurance, ENV["ZTLP_MIN_ASSURANCE"]
    AuditLog.record!("auth.assurance_insufficient", ip: request.remote_ip, status: "denied",
                      details: { actual: r.assurance, required: ENV["ZTLP_MIN_ASSURANCE"] })
    render "errors/assurance_insufficient", status: :forbidden, layout: "bare"
  end

  def gateway_required? = ENV.fetch("ZTLP_REQUIRE_GATEWAY", Rails.env.production? ? "1" : "0") == "1"

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

    admin = Admin.active.find_by(username: sso_username(r.subject))
    return unless admin

    sign_in!(admin)
    session[:via] = "ztlp"
    session[:device] = r.device_name
    session[:assurance] = r.assurance
    AuditLog.record!("auth.login_ztlp", admin: admin, ip: request.remote_ip,
                     details: { device: r.device_name, zone: r.zone, assurance: r.assurance })
  end

  # The gateway subject is either the --admin-pubkey-email value ("steve") or the device's NS owner
  # ("steve@trs.ztlp" legacy CLI form, or "steve.users.trs.ztlp" once the panel publishes). An owner in the panel's OWN zone maps to the local admin name; any other
  # zone stays as-is and therefore matches no admin (usernames cannot contain "@").
  def sso_username(subject)
    name = subject.to_s.strip.downcase
    zone = Zone.primary&.name.to_s.downcase
    return name if zone.empty?

    local, domain = name.split("@", 2)
    return local if domain.present? && domain == zone

    users_suffix = ".users.#{zone}" # panel-published owner form (spec F4)
    name.end_with?(users_suffix) ? name.delete_suffix(users_suffix) : name
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

  def load_zone
    @zone ||= Zone.primary
  end

  # Accepts both styles: audit!(..., details: { a: 1 }) and audit!(..., a: 1). Both land at the TOP
  # level of the row's details (a `details:` kwarg used to be nested under details.details).
  def audit!(action, target: nil, status: "ok", details: nil, **extra)
    payload = (details || {}).to_h.merge(extra)
    AuditLog.record!(action, admin: current_admin, target: target, status: status, details: payload,
                             ip: request.remote_ip)
  end
end
