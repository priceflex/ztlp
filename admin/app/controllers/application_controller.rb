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
