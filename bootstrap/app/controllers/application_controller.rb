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
    @current_admin ||= AdminUser.find_by(id: session[:admin_user_id]) || trusted_gateway_admin
  end

  def trusted_gateway_admin
    return unless ActiveModel::Type::Boolean.new.cast(ENV["ZTLP_TRUST_GATEWAY_AUTH"])
    return unless request.headers["X-ZTLP-Authenticated"].to_s == "1"

    email = request.headers["X-ZTLP-Admin-Email"].to_s.downcase.strip
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
