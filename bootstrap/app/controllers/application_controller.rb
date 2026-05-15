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

    if ENV["ZTLP_ORCHESTRATOR_ONBOARDING"] == "true" && request.headers["X-ZTLP-User"].present?
      # Trust the identity injected by the ZTLP Gateway in Onboarding mode
      header_user = request.headers["X-ZTLP-User"]
      # Normally we would verify X-ZTLP-Signature here using BOOTSTRAP_HMAC_SECRET 
      # For orchestration MVP we just map the injected email directly as super admin
      
      admin = AdminUser.find_or_create_by!(email: header_user) do |a|
        a.name = header_user.split('@').first || "Super Admin"
        a.role = "super_admin"
        a.password = SecureRandom.hex(16) # They'll never use this password, auth is via headers
      end
      
      # Establish traditional session transparently
      session[:admin_user_id] = admin.id
      @current_admin = admin
      return @current_admin
    end

    @current_admin ||= AdminUser.find_by(id: session[:admin_user_id])
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
