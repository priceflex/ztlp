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
