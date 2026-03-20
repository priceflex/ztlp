# frozen_string_literal: true

class SessionsController < ApplicationController
  skip_before_action :require_authentication, only: [:new, :create]
  layout "login", only: [:new, :create]

  # GET /login
  def new
    redirect_to root_path if admin_signed_in?
  end

  # POST /login
  def create
    admin = AdminUser.find_by("LOWER(email) = ?", params[:email].to_s.downcase.strip)

    if admin.nil?
      flash.now[:alert] = "Invalid email or password."
      render :new, status: :unprocessable_entity
      return
    end

    if admin.locked?
      AuditLog.record(
        action: "admin_login_failed",
        target: admin,
        status: "failure",
        details: { reason: "account_locked", email: admin.email },
        ip_address: request.remote_ip
      )
      flash.now[:alert] = "Account locked. Try again in #{admin.lockout_minutes_remaining} minutes."
      render :new, status: :unprocessable_entity
      return
    end

    if admin.authenticate(params[:password].to_s)
      session[:admin_user_id] = admin.id
      admin.record_login!(request.remote_ip)

      AuditLog.record(
        action: "admin_login",
        target: admin,
        status: "success",
        details: { email: admin.email },
        ip_address: request.remote_ip
      )

      intended = session.delete(:intended_url) || root_path
      redirect_to intended, notice: "Signed in successfully."
    else
      admin.record_failed_login!

      AuditLog.record(
        action: admin.locked? ? "admin_locked" : "admin_login_failed",
        target: admin,
        status: "failure",
        details: { email: admin.email, failed_attempts: admin.failed_login_attempts },
        ip_address: request.remote_ip
      )

      if admin.locked?
        flash.now[:alert] = "Account locked. Try again in #{admin.lockout_minutes_remaining} minutes."
      else
        flash.now[:alert] = "Invalid email or password."
      end

      render :new, status: :unprocessable_entity
    end
  end

  # DELETE /logout
  def destroy
    session.delete(:admin_user_id)
    redirect_to login_path, notice: "Signed out successfully."
  end
end
