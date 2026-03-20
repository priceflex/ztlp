# frozen_string_literal: true

module Admin
  class UsersController < ApplicationController
    before_action :require_super_admin
    before_action :set_admin_user, only: [:edit, :update, :destroy, :unlock]

    # GET /admin/users
    def index
      @admin_users = AdminUser.ordered
    end

    # GET /admin/users/new
    def new
      @admin_user = AdminUser.new
    end

    # POST /admin/users
    def create
      @admin_user = AdminUser.new(admin_user_params)

      if @admin_user.save
        AuditLog.record(
          action: "admin_created",
          target: @admin_user,
          status: "success",
          details: { email: @admin_user.email, role: @admin_user.role },
          ip_address: request.remote_ip
        )
        redirect_to admin_users_path, notice: "Admin user created successfully."
      else
        render :new, status: :unprocessable_entity
      end
    end

    # GET /admin/users/:id/edit
    def edit
    end

    # PATCH /admin/users/:id
    def update
      params_to_use = admin_user_params
      # Don't require password on update if not provided
      params_to_use = params_to_use.except(:password, :password_confirmation) if params_to_use[:password].blank?

      if @admin_user.update(params_to_use)
        AuditLog.record(
          action: "admin_updated",
          target: @admin_user,
          status: "success",
          details: { email: @admin_user.email, role: @admin_user.role },
          ip_address: request.remote_ip
        )
        redirect_to admin_users_path, notice: "Admin user updated successfully."
      else
        render :edit, status: :unprocessable_entity
      end
    end

    # DELETE /admin/users/:id
    def destroy
      if @admin_user == current_admin
        redirect_to admin_users_path, alert: "You cannot delete your own account."
        return
      end

      @admin_user.destroy!
      AuditLog.record(
        action: "admin_deleted",
        target: nil,
        status: "success",
        details: { email: @admin_user.email, name: @admin_user.name },
        ip_address: request.remote_ip
      )
      redirect_to admin_users_path, notice: "Admin user deleted."
    end

    # POST /admin/users/:id/unlock
    def unlock
      @admin_user.unlock!
      AuditLog.record(
        action: "admin_unlocked",
        target: @admin_user,
        status: "success",
        details: { email: @admin_user.email },
        ip_address: request.remote_ip
      )
      redirect_to admin_users_path, notice: "Account unlocked."
    end

    private

    def set_admin_user
      @admin_user = AdminUser.find(params[:id])
    end

    def admin_user_params
      params.require(:admin_user).permit(:email, :name, :password, :password_confirmation, :role)
    end
  end
end
