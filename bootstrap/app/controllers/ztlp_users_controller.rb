# frozen_string_literal: true

class ZtlpUsersController < ApplicationController
  before_action :set_network
  before_action :set_user, only: [:show, :destroy, :suspend, :reactivate, :cascade_revoke, :update_role]

  def index
    @users = @network.ztlp_users.includes(:ztlp_devices, :ztlp_groups).order(:name)
  end

  def show
    @devices = @user.ztlp_devices.includes(:machine)
    @groups = @user.ztlp_groups
    @activity = AuditLog.for_target("ZtlpUser", @user.id).recent.limit(20)
  end

  def new
    @user = @network.ztlp_users.new(role: "user", status: "active")
  end

  def create
    @user = @network.ztlp_users.new(user_params)
    @user.status = "active"

    if @user.save
      AuditLog.record(
        action: "ztlp_user_create",
        target: @user,
        details: { name: @user.name, role: @user.role, network: @network.name }
      )
      redirect_to network_ztlp_user_path(@network, @user), notice: "User '#{@user.name}' created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    reason = params[:reason] || "Revoked via Bootstrap UI"
    @user.revoke!(reason: reason)
    AuditLog.record(
      action: "ztlp_user_revoke",
      target: @user,
      details: { name: @user.name, reason: reason, network: @network.name }
    )
    redirect_to network_ztlp_users_path(@network), notice: "User '#{@user.name}' revoked."
  end

  # POST /networks/:network_id/users/:id/suspend
  def suspend
    @user.suspend!
    AuditLog.record(
      action: "ztlp_user_suspend",
      target: @user,
      details: { name: @user.name, network: @network.name }
    )
    redirect_to network_ztlp_user_path(@network, @user), notice: "User '#{@user.name}' suspended."
  end

  # POST /networks/:network_id/users/:id/reactivate
  def reactivate
    @user.reactivate!
    AuditLog.record(
      action: "ztlp_user_reactivate",
      target: @user,
      details: { name: @user.name, network: @network.name }
    )
    redirect_to network_ztlp_user_path(@network, @user), notice: "User '#{@user.name}' reactivated."
  end

  # POST /networks/:network_id/users/:id/cascade_revoke
  def cascade_revoke
    reason = params[:reason] || "Cascade revoked via Bootstrap UI"
    device_count = @user.ztlp_devices.enrolled.count
    @user.cascade_revoke!(reason: reason)
    AuditLog.record(
      action: "ztlp_user_cascade_revoke",
      target: @user,
      details: { name: @user.name, reason: reason, devices_revoked: device_count, network: @network.name }
    )
    redirect_to network_ztlp_user_path(@network, @user), notice: "User '#{@user.name}' and #{device_count} device(s) revoked."
  end

  # PATCH /networks/:network_id/users/:id/update_role
  def update_role
    new_role = params[:role]
    if %w[user tech admin].include?(new_role) && @user.update(role: new_role)
      AuditLog.record(
        action: "ztlp_user_update_role",
        target: @user,
        details: { name: @user.name, role: new_role, network: @network.name }
      )
      redirect_to network_ztlp_user_path(@network, @user), notice: "Role updated to '#{new_role}'."
    else
      redirect_to network_ztlp_user_path(@network, @user), alert: "Invalid role."
    end
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_user
    @user = @network.ztlp_users.find(params[:id])
  end

  def user_params
    params.require(:ztlp_user).permit(:name, :role, :email)
  end
end
