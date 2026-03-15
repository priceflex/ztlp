# frozen_string_literal: true

class ZtlpUsersController < ApplicationController
  before_action :set_network
  before_action :set_user, only: [:show, :destroy]

  def index
    @users = @network.ztlp_users.includes(:ztlp_devices, :ztlp_groups).order(:name)
  end

  def show
    @devices = @user.ztlp_devices.includes(:machine)
    @groups = @user.ztlp_groups
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
