# frozen_string_literal: true

class IdentityController < ApplicationController
  before_action :set_network

  def index
    @tab = params[:tab].presence || "overview"

    @users = @network.ztlp_users.includes(:ztlp_devices, :ztlp_groups)
    @devices = @network.ztlp_devices.includes(:ztlp_user, :machine)
    @groups = @network.ztlp_groups.includes(:group_memberships, :ztlp_users)

    # Counts for overview
    @active_users_count = @network.ztlp_users.active.count
    @suspended_users_count = @network.ztlp_users.suspended.count
    @enrolled_devices_count = @network.ztlp_devices.enrolled.count
    @groups_count = @network.ztlp_groups.count
    @revoked_count = @network.ztlp_users.revoked.count + @network.ztlp_devices.revoked.count

    # Apply filters for Users tab
    if @tab == "users"
      @users = apply_user_filters(@users)
    end

    # Apply filters for Devices tab
    if @tab == "devices"
      @devices = apply_device_filters(@devices)
    end

    # Sort
    @users = apply_user_sort(@users)
    @devices = @devices.order(:name)

    # Recent identity activity for overview
    @recent_activity = AuditLog.where("action LIKE ?", "ztlp_%")
                               .order(created_at: :desc)
                               .limit(15)
  end

  private

  def set_network
    @network = Network.find(params[:id])
  end

  def apply_user_filters(scope)
    scope = scope.where(role: params[:role]) if params[:role].present?
    scope = scope.where(status: params[:status]) if params[:status].present?
    if params[:search].present?
      term = "%#{params[:search]}%"
      scope = scope.where("name LIKE ? OR email LIKE ?", term, term)
    end
    scope
  end

  def apply_device_filters(scope)
    scope = scope.where(status: params[:device_status]) if params[:device_status].present?
    scope = scope.where(ztlp_user_id: params[:owner_id]) if params[:owner_id].present?
    if params[:device_search].present?
      term = "%#{params[:device_search]}%"
      scope = scope.where("name LIKE ?", term)
    end
    scope
  end

  def apply_user_sort(scope)
    allowed = %w[name role status created_at]
    col = allowed.include?(params[:sort]) ? params[:sort] : "name"
    dir = params[:dir] == "desc" ? :desc : :asc
    scope.order(col => dir)
  end
end
