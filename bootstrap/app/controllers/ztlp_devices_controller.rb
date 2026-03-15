# frozen_string_literal: true

class ZtlpDevicesController < ApplicationController
  before_action :set_network
  before_action :set_device, only: [:show, :destroy]

  def index
    @devices = @network.ztlp_devices.includes(:ztlp_user, :machine).order(:name)
    @devices = @devices.where(ztlp_user_id: params[:user_id]) if params[:user_id].present?
    @devices = @devices.where(status: params[:status]) if params[:status].present?
  end

  def show
  end

  def destroy
    reason = params[:reason] || "Revoked via Bootstrap UI"
    @device.revoke!(reason: reason)
    AuditLog.record(
      action: "ztlp_device_revoke",
      target: @device,
      details: { name: @device.name, reason: reason, network: @network.name }
    )
    redirect_to network_ztlp_devices_path(@network), notice: "Device '#{@device.name}' revoked."
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_device
    @device = @network.ztlp_devices.find(params[:id])
  end
end
